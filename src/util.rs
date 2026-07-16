use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Limit for `run`: every caller asks a quick status question, so a command
/// still running after this is hung (e.g. `tmutil` waiting on an absent disk).
pub const RUN_TIMEOUT: Duration = Duration::from_secs(30);

/// Run a command, capture stdout as UTF-8 (lossy). Returns None on spawn failure,
/// timeout, or non-zero exit with empty stdout.
pub fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = capture(cmd, args, RUN_TIMEOUT)?;
    if out.timed_out || (!out.success && out.stdout.trim().is_empty()) {
        return None;
    }
    Some(out.stdout)
}

/// Run a command with a hard wall-clock timeout, killing it and returning
/// whatever stdout was produced so far (partial results are useful for `log show`).
pub fn run_with_timeout(cmd: &str, args: &[&str], timeout: Duration) -> (String, bool) {
    capture(cmd, args, timeout)
        .map(|out| (out.stdout, out.timed_out))
        .unwrap_or_default()
}

/// What one bounded command run produced. `success` is false after a timeout kill.
pub struct Captured {
    pub stdout: String,
    pub stderr: String,
    pub success: bool,
    pub timed_out: bool,
}

/// Run a command with stdin closed and a hard wall-clock timeout. On expiry the
/// child is killed and the output so far is kept. None only on spawn failure.
pub fn capture(cmd: &str, args: &[&str], timeout: Duration) -> Option<Captured> {
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    // Drain both pipes on threads so a chatty child can't block on a full pipe.
    fn drain(mut pipe: impl Read + Send + 'static) -> std::sync::mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = pipe.read_to_end(&mut buf);
            let _ = tx.send(buf);
        });
        rx
    }
    let stdout = drain(child.stdout.take()?);
    let stderr = drain(child.stderr.take()?);
    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = child.kill();
                timed_out = true;
                let _ = child.wait();
                break None;
            }
            Err(_) => break None,
        }
    };
    // A grandchild can hold a pipe open after the child exits; don't wait forever.
    let text = |rx: std::sync::mpsc::Receiver<Vec<u8>>| {
        let buf = rx.recv_timeout(Duration::from_secs(5)).unwrap_or_default();
        String::from_utf8_lossy(&buf).into_owned()
    };
    Some(Captured {
        stdout: text(stdout),
        stderr: text(stderr),
        success: status.is_some_and(|s| s.success()),
        timed_out,
    })
}

/// Real executable path of a running process, from the kernel (`proc_pidpath`).
/// Unlike `ps -o comm=`, the process cannot spoof it by rewriting argv[0].
pub fn pid_path(pid: u32) -> Option<String> {
    // PROC_PIDPATHINFO_MAXSIZE (4 × MAXPATHLEN) from <libproc.h>.
    let mut buf = vec![0u8; 4096];
    let len = unsafe { proc_pidpath(pid as i32, buf.as_mut_ptr(), buf.len() as u32) };
    (len > 0).then(|| String::from_utf8_lossy(&buf[..len as usize]).into_owned())
}

/// Outcome of a `stream_lines` pass. `timed_out` and `spawn_failed` are the
/// obvious failures; `exit_ok` is false when the child exited non-zero on its
/// own (not from our kill), which — for a tool whose job is telling the truth
/// about a Mac — must never be mistaken for "scanned clean". `stderr_tail`
/// carries a short reason for the report note.
#[derive(Default)]
pub struct StreamOutcome {
    pub timed_out: bool,
    pub cancelled: bool,
    pub spawn_failed: bool,
    pub exit_ok: bool,
    pub stderr_tail: String,
}

/// Stream a command's stdout line by line into `on_line`, with a hard wall-clock
/// timeout. Lines that arrived before the child exited (or was killed) are all
/// delivered — the drain blocks on the reader until EOF so the newest lines are
/// never dropped.
pub fn stream_lines(
    cmd: &str,
    args: &[&str],
    timeout: Duration,
    cancel: &crate::progress::CancellationToken,
    mut on_line: impl FnMut(&str),
    mut on_tick: impl FnMut(),
) -> StreamOutcome {
    use std::io::BufRead;
    if cancel.is_cancelled() {
        return StreamOutcome {
            cancelled: true,
            exit_ok: true,
            ..Default::default()
        };
    }
    let child = Command::new(cmd)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(_) => {
            return StreamOutcome {
                spawn_failed: true,
                ..Default::default()
            }
        }
    };
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let reader = std::thread::spawn(move || {
        let buf = std::io::BufReader::new(stdout);
        for line in buf.lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    // Drain stderr concurrently so a chatty error stream can't deadlock the pipe.
    let err_reader = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = std::io::BufReader::new(stderr).read_to_string(&mut s);
        s
    });
    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let mut cancelled = false;
    // Blocking drain of every queued line until the reader closes the channel
    // at stdout EOF — the fix for the tail-loss race where the newest events
    // were dropped when the child exited mid-buffer.
    let drain = |on_line: &mut dyn FnMut(&str)| {
        while let Ok(line) = rx.recv() {
            on_line(&line);
        }
    };
    loop {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(line) => on_line(&line),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if child.try_wait().ok().flatten().is_some() {
                    drain(&mut on_line);
                    break;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
        on_tick();
        if cancel.is_cancelled() {
            let _ = child.kill();
            cancelled = true;
            drain(&mut on_line);
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            timed_out = true;
            drain(&mut on_line);
            break;
        }
    }
    let status = child.wait().ok();
    let _ = reader.join();
    let stderr_out = err_reader.join().unwrap_or_default();
    // A timeout kill produces a non-success status by design — that's not an error.
    let exit_ok = timed_out || cancelled || status.map(|s| s.success()).unwrap_or(false);
    let stderr_tail = stderr_out
        .lines()
        .filter(|l| !l.trim().is_empty())
        .rev()
        .take(3)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("; ");
    StreamOutcome {
        timed_out,
        cancelled,
        spawn_failed: false,
        exit_ok,
        stderr_tail,
    }
}

/// Parse "30m" / "6h" / "24h" / "3d" / "2w" into a Duration.
pub fn parse_window(s: &str) -> Option<Duration> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.len().checked_sub(1)?);
    let n: u64 = num.parse().ok()?;
    let secs = match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 3600,
        "d" => n * 86400,
        "w" => n * 604800,
        _ => return None,
    };
    Some(Duration::from_secs(secs))
}

pub fn is_root() -> bool {
    unsafe { libc_geteuid() == 0 }
}

/// True on Apple silicon, even when this binary runs under Rosetta
/// (`hw.optional.arm64` reports the hardware, not the process architecture).
pub fn is_apple_silicon() -> bool {
    static CACHE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *CACHE.get_or_init(|| {
        run("/usr/sbin/sysctl", &["-n", "hw.optional.arm64"])
            .map(|s| s.trim() == "1")
            .unwrap_or(false)
    })
}

/// How to start Apple Diagnostics on this Mac, per Apple Support "Use Apple
/// Diagnostics to test your Mac" (support.apple.com/102550). Holding D alone
/// only works on Intel Macs.
pub fn apple_diagnostics_step() -> &'static str {
    if is_apple_silicon() {
        "Run Apple Diagnostics: shut down, press and hold the power button (Touch ID on \
         laptops) until the startup options appear, release it, then press and hold ⌘D"
    } else {
        "Run Apple Diagnostics: turn the Mac on and immediately press and hold D (or ⌥D if \
         D doesn't work) until the diagnostics screen appears"
    }
}

extern "C" {
    #[link_name = "geteuid"]
    fn libc_geteuid() -> u32;
    fn proc_pidpath(pid: i32, buffer: *mut u8, buffersize: u32) -> i32;
}

/// "1d 14h" style uptime from seconds.
pub fn human_duration(secs: u64) -> String {
    let d = secs / 86400;
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else {
        format!("{m}m")
    }
}

pub fn human_bytes(b: u64) -> String {
    const G: f64 = 1_000_000_000.0;
    const M: f64 = 1_000_000.0;
    let b = b as f64;
    if b >= G {
        format!("{:.1} GB", b / G)
    } else {
        format!("{:.0} MB", b / M)
    }
}

/// Wrap text to `width`, indenting continuation lines with `indent`.
pub fn wrap(text: &str, width: usize, indent: &str) -> String {
    let mut out = String::new();
    let mut line_len = 0usize;
    for word in text.split_whitespace() {
        if line_len == 0 {
            out.push_str(word);
            line_len = word.len();
        } else if line_len + 1 + word.len() > width {
            out.push('\n');
            out.push_str(indent);
            out.push_str(word);
            line_len = indent.len() + word.len();
        } else {
            out.push(' ');
            out.push_str(word);
            line_len += 1 + word.len();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::stream_lines;
    use crate::progress::CancellationToken;
    use std::time::{Duration, Instant};

    #[test]
    fn cancellation_stops_and_reaps_streamed_child() {
        let cancel = CancellationToken::default();
        let signal = cancel.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            signal.cancel();
        });
        let started = Instant::now();
        let outcome = stream_lines(
            "/bin/sleep",
            &["5"],
            Duration::from_secs(10),
            &cancel,
            |_| {},
            || {},
        );
        assert!(outcome.cancelled);
        assert!(outcome.exit_ok);
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
