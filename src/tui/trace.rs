//! Field trace for the dashboard. A freeze in the field left no evidence once
//! the window was closed, so the dashboard writes a small timestamped log next
//! to its reports, and a watchdog thread records (and `sample`s) the UI loop or
//! the scan worker when either stops making progress.

use chrono::Local;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const UI_STALL: Duration = Duration::from_secs(5);
const WORKER_SILENT: Duration = Duration::from_secs(20);
const ALIVE_EVERY: Duration = Duration::from_secs(30);

struct Inner {
    file: Mutex<File>,
    started: Instant,
    dir: PathBuf,
    base: String,
}

/// Append-only trace file. A disabled trace (no writable folder) drops lines.
#[derive(Clone, Default)]
pub struct Trace(Option<Arc<Inner>>);

impl Trace {
    /// Create `MacTriage-<stamp>-trace.log` on the Desktop (else $HOME), 0600,
    /// never overwriting an existing file.
    pub fn open() -> Self {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        let dir = if home.join("Desktop").is_dir() {
            home.join("Desktop")
        } else {
            home
        };
        Self::open_in(&dir)
    }

    pub fn open_in(dir: &Path) -> Self {
        let base = format!("MacTriage-{}", Local::now().format("%Y%m%d-%H%M%S"));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.join(format!("{base}-trace.log")));
        match file {
            Ok(file) => Trace(Some(Arc::new(Inner {
                file: Mutex::new(file),
                started: Instant::now(),
                dir: dir.to_path_buf(),
                base,
            }))),
            Err(_) => Trace(None),
        }
    }

    pub fn path(&self) -> Option<PathBuf> {
        self.0
            .as_ref()
            .map(|i| i.dir.join(format!("{}-trace.log", i.base)))
    }

    pub fn line(&self, msg: impl AsRef<str>) {
        let Some(inner) = &self.0 else { return };
        let Ok(mut file) = inner.file.lock() else {
            return;
        };
        let _ = writeln!(
            file,
            "{} +{:>7.1}s {}",
            Local::now().format("%H:%M:%S%.3f"),
            inner.started.elapsed().as_secs_f64(),
            msg.as_ref()
        );
        let _ = file.flush();
    }

    /// Run `sample` on `pid` for 3 s and save the call stacks next to the trace.
    /// With `sudo`, uses `sudo -n` (the launcher's cached credential); it never
    /// prompts. Output is captured through stdout so a root-run sample still
    /// leaves a file the user owns.
    fn sample(&self, pid: u32, sudo: bool, tag: &str) {
        let Some(inner) = &self.0 else { return };
        let mut cmd = if sudo {
            let mut c = Command::new("/usr/bin/sudo");
            c.arg("-n").arg("/usr/bin/sample");
            c
        } else {
            Command::new("/usr/bin/sample")
        };
        cmd.arg(pid.to_string())
            .args(["3", "-mayDie", "-file", "/dev/stdout"]);
        let out = match cmd.output() {
            Ok(out) => out,
            Err(e) => {
                self.line(format!("sample {tag} pid {pid}: could not run: {e}"));
                return;
            }
        };
        if !out.status.success() || out.stdout.is_empty() {
            let err = String::from_utf8_lossy(&out.stderr);
            self.line(format!(
                "sample {tag} pid {pid}: failed ({}): {}",
                out.status,
                err.trim().chars().take(200).collect::<String>()
            ));
            return;
        }
        let path = inner
            .dir
            .join(format!("{}-{tag}-sample-{pid}.txt", inner.base));
        let saved = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .and_then(|mut f| f.write_all(&out.stdout));
        match saved {
            Ok(()) => self.line(format!("sample {tag} pid {pid}: saved {}", path.display())),
            Err(e) => self.line(format!("sample {tag} pid {pid}: could not save: {e}")),
        }
    }
}

/// Where the UI loop was when it last checked in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Stage {
    Poll = 0,
    Draw = 1,
    Input = 2,
    Key = 3,
}

impl Stage {
    fn name(v: u8) -> &'static str {
        match v {
            0 => "poll worker events",
            1 => "draw to terminal",
            2 => "wait for keyboard input",
            3 => "handle a key",
            _ => "unknown",
        }
    }
}

/// Shared liveness state read by the watchdog thread.
pub struct Heartbeat {
    epoch: Instant,
    ui_ms: AtomicU64,
    stage: AtomicU8,
    worker_ms: AtomicU64,
    worker_pid: AtomicU32,
    worker_sudo: AtomicBool,
    running: AtomicBool,
    progress_permille: AtomicU32,
    label: Mutex<String>,
}

impl Default for Heartbeat {
    fn default() -> Self {
        Self {
            epoch: Instant::now(),
            ui_ms: AtomicU64::new(0),
            stage: AtomicU8::new(Stage::Poll as u8),
            worker_ms: AtomicU64::new(0),
            worker_pid: AtomicU32::new(0),
            worker_sudo: AtomicBool::new(false),
            running: AtomicBool::new(false),
            progress_permille: AtomicU32::new(0),
            label: Mutex::new(String::new()),
        }
    }
}

impl Heartbeat {
    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    pub fn beat(&self, stage: Stage) {
        self.ui_ms.store(self.now_ms(), Ordering::Release);
        self.stage.store(stage as u8, Ordering::Release);
    }

    /// Called by the worker reader thread for every line it receives.
    pub fn worker_event(&self) {
        self.worker_ms.store(self.now_ms(), Ordering::Release);
    }

    pub fn worker_started(&self, pid: u32, sudo: bool) {
        self.worker_pid.store(pid, Ordering::Release);
        self.worker_sudo.store(sudo, Ordering::Release);
        self.worker_event();
        self.running.store(true, Ordering::Release);
    }

    pub fn worker_stopped(&self) {
        self.running.store(false, Ordering::Release);
    }

    pub fn progress(&self, overall: f64, label: &str) {
        self.progress_permille
            .store((overall.clamp(0.0, 1.0) * 1000.0) as u32, Ordering::Release);
        if let Ok(mut l) = self.label.lock() {
            l.clear();
            l.push_str(label);
        }
    }

    fn label(&self) -> String {
        self.label.lock().map(|l| l.clone()).unwrap_or_default()
    }
}

/// The process to sample for the worker. Under sudo the direct child is the
/// sudo process, so take its child (sudo forks the command).
fn worker_target(hb: &Heartbeat) -> Option<(u32, bool)> {
    let pid = hb.worker_pid.load(Ordering::Acquire);
    if pid == 0 {
        return None;
    }
    if !hb.worker_sudo.load(Ordering::Acquire) {
        return Some((pid, false));
    }
    let out = Command::new("/usr/bin/pgrep")
        .args(["-P", &pid.to_string()])
        .output()
        .ok()?;
    let child = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()?
        .trim()
        .parse()
        .ok()?;
    Some((child, true))
}

/// Start the watchdog thread. It runs until the process exits.
pub fn spawn_watchdog(trace: Trace, hb: Arc<Heartbeat>) {
    if trace.0.is_none() {
        return;
    }
    std::thread::spawn(move || {
        let mut ui_reported = false;
        let mut worker_reported = false;
        let mut last_alive = Instant::now();
        loop {
            std::thread::sleep(Duration::from_secs(1));
            let now = hb.now_ms();
            let ui_age =
                Duration::from_millis(now.saturating_sub(hb.ui_ms.load(Ordering::Acquire)));
            let stage = Stage::name(hb.stage.load(Ordering::Acquire));
            if ui_age > UI_STALL && !ui_reported {
                ui_reported = true;
                trace.line(format!(
                    "STALL: UI loop has not checked in for {:.0}s; last stage: {stage}",
                    ui_age.as_secs_f64()
                ));
                trace.sample(std::process::id(), false, "ui");
            } else if ui_age <= UI_STALL && ui_reported {
                ui_reported = false;
                trace.line("UI loop resumed");
            }

            let running = hb.running.load(Ordering::Acquire);
            let worker_age =
                Duration::from_millis(now.saturating_sub(hb.worker_ms.load(Ordering::Acquire)));
            if running && worker_age > WORKER_SILENT && !worker_reported {
                worker_reported = true;
                trace.line(format!(
                    "STALL: no worker output for {:.0}s; last label: {}",
                    worker_age.as_secs_f64(),
                    hb.label()
                ));
                match worker_target(&hb) {
                    Some((pid, sudo)) => trace.sample(pid, sudo, "worker"),
                    None => trace.line("sample worker: worker process not found"),
                }
            } else if worker_reported && (!running || worker_age <= WORKER_SILENT) {
                worker_reported = false;
                trace.line("worker output resumed");
            }

            if running && last_alive.elapsed() >= ALIVE_EVERY {
                last_alive = Instant::now();
                trace.line(format!(
                    "alive: {:.1}% · {} · UI stage {stage} ({:.1}s ago) · last worker output {:.1}s ago",
                    hb.progress_permille.load(Ordering::Acquire) as f64 / 10.0,
                    hb.label(),
                    ui_age.as_secs_f64(),
                    worker_age.as_secs_f64()
                ));
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::Trace;

    #[test]
    fn trace_writes_lines_and_never_overwrites() {
        let dir = std::env::temp_dir().join(format!("mactriage-trace-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let t = Trace::open_in(&dir);
        let path = t.path().expect("trace enabled");
        t.line("hello");
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("hello"), "{body}");
        // Same second, same name: create_new must refuse rather than truncate.
        let again = Trace::open_in(&dir);
        if again.path() == Some(path.clone()) {
            panic!("second trace reported the same path");
        }
        assert!(std::fs::read_to_string(&path).unwrap().contains("hello"));
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    #[ignore = "slow (~10 s) and runs /usr/bin/sample; run with --ignored"]
    fn watchdog_reports_and_samples_a_stalled_ui_loop() {
        let dir = std::env::temp_dir().join(format!("mactriage-wd-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let t = Trace::open_in(&dir);
        let path = t.path().unwrap();
        // The UI loop never beats, so the watchdog must see a stall after 5 s.
        super::spawn_watchdog(t, std::sync::Arc::default());
        std::thread::sleep(std::time::Duration::from_secs(11));
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("STALL: UI loop"), "{body}");
        assert!(
            body.contains("sample ui pid") && body.contains("saved"),
            "{body}"
        );
    }

    #[test]
    fn missing_folder_disables_trace() {
        let t = Trace::open_in(std::path::Path::new("/nonexistent/mactriage"));
        assert!(t.path().is_none());
        t.line("dropped");
    }
}
