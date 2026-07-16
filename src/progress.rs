//! Live progress bar on stderr. Real progress, not a spinner: the unified-log
//! pass reports the timestamp of each line it streams, so the bar tracks how
//! much of the requested window has actually been scanned.

use std::io::Write;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};

const BAR_CELLS: usize = 28;

struct Bar {
    /// Current phase occupies [base, base+span] of the overall 0..1 bar.
    base: f64,
    span: f64,
    frac: f64,
    label: String,
    last_draw: Instant,
    drawn: bool,
}

pub struct Progress {
    inner: Option<Mutex<Bar>>,
}

/// Output-independent progress contract used by the CLI bar and the TUI worker
/// protocol. Fractions passed to `update` are relative to the current phase.
pub trait Reporter: Send + Sync {
    fn phase(&self, base: f64, span: f64, label: &str);
    fn update(&self, frac: f64, label: Option<&str>);
    fn finish(&self);
}

#[derive(Clone, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

impl Progress {
    pub fn new(enabled: bool) -> Self {
        use std::io::IsTerminal;
        let on = enabled
            && (std::io::stderr().is_terminal()
                || std::env::var_os("MACTRIAGE_FORCE_PROGRESS").is_some());
        Progress {
            inner: on.then(|| {
                Mutex::new(Bar {
                    base: 0.0,
                    span: 1.0,
                    frac: 0.0,
                    label: String::new(),
                    last_draw: Instant::now() - Duration::from_secs(1),
                    drawn: false,
                })
            }),
        }
    }

    pub fn disabled() -> Self {
        Progress { inner: None }
    }

    /// Enter a phase occupying [base, base+span] of the overall bar.
    fn set_phase(&self, base: f64, span: f64, label: &str) {
        let Some(m) = &self.inner else { return };
        let mut b = m.lock().unwrap();
        b.base = base;
        b.span = span;
        b.frac = 0.0;
        b.label = label.to_string();
        draw(&mut b, true);
    }

    /// Update progress within the current phase (0..1), optionally relabeling.
    fn set_update(&self, frac: f64, label: Option<&str>) {
        let Some(m) = &self.inner else { return };
        let mut b = m.lock().unwrap();
        b.frac = frac.clamp(0.0, 1.0);
        if let Some(l) = label {
            b.label = l.to_string();
        }
        draw(&mut b, false);
    }

    /// Clear the bar line (call before printing the report).
    fn clear(&self) {
        let Some(m) = &self.inner else { return };
        let b = m.lock().unwrap();
        if b.drawn {
            eprint!("\r\x1b[2K");
            let _ = std::io::stderr().flush();
        }
    }
}

impl Reporter for Progress {
    fn phase(&self, base: f64, span: f64, label: &str) {
        self.set_phase(base, span, label);
    }

    fn update(&self, frac: f64, label: Option<&str>) {
        self.set_update(frac, label);
    }

    fn finish(&self) {
        self.clear();
    }
}

fn draw(b: &mut Bar, force: bool) {
    // Throttle redraws; a busy log pass can call update thousands of times/sec.
    if !force && b.last_draw.elapsed() < Duration::from_millis(100) {
        return;
    }
    b.last_draw = Instant::now();
    b.drawn = true;
    let overall = (b.base + b.frac * b.span).clamp(0.0, 1.0);
    let filled = (overall * BAR_CELLS as f64).round() as usize;
    let bar: String = "█".repeat(filled) + &"░".repeat(BAR_CELLS - filled);
    eprint!("\r\x1b[2K  ▕{bar}▏ {:>3.0}% · {}", overall * 100.0, b.label);
    let _ = std::io::stderr().flush();
}
