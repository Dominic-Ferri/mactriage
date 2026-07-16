//! Private newline-delimited JSON protocol between the unprivileged TUI and a
//! bundled scan worker. This keeps Terminal UI state and exported files owned by
//! the logged-in user while allowing only the read-only scanner to run via sudo.

use crate::progress::{CancellationToken, Reporter};
use crate::report::Report;
use crate::scan::{self, ScanOpts, SnapshotOpts};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufWriter, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Args, Debug)]
pub struct WorkerOpts {
    #[command(subcommand)]
    pub action: WorkerAction,
}

#[derive(Subcommand, Debug)]
pub enum WorkerAction {
    Scan(ScanOpts),
    Snapshot(SnapshotOpts),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum WorkerEvent {
    Progress { overall: f64, label: String },
    Complete { report: Box<Report> },
    Cancelled { report: Box<Report> },
    Error { code: i32, message: String },
}

#[derive(Clone)]
struct ProtocolWriter {
    out: Arc<Mutex<BufWriter<std::io::Stdout>>>,
}

impl ProtocolWriter {
    fn new() -> Self {
        Self {
            out: Arc::new(Mutex::new(BufWriter::new(std::io::stdout()))),
        }
    }

    fn send(&self, event: &WorkerEvent) -> bool {
        let Ok(mut out) = self.out.lock() else {
            return false;
        };
        serde_json::to_writer(&mut *out, event).is_ok()
            && out.write_all(b"\n").is_ok()
            && out.flush().is_ok()
    }
}

struct ProtocolState {
    base: f64,
    span: f64,
    label: String,
    last_send: Instant,
}

struct ProtocolProgress {
    writer: ProtocolWriter,
    cancel: CancellationToken,
    state: Mutex<ProtocolState>,
}

impl ProtocolProgress {
    fn new(writer: ProtocolWriter, cancel: CancellationToken) -> Self {
        Self {
            writer,
            cancel,
            state: Mutex::new(ProtocolState {
                base: 0.0,
                span: 1.0,
                label: String::new(),
                last_send: Instant::now() - Duration::from_secs(1),
            }),
        }
    }

    fn emit(&self, overall: f64, label: String) {
        if !self.writer.send(&WorkerEvent::Progress {
            overall: overall.clamp(0.0, 1.0),
            label,
        }) {
            self.cancel.cancel();
        }
    }
}

impl Reporter for ProtocolProgress {
    fn phase(&self, base: f64, span: f64, label: &str) {
        let Ok(mut state) = self.state.lock() else {
            self.cancel.cancel();
            return;
        };
        state.base = base;
        state.span = span;
        state.label = label.to_string();
        state.last_send = Instant::now();
        let overall = base.clamp(0.0, 1.0);
        let label = state.label.clone();
        drop(state);
        self.emit(overall, label);
    }

    fn update(&self, frac: f64, label: Option<&str>) {
        let Ok(mut state) = self.state.lock() else {
            self.cancel.cancel();
            return;
        };
        if let Some(label) = label {
            state.label = label.to_string();
        }
        let force = frac >= 1.0;
        if !force && state.last_send.elapsed() < Duration::from_millis(75) {
            return;
        }
        state.last_send = Instant::now();
        let overall = state.base + frac.clamp(0.0, 1.0) * state.span;
        let label = state.label.clone();
        drop(state);
        self.emit(overall, label);
    }

    fn finish(&self) {}
}

pub fn run_worker(opts: WorkerOpts) -> i32 {
    let cancel = CancellationToken::default();
    let cancel_reader = cancel.clone();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut line = String::new();
        if stdin.lock().read_line(&mut line).is_ok()
            && (line.trim().eq_ignore_ascii_case("cancel") || line.is_empty())
        {
            cancel_reader.cancel();
        }
    });

    let writer = ProtocolWriter::new();
    let progress = ProtocolProgress::new(writer.clone(), cancel.clone());
    let result = match opts.action {
        WorkerAction::Scan(scan_opts) => scan::collect_scan(&scan_opts, &progress, &cancel),
        WorkerAction::Snapshot(snapshot_opts) => {
            Ok(scan::collect_snapshot(&snapshot_opts, &progress, &cancel))
        }
    };

    match result {
        Ok(run) if run.cancelled => {
            let sent = writer.send(&WorkerEvent::Cancelled {
                report: Box::new(run.report),
            });
            if sent {
                130
            } else {
                70
            }
        }
        Ok(run) => {
            let code = run.report.exit_code();
            if writer.send(&WorkerEvent::Complete {
                report: Box::new(run.report),
            }) {
                code
            } else {
                70
            }
        }
        Err(error) => {
            let _ = writer.send(&WorkerEvent::Error {
                code: error.code,
                message: error.message,
            });
            error.code
        }
    }
}

#[cfg(test)]
mod tests {
    use super::WorkerEvent;

    #[test]
    fn progress_event_round_trips() {
        let event = WorkerEvent::Progress {
            overall: 0.42,
            label: "unified log".into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let decoded: WorkerEvent = serde_json::from_str(&json).unwrap();
        match decoded {
            WorkerEvent::Progress { overall, label } => {
                assert_eq!(overall, 0.42);
                assert_eq!(label, "unified log");
            }
            _ => panic!("wrong event variant"),
        }
    }
}
