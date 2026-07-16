use crate::protocol::WorkerEvent;
use crate::report::{HostInfo, Report};
use chrono::Local;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Home,
    Running,
    Results,
    Rules,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Full,
    Fast,
    Snapshot,
}

impl Profile {
    pub const ALL: [Self; 3] = [Self::Full, Self::Fast, Self::Snapshot];

    pub fn label(self) -> &'static str {
        match self {
            Self::Full => "Full scan",
            Self::Fast => "Fast scan",
            Self::Snapshot => "Live snapshot",
        }
    }

    pub fn detail(self) -> &'static str {
        match self {
            Self::Full => "6h unified log · 7d DiagnosticReports · all audits",
            Self::Fast => "DiagnosticReports, vitals, and audits · unified log skipped",
            Self::Snapshot => "Current memory, thermal, disk, battery, and network only",
        }
    }

    fn worker_args(self) -> Vec<&'static str> {
        match self {
            Self::Full => vec!["__worker", "scan", "--full"],
            Self::Fast => vec!["__worker", "scan", "--no-log", "--full"],
            Self::Snapshot => vec!["__worker", "snapshot"],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultTab {
    Summary,
    Findings,
    Recovery,
    Vitals,
    Coverage,
}

impl ResultTab {
    pub const ALL: [Self; 5] = [
        Self::Summary,
        Self::Findings,
        Self::Recovery,
        Self::Vitals,
        Self::Coverage,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Summary => "Summary",
            Self::Findings => "Findings",
            Self::Recovery => "Recovery",
            Self::Vitals => "Vitals",
            Self::Coverage => "Coverage",
        }
    }
}

enum BackgroundEvent {
    Worker(WorkerEvent),
    Stderr(String),
    StreamClosed,
}

struct WorkerControl {
    child: Child,
    stdin: ChildStdin,
}

impl WorkerControl {
    fn request_cancel(&mut self) -> std::io::Result<()> {
        self.stdin.write_all(b"cancel\n")?;
        self.stdin.flush()
    }
}

pub struct App {
    pub screen: Screen,
    pub profile_index: usize,
    pub progress: f64,
    pub progress_label: String,
    pub report: Option<Report>,
    pub selected_finding: usize,
    pub result_scroll: u16,
    pub result_tab: ResultTab,
    pub rules_scroll: u16,
    pub status: String,
    pub show_help: bool,
    pub privileged: bool,
    pub host: HostInfo,
    pub started_at: Option<Instant>,
    pub cancelling: bool,
    should_quit: bool,
    quit_after_worker: bool,
    export_armed: bool,
    worker: Option<WorkerControl>,
    background_tx: Sender<BackgroundEvent>,
    background_rx: Receiver<BackgroundEvent>,
    exit_code: i32,
    worker_had_terminal_event: bool,
    worker_exited: bool,
    worker_stream_closed: bool,
    worker_exit_description: String,
    worker_stderr: String,
}

impl App {
    pub fn new(privileged: bool) -> Self {
        let (background_tx, background_rx) = mpsc::channel();
        Self {
            screen: Screen::Home,
            profile_index: 0,
            progress: 0.0,
            progress_label: "ready".into(),
            report: None,
            selected_finding: 0,
            result_scroll: 0,
            result_tab: ResultTab::Summary,
            rules_scroll: 0,
            status: if privileged {
                "Full coverage authorized for this launch".into()
            } else {
                "Reduced coverage: privileged sources will be reported as skipped".into()
            },
            show_help: false,
            privileged,
            host: crate::host::host_info(false),
            started_at: None,
            cancelling: false,
            should_quit: false,
            quit_after_worker: false,
            export_armed: false,
            worker: None,
            background_tx,
            background_rx,
            exit_code: 0,
            worker_had_terminal_event: false,
            worker_exited: false,
            worker_stream_closed: false,
            worker_exit_description: String::new(),
            worker_stderr: String::new(),
        }
    }

    pub fn selected_profile(&self) -> Profile {
        Profile::ALL[self.profile_index]
    }

    pub fn should_quit(&self) -> bool {
        self.should_quit
    }

    pub fn exit_code(&self) -> i32 {
        self.exit_code
    }

    pub fn cancel_and_reap_worker(&mut self) {
        let Some(worker) = self.worker.as_mut() else {
            return;
        };
        let _ = worker.request_cancel();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match worker.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Ok(None) | Err(_) => {
                    let _ = worker.child.kill();
                    let _ = worker.child.wait();
                    break;
                }
            }
        }
        self.worker = None;
    }

    pub fn elapsed(&self) -> Duration {
        self.started_at
            .map(|time| time.elapsed())
            .unwrap_or_default()
    }

    pub fn start_selected(&mut self) {
        if self.worker.is_some() {
            return;
        }
        let profile = self.selected_profile();
        match self.spawn_worker(profile) {
            Ok(worker) => {
                self.worker = Some(worker);
                self.screen = Screen::Running;
                self.progress = 0.0;
                self.progress_label = "starting scan worker".into();
                self.status = format!("{} started", profile.label());
                self.report = None;
                self.selected_finding = 0;
                self.result_scroll = 0;
                self.started_at = Some(Instant::now());
                self.cancelling = false;
                self.quit_after_worker = false;
                self.export_armed = false;
                self.worker_had_terminal_event = false;
                self.worker_exited = false;
                self.worker_stream_closed = false;
                self.worker_exit_description.clear();
                self.worker_stderr.clear();
            }
            Err(error) => {
                self.status = format!("Could not start scan: {error}");
                self.exit_code = 70;
            }
        }
    }

    fn spawn_worker(&self, profile: Profile) -> std::io::Result<WorkerControl> {
        let executable = std::env::current_exe()?;
        let mut command = if self.privileged {
            let mut command = Command::new("/usr/bin/sudo");
            command.arg("-n").arg(&executable);
            command
        } else {
            Command::new(&executable)
        };
        command
            .args(profile.worker_args())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("worker stdin was not available"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("worker stdout was not available"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| std::io::Error::other("worker stderr was not available"))?;

        let event_tx = self.background_tx.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                match line {
                    Ok(line) if line.trim().is_empty() => {}
                    Ok(line) => match serde_json::from_str::<WorkerEvent>(&line) {
                        Ok(event) => {
                            if event_tx.send(BackgroundEvent::Worker(event)).is_err() {
                                return;
                            }
                        }
                        Err(error) => {
                            let _ = event_tx.send(BackgroundEvent::Stderr(format!(
                                "worker protocol error: {error}"
                            )));
                        }
                    },
                    Err(error) => {
                        let _ = event_tx.send(BackgroundEvent::Stderr(format!(
                            "worker stream error: {error}"
                        )));
                        break;
                    }
                }
            }
            let _ = event_tx.send(BackgroundEvent::StreamClosed);
        });

        let error_tx = self.background_tx.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                if !line.trim().is_empty() && error_tx.send(BackgroundEvent::Stderr(line)).is_err()
                {
                    break;
                }
            }
        });
        Ok(WorkerControl { child, stdin })
    }

    pub fn poll_background(&mut self) -> bool {
        let mut changed = false;
        while let Ok(event) = self.background_rx.try_recv() {
            changed = true;
            match event {
                BackgroundEvent::Worker(event) => self.handle_worker_event(event),
                BackgroundEvent::Stderr(line) => {
                    self.worker_stderr = line.chars().take(240).collect();
                }
                BackgroundEvent::StreamClosed => {
                    self.worker_stream_closed = true;
                    self.finalize_worker_state();
                }
            }
        }

        let status = match self.worker.as_mut() {
            Some(worker) => Some(worker.child.try_wait()),
            None => None,
        };
        match status {
            Some(Ok(Some(status))) => {
                changed = true;
                self.worker = None;
                self.worker_exited = true;
                self.worker_exit_description = status.to_string();
                self.finalize_worker_state();
            }
            Some(Ok(None)) | None => {}
            Some(Err(error)) => {
                changed = true;
                self.worker = None;
                self.worker_exited = true;
                self.worker_stream_closed = true;
                self.worker_exit_description = format!("status error: {error}");
                self.finalize_worker_state();
            }
        }
        changed
    }

    fn finalize_worker_state(&mut self) {
        if self.worker_had_terminal_event {
            if self.worker_exited && self.quit_after_worker {
                self.should_quit = true;
            }
            return;
        }
        if self.worker_exited && self.worker_stream_closed {
            self.screen = Screen::Home;
            self.exit_code = 70;
            self.status = if self.worker_stderr.is_empty() {
                format!(
                    "Scan worker exited unexpectedly ({})",
                    self.worker_exit_description
                )
            } else {
                format!("Scan worker failed: {}", self.worker_stderr)
            };
            if self.quit_after_worker {
                self.should_quit = true;
            }
        }
    }

    fn handle_worker_event(&mut self, event: WorkerEvent) {
        match event {
            WorkerEvent::Progress { overall, label } => {
                self.progress = overall.clamp(0.0, 1.0);
                self.progress_label = label;
            }
            WorkerEvent::Complete { report } => {
                self.worker_had_terminal_event = true;
                self.exit_code = report.exit_code();
                self.report = Some(*report);
                self.result_tab = ResultTab::Summary;
                self.result_scroll = 0;
                self.screen = Screen::Results;
                self.progress = 1.0;
                // Auto-save the report so a tech who quits without pressing
                // `e e` still walks away with the evidence (field request:
                // "it didn't generate any logs next to it").
                self.export_report();
                self.status = format!("Scan complete — {}", self.status);
                self.finalize_worker_state();
            }
            WorkerEvent::Cancelled { report } => {
                self.worker_had_terminal_event = true;
                self.exit_code = 130;
                self.report = Some(*report);
                self.result_tab = ResultTab::Coverage;
                self.result_scroll = 0;
                self.screen = Screen::Results;
                self.status = "Scan cancelled — partial results only".into();
                self.finalize_worker_state();
            }
            WorkerEvent::Error { code, message } => {
                self.worker_had_terminal_event = true;
                self.exit_code = code;
                self.screen = Screen::Home;
                self.status = format!("Scan failed: {message}");
                self.finalize_worker_state();
            }
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) {
        self.export_armed &= key.code == KeyCode::Char('e');
        if self.show_help {
            if matches!(
                key.code,
                KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q')
            ) {
                self.show_help = false;
            }
            return;
        }
        if key.code == KeyCode::Char('?') {
            self.show_help = true;
            return;
        }
        match self.screen {
            Screen::Home => self.handle_home_key(key),
            Screen::Running => self.handle_running_key(key),
            Screen::Results => self.handle_results_key(key),
            Screen::Rules => self.handle_rules_key(key),
        }
    }

    fn handle_home_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.profile_index = self.profile_index.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.profile_index = (self.profile_index + 1).min(Profile::ALL.len() - 1);
            }
            KeyCode::Enter => self.start_selected(),
            KeyCode::Char('l') => {
                self.screen = Screen::Rules;
                self.rules_scroll = 0;
            }
            KeyCode::Char('q') => self.should_quit = true,
            _ => {}
        }
    }

    fn handle_running_key(&mut self, key: KeyEvent) {
        if matches!(key.code, KeyCode::Esc | KeyCode::Char('q')) && !self.cancelling {
            self.cancelling = true;
            self.quit_after_worker = key.code == KeyCode::Char('q');
            self.status = "Cancelling safely; waiting for the scanner to exit…".into();
            if let Some(worker) = self.worker.as_mut() {
                if let Err(error) = worker.request_cancel() {
                    self.status = format!("Could not signal cancellation: {error}");
                }
            }
        }
    }

    fn handle_results_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Left | KeyCode::BackTab => self.previous_tab(),
            KeyCode::Right | KeyCode::Tab => self.next_tab(),
            KeyCode::Up | KeyCode::Char('k') if self.result_tab == ResultTab::Findings => {
                self.selected_finding = self.selected_finding.saturating_sub(1);
                self.result_scroll = 0;
            }
            KeyCode::Down | KeyCode::Char('j') if self.result_tab == ResultTab::Findings => {
                let last = self
                    .report
                    .as_ref()
                    .map(|report| report.findings.len().saturating_sub(1))
                    .unwrap_or(0);
                self.selected_finding = (self.selected_finding + 1).min(last);
                self.result_scroll = 0;
            }
            KeyCode::PageUp => {
                self.result_scroll = self.result_scroll.saturating_sub(10);
            }
            KeyCode::PageDown => {
                self.result_scroll = self.result_scroll.saturating_add(10);
            }
            KeyCode::Char('r') => self.start_selected(),
            KeyCode::Char('e') => {
                if self.export_armed {
                    self.export_armed = false;
                    self.export_report();
                } else {
                    self.export_armed = true;
                    self.status =
                        "Press e again to export HTML and JSON without overwriting files".into();
                }
            }
            KeyCode::Esc => {
                self.screen = Screen::Home;
                self.status = "Ready".into();
            }
            KeyCode::Char('q') => self.should_quit = true,
            _ => {}
        }
    }

    fn handle_rules_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.rules_scroll = self.rules_scroll.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.rules_scroll = self.rules_scroll.saturating_add(1);
            }
            KeyCode::PageUp => {
                self.rules_scroll = self.rules_scroll.saturating_sub(10);
            }
            KeyCode::PageDown => {
                self.rules_scroll = self.rules_scroll.saturating_add(10);
            }
            KeyCode::Esc => self.screen = Screen::Home,
            KeyCode::Char('q') => self.should_quit = true,
            _ => {}
        }
    }

    fn previous_tab(&mut self) {
        let index = ResultTab::ALL
            .iter()
            .position(|tab| *tab == self.result_tab)
            .unwrap_or(0);
        self.result_tab = ResultTab::ALL[index.saturating_sub(1)];
        self.result_scroll = 0;
    }

    fn next_tab(&mut self) {
        let index = ResultTab::ALL
            .iter()
            .position(|tab| *tab == self.result_tab)
            .unwrap_or(0);
        self.result_tab = ResultTab::ALL[(index + 1).min(ResultTab::ALL.len() - 1)];
        self.result_scroll = 0;
    }

    fn export_report(&mut self) {
        let Some(report) = self.report.as_ref() else {
            self.status = "No report is available to export".into();
            return;
        };
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        let directory = if home.join("Desktop").is_dir() {
            home.join("Desktop")
        } else {
            home
        };
        let stamp = Local::now().format("%Y%m%d-%H%M%S");
        let base = format!("MacTriage-{stamp}");
        let html_path = directory.join(format!("{base}.html"));
        let json_path = directory.join(format!("{base}.json"));
        let html = crate::html::render(report);
        let json = match serde_json::to_string_pretty(report) {
            Ok(json) => json,
            Err(error) => {
                self.status = format!("Could not serialize report: {error}");
                return;
            }
        };
        let result = create_new(&html_path, html.as_bytes())
            .and_then(|_| create_new(&json_path, json.as_bytes()));
        self.status = match result {
            Ok(()) => format!(
                "Exported {} and {}",
                html_path.display(),
                json_path.display()
            ),
            Err(error) => format!(
                "Export incomplete: {error}. Any successfully created report was left intact"
            ),
        };
    }
}

fn create_new(path: &PathBuf, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::{App, Profile, ResultTab, Screen};
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn home_navigation_is_bounded() {
        let mut app = App::new(false);
        app.handle_key(key(KeyCode::Up));
        assert_eq!(app.selected_profile(), Profile::Full);
        app.handle_key(key(KeyCode::Down));
        app.handle_key(key(KeyCode::Down));
        app.handle_key(key(KeyCode::Down));
        assert_eq!(app.selected_profile(), Profile::Snapshot);
    }

    #[test]
    fn rules_and_help_return_cleanly() {
        let mut app = App::new(false);
        app.handle_key(key(KeyCode::Char('l')));
        assert_eq!(app.screen, Screen::Rules);
        app.handle_key(key(KeyCode::Esc));
        assert_eq!(app.screen, Screen::Home);
        app.handle_key(key(KeyCode::Char('?')));
        assert!(app.show_help);
        app.handle_key(key(KeyCode::Esc));
        assert!(!app.show_help);
    }

    #[test]
    fn result_tabs_do_not_wrap() {
        let mut app = App::new(false);
        app.screen = Screen::Results;
        app.handle_key(key(KeyCode::Left));
        assert_eq!(app.result_tab, ResultTab::Summary);
        for _ in 0..8 {
            app.handle_key(key(KeyCode::Right));
        }
        assert_eq!(app.result_tab, ResultTab::Coverage);
    }

    #[test]
    fn result_scroll_is_bounded_and_resets_between_tabs() {
        let mut app = App::new(false);
        app.screen = Screen::Results;
        app.handle_key(key(KeyCode::PageDown));
        assert_eq!(app.result_scroll, 10);
        app.handle_key(key(KeyCode::PageUp));
        app.handle_key(key(KeyCode::PageUp));
        assert_eq!(app.result_scroll, 0);
        app.handle_key(key(KeyCode::PageDown));
        app.handle_key(key(KeyCode::Right));
        assert_eq!(app.result_scroll, 0);
    }

    #[test]
    fn scan_profiles_request_uncapped_findings() {
        for profile in [Profile::Full, Profile::Fast] {
            assert!(profile.worker_args().contains(&"--full"));
        }
    }
}
