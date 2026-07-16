//! Scan orchestration shared by the classic CLI, the TUI worker, and watch mode.

use crate::progress::{CancellationToken, Reporter};
use crate::report::{Category, Finding, Report, Severity};
use crate::{
    audit, boot, correlate, files, host, logscan, netcheck, power, recovery, security, storage,
    util, watch,
};
use chrono::{DateTime, Local, NaiveDate, NaiveDateTime, TimeZone, Utc};
use clap::Args;
use std::collections::HashSet;
use std::time::{Duration, Instant};

#[derive(Args, Clone, Debug)]
pub struct ScanOpts {
    /// Unified-log window to scan (e.g. 30m, 6h, 24h, 3d). Cost scales with the
    /// window and how chatty the Mac is: 6h takes ~2–5 minutes; use --timeout
    /// for big windows
    #[arg(long, default_value = "6h")]
    pub last: String,

    /// Age cutoff for DiagnosticReports files (panics matter for weeks; files are cheap to scan)
    #[arg(long, default_value = "7d")]
    pub files_last: String,

    /// Scan an absolute range instead: start date/time, local ("2026-07-01" or
    /// "2026-07-01 08:30"). Overrides --last and --files-last
    #[arg(long, value_name = "DATETIME")]
    pub from: Option<String>,

    /// End of the --from range (same formats; default: now)
    #[arg(long, value_name = "DATETIME", requires = "from")]
    pub to: Option<String>,

    /// Only scan these categories (repeatable)
    #[arg(long, value_enum)]
    pub only: Vec<Category>,

    /// Skip these categories (repeatable)
    #[arg(long, value_enum)]
    pub skip: Vec<Category>,

    /// Machine-readable JSON report on stdout (schema_version 2)
    #[arg(long)]
    pub json: bool,

    /// Also write a self-contained HTML report to this path
    #[arg(long, value_name = "PATH")]
    pub html: Option<String>,

    /// Hide findings below this severity (also floors the exit code)
    #[arg(long, value_enum)]
    pub min_severity: Option<Severity>,

    /// Seconds allowed for the unified-log pass before it is killed (partial
    /// results kept). A cap, not a duration: 240 s cut off a 6h pass that needs
    /// ~270 s under sudo on a busy Mac, losing the newest events.
    #[arg(long, default_value_t = 600)]
    pub timeout: u64,

    /// Fast mode: skip the unified log entirely (files + vitals only)
    #[arg(long)]
    pub no_log: bool,

    /// Don't cap findings per category (default cap: 10)
    #[arg(long)]
    pub full: bool,

    /// -v: show evidence excerpts; -vv: debug timing/skips to stderr
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Findings only: no header or vitals (keeps the one-line verdict)
    #[arg(short, long)]
    pub quiet: bool,

    /// Disable colored output (also honors NO_COLOR and non-TTY pipes automatically)
    #[arg(long)]
    pub no_color: bool,
}

impl Default for ScanOpts {
    fn default() -> Self {
        Self {
            last: "6h".into(),
            files_last: "7d".into(),
            from: None,
            to: None,
            only: Vec::new(),
            skip: Vec::new(),
            json: false,
            html: None,
            min_severity: None,
            timeout: 600,
            no_log: false,
            full: false,
            verbose: 0,
            quiet: false,
            no_color: false,
        }
    }
}

#[derive(Args, Clone, Debug, Default)]
pub struct SnapshotOpts {
    /// Machine-readable JSON report on stdout
    #[arg(long)]
    pub json: bool,
    /// -v: show evidence excerpts
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
    /// Disable colored output
    #[arg(long)]
    pub no_color: bool,
}

#[derive(Args, Clone, Debug, Default)]
pub struct SecurityOpts {
    /// Machine-readable JSON report on stdout
    #[arg(long)]
    pub json: bool,
    /// Also write a self-contained HTML report to this path
    #[arg(long, value_name = "PATH")]
    pub html: Option<String>,
    /// -v: show evidence excerpts
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
    /// Disable colored output
    #[arg(long)]
    pub no_color: bool,
}

#[derive(Debug)]
pub struct ScanFailure {
    pub code: i32,
    pub message: String,
}

impl ScanFailure {
    fn usage(message: impl Into<String>) -> Self {
        Self {
            code: 2,
            message: message.into(),
        }
    }
}

pub struct ScanRun {
    pub report: Report,
    pub cancelled: bool,
}

fn categories(only: &[Category], skip: &[Category]) -> HashSet<Category> {
    let mut set: HashSet<Category> = if only.is_empty() {
        Category::ALL.iter().copied().collect()
    } else {
        only.iter().copied().collect()
    };
    for s in skip {
        set.remove(s);
    }
    set
}

fn parse_datetime(s: &str) -> Option<DateTime<Utc>> {
    let s = s.trim();
    if let Ok(nt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M") {
        return Local
            .from_local_datetime(&nt)
            .single()
            .map(|t| t.with_timezone(&Utc));
    }
    if let Ok(nd) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        let nt = nd.and_hms_opt(0, 0, 0)?;
        return Local
            .from_local_datetime(&nt)
            .single()
            .map(|t| t.with_timezone(&Utc));
    }
    None
}

pub fn collect_scan(
    opts: &ScanOpts,
    prog: &dyn Reporter,
    cancel: &CancellationToken,
) -> Result<ScanRun, ScanFailure> {
    let started = Instant::now();
    let root = util::is_root();
    let cats = categories(&opts.only, &opts.skip);
    let now = Utc::now();

    let (log_since, files_since, until, window_desc) = if let Some(from) = &opts.from {
        let Some(from_t) = parse_datetime(from) else {
            return Err(ScanFailure::usage(format!(
                "cannot parse --from '{from}' (use \"2026-07-01\" or \"2026-07-01 08:30\")"
            )));
        };
        let to_t = match &opts.to {
            Some(to) => parse_datetime(to)
                .ok_or_else(|| ScanFailure::usage(format!("cannot parse --to '{to}'")))?,
            None => now,
        };
        if to_t < from_t {
            return Err(ScanFailure::usage("--to is before --from (empty range)"));
        }
        let desc = format!(
            "{} → {}",
            from_t.with_timezone(&Local).format("%Y-%m-%d %H:%M"),
            to_t.with_timezone(&Local).format("%Y-%m-%d %H:%M")
        );
        (from_t, from_t, to_t, desc)
    } else {
        let Some(log_w) = util::parse_window(&opts.last) else {
            return Err(ScanFailure::usage(format!(
                "cannot parse --last '{}' (use e.g. 30m, 6h, 3d)",
                opts.last
            )));
        };
        let Some(files_w) = util::parse_window(&opts.files_last) else {
            return Err(ScanFailure::usage(format!(
                "cannot parse --files-last '{}'",
                opts.files_last
            )));
        };
        let desc = if opts.no_log {
            format!("logs skipped · files {}", opts.files_last)
        } else {
            format!("logs {} · files {}", opts.last, opts.files_last)
        };
        (
            now - chrono::Duration::from_std(log_w).unwrap_or_default(),
            now - chrono::Duration::from_std(files_w).unwrap_or_default(),
            now,
            desc,
        )
    };

    let mut report = Report {
        schema_version: crate::report::SCHEMA_VERSION,
        tool: crate::report::TOOL_NAME.into(),
        tool_version: crate::report::TOOL_VERSION.into(),
        generated_at: now,
        scan_window: window_desc,
        window_since: Some(if opts.from.is_some() {
            log_since
        } else {
            files_since.min(log_since)
        }),
        window_until: Some(until),
        complete: true,
        host: host::host_info(root),
        vitals: Vec::new(),
        findings: Vec::new(),
        skipped: Vec::new(),
        notes: Vec::new(),
        recovery: None,
        stats: Default::default(),
        log_events: Vec::new(),
    };
    if !root {
        report.skipped.push(crate::report::Skipped {
            what: "/var/db/PanicReporter".into(),
            reason: "kernel panic record is root-only — re-run with sudo".into(),
        });
    }

    let (files_span, log_span, rest_base) = if opts.no_log {
        (0.4, 0.0, 0.4)
    } else {
        (0.05, 0.80, 0.85)
    };

    prog.phase(0.0, files_span, "diagnostic report files");
    let t = Instant::now();
    let file_res = files::scan(&files::report_dirs(root), files_since, until, &cats);
    if opts.verbose >= 2 {
        eprintln!(
            "[debug] files pass: {} files in {:?}",
            file_res.files_scanned,
            t.elapsed()
        );
    }
    report.stats.files_scanned = file_res.files_scanned;
    report.stats.files_unparsed = file_res.files_unparsed;
    for dir in &file_res.denied_dirs {
        report.complete = false;
        report.skipped.push(crate::report::Skipped {
            what: dir.clone(),
            reason: "permission denied — grant this terminal Full Disk Access (System Settings ▸ \
                     Privacy & Security ▸ Full Disk Access) for complete coverage"
                .into(),
        });
    }

    let mut cancelled = cancel.is_cancelled();
    let mut log_findings = Vec::new();
    if opts.no_log {
        report.skipped.push(crate::report::Skipped {
            what: "unified log".into(),
            reason: "skipped (--no-log)".into(),
        });
    } else if !cancelled {
        prog.phase(files_span, log_span, "unified log · starting (index scan)…");
        let t = Instant::now();
        let log_res = logscan::scan(
            log_since,
            opts.from.as_ref().map(|_| until),
            &cats,
            Duration::from_secs(opts.timeout),
            opts.verbose,
            prog,
            cancel,
        );
        if opts.verbose >= 2 {
            eprintln!(
                "[debug] log pass: {} lines in {:?}",
                log_res.log_lines,
                t.elapsed()
            );
        }
        report.stats.log_lines = log_res.log_lines;
        report.stats.log_rules_run = log_res.log_rules_run;
        cancelled |= log_res.cancelled;
        if log_res.timed_out {
            report.complete = false;
            report.notes.push(format!(
                "unified-log pass hit the {}s timeout — log show reads oldest-first, so the MOST RECENT events are missing (raise --timeout or shrink --last)",
                opts.timeout
            ));
        }
        if log_res.failed {
            report.complete = false;
            report.notes.push(format!(
                "unified-log pass FAILED ({}) — log findings are missing; this is NOT a clean result",
                log_res.error.as_deref().unwrap_or("log show error")
            ));
        } else if !log_res.timed_out && !log_res.cancelled && log_res.log_lines == 0 {
            let win_hours = (until - log_since).num_hours();
            if win_hours >= 2 {
                report.complete = false;
                report.notes.push(format!(
                    "unified-log pass returned 0 lines over ~{win_hours}h — logd may be unavailable \
                     or access-restricted; log-based findings may be missing"
                ));
            }
        }
        log_findings = log_res.findings;
        report.log_events = log_res.events;
    }

    let mut all: Vec<Finding> = file_res.findings;
    all.extend(log_findings);
    let mut loaded_kexts = Vec::new();
    let mut installs = Vec::new();
    let rest_span = 1.0 - rest_base;
    let step =
        |i: f64, label: &str| prog.phase(rest_base + i * rest_span / 6.0, rest_span / 6.0, label);

    if !cancelled {
        step(0.0, "live vitals");
        let snap = host::scan(&cats, root);
        report.vitals.extend(snap.vitals);
        report.skipped.extend(snap.skipped);
        all.extend(snap.findings);
        cancelled = cancel.is_cancelled();
    }
    if !cancelled {
        step(1.0, "battery & power");
        let pw = power::scan(&cats);
        report.vitals.extend(pw.vitals);
        all.extend(pw.findings);
        cancelled = cancel.is_cancelled();
    }
    if !cancelled {
        step(2.0, "network checks");
        let net = netcheck::scan(&cats, root);
        report.vitals.extend(net.vitals);
        report.skipped.extend(net.skipped);
        all.extend(net.findings);
        cancelled = cancel.is_cancelled();
    }
    if !cancelled {
        step(3.0, "storage & backups");
        all.extend(storage::scan(&cats));
        cancelled = cancel.is_cancelled();
    }
    if !cancelled {
        step(4.0, "launch items · kexts · posture · security");
        let audit_res = audit::scan(&cats, root, files_since);
        report.skipped.extend(audit_res.skipped);
        loaded_kexts = audit_res.loaded_kexts;
        installs = audit_res.installs;
        all.extend(audit_res.findings);
        if cats.contains(&Category::Security) {
            let sec = security::scan(root);
            report.vitals.extend(sec.vitals);
            report.skipped.extend(sec.skipped);
            security::supersede_profile_count(&mut all, &sec.findings);
            all.extend(sec.findings);
        }
        cancelled = cancel.is_cancelled();
    }
    if !cancelled {
        step(5.0, "boot timing");
        if !opts.no_log {
            all.extend(boot::scan(&cats, files_since));
        }
        cancelled = cancel.is_cancelled();
    }

    prog.update(
        1.0,
        Some(if cancelled {
            "cancelled"
        } else {
            "correlating"
        }),
    );
    report.findings = correlate::run(all, &file_res.panic_kexts, &loaded_kexts, &installs);
    if let Some(boot) = host::boot_time() {
        apply_boot_phase(&mut report.findings, boot);
    }

    if cancelled {
        report.complete = false;
        report.notes.push(
            "scan cancelled by user — results are partial and must not be treated as healthy"
                .into(),
        );
    }
    let full_recovery_coverage =
        root && opts.only.is_empty() && opts.skip.is_empty() && !opts.no_log && !cancelled;
    report.recovery = Some(recovery::assess(&report, full_recovery_coverage));

    if let Some(min) = opts.min_severity {
        report.findings.retain(|f| f.severity >= min);
    }
    report.finalize(if opts.full { None } else { Some(10) });
    report.stats.duration_ms = started.elapsed().as_millis() as u64;
    prog.finish();
    Ok(ScanRun { report, cancelled })
}

/// Log findings whose EVERY matched event falls inside the first ~2 minutes
/// after boot are almost always startup sequencing (kext staging, watchdog
/// config, radio bring-up), not runtime faults: tag them and step severity down
/// one level so boot noise cannot drive recovery escalation. Fatal findings are
/// never downgraded.
pub(crate) fn apply_boot_phase(findings: &mut [Finding], boot: DateTime<Utc>) {
    let cutoff = boot + chrono::Duration::seconds(120);
    for f in findings.iter_mut() {
        if !f.rule_id.starts_with("log.") || f.severity == Severity::Critical {
            continue;
        }
        let Some(last) = f.timestamp else { continue };
        let first = f.first_seen.unwrap_or(last);
        if first >= boot && last <= cutoff {
            f.severity = match f.severity {
                Severity::High => Severity::Medium,
                Severity::Medium => Severity::Low,
                _ => Severity::Info,
            };
            f.detail.push_str(
                " ⏱ Every matched event falls within ~2 minutes of boot — normal startup \
                 sequencing is the likeliest explanation; severity reduced one level.",
            );
        }
    }
}

pub fn collect_snapshot(
    _opts: &SnapshotOpts,
    prog: &dyn Reporter,
    cancel: &CancellationToken,
) -> ScanRun {
    let started = Instant::now();
    let root = util::is_root();
    let cats: HashSet<Category> = Category::ALL.iter().copied().collect();
    let mut report = Report {
        schema_version: crate::report::SCHEMA_VERSION,
        tool: crate::report::TOOL_NAME.into(),
        tool_version: crate::report::TOOL_VERSION.into(),
        generated_at: Utc::now(),
        scan_window: "snapshot — live vitals only".into(),
        window_since: None,
        window_until: None,
        complete: true,
        host: host::host_info(root),
        vitals: Vec::new(),
        findings: Vec::new(),
        skipped: Vec::new(),
        notes: Vec::new(),
        recovery: None,
        stats: Default::default(),
        log_events: Vec::new(),
    };

    prog.phase(0.0, 0.34, "live vitals");
    let snap = host::scan(&cats, root);
    report.vitals.extend(snap.vitals);
    report.skipped.extend(snap.skipped);
    report.findings.extend(snap.findings);
    let mut cancelled = cancel.is_cancelled();
    if !cancelled {
        prog.phase(0.34, 0.33, "battery & power");
        let pw = power::scan(&cats);
        report.vitals.extend(pw.vitals);
        report.findings.extend(pw.findings);
        cancelled = cancel.is_cancelled();
    }
    if !cancelled {
        prog.phase(0.67, 0.33, "network checks");
        let net = netcheck::scan(&cats, root);
        report.vitals.extend(net.vitals);
        report.skipped.extend(net.skipped);
        report.findings.extend(net.findings);
        cancelled = cancel.is_cancelled();
    }
    if cancelled {
        report.complete = false;
        report
            .notes
            .push("snapshot cancelled by user — results are partial".into());
    }
    report.finalize(None);
    report.stats.duration_ms = started.elapsed().as_millis() as u64;
    prog.finish();
    ScanRun { report, cancelled }
}

/// `mactriage security`: posture + sec.* checks only — no logs, no report files.
/// Read-only; finishes in seconds.
pub fn collect_security(prog: &dyn Reporter) -> Report {
    let started = Instant::now();
    let root = util::is_root();
    // Posture (SIP, Gatekeeper, FileVault, firewall, XProtect) plus the two
    // persistence surfaces: launch items / BTM, and loaded kexts. Without
    // them a planted LaunchAgent never appears in a "security" report.
    let cats: HashSet<Category> = [Category::Posture, Category::LaunchItems, Category::Kexts]
        .into_iter()
        .collect();
    let mut report = Report {
        schema_version: crate::report::SCHEMA_VERSION,
        tool: crate::report::TOOL_NAME.into(),
        tool_version: crate::report::TOOL_VERSION.into(),
        generated_at: Utc::now(),
        scan_window: "security audit — current settings".into(),
        window_since: None,
        window_until: None,
        complete: true,
        host: host::host_info(root),
        vitals: Vec::new(),
        findings: Vec::new(),
        skipped: Vec::new(),
        notes: Vec::new(),
        recovery: None,
        stats: Default::default(),
        log_events: Vec::new(),
    };
    prog.phase(0.0, 0.2, "posture · launch items · kexts");
    let audit_res = audit::scan(&cats, root, Utc::now());
    report.skipped.extend(audit_res.skipped);
    report.findings.extend(audit_res.findings);
    prog.phase(0.2, 0.8, "security settings · MDM · certificates");
    let sec = security::scan(root);
    report.vitals.extend(sec.vitals);
    report.skipped.extend(sec.skipped);
    security::supersede_profile_count(&mut report.findings, &sec.findings);
    report.findings.extend(sec.findings);
    if !root {
        report.notes.push(
            "run with sudo for full coverage (computer-level profiles, Bootstrap Token, Jamf \
             server check, Background Task Management, other users' listeners)"
                .into(),
        );
    }
    report.finalize(None);
    report.stats.duration_ms = started.elapsed().as_millis() as u64;
    prog.finish();
    report
}

/// Cheap scan used by `watch run`: files since the last watch run (so nothing
/// between runs is missed) + live vitals, no unified log.
pub fn scan_for_watch() -> Report {
    let root = util::is_root();
    let cats: HashSet<Category> = Category::ALL.iter().copied().collect();
    let now = Utc::now();
    let elapsed = watch::last_run()
        .map(|t| now - t)
        .unwrap_or_else(|| chrono::Duration::hours(6));
    let elapsed = elapsed.clamp(chrono::Duration::hours(1), chrono::Duration::days(2));
    let since = now - elapsed;

    let mut report = Report {
        schema_version: crate::report::SCHEMA_VERSION,
        tool: crate::report::TOOL_NAME.into(),
        tool_version: crate::report::TOOL_VERSION.into(),
        generated_at: now,
        scan_window: format!(
            "watch — files {} + vitals",
            util::human_duration(elapsed.num_seconds().max(0) as u64)
        ),
        window_since: Some(since),
        window_until: Some(now),
        complete: true,
        host: host::host_info(root),
        vitals: Vec::new(),
        findings: Vec::new(),
        skipped: Vec::new(),
        notes: Vec::new(),
        recovery: None,
        stats: Default::default(),
        log_events: Vec::new(),
    };
    let file_res = files::scan(&files::report_dirs(root), since, now, &cats);
    report.stats.files_scanned = file_res.files_scanned;
    let snap = host::scan(&cats, root);
    let pw = power::scan(&cats);
    let net = netcheck::scan(&cats, root);
    let mut all = file_res.findings;
    all.extend(snap.findings);
    all.extend(pw.findings);
    all.extend(net.findings);
    report.findings = correlate::run(all, &file_res.panic_kexts, &[], &[]);
    report.finalize(None);
    report
}
