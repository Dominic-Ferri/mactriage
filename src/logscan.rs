//! log.* rules — one unified-log pass, classified into findings in Rust.

use crate::report::{Category, Evidence, Finding, LogEvent, Severity};
use chrono::{DateTime, Utc};
use std::collections::HashSet;
use std::time::Duration;

pub struct LogRule {
    pub id: &'static str,
    pub category: Category,
    pub category_str: &'static str,
    /// Clause OR-ed into the single `log show` predicate.
    pub predicate: &'static str,
    /// (process, message) -> matched
    pub matches: fn(&str, &str) -> bool,
}

pub const LOG_RULES: &[LogRule] = &[
    LogRule {
        id: "log.shutdown_cause",
        category: Category::Power,
        category_str: "power",
        predicate: r#"eventMessage CONTAINS "Previous shutdown cause""#,
        matches: |_, m| m.contains("Previous shutdown cause"),
    },
    LogRule {
        id: "log.crash_reported",
        category: Category::Crashes,
        category_str: "crash",
        predicate: r#"(process == "ReportCrash" AND (eventMessage CONTAINS "Saved crash report" OR eventMessage CONTAINS "Formulating fatal"))"#,
        matches: |p, m| {
            p == "ReportCrash"
                && (m.contains("Saved crash report") || m.contains("Formulating fatal"))
        },
    },
    LogRule {
        id: "log.jetsam",
        category: Category::Memory,
        category_str: "memory",
        predicate: r#"(eventMessage CONTAINS "memorystatus" AND (eventMessage CONTAINS "kill" OR eventMessage CONTAINS "low swap"))"#,
        matches: |_, m| {
            // "killing (idle) X due to idle-exit" is the kernel reclaiming IDLE
            // daemons — routine housekeeping, not memory pressure. A 2026-09-09
            // field run counted 2400 of these as a high pressure finding.
            let l = m.to_lowercase();
            m.contains("memorystatus")
                && (m.contains("kill") || m.contains("low swap"))
                && !l.contains("idle-exit")
                && !l.contains("killing (idle)")
                && !l.contains("killing_idle")
        },
    },
    LogRule {
        id: "log.watchdog",
        category: Category::Hangs,
        category_str: "hang",
        predicate: r#"(eventMessage CONTAINS[c] "watchdog timeout" OR (process == "watchdogd" AND eventMessage CONTAINS[c] "unresponsive"))"#,
        matches: |p, m| {
            let l = m.to_lowercase();
            // launchd's "setting launch watchdog timeout to N secs from overlay"
            // is job *configuration*, not watchdogd catching a hung daemon.
            (l.contains("watchdog timeout") && !l.contains("setting launch watchdog timeout"))
                || (p == "watchdogd" && l.contains("unresponsive"))
        },
    },
    LogRule {
        id: "log.thermal",
        category: Category::Thermal,
        category_str: "thermal",
        predicate: r#"(eventMessage CONTAINS[c] "thermal pressure" OR eventMessage CONTAINS "CPU_Speed_Limit")"#,
        // Only records of pressure going UP (or a real speed limit) count;
        // see `thermal_elevated`.
        matches: |_, m| thermal_elevated(m),
    },
    LogRule {
        id: "log.io_errors",
        category: Category::Io,
        category_str: "i/o",
        predicate: r#"(eventMessage CONTAINS[c] "I/O error" OR process == "fsck_apfs" OR eventMessage CONTAINS "fsck_apfs" OR (eventMessage CONTAINS[c] "apfs" AND (eventMessage CONTAINS[c] "error" OR eventMessage CONTAINS[c] "fail" OR eventMessage CONTAINS[c] "corrupt" OR eventMessage CONTAINS[c] "invalid" OR eventMessage CONTAINS[c] "damaged" OR eventMessage CONTAINS[c] "not ok")))"#,
        matches: io_failure,
    },
    LogRule {
        id: "log.gpu_reset",
        category: Category::Gpu,
        category_str: "gpu",
        predicate: r#"(eventMessage CONTAINS[c] "GPU reset" OR eventMessage CONTAINS[c] "GPU hang" OR eventMessage CONTAINS[c] "GPU restart")"#,
        matches: |_, m| {
            let l = m.to_lowercase();
            l.contains("gpu reset") || l.contains("gpu hang") || l.contains("gpu restart")
        },
    },
    LogRule {
        id: "log.launchd_services",
        category: Category::Services,
        category_str: "services",
        predicate: r#"(process == "launchd" AND (eventMessage CONTAINS "exited with abnormal" OR eventMessage CONTAINS "throttling respawn" OR eventMessage CONTAINS "Crashed:"))"#,
        matches: |p, m| {
            p == "launchd"
                && (m.contains("exited with abnormal")
                    || m.contains("throttling respawn")
                    || m.contains("Crashed:"))
        },
    },
    LogRule {
        id: "log.spotlight",
        category: Category::Spotlight,
        category_str: "spotlight",
        predicate: r#"((process == "mds" OR process == "mds_stores" OR process == "mdworker" OR process == "mdworker_shared") AND eventMessage CONTAINS[c] "error")"#,
        matches: |p, m| {
            let l = m.to_lowercase();
            // XPC reconnect chatter contains the word "error" ("XPC_ERROR_
            // CONNECTION_INTERRUPTED") after a successful re-init — not an
            // indexer fault. 2026-09-09: 128 "errors", majority this shape.
            matches!(p, "mds" | "mds_stores" | "mdworker" | "mdworker_shared")
                && l.contains("error")
                && !l.contains("re-initialization successful")
                && !l.contains("xpc_error_connection_interrupted")
                // mds couldn't hand results to a search client that already
                // went away (2026-09-30: 30 of 70 "errors").
                && !l.contains("fetchqueryresultsfortaskid got connection error")
                // "stat succeeded, getattrlist returned error 2": the file was
                // deleted between the two calls (ENOENT) — temp-file churn.
                && !(l.contains("stat succeeded") && l.contains("getattrlist returned error"))
        },
    },
    LogRule {
        id: "log.kext",
        category: Category::Services,
        category_str: "services",
        predicate: r#"(process == "kernelmanagerd" AND (eventMessage CONTAINS[c] "fail" OR eventMessage CONTAINS[c] "reject" OR eventMessage CONTAINS[c] "not authorized"))"#,
        matches: |p, m| {
            let l = m.to_lowercase();
            p == "kernelmanagerd"
                && (l.contains("fail") || l.contains("reject") || l.contains("not authorized"))
        },
    },
    LogRule {
        id: "log.usb_tb",
        category: Category::Io,
        category_str: "i/o",
        predicate: r#"(eventMessage CONTAINS[c] "over-current" OR eventMessage CONTAINS[c] "overcurrent" OR (eventMessage CONTAINS "Thunderbolt" AND eventMessage CONTAINS[c] "error"))"#,
        matches: |p, m| {
            let l = m.to_lowercase();
            // accessoryupdaterd's MobileAccessoryUpdate steps mention
            // "Thunderbolt" and end in "error:(null)" — firmware-update
            // bookkeeping, not bus errors.
            if p == "accessoryupdaterd" || l.contains("error:(null)") || l.contains("error: (null)")
            {
                return false;
            }
            l.contains("over-current")
                || l.contains("overcurrent")
                || (m.contains("Thunderbolt") && l.contains("error"))
        },
    },
    LogRule {
        id: "log.sleep_wake",
        category: Category::Power,
        category_str: "sleep/wake",
        predicate: r#"(eventMessage CONTAINS "Wake transition timed out" OR eventMessage CONTAINS "Sleep transition timed out" OR eventMessage CONTAINS[c] "sleep failed")"#,
        matches: |_, m| {
            m.contains("Wake transition timed out")
                || m.contains("Sleep transition timed out")
                || m.to_lowercase().contains("sleep failed")
        },
    },
    // ── v0.2.0 rules ────────────────────────────────────────────────────────
    LogRule {
        id: "log.wifi",
        category: Category::Network,
        category_str: "network",
        predicate: r#"(process == "airportd" AND (eventMessage CONTAINS[c] "deauth" OR eventMessage CONTAINS[c] "roam failed" OR eventMessage CONTAINS[c] "link down" OR eventMessage CONTAINS[c] "association failed"))"#,
        matches: |p, m| {
            let l = m.to_lowercase();
            // corewifi RPC tracing ("BEGIN/END REQ [GET LINK DOWN STATUS]") is a
            // status *query*, not a link event — the 2026-09-08 field report
            // counted 225 of these as Wi-Fi instability on a -53 dBm link.
            // WiFiUsageSession "_generateState" telemetry dumps embed counter
            // names like LinkDown* — statistics, not events (2026-09-09 run).
            p == "airportd"
                && !l.contains("link down status")
                && !l.contains("wifiusagesession")
                && !l.contains("_generatestate")
                && (l.contains("deauth")
                    || l.contains("roam failed")
                    || l.contains("link down")
                    || l.contains("association failed"))
        },
    },
    LogRule {
        id: "log.mdnsresponder",
        category: Category::Network,
        category_str: "network",
        predicate: r#"(process == "mDNSResponder" AND (eventMessage CONTAINS[c] "no route to host" OR eventMessage CONTAINS[c] "server busy" OR eventMessage CONTAINS[c] "timed out"))"#,
        matches: |p, m| {
            let l = m.to_lowercase();
            p == "mDNSResponder"
                && (l.contains("no route to host")
                    || l.contains("server busy")
                    || l.contains("timed out"))
        },
    },
    LogRule {
        id: "log.bluetooth",
        category: Category::Bluetooth,
        category_str: "bluetooth",
        predicate: r#"(process == "bluetoothd" AND (eventMessage CONTAINS[c] "connection failed" OR eventMessage CONTAINS[c] "connection timeout" OR eventMessage CONTAINS[c] "disconnected unexpectedly" OR eventMessage CONTAINS[c] "le connection failed"))"#,
        matches: |p, m| {
            let l = m.to_lowercase();
            p == "bluetoothd"
                && (l.contains("connection failed")
                    || l.contains("connection timeout")
                    || l.contains("disconnected unexpectedly")
                    || l.contains("le connection failed"))
        },
    },
    LogRule {
        id: "log.gatekeeper",
        category: Category::Security,
        category_str: "security",
        predicate: r#"(process == "syspolicyd" AND (eventMessage CONTAINS[c] "denied" OR eventMessage CONTAINS[c] "blocked"))"#,
        matches: |p, m| {
            let l = m.to_lowercase();
            gatekeeper_denial(p, &l)
        },
    },
    LogRule {
        id: "log.keychain",
        category: Category::Security,
        category_str: "security",
        predicate: r#"((process == "secd" OR process == "securityd") AND (eventMessage CONTAINS "-25293" OR eventMessage CONTAINS "-34018" OR eventMessage CONTAINS[c] "keychain is locked"))"#,
        matches: |p, m| {
            matches!(p, "secd" | "securityd")
                && (m.contains("-25293")
                    || m.contains("-34018")
                    || m.to_lowercase().contains("keychain is locked"))
        },
    },
    LogRule {
        id: "log.software_update",
        category: Category::Updates,
        category_str: "updates",
        predicate: r#"((process == "softwareupdated" OR process == "UpdateBrainService" OR process == "osinstallersetupd" OR process == "com.apple.MobileSoftwareUpdate.UpdateBrainService") AND (eventMessage CONTAINS[c] "previous software update asset is no longer prepared" OR eventMessage CONTAINS[c] "failed to prepare" OR eventMessage CONTAINS[c] "failed to install" OR eventMessage CONTAINS[c] "installation failed" OR eventMessage CONTAINS[c] "personalization failed" OR eventMessage CONTAINS[c] "update failed" OR eventMessage CONTAINS[c] "MSU_ERR" OR eventMessage CONTAINS[c] "SUErrorDomain" OR eventMessage CONTAINS[c] "MobileSoftwareUpdateErrorDomain" OR eventMessage CONTAINS[c] "error 7408"))"#,
        matches: software_update_failure,
    },
    LogRule {
        id: "log.backupd",
        category: Category::Backups,
        category_str: "backups",
        predicate: r#"(process == "backupd" AND (eventMessage CONTAINS[c] "failed" OR eventMessage CONTAINS[c] "error"))"#,
        matches: |p, m| {
            let l = m.to_lowercase();
            // backupd probes snapshot support on every volume; "Operation not
            // supported" from fs_snapshot_list shows up on healthy Macs.
            p == "backupd"
                && !l.contains("fs_snapshot_list failed: operation not supported")
                && !l.contains("failed to get unit")
                && !l.contains("sticky exclusion")
                && !l.contains("re-initialization successful")
                && !l.contains("xpc_error_connection_interrupted")
                // "Backup failed: BACKUP_DELAYED_NOT_ENOUGH_ELAPSED_TIME" is the
                // scheduler deferring a run, not a failed backup.
                && !l.contains("backup_delayed")
                && (l.contains("failed") || l.contains("error"))
        },
    },
];

fn io_failure(process: &str, message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    // Sandbox/MACF policy denials mention APFS ("IOUC AppleAPFSUserClient
    // failed MACF") but are permission events, not storage errors — a
    // 2026-09-09 run escalated 64 of them to a High disk finding. Keybag
    // unwrap/unload failures are volume lock-state churn, likewise not I/O.
    if message.contains("failed macf") || message.contains("apfs_keybag_") {
        return false;
    }
    // Page-in failures of the Spotlight store are index corruption, not disk
    // failure — they belong to the Spotlight story, not a hardware I/O alert.
    if message.contains("mds_stores")
        || message.contains("mdworker")
        || message.contains("spotlight")
    {
        return false;
    }
    // Failed MOUNT attempts (locked/encrypted secondary volumes being retried
    // by automount) are mount outcomes, not media errors — 12 of them re-made
    // the High disk finding minutes after the MACF fix.
    if message.contains("vfsop_mount")
        || message.contains("apfs_mount failed")
        || message.contains("unwrap metadata crypto state")
    {
        return false;
    }
    if message.contains("i/o error") {
        return true;
    }

    let successful_check = [
        "appears to be ok",
        "exit code is 0",
        "exit status 0",
        "no errors found",
    ]
    .iter()
    .any(|marker| message.contains(marker));
    if successful_check {
        return false;
    }

    // "invalid" must not fire on "invalidating/invalidate" — routine APFS
    // cache/range cleanup ("invalidating reserved ranges after deletion")
    // matched as corruption in a 2026-09-09 field run.
    let invalid_state = message.contains("invalid") && !message.contains("invalidat");
    let failure = invalid_state
        || ["error", "fail", "corrupt", "damaged", "not ok"]
            .iter()
            .any(|marker| message.contains(marker));
    if process == "fsck_apfs" || message.contains("fsck_apfs") {
        return failure;
    }

    let storage_process = matches!(
        process,
        "kernel" | "apfsd" | "diskmanagementd" | "diskarbitrationd" | "diskutil"
    );
    storage_process && message.contains("apfs") && failure
}

pub(crate) fn software_update_failure(process: &str, message: &str) -> bool {
    let update_process = matches!(
        process,
        "softwareupdated" | "UpdateBrainService" | "osinstallersetupd"
    ) || process.ends_with(".UpdateBrainService");
    if !update_process {
        return false;
    }
    let message = message.to_ascii_lowercase();
    [
        "previous software update asset is no longer prepared",
        "failed to prepare",
        "failed to install",
        "installation failed",
        "personalization failed",
        "update failed",
        "msu_err",
        "suerrordomain",
        "mobilesoftwareupdateerrordomain",
        "error 7408",
    ]
    .iter()
    .any(|needle| message.contains(needle))
}

struct Hit {
    ts: Option<DateTime<Utc>>,
    process: String,
    message: String,
}

pub struct LogScanResult {
    pub findings: Vec<Finding>,
    /// Every matched line (full hits, not just the 3-excerpt evidence), for the
    /// JSON report's `log_events` section.
    pub events: Vec<LogEvent>,
    pub log_lines: u64,
    pub log_rules_run: u32,
    pub timed_out: bool,
    pub cancelled: bool,
    /// The `log show` pass could not be trusted to be complete (spawn failure or
    /// non-zero exit). Callers surface this so a failed scan never reads as clean.
    pub failed: bool,
    /// Short reason (stderr tail) when `failed`, for the report note.
    pub error: Option<String>,
}

pub fn scan(
    since: DateTime<Utc>,
    until: Option<DateTime<Utc>>,
    categories: &HashSet<Category>,
    timeout: Duration,
    verbose: u8,
    progress: &dyn crate::progress::Reporter,
    cancel: &crate::progress::CancellationToken,
) -> LogScanResult {
    let rules: Vec<&LogRule> = LOG_RULES
        .iter()
        .filter(|r| categories.contains(&r.category))
        .collect();
    if rules.is_empty() {
        return LogScanResult {
            findings: vec![],
            events: vec![],
            log_lines: 0,
            log_rules_run: 0,
            timed_out: false,
            cancelled: false,
            failed: false,
            error: None,
        };
    }
    let predicate = rules
        .iter()
        .map(|r| r.predicate)
        .collect::<Vec<_>>()
        .join(" OR ");

    let start = since
        .with_timezone(&chrono::Local)
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    let mut args: Vec<String> = vec![
        "show".into(),
        "--style".into(),
        "ndjson".into(),
        "--start".into(),
        start,
        "--predicate".into(),
        predicate,
    ];
    if let Some(u) = until {
        args.push("--end".into());
        args.push(
            u.with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M:%S")
                .to_string(),
        );
    }
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    if verbose >= 2 {
        eprintln!("[debug] log {}", args.join(" "));
    }

    let window_end = until.unwrap_or_else(Utc::now);
    let window_total = (window_end - since).num_seconds().max(1) as f64;
    let mut per_rule: Vec<Vec<Hit>> = rules.iter().map(|_| Vec::new()).collect();
    let mut log_lines = 0u64;

    // Progress is driven two ways and the bar takes the max:
    //  - real position: matching lines arrive in chronological order, so each
    //    line's timestamp says how far into the window we are;
    //  - wall-clock estimate (~25s per hour of window) so the bar still moves
    //    on quiet systems where matches are sparse.
    let ts_frac = std::cell::Cell::new(0.0f64);
    let shown_frac = std::cell::Cell::new(0.0f64);
    let pass_start = std::time::Instant::now();
    let est_total_secs = (window_total / 3600.0 * 25.0).max(10.0);

    // Absolute path: bare `log` can be shadowed by shell aliases on some setups.
    let outcome = crate::util::stream_lines(
        "/usr/bin/log",
        &arg_refs,
        timeout,
        cancel,
        |line| {
            let v: serde_json::Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => return,
            };
            // ndjson output ends with a {"finished": N} sentinel record (documented
            // in log(1)) — not a log event, don't count it.
            if v.get("finished").is_some() {
                return;
            }
            log_lines += 1;
            let ts = v
                .get("timestamp")
                .and_then(|t| t.as_str())
                .and_then(crate::files::parse_report_time);
            if let Some(t) = ts {
                let scanned = (t - since).num_seconds().max(0) as f64;
                ts_frac.set((scanned / window_total).clamp(0.0, 1.0));
                let frac = ts_frac.get().max(shown_frac.get());
                shown_frac.set(frac);
                progress.update(
                    frac,
                    Some(&format!(
                        "unified log · {} of {} scanned",
                        crate::util::human_duration(scanned as u64),
                        crate::util::human_duration(window_total as u64)
                    )),
                );
            }
            let process = v
                .get("processImagePath")
                .and_then(|p| p.as_str())
                .map(|p| p.rsplit('/').next().unwrap_or(p).to_string())
                .or_else(|| v.get("process").and_then(|p| p.as_str()).map(String::from))
                .unwrap_or_default();
            let message = v.get("eventMessage").and_then(|m| m.as_str()).unwrap_or("");
            // logd records every `log show` invocation INCLUDING the predicate text,
            // which contains all our match keywords — skip those self-referential
            // lines or this scanner reports its own previous runs as findings.
            if message.contains("--predicate") || message.contains("run noninteractively") {
                return;
            }
            // Known-nominal noise that keyword matchers would misread.
            if message.contains("thermal pressure level=0")
                || message.contains("Thermal pressure state: 0")
                || message.contains("approval entry")
            {
                return;
            }
            for (i, rule) in rules.iter().enumerate() {
                if (rule.matches)(&process, message) {
                    per_rule[i].push(Hit {
                        ts,
                        process: process.clone(),
                        message: message.chars().take(500).collect(),
                    });
                    break;
                }
            }
        },
        || {
            // Idle tick: advance by wall-clock estimate, capped so the bar never
            // claims completion before the pass actually ends.
            let est = (pass_start.elapsed().as_secs_f64() / est_total_secs).min(0.97);
            if est > shown_frac.get() {
                shown_frac.set(est);
                progress.update(est, None);
            }
        },
    );

    let mut findings = Vec::new();
    for (i, rule) in rules.iter().enumerate() {
        if let Some(f) = summarize(rule, &per_rule[i]) {
            findings.push(f);
        }
    }
    let mut events: Vec<LogEvent> = Vec::new();
    for (rule, hits) in rules.iter().zip(per_rule) {
        for h in hits {
            events.push(LogEvent {
                timestamp: h.ts,
                rule_id: rule.id.into(),
                process: h.process,
                message: h.message,
            });
        }
    }
    events.sort_by_key(|e| e.timestamp);
    // A spawn failure or a non-zero `log show` exit (bad predicate, corrupted
    // logd store, TCC denial) must be reported, not silently read as "clean".
    let failed = outcome.spawn_failed || !outcome.exit_ok;
    let error = if outcome.spawn_failed {
        Some("could not launch /usr/bin/log".to_string())
    } else if !outcome.exit_ok {
        Some(if outcome.stderr_tail.is_empty() {
            "log show exited non-zero".to_string()
        } else {
            outcome.stderr_tail.clone()
        })
    } else {
        None
    };
    LogScanResult {
        findings,
        events,
        log_lines,
        log_rules_run: rules.len() as u32,
        timed_out: outcome.timed_out,
        cancelled: outcome.cancelled,
        failed,
        error,
    }
}

/// Turn a rule's hit list into one finding (count-scaled severity), or None.
fn summarize(rule: &LogRule, hits: &[Hit]) -> Option<Finding> {
    if hits.is_empty() {
        return None;
    }
    let count = hits.len() as u32;
    let first = hits.iter().filter_map(|h| h.ts).min();
    let last = hits.iter().filter_map(|h| h.ts).max();
    let sample = &hits[hits.len() - 1];

    let (severity, summary, detail, next_step): (Severity, String, String, String) = match rule.id {
        "log.shutdown_cause" => shutdown_cause(sample)?,
        "log.crash_reported" => (
            Severity::Info,
            format!("Crash reporter fired {count} time(s)"),
            "Crash reporter activity in the log; corroborates the .ips crash findings above."
                .into(),
            "See the crash findings above — this is the same events from the log side.".into(),
        ),
        "log.jetsam" => (
            if count > 10 { Severity::High } else { Severity::Medium },
            format!("Kernel memory-pressure kills in the log ({count} events)"),
            "The kernel killed or warned about processes under memory pressure during the scan \
             window. Sustained jetsam activity means the Mac is memory-bound."
                .into(),
            "Check current pressure: `memory_pressure -Q`, and find the hog: `top -o mem -n 5 -l 1`."
                .into(),
        ),
        "log.watchdog" => (
            if count > 3 { Severity::High } else { Severity::Medium },
            format!("Watchdog flagged unresponsive system daemons ({count} events)"),
            "watchdogd caught core daemons hanging long enough to be flagged. Repeated watchdog \
             timeouts precede forced restarts."
                .into(),
            "Identify the daemon in the evidence line; check its log stream and recent updates."
                .into(),
        ),
        "log.thermal" => {
            let records: Vec<(Option<DateTime<Utc>>, &str)> =
                hits.iter().map(|h| (h.ts, h.message.as_str())).collect();
            thermal_verdict(&records)
        }
        "log.io_errors" => (
            if count > 10 { Severity::High } else { Severity::Medium },
            format!("Disk / APFS I/O errors in the log ({count} events)"),
            "The storage stack reported errors. Occasional retries can be benign; clusters of I/O \
             errors are how failing disks and corrupted containers announce themselves."
                .into(),
            "Check SMART: `diskutil info disk0 | grep SMART`, then verify the container: \
             `diskutil verifyVolume /` (read-only check). Back up before anything else."
                .into(),
        ),
        "log.gpu_reset" => (
            if count > 3 { Severity::High } else { Severity::Medium },
            format!("GPU hangs/resets recorded by the driver ({count} events)"),
            "The GPU driver logged hang/reset activity — corroborates .gpuRestart reports.".into(),
            "Update macOS and the heaviest graphics apps; if it persists across apps, suspect \
             hardware."
                .into(),
        ),
        "log.launchd_services" => {
            let procs = top_processes(hits, 3);
            (
                if count > 20 { Severity::High } else { Severity::Medium },
                format!("launchd services exiting abnormally ({count} events)"),
                format!(
                    "Background services crashed or were throttled for respawning too fast. \
                     Most active: {procs}. A crash-looping service burns CPU and never delivers \
                     whatever it was supposed to do."
                ),
                "List suspects: `launchctl list | grep -v '^-.*0'` (non-zero last-exit), then fix \
                 or unload the guilty plist."
                    .into(),
            )
        }
        "log.spotlight" => (
            if count > 50 { Severity::Medium } else { Severity::Low },
            format!("Spotlight indexer errors ({count} events)"),
            "The Spotlight indexer logged faults. A wedged index makes mds/mds_stores burn CPU \
             and disk indefinitely."
                .into(),
            "If mds_stores is hot in Activity Monitor, rebuild the index: `sudo mdutil -E /`."
                .into(),
        ),
        "log.kext" => (
            Severity::Medium,
            format!("Kernel extension load failures ({count} events)"),
            "kernelmanagerd failed or refused to load kexts. Software depending on those kexts \
             will malfunction until the kext is approved, updated, or removed."
                .into(),
            "See what's staged and failing: `kmutil showloaded --collection aux` and check System \
             Settings ▸ Privacy & Security for a pending approval."
                .into(),
        ),
        "log.usb_tb" => (
            if count > 10 { Severity::High } else { Severity::Medium },
            format!("USB / Thunderbolt errors ({count} events)"),
            "Over-current or link errors on USB/Thunderbolt. A shorting cable/device can cut \
             power to ports; link errors mean flaky cable, hub, or device."
                .into(),
            "Unplug everything, reconnect one device at a time, and prefer direct connection over \
             hubs to find the culprit."
                .into(),
        ),
        "log.sleep_wake" => (
            if count > 3 { Severity::High } else { Severity::Medium },
            format!("Sleep/wake failures ({count} events)"),
            "Sleep or wake transitions failed or timed out — often kernel-level trouble while \
             asleep (a driver refusing to sleep, or a device waking the machine)."
                .into(),
            "Check wake history: `pmset -g log | grep -i 'wake from'` and look for a repeating \
             wake reason; suspect USB devices and network wake."
                .into(),
        ),
        "log.wifi" => (
            if count > 20 { Severity::Medium } else { Severity::Low },
            format!("Wi-Fi instability: deauth/roam/link failures ({count} events)"),
            "airportd logged repeated association, roaming, or link failures. Constant deauths \
             mean AP-side trouble, interference, or a marginal signal."
                .into(),
            "Check quality now: `sudo wdutil info` (RSSI vs noise). If RSSI < -75 dBm move closer \
             or change channel; if it's strong, suspect the AP or DHCP."
                .into(),
        ),
        "log.mdnsresponder" => (
            Severity::Low,
            format!("DNS resolver (mDNSResponder) trouble ({count} events)"),
            "The system resolver logged timeouts or reachability trouble — DNS lookups were slow \
             or failing during the window."
                .into(),
            "Verify now: `dig apple.com` and `scutil --dns`; if the configured resolver is dead, \
             fix DNS in Network settings."
                .into(),
        ),
        "log.bluetooth" => {
            let messages: Vec<&str> = hits.iter().map(|h| h.message.as_str()).collect();
            bluetooth_verdict(&messages)
        }
        "log.gatekeeper" => (
            if count > 10 { Severity::Medium } else { Severity::Low },
            format!("Gatekeeper blocked app launches ({count} events)"),
            "syspolicyd denied application launches or component loads. Users experience this as \
             'app is damaged / can't be opened' dialogs."
                .into(),
            "Identify the app in the evidence; if it's trusted, re-download a notarized build. \
             Never blanket-disable Gatekeeper for one app."
                .into(),
        ),
        "log.keychain" => {
            let messages: Vec<&str> = hits.iter().map(|h| h.message.as_str()).collect();
            let (severity, detail, next) = keychain_verdict(&messages);
            (severity, format!("Keychain errors recurring ({count} events)"), detail, next)
        }
        "log.software_update" => {
            let prepared_state_lost = hits.iter().any(|h| {
                h.message
                    .to_ascii_lowercase()
                    .contains("no longer prepared")
            });
            (
                if count >= 3 {
                    Severity::Medium
                } else {
                    Severity::Low
                },
                format!("Software Update failure(s) recorded ({count} events)"),
                if prepared_state_lost {
                    "Software Update lost its prepared asset state. This commonly follows an unexpected restart or kernel panic; it does not by itself prove macOS is corrupt."
                        .into()
                } else {
                    "The macOS update pipeline recorded a specific preparation, installation, personalization, or update-domain failure. An update error alone does not justify erasing the Mac."
                        .into()
                },
                "Correlate this with panic, power, storage, and extension findings. Resolve those first; if the Mac is stable and the same update failure repeats, reinstall macOS from Recovery without erasing before considering a clean install."
                    .into(),
            )
        }
        "log.backupd" => (
            if count > 10 { Severity::Medium } else { Severity::Low },
            format!("Time Machine errors in the log ({count} events)"),
            "backupd logged failures during the window — backups may be silently failing.".into(),
            "Check the last completed backup: `tmutil latestbackup`, and the destination: \
             `tmutil destinationinfo`."
                .into(),
        ),
        _ => return None,
    };

    let mut f = Finding::new(rule.id, severity, rule.category_str, &summary);
    f.detail = detail;
    f.next_step = Some(next_step);
    f.count = count;
    f.timestamp = last;
    f.first_seen = if count > 1 { first } else { None };
    for h in hits.iter().rev().take(3) {
        f.evidence.push(Evidence {
            source: format!("unified log · {}", h.process),
            // Hits keep up to 500 chars for the JSON log_events dump; evidence
            // excerpts stay at the 200-char display width.
            excerpt: h.message.chars().take(200).collect(),
        });
    }
    Some(f)
}

/// Previous-shutdown-cause codes; the interesting ones mean the machine died.
fn shutdown_cause(sample: &Hit) -> Option<(Severity, String, String, String)> {
    let code: i64 = sample.message.rsplit(':').next()?.trim().parse().ok()?;
    let (sev, meaning) = shutdown_severity(code)?;
    Some((
        sev,
        format!("Last shutdown was abnormal: {meaning} (code {code})"),
        format!(
            "macOS recorded shutdown cause {code}: {meaning}. Anything other than a normal \
             shutdown (5) means the machine lost power or the OS was killed."
        ),
        "Correlate with panic/thermal findings above. Codes in the -60s are hangs, -20/-71 are \
         thermal, 0/3 are power. Repeated abnormal causes on a desktop point at PSU/power."
            .into(),
    ))
}

/// Classify a `Previous shutdown cause` code. `None` = normal shutdown,
/// not a finding. Meanings per SMC firmware STOP_CAUSE constants (via
/// acidanthera/VirtualSMC SMCKeys.txt) and Apple's open-source SMCShutdownCause
/// table — note these codes are an Intel-SMC mechanism and generally do not
/// appear on Apple Silicon Macs at all.
pub(crate) fn shutdown_severity(code: i64) -> Option<(Severity, &'static str)> {
    Some(match code {
        1 | 5 | 7 => return None, // warm reset / software shutdown / normal SoC shutdown
        0 => (
            Severity::Medium,
            "power loss — battery disconnected / sudden cut",
        ),
        2 => (Severity::Medium, "power supply disconnected"),
        3 => (Severity::High, "hard shutdown — power button held >4s"),
        -2 => (Severity::High, "power supply fault"),
        -3 => (
            Severity::High,
            "thermal shutdown — multiple temperature sensors over limit",
        ),
        -14 => (Severity::High, "electricity spike/surge detected"),
        -20 => (
            Severity::Critical,
            "forced shutdown: battery/thermal management (BridgeOS/T2)",
        ),
        -30 => (
            Severity::High,
            "thermal shutdown — temperature over limit timeout",
        ),
        -60 => (
            Severity::Medium,
            "battery fully drained — machine died on empty battery",
        ),
        -61 | -62 => (
            Severity::Critical,
            "watchdog forced restart: unresponsive OS",
        ),
        -63 | -65 | -67 => (
            Severity::Medium,
            "unknown T2-era forced shutdown (often logic board)",
        ),
        // SMC firmware calls this STOP_CAUSE_UNKNOWN_64; community sources
        // associate it with kernel panics. Not officially "kernel panic".
        -64 => (
            Severity::High,
            "unknown forced shutdown (often follows a kernel panic — check for a panic report)",
        ),
        -70 | -72 | -82 | -83 | -84 | -86 | -100 | -101 => {
            (Severity::High, "thermal shutdown — sensor over limit")
        }
        -71 => (Severity::High, "memory (SO-DIMM) over temperature"),
        -74 => (Severity::High, "battery over temperature"),
        -75 => (Severity::High, "AC adapter communication fault"),
        -78 => (Severity::High, "incorrect current from AC adapter"),
        -79 => (Severity::High, "incorrect current from battery"),
        -81 => (Severity::Critical, "thermal forced shutdown (overtemp)"),
        -95 => (Severity::Critical, "CPU thermal emergency shutdown"),
        -103 => (Severity::High, "battery cell undervoltage"),
        -104 => (Severity::High, "battery fault"),
        -108 | -112 => (Severity::High, "memory subsystem fault"),
        -127 => (Severity::Critical, "PMU forced shutdown"),
        -128 => (Severity::High, "unknown forced shutdown"),
        _ => (Severity::Medium, "abnormal shutdown (unrecognized code)"),
    })
}

/// `CPU_Speed_Limit = 80` → Some(80).
pub fn cpu_speed_limit(message: &str) -> Option<u32> {
    let idx = message.find("CPU_Speed_Limit")?;
    let digits: String = message[idx..]
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

/// A log record that shows thermal pressure going UP, or the CPU actually
/// speed-limited. Many daemons log the all-clear ("dropped to nominal", "is
/// elevated: false"), poll the level (`level=0`), or react to pressure; the
/// 2026-09-30 field run counted all of those as 14 "throttling events" for one
/// 3-minute episode.
pub fn thermal_elevated(message: &str) -> bool {
    if message.contains("CPU_Speed_Limit") {
        return cpu_speed_limit(message).is_some_and(|v| v < 100);
    }
    let l = message.to_lowercase();
    if !l.contains("thermal pressure") {
        return false;
    }
    const NOT_ELEVATED: &[&str] = &[
        "dropped",
        "nominal",
        "elevated: false",
        "level=0",
        "polling",
        "register",
        "monitor",
        "limiting maximum active count",
        "mlvnr",
    ];
    const ELEVATED: &[&str] = &[
        "rose to",
        "raised to",
        "increased to",
        "elevated: true",
        "moderate",
        "heavy",
        "serious",
        "critical",
        "trapping",
        "sleeping",
    ];
    !NOT_ELEVATED.iter().any(|n| l.contains(n)) && ELEVATED.iter().any(|e| l.contains(e))
}

/// Severity, summary, detail, next step for thermal records. Several apps echo
/// the same transition within milliseconds, so records less than 5 minutes
/// apart form one episode.
pub fn thermal_verdict(
    records: &[(Option<DateTime<Utc>>, &str)],
) -> (Severity, String, String, String) {
    let mut times: Vec<DateTime<Utc>> = records.iter().filter_map(|(t, _)| *t).collect();
    times.sort();
    let mut episodes = records.iter().filter(|(t, _)| t.is_none()).count();
    let mut prev: Option<DateTime<Utc>> = None;
    for t in times {
        if prev.is_none_or(|p| t - p > chrono::Duration::minutes(5)) {
            episodes += 1;
        }
        prev = Some(t);
    }
    let min_speed = records.iter().filter_map(|(_, m)| cpu_speed_limit(m)).min();
    let severity = if min_speed.is_some_and(|v| v <= 50) || episodes >= 30 {
        Severity::High
    } else if min_speed.is_some() || episodes >= 10 {
        Severity::Medium
    } else {
        Severity::Low
    };
    let summary = match min_speed {
        Some(v) => format!("CPU throttled for heat (down to {v}% speed, {episodes} episode(s))"),
        None => format!("Thermal pressure rose above nominal ({episodes} episode(s))"),
    };
    let detail = format!(
        "macOS raised thermal pressure {episodes} time(s) in the window{}; apps and the CPU back \
         off until it cools. Brief episodes under heavy load are normal, especially on fanless \
         MacBook Air models. Frequent or long ones point at blocked vents, high ambient \
         temperature, a runaway process, or a sensor fault.",
        match min_speed {
            Some(v) => format!(", and the CPU was limited to {v}% speed"),
            None => String::new(),
        }
    );
    let next = "Check live: `pmset -g therm` (CPU_Speed_Limit below 100 means throttling now). \
                Look in Activity Monitor for a runaway process, keep vents clear, and on Macs \
                with a fan, listen for it."
        .to_string();
    (severity, summary, detail, next)
}

/// Severity, summary, detail, next step for bluetoothd connection failures.
/// When every failure is a reconnect retry to ONE device, it is almost always
/// a Continuity link (the user's iPhone or Watch waking and sleeping) or a
/// paired device out of range. 2026-09-30: 65 "failures" were all retries to
/// one iPhone (Md iPhone18,2) that bluetoothd logged as awake/asleep 490 times.
pub fn bluetooth_verdict(messages: &[&str]) -> (Severity, String, String, String) {
    let count = messages.len();
    let mut devices: Vec<&str> = messages
        .iter()
        .filter_map(|m| m.split('"').nth(1))
        .filter(|d| !d.is_empty())
        .collect();
    devices.sort_unstable();
    devices.dedup();
    let all_retries = messages
        .iter()
        .all(|m| m.to_lowercase().contains("retrying"));
    if devices.len() == 1 && all_retries {
        return (
            Severity::Low,
            format!("Bluetooth keeps retrying one device ({count} attempts)"),
            format!(
                "All {count} failures are reconnect retries to a single device ({}). The usual \
                 source is the user's iPhone or Apple Watch keeping its Continuity link \
                 (Handoff, Universal Clipboard, Auto Unlock) alive as it sleeps and wakes, or a \
                 paired device that is out of range. It matters only if that device is a \
                 keyboard, mouse, or headset that keeps dropping.",
                devices[0]
            ),
            "No action unless a Bluetooth accessory is actually dropping; if one is, check its \
             battery and re-pair it."
                .into(),
        );
    }
    let device_note = if devices.is_empty() {
        String::new()
    } else {
        format!(", {} device(s)", devices.len())
    };
    (
        if count > 20 {
            Severity::Medium
        } else {
            Severity::Low
        },
        format!("Bluetooth connection failures ({count} events{device_note})"),
        "bluetoothd logged repeated connection failures/timeouts. For BT input devices this \
         is felt as lag, stutter, or drops."
            .into(),
        "Check the device battery first. Then interference: 2.4 GHz congestion, USB 3 hubs \
         near the antenna. Re-pair the worst device."
            .into(),
    )
}

/// A syspolicyd line that records Gatekeeper denying something. Its QUIC
/// connection summaries count DATA_BLOCKED / STREAM_DATA_BLOCKED frames —
/// flow control, not Gatekeeper (2026-09-30: all 12 "blocked launches" on a
/// healthy Mac were these). `lower` is the lowercased message.
pub fn gatekeeper_denial(process: &str, lower: &str) -> bool {
    process == "syspolicyd"
        && !lower.contains("quic_conn_log_summary")
        && (lower.contains("denied") || lower.contains("blocked"))
}

/// Severity, detail and next step for secd/securityd keychain errors, by
/// error code (meanings from `security error <code>`):
/// -25293 errSecAuthFailed — wrong user name or password (a real problem);
/// -34018 errSecMissingEntitlement — the calling app asked for a keychain
///        group it isn't entitled to (an app bug, not the user's keychain);
/// -25308 errSecInteractionNotAllowed — keychain locked (sleep / screen lock).
/// Only a flood of real authentication failures is Medium; before 0.11.1 the
/// total of all three codes decided that, so 386 locked-bag denials plus two
/// Teams entitlement errors read as "keychain password out of sync".
pub fn keychain_verdict(messages: &[&str]) -> (Severity, String, String) {
    let auth = messages.iter().filter(|m| m.contains("-25293")).count();
    let entitlement: Vec<&str> = messages
        .iter()
        .copied()
        .filter(|m| m.contains("-34018"))
        .collect();
    let locked = messages.len() - auth - entitlement.len();
    // secd messages start with the client, e.g. "MSTeams[20447]/1#22 LF=0 …".
    let mut apps: Vec<&str> = entitlement
        .iter()
        .filter_map(|m| m.split('[').next())
        .map(str::trim)
        .filter(|a| !a.is_empty() && !a.contains(' '))
        .collect();
    apps.sort_unstable();
    apps.dedup();

    let mut parts = Vec::new();
    if auth > 0 {
        parts.push(format!(
            "{auth} authentication failure(s) (-25293, wrong password): users see endless \
             password prompts or silent credential failures"
        ));
    }
    if !entitlement.is_empty() {
        parts.push(format!(
            "{} missing-entitlement error(s) (-34018){}: an app asked for a keychain group it \
             isn't entitled to, which is a bug in that app, not a broken keychain",
            entitlement.len(),
            if apps.is_empty() {
                String::new()
            } else {
                format!(" from {}", apps.join(", "))
            }
        ));
    }
    if locked > 0 {
        parts.push(format!(
            "{locked} access attempt(s) while the keychain was locked (-25308), which is expected \
             on a laptop that sleeps or locks its screen"
        ));
    }
    let detail = format!("secd/securityd logged {}.", parts.join("; "));
    let severity = if auth > 20 {
        Severity::Medium
    } else {
        Severity::Low
    };
    let next = if auth > 0 {
        "Check Keychain Access for the affected item; a login-keychain password out of sync with \
         the account password is the classic cause."
            .to_string()
    } else if !entitlement.is_empty() {
        format!(
            "No keychain repair needed. If {} has sign-in trouble, update or reinstall it.",
            if apps.is_empty() {
                "the app".to_string()
            } else {
                apps.join(" / ")
            }
        )
    } else {
        "No action unless the user is also seeing password prompts while unlocked. Locked-bag \
         denials during sleep/lock are normal."
            .to_string()
    };
    (severity, detail, next)
}

fn top_processes(hits: &[Hit], n: usize) -> String {
    let mut counts: std::collections::HashMap<&str, u32> = Default::default();
    for h in hits {
        // launchd messages name the service; fall back to logging process
        *counts.entry(h.process.as_str()).or_insert(0) += 1;
    }
    let mut v: Vec<_> = counts.into_iter().collect();
    v.sort_by_key(|&(_, c)| std::cmp::Reverse(c));
    v.into_iter()
        .take(n)
        .map(|(p, c)| format!("{p} (×{c})"))
        .collect::<Vec<_>>()
        .join(", ")
}
