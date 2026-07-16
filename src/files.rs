//! file.* rules — DiagnosticReports scanners.

use crate::report::{Category, Evidence, Finding, Severity};
use chrono::{DateTime, Local, NaiveDateTime, TimeZone, Utc};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub struct FileScanResult {
    pub findings: Vec<Finding>,
    pub files_scanned: u32,
    pub files_unparsed: u32,
    pub panic_kexts: Vec<String>,
    /// Report directories that could not be read because of permissions —
    /// almost always Terminal lacking Full Disk Access. Surfaced so a partial
    /// scan is never mistaken for a healthy one.
    pub denied_dirs: Vec<String>,
}

pub fn report_dirs(root: bool) -> Vec<PathBuf> {
    // Test fixture override: point the scanner at a directory of sample reports.
    if let Some(fixture) = std::env::var_os("MACTRIAGE_REPORTS_DIR") {
        return vec![PathBuf::from(fixture)];
    }
    let mut dirs = vec![PathBuf::from("/Library/Logs/DiagnosticReports")];
    if root {
        if let Ok(users) = std::fs::read_dir("/Users") {
            for u in users.flatten() {
                let d = u.path().join("Library/Logs/DiagnosticReports");
                if d.is_dir() {
                    dirs.push(d);
                }
            }
        }
        dirs.push(PathBuf::from("/var/db/PanicReporter"));
    } else if let Some(home) = std::env::var_os("HOME") {
        dirs.push(PathBuf::from(home).join("Library/Logs/DiagnosticReports"));
    }
    // Retired subdirs hold rotated reports; panics matter for weeks.
    let retired: Vec<PathBuf> = dirs.iter().map(|d| d.join("Retired")).collect();
    dirs.extend(retired);
    dirs
}

pub fn scan(
    dirs: &[PathBuf],
    since: DateTime<Utc>,
    until: DateTime<Utc>,
    categories: &HashSet<Category>,
) -> FileScanResult {
    let mut res = FileScanResult {
        findings: Vec::new(),
        files_scanned: 0,
        files_unparsed: 0,
        panic_kexts: Vec::new(),
        denied_dirs: Vec::new(),
    };
    for dir in dirs {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                // A permission error on a real report dir means coverage is
                // incomplete (no Full Disk Access) — record it, don't swallow it.
                if e.kind() == std::io::ErrorKind::PermissionDenied && dir.exists() {
                    res.denied_dirs.push(dir.display().to_string());
                }
                continue;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let mtime: DateTime<Utc> = match entry.metadata().and_then(|m| m.modified()) {
                Ok(t) => t.into(),
                Err(_) => continue,
            };
            if mtime < since || mtime > until {
                continue;
            }
            res.files_scanned += 1;
            match parse_report(&path, categories) {
                Some(ParsedReport::Finding(mut f)) => {
                    if f.timestamp.is_none() {
                        f.timestamp = Some(mtime);
                    }
                    if let Some(kexts) =
                        f.evidence.iter().find(|e| e.source == "kexts_in_backtrace")
                    {
                        for k in kexts.excerpt.split(", ") {
                            res.panic_kexts.push(k.to_string());
                        }
                        f.evidence.retain(|e| e.source != "kexts_in_backtrace");
                    }
                    res.findings.push(f);
                }
                Some(ParsedReport::Skipped) => {}
                None => res.files_unparsed += 1,
            }
        }
    }
    res
}

enum ParsedReport {
    Finding(Finding),
    Skipped, // category filtered out or intentionally ignored file type
}

fn wants(categories: &HashSet<Category>, c: Category) -> bool {
    categories.contains(&c)
}

fn parse_report(path: &Path, categories: &HashSet<Category>) -> Option<ParsedReport> {
    let name = path.file_name()?.to_string_lossy().to_string();
    let ext = path.extension().map(|e| e.to_string_lossy().to_string());
    match ext.as_deref() {
        Some("ips") | Some("panic") => parse_ips_or_panic(path, &name, categories),
        Some("crash") => {
            if !wants(categories, Category::Crashes) {
                return Some(ParsedReport::Skipped);
            }
            parse_legacy_crash(path, &name)
        }
        Some("hang") | Some("spin") => {
            if !wants(categories, Category::Hangs) {
                return Some(ParsedReport::Skipped);
            }
            parse_hang(path, &name)
        }
        Some("shutdownStall") => {
            if !wants(categories, Category::Hangs) {
                return Some(ParsedReport::Skipped);
            }
            parse_shutdown_stall(path, &name)
        }
        Some("gpuRestart") => {
            if !wants(categories, Category::Gpu) {
                return Some(ParsedReport::Skipped);
            }
            parse_gpu_restart(path, &name)
        }
        Some("diag") => parse_diag(path, &name, categories),
        _ => {
            // Unrecognized report kept for review, but only real report-looking files.
            if name.contains("core_analytics") || name.starts_with('.') {
                return Some(ParsedReport::Skipped);
            }
            let mut f = Finding::new(
                "file.unknown_report",
                Severity::Info,
                "other",
                &format!("Unrecognized diagnostic report: {name}"),
            );
            f.detail =
                "Diagnostic report of a type mactriage doesn't parse yet; kept for manual review."
                    .into();
            f.evidence.push(Evidence {
                source: path.display().to_string(),
                excerpt: String::new(),
            });
            Some(ParsedReport::Finding(f))
        }
    }
}

/// First line of modern reports is a JSON header with bug_type.
fn read_header_and_body(path: &Path) -> Option<(serde_json::Value, String)> {
    let content = std::fs::read_to_string(path).ok()?;
    let (first, rest) = content.split_once('\n')?;
    let header: serde_json::Value = serde_json::from_str(first).ok()?;
    Some((header, rest.to_string()))
}

fn header_time(header: &serde_json::Value) -> Option<DateTime<Utc>> {
    let ts = header.get("timestamp")?.as_str()?;
    parse_report_time(ts)
}

/// "2026-07-16 13:27:14.00 -0400" (reports), "2026-07-16 13:27:14.123456-0400"
/// (unified-log ndjson — no space before the offset), or zoneless local time.
pub fn parse_report_time(s: &str) -> Option<DateTime<Utc>> {
    for fmt in [
        "%Y-%m-%d %H:%M:%S%.f %z",
        "%Y-%m-%d %H:%M:%S %z",
        "%Y-%m-%d %H:%M:%S%.f%z",
    ] {
        if let Ok(t) = DateTime::parse_from_str(s.trim(), fmt) {
            return Some(t.with_timezone(&Utc));
        }
    }
    // Filename-style local time without zone: "2026-07-16 13:27:14"
    if let Ok(nt) = NaiveDateTime::parse_from_str(s.trim(), "%Y-%m-%d %H:%M:%S") {
        return Local
            .from_local_datetime(&nt)
            .single()
            .map(|t| t.with_timezone(&Utc));
    }
    None
}

fn parse_ips_or_panic(
    path: &Path,
    name: &str,
    categories: &HashSet<Category>,
) -> Option<ParsedReport> {
    // Legacy `.panic` files are plain text with no JSON header, so the header
    // reader returns None for them — handle that before it swallows the file.
    let Some((header, body)) = read_header_and_body(path) else {
        if name.ends_with(".panic") {
            if !wants(categories, Category::Panics) {
                return Some(ParsedReport::Skipped);
            }
            let text = std::fs::read_to_string(path).ok()?;
            return Some(ParsedReport::Finding(parse_panic_body(path, &text, None)));
        }
        return None;
    };
    let bug_type = header
        .get("bug_type")
        .and_then(|b| b.as_str())
        .unwrap_or("");
    let ts = header_time(&header);
    match bug_type {
        "210" => {
            if !wants(categories, Category::Panics) {
                return Some(ParsedReport::Skipped);
            }
            Some(ParsedReport::Finding(parse_panic_body(path, &body, ts)))
        }
        "298" => {
            if !wants(categories, Category::Memory) {
                return Some(ParsedReport::Skipped);
            }
            parse_jetsam(path, &body, ts)
        }
        "309" => {
            if !wants(categories, Category::Crashes) {
                return Some(ParsedReport::Skipped);
            }
            parse_crash_309(path, &header, &body, ts)
        }
        "288" => {
            if !wants(categories, Category::Hangs) {
                return Some(ParsedReport::Skipped);
            }
            let app = header
                .get("app_name")
                .and_then(|a| a.as_str())
                .unwrap_or("unknown process")
                .to_string();
            Some(ParsedReport::Finding(hang_finding(path, &app, &body, ts)))
        }
        // 143 is the legacy cheatsheet tag for cpu_resource; Apple's current
        // OSAnalytics config uses 202 (SymptomsCPUUsage). Accept both.
        "143" | "202" => {
            if !wants(categories, Category::ResourceAbuse) {
                return Some(ParsedReport::Skipped);
            }
            Some(ParsedReport::Finding(cpu_resource_finding(
                path,
                header
                    .get("app_name")
                    .and_then(|a| a.as_str())
                    .unwrap_or("unknown"),
                &body,
                ts,
            )))
        }
        // 24 = SleepWakeFailure (Apple OSAnalytics config) — kernel-level
        // sleep/wake transition failure.
        "24" => {
            if !wants(categories, Category::Power) {
                return Some(ParsedReport::Skipped);
            }
            let mut f = Finding::new(
                "file.sleep_wake_failure",
                Severity::High,
                "sleep/wake",
                "Sleep wake failure — the Mac died instead of waking",
            );
            f.detail = "The kernel's sleep/wake transition failed outright (the classic 'closed \
                        the lid, found it dead or burning hot in the bag'). Usually a driver or \
                        device refusing to sleep, or a firmware bug."
                .into();
            f.next_step = Some(
                "Check wake history: `pmset -g log | grep -i 'wake from'`. Suspect USB/Thunderbolt \
                 devices, network wake, and any third-party kext in the inventory."
                    .into(),
            );
            f.timestamp = ts;
            f.evidence.push(Evidence {
                source: path.display().to_string(),
                excerpt: String::new(),
            });
            Some(ParsedReport::Finding(f))
        }
        // 115 = ResetCount — "Boot failure count: N" reports; repeated failed
        // boots mean the Mac is crashing before login.
        "115" => {
            if !wants(categories, Category::Boot) {
                return Some(ParsedReport::Skipped);
            }
            let boot_failures = body
                .lines()
                .find(|l| l.contains("Boot failure count"))
                .and_then(|l| l.rsplit(':').next())
                .and_then(|n| n.trim().parse::<u32>().ok())
                .unwrap_or(1);
            let sev = if boot_failures >= 3 {
                Severity::High
            } else {
                Severity::Medium
            };
            let mut f = Finding::new(
                "file.reset_count",
                sev,
                "boot",
                &format!(
                    "Boot failure count: {boot_failures} — the Mac is failing to boot cleanly"
                ),
            );
            f.count = boot_failures;
            f.detail = "The firmware counted consecutive failed boots. Repeated boot failures \
                        precede a Mac that won't start at all — usually a corrupt boot volume, \
                        a failing SSD, or a bad update."
                .into();
            f.next_step = Some(
                "Back up now. Then check the boot volume: `diskutil verifyVolume /`, and review \
                 recent installs in this report."
                    .into(),
            );
            f.timestamp = ts;
            f.evidence.push(Evidence {
                source: path.display().to_string(),
                excerpt: body
                    .lines()
                    .find(|l| l.contains("Boot failure count") || l.contains("Boot faults"))
                    .unwrap_or("")
                    .trim()
                    .to_string(),
            });
            Some(ParsedReport::Finding(f))
        }
        // 409 = SystemWatchdogCrash — the userspace watchdog killed a critical
        // service (loginwindow/WindowServer-class hang).
        "409" => {
            if !wants(categories, Category::Hangs) {
                return Some(ParsedReport::Skipped);
            }
            let mut f = Finding::new(
                "file.system_watchdog",
                Severity::High,
                "hang",
                "System watchdog killed a critical service",
            );
            f.detail = "A core service (loginwindow/WindowServer class) hung hard enough that the \
                        userspace watchdog forcibly restarted it — the login screen or UI locked \
                        up from the user's side."
                .into();
            f.next_step = Some(
                "Identify the killed service in the report; correlate with crash and hang findings \
                 for that process in this window."
                    .into(),
            );
            f.timestamp = ts;
            f.evidence.push(Evidence {
                source: path.display().to_string(),
                excerpt: String::new(),
            });
            Some(ParsedReport::Finding(f))
        }
        // 151 = ForceReset, 301 = SystemMemoryReset — the machine was force-
        // reset or the memory subsystem reset itself.
        "151" | "301" => {
            if !wants(categories, Category::Power) {
                return Some(ParsedReport::Skipped);
            }
            let what = if bug_type == "151" {
                "Forced reset event"
            } else {
                "Memory subsystem reset"
            };
            let mut f = Finding::new("file.force_reset", Severity::High, "power", what);
            f.detail = "The machine was force-reset (or its memory subsystem reset). If the user \
                        didn't hold the power button, this is hardware/firmware territory."
                .into();
            f.next_step = Some(
                "Correlate with shutdown-cause and panic findings; run Apple Diagnostics if it \
                 recurs."
                    .into(),
            );
            f.timestamp = ts;
            f.evidence.push(Evidence {
                source: path.display().to_string(),
                excerpt: String::new(),
            });
            Some(ParsedReport::Finding(f))
        }
        "142" => {
            if !wants(categories, Category::ResourceAbuse) {
                return Some(ParsedReport::Skipped);
            }
            Some(ParsedReport::Finding(wakeups_finding(
                path,
                header
                    .get("app_name")
                    .and_then(|a| a.as_str())
                    .unwrap_or("unknown"),
                &body,
                ts,
            )))
        }
        _ => {
            // Legacy .panic files are plain text (no JSON header).
            if name.ends_with(".panic") {
                if !wants(categories, Category::Panics) {
                    return Some(ParsedReport::Skipped);
                }
                let text = std::fs::read_to_string(path).ok()?;
                return Some(ParsedReport::Finding(parse_panic_body(path, &text, None)));
            }
            None
        }
    }
}

fn parse_panic_body(path: &Path, body: &str, ts: Option<DateTime<Utc>>) -> Finding {
    // Body may be JSON with panicString / macOSPanicString, or raw text.
    let body_json = serde_json::from_str::<serde_json::Value>(body).ok();
    let panic_string = body_json
        .as_ref()
        .and_then(|v| {
            v.get("panicString")
                .or_else(|| v.get("macOSPanicString"))
                .and_then(|s| s.as_str())
                .map(String::from)
        })
        .unwrap_or_else(|| body.to_string());
    // BridgeOS/T2 and SEP panics arrive as ordinary bug_type 210 with
    // "caused_by": "bridgeos" — surface it so recovery's firmware-panic
    // detector can see it.
    let caused_by = body_json
        .as_ref()
        .and_then(|v| v.get("caused_by").and_then(|c| c.as_str()))
        .map(String::from);

    let first_line = panic_string
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("kernel panic")
        .trim()
        .to_string();

    let mut kexts: Vec<String> = Vec::new();
    if let Some(idx) = panic_string.find("Kernel Extensions in backtrace") {
        for line in panic_string[idx..].lines().skip(1).take(20) {
            let l = line.trim();
            if l.is_empty() || l.starts_with("last") || l.starts_with("Process") {
                break;
            }
            // "com.vendor.driver(1.2.3)[UUID]@0x..."
            if let Some(kid) = l.split(['(', '[', '@']).next() {
                let kid = kid.trim();
                if kid.contains('.') {
                    kexts.push(kid.to_string());
                }
            }
        }
    }

    let mut f = Finding::new(
        "file.kernel_panic",
        Severity::Critical,
        "panic",
        "Kernel panic",
    );
    f.summary = format!(
        "Kernel panic{} — {}",
        caused_by
            .as_deref()
            .map(|c| format!(" (caused_by: {c})"))
            .unwrap_or_default(),
        first_line.chars().take(120).collect::<String>()
    );
    f.detail = if kexts.is_empty() {
        "The kernel itself crashed and the Mac restarted. No third-party kexts in the backtrace — \
         suspect hardware, a macOS bug, or a driver loaded outside the backtrace."
            .into()
    } else {
        format!(
            "The kernel itself crashed and the Mac restarted. Kernel extensions in the backtrace: {}. \
             A third-party kext in the backtrace is the prime suspect.",
            kexts.join(", ")
        )
    };
    let blame = classify_panic(&panic_string, caused_by.as_deref(), &kexts);
    if let Some(b) = &blame {
        f.detail.push_str(&format!(
            " Points to: {} ({}).",
            b.subsystem,
            b.class.label()
        ));
    }
    f.next_step = Some(format!(
        "If it recurs, note what hardware/apps were in use. Update or remove any third-party kext \
         in the backtrace. {} to rule out hardware.",
        crate::util::apple_diagnostics_step()
    ));
    f.timestamp = ts;
    f.evidence.push(Evidence {
        source: path.display().to_string(),
        excerpt: first_line,
    });
    if !kexts.is_empty() {
        f.evidence.push(Evidence {
            source: "kexts_in_backtrace".into(),
            excerpt: kexts.join(", "),
        });
    }
    if let Some(b) = blame {
        f.evidence.push(Evidence {
            source: "panic classifier".into(),
            excerpt: format!(
                "{}: {} (marker \"{}\")",
                b.class.tag(),
                b.subsystem,
                b.marker
            ),
        });
    }
    f
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlameClass {
    HardwareSuspect,
    Firmware,
    Software,
}

impl BlameClass {
    /// Machine-readable tag in the classifier evidence; recovery.rs keys on
    /// "hardware-suspect".
    pub fn tag(self) -> &'static str {
        match self {
            Self::HardwareSuspect => "hardware-suspect",
            Self::Firmware => "firmware/coprocessor",
            Self::Software => "software",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::HardwareSuspect => "likely hardware",
            Self::Firmware => "firmware or coprocessor, can be hardware",
            Self::Software => "likely software",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PanicBlame {
    pub class: BlameClass,
    pub subsystem: &'static str,
    pub marker: String,
}

/// Panic-string markers of a fault the hardware itself reported. Only markers
/// with a documented meaning are listed; anything else stays unclassified.
/// - CATERR: Intel's catastrophic-error signal — an unrecoverable internal
///   CPU fault; on Macs it is logic-board / CPU failure territory.
/// - Machine check: Intel SDM Vol. 3, "Machine-Check Architecture" — the
///   mechanism the CPU uses to report hardware (machine) errors.
/// - ECC errors are memory errors by definition.
const HARDWARE_PANIC_MARKERS: &[(&str, &str)] = &[
    ("caterr", "Intel CPU / logic board (CATERR)"),
    // Matches the "Machine Check at …" panic headline, not the register dump.
    ("machine check", "CPU or memory (machine check)"),
    ("uncorrectable ecc", "memory (uncorrectable ECC error)"),
    ("ecc error", "memory (ECC error)"),
];

/// Panics raised by a coprocessor or its firmware (Secure Enclave, T2/BridgeOS,
/// SMC/PMU power controllers, ANS storage controller, DCP display, AOP
/// always-on processor, RTKit). Firmware first, but can be hardware.
pub const FIRMWARE_PANIC_MARKERS: &[&str] = &[
    "sep panic",
    "secure enclave",
    "applesepmanager",
    "applesepkeystore",
    ":sks",
    "/sks",
    "bridgeos",
    "smc panic",
    "pmu panic",
    "ans panic",
    "dcp panic",
    "aop panic",
    "rtkit",
];

/// Best guess at which layer a panic came from. None when nothing matches.
pub fn classify_panic(
    panic_string: &str,
    caused_by: Option<&str>,
    kexts: &[String],
) -> Option<PanicBlame> {
    let text = format!("{} {}", caused_by.unwrap_or(""), panic_string).to_ascii_lowercase();
    if let Some((marker, subsystem)) = HARDWARE_PANIC_MARKERS
        .iter()
        .find(|(m, _)| text.contains(m))
    {
        return Some(PanicBlame {
            class: BlameClass::HardwareSuspect,
            subsystem,
            marker: (*marker).into(),
        });
    }
    if let Some(marker) = FIRMWARE_PANIC_MARKERS.iter().find(|m| text.contains(*m)) {
        return Some(PanicBlame {
            class: BlameClass::Firmware,
            subsystem: "a coprocessor or its firmware",
            marker: (*marker).into(),
        });
    }
    if let Some(kext) = kexts.iter().find(|k| !k.starts_with("com.apple.")) {
        return Some(PanicBlame {
            class: BlameClass::Software,
            subsystem: "a third-party kernel extension",
            marker: kext.clone(),
        });
    }
    if text.contains("userspace watchdog timeout") {
        return Some(PanicBlame {
            class: BlameClass::Software,
            subsystem: "a hung system process (userspace watchdog)",
            marker: "userspace watchdog timeout".into(),
        });
    }
    None
}

/// Jetsam kill-reason classes, per xnu `memstat_kill_cause_name[]`
/// (bsd/kern/kern_memorystatus.c) and Apple's doc/vm/memorystatus_kills.md.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum JetsamClass {
    /// Routine reaping of idle processes — not a memory problem.
    Housekeeping,
    /// One process crossed its own cap — a leak in that process.
    PerProcessCap,
    /// A shared system resource ran out; the victim is often not the culprit.
    SystemPressure,
}

fn jetsam_class(reason: &str) -> JetsamClass {
    match reason {
        // System-wide exhaustion. "highwater" is a soft per-process limit that
        // only kills while the system is under pressure, so it counts as
        // system pressure. "vm-thrashing" is the pre-10.14 name for
        // "proc-thrashing"; "low-swap" is effectively iOS-only but system-level.
        "vm-pageshortage"
        | "vm-compressor-space-shortage"
        | "vm-compressor-thrashing"
        | "fc-thrashing"
        | "zone-map-exhaustion"
        | "vnode-limit"
        | "vm-pageout-starvation"
        | "proc-thrashing"
        | "vm-thrashing"
        | "highwater"
        | "low-swap" => JetsamClass::SystemPressure,
        "idle-exit" | "long-idle-exit" | "sustained-memory-pressure" => JetsamClass::Housekeeping,
        // per-process-limit, conclave-limit, and anything unrecognized.
        _ => JetsamClass::PerProcessCap,
    }
}

fn parse_jetsam(path: &Path, body: &str, ts: Option<DateTime<Utc>>) -> Option<ParsedReport> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let largest = v
        .get("largestProcess")
        .and_then(|l| l.as_str())
        .unwrap_or("unknown")
        .to_string();
    let mut killed: Vec<(String, String)> = Vec::new();
    if let Some(procs) = v.get("processes").and_then(|p| p.as_array()) {
        for p in procs {
            if let (Some(name), Some(reason)) = (
                p.get("name").and_then(|n| n.as_str()),
                p.get("reason").and_then(|r| r.as_str()),
            ) {
                killed.push((name.to_string(), reason.to_string()));
            }
        }
    }
    // Key the finding by the VICTIM, not by whichever process happened to be
    // biggest at the moment of the kill — otherwise one recurring victim shows
    // up as several findings named after innocent bystanders.
    let victim = killed
        .first()
        .map(|(n, _)| n.clone())
        .unwrap_or_else(|| "unknown".to_string());
    // Worst class across all killed processes drives the finding.
    let class = killed
        .iter()
        .map(|(_, r)| jetsam_class(r))
        .max()
        .unwrap_or(JetsamClass::PerProcessCap);
    let killed_list = killed
        .iter()
        .take(5)
        .map(|(n, r)| format!("{n} ({r})"))
        .collect::<Vec<_>>()
        .join(", ");

    let mut f = if class == JetsamClass::Housekeeping {
        let mut f = Finding::new(
            "file.jetsam",
            Severity::Low,
            "memory",
            "Jetsam reaped idle processes (routine housekeeping)",
        );
        f.detail = format!(
            "The kernel reaped idle, assertion-less daemons ({killed_list}). This is normal \
             memory management, not a shortage — no action needed."
        );
        f.next_step = None;
        f
    } else if class == JetsamClass::SystemPressure {
        let mut f = Finding::new(
            "file.jetsam",
            Severity::High,
            "memory",
            &format!("System memory-pressure kill (jetsam) — killed {victim}"),
        );
        f.detail = format!(
            "The kernel ran out of memory headroom and force-killed processes ({killed_list}). \
             {largest} held the most memory when the kill fired. Frequent system-pressure jetsam \
             events mean this Mac genuinely needs more free RAM: check for a leaking process or \
             reduce concurrent workload."
        );
        f.next_step = Some(format!(
            "Find the memory hog now: `top -o mem -n 5 -l 1` — {largest} was the biggest when the \
             kill fired. Quit or restart it, or reduce concurrent workload."
        ));
        f
    } else {
        let mut f = Finding::new(
            "file.jetsam",
            Severity::Medium,
            "memory",
            &format!("{victim} exceeded its own memory limit (jetsam per-process cap)"),
        );
        f.detail = format!(
            "{victim} crossed the resident-memory cap macOS imposes on it ({killed_list}) — a leak \
             or runaway allocation in that process, NOT the system running out of memory. Overall \
             memory pressure is reported separately in the vitals."
        );
        f.next_step = Some(format!(
            "If this repeats, {victim} is leaking: restart it, check for an update, and watch it \
             with `top -pid $(pgrep {victim})`."
        ));
        f
    };
    f.process = Some(victim);
    f.timestamp = ts;
    f.evidence.push(Evidence {
        source: path.display().to_string(),
        excerpt: format!("killed: {killed_list} · largest process at kill: {largest}"),
    });
    Some(ParsedReport::Finding(f))
}

fn parse_crash_309(
    path: &Path,
    header: &serde_json::Value,
    body: &str,
    ts: Option<DateTime<Utc>>,
) -> Option<ParsedReport> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let proc_name = v
        .get("procName")
        .and_then(|p| p.as_str())
        .or_else(|| header.get("app_name").and_then(|a| a.as_str()))
        .unwrap_or("unknown")
        .to_string();
    let exc_type = v
        .pointer("/exception/type")
        .and_then(|t| t.as_str())
        .unwrap_or("unknown exception");
    let signal = v.pointer("/exception/signal").and_then(|s| s.as_str());
    let term = v
        .pointer("/termination/indicator")
        .and_then(|t| t.as_str())
        .map(String::from);

    let mut excerpt = format!("exception {exc_type}");
    if let Some(sig) = signal {
        excerpt.push_str(&format!(" / {sig}"));
    }
    if let Some(t) = &term {
        excerpt.push_str(&format!(", {t}"));
    }

    // `ExcUserFault_*` reports are simulated crash reports: a process logged an
    // os_log fault (os_fault_with_payload → EXC_GUARD, "Application Triggered
    // Fault") and macOS captured a diagnostic snapshot WITHOUT terminating it.
    // Verified 2026-09-30: nsattributedstringagent pid 29401 kept logging for
    // 2 minutes after its report. Counting these as crashes produced false
    // "crash-looping" findings for nsattributedstringagent and jamf.
    let is_user_fault = path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.starts_with("ExcUserFault_"));
    if is_user_fault {
        let mut f = Finding::new(
            "file.user_fault",
            Severity::Info,
            "crash",
            &format!("{proc_name} logged a non-fatal fault report (it kept running)"),
        );
        f.process = Some(proc_name.clone());
        f.detail = format!(
            "{proc_name} recorded an internal fault and macOS saved a diagnostic snapshot \
             (ExcUserFault report, {excerpt}). The process was not terminated, so this is not a \
             crash; the report exists for Apple or the vendor."
        );
        f.next_step = Some(format!(
            "No action unless {proc_name} visibly misbehaves; if it does, include these reports \
             when contacting the vendor."
        ));
        f.timestamp = ts;
        f.evidence.push(Evidence {
            source: path.display().to_string(),
            excerpt,
        });
        return Some(ParsedReport::Finding(f));
    }

    let mut f = Finding::new(
        "file.crash",
        Severity::Medium,
        "crash",
        &format!("{proc_name} crashed ({exc_type})"),
    );
    f.process = Some(proc_name.clone());
    f.detail = format!(
        "{proc_name} crashed with {excerpt}. One-off crashes happen; repeated crashes of the same \
         process point at a real defect, a bad update, or corrupted state."
    );
    // "Code Signature Invalid" / "Launch Constraint Violation" kills cannot be
    // fixed by reinstalling the app — for system components (Dock, Finder) that
    // advice is impossible on the sealed system volume.
    let signing_kill = excerpt.contains("Code Signature Invalid")
        || excerpt.contains("Launch Constraint Violation");
    f.next_step = Some(if signing_kill {
        format!(
            "{proc_name} was killed by a code-signing/launch-constraint check, not an app defect. \
             Often transient right after an OS update or restart; if it recurs, reinstall macOS \
             in place from Recovery (non-erasing) — do not try to reinstall {proc_name} itself."
        )
    } else {
        format!(
            "If it repeats, update or reinstall {proc_name}; clearing its preferences/caches often \
             fixes corrupted-state crashes."
        )
    });
    f.timestamp = ts;
    f.evidence.push(Evidence {
        source: path.display().to_string(),
        excerpt,
    });
    Some(ParsedReport::Finding(f))
}

fn hang_finding(path: &Path, app: &str, body: &str, ts: Option<DateTime<Utc>>) -> Finding {
    let duration = hang_duration(body);
    let mut f = Finding::new(
        "file.hang",
        Severity::Medium,
        "hang",
        &match duration {
            Some(d) => format!("{app} was unresponsive for {d:.2}s"),
            None => format!("{app} was unresponsive (hang report)"),
        },
    );
    f.process = Some(app.to_string());
    f.detail = format!(
        "macOS captured {app} not responding to events (spinning beachball). Occasional short hangs \
         are normal under load; repeated or long hangs mean the app is blocking on something — \
         disk, network, a lock, or a bug."
    );
    f.next_step = Some(format!(
        "If it hangs again, capture it in the act: `sample {app} 5` (or `sudo spindump {app}`), \
         then update or reinstall the app."
    ));
    f.timestamp = ts;
    f.evidence.push(Evidence {
        source: path.display().to_string(),
        excerpt: String::new(),
    });
    f
}

/// Duration from "Date/Time:" to "End time:" header lines, or a "duration" JSON key.
fn hang_duration(body: &str) -> Option<f64> {
    let mut start = None;
    let mut end = None;
    for line in body.lines().take(30) {
        if let Some(v) = line.strip_prefix("Date/Time:") {
            start = parse_report_time(v.trim());
        } else if let Some(v) = line.strip_prefix("End time:") {
            end = parse_report_time(v.trim());
        }
    }
    match (start, end) {
        (Some(s), Some(e)) => Some((e - s).num_milliseconds() as f64 / 1000.0),
        _ => serde_json::from_str::<serde_json::Value>(body)
            .ok()
            .and_then(|v| v.get("duration").and_then(|d| d.as_f64())),
    }
}

fn parse_hang(path: &Path, name: &str) -> Option<ParsedReport> {
    let content = std::fs::read_to_string(path).ok()?;
    let app = text_field(&content, "Command:")
        .or_else(|| text_field(&content, "Process:"))
        .or_else(|| name.split(['_', '-']).next().map(String::from))
        .unwrap_or_else(|| "unknown".into());
    let ts = text_field(&content, "Date/Time:").and_then(|t| parse_report_time(&t));
    Some(ParsedReport::Finding(hang_finding(
        path, &app, &content, ts,
    )))
}

fn parse_shutdown_stall(path: &Path, _name: &str) -> Option<ParsedReport> {
    let content = std::fs::read_to_string(path).ok()?;
    let proc_name = text_field(&content, "Command:").or_else(|| text_field(&content, "Process:"));
    let ts = text_field(&content, "Date/Time:").and_then(|t| parse_report_time(&t));
    let mut f = Finding::new(
        "file.shutdown_stall",
        Severity::Medium,
        "hang",
        "a process stalled system shutdown",
    );
    if let Some(p) = &proc_name {
        f.summary = format!("{p} stalled system shutdown");
        f.process = Some(p.clone());
    }
    f.detail = "A process refused to exit at shutdown, forcing macOS to wait or kill it. Repeated \
                stalls point at a misbehaving daemon or app."
        .into();
    f.next_step = Some(
        "If it repeats, read the stall report for the guilty process, then find its job with \
         `launchctl list | grep -iv com.apple` and update or remove that software."
            .into(),
    );
    f.timestamp = ts;
    f.evidence.push(Evidence {
        source: path.display().to_string(),
        excerpt: String::new(),
    });
    Some(ParsedReport::Finding(f))
}

fn parse_gpu_restart(path: &Path, _name: &str) -> Option<ParsedReport> {
    let content = std::fs::read_to_string(path).unwrap_or_default();
    let ts = text_field(&content, "Date/Time:").and_then(|t| parse_report_time(&t));
    let mut f = Finding::new(
        "file.gpu_restart",
        Severity::Medium,
        "gpu",
        "GPU hang caused a driver reset",
    );
    f.detail = "The GPU stopped responding and the driver reset it (screen may have frozen or \
                flashed). Occasional restarts under heavy graphics load can be benign; repeated \
                ones point at a driver bug, a bad app, or failing hardware."
        .into();
    f.next_step = Some(
        "Note which app was on screen; update it and macOS. If restarts continue across apps, run \
         Apple Diagnostics to rule out the GPU itself."
            .into(),
    );
    f.timestamp = ts;
    f.evidence.push(Evidence {
        source: path.display().to_string(),
        excerpt: String::new(),
    });
    Some(ParsedReport::Finding(f))
}

fn parse_legacy_crash(path: &Path, name: &str) -> Option<ParsedReport> {
    let content = std::fs::read_to_string(path).ok()?;
    let proc_name = text_field(&content, "Process:")
        .map(|p| p.split_whitespace().next().unwrap_or(&p).to_string())
        .or_else(|| name.split(['_', '-']).next().map(String::from))
        .unwrap_or_else(|| "unknown".into());
    let exc = text_field(&content, "Exception Type:").unwrap_or_else(|| "unknown".into());
    let ts = text_field(&content, "Date/Time:").and_then(|t| parse_report_time(&t));
    let mut f = Finding::new(
        "file.crash",
        Severity::Medium,
        "crash",
        &format!("{proc_name} crashed ({exc})"),
    );
    f.process = Some(proc_name.clone());
    f.detail = format!(
        "{proc_name} crashed with {exc}. One-off crashes happen; repeated crashes of the same \
         process point at a real defect, a bad update, or corrupted state."
    );
    f.next_step = Some(format!("If it repeats, update or reinstall {proc_name}."));
    f.timestamp = ts;
    f.evidence.push(Evidence {
        source: path.display().to_string(),
        excerpt: format!("exception {exc}"),
    });
    Some(ParsedReport::Finding(f))
}

fn parse_diag(path: &Path, name: &str, categories: &HashSet<Category>) -> Option<ParsedReport> {
    let content = std::fs::read_to_string(path).ok()?;
    let app = text_field(&content, "Command:")
        .or_else(|| name.split('_').next().map(String::from))
        .unwrap_or_else(|| "unknown".into());
    let ts = text_field(&content, "Date/Time:").and_then(|t| parse_report_time(&t));
    if name.contains("cpu_resource") || content.contains("Event:            cpu usage") {
        if !wants(categories, Category::ResourceAbuse) {
            return Some(ParsedReport::Skipped);
        }
        return Some(ParsedReport::Finding(cpu_resource_finding(
            path, &app, &content, ts,
        )));
    }
    if name.contains("wakeups_resource") || content.contains("Event:            wakeups") {
        if !wants(categories, Category::ResourceAbuse) {
            return Some(ParsedReport::Skipped);
        }
        return Some(ParsedReport::Finding(wakeups_finding(
            path, &app, &content, ts,
        )));
    }
    // Sleep Wake Failure reports are spindump text with no JSON header —
    // match by filename (bug_type 24, Apple OSAnalytics config).
    let lowered = name.to_lowercase();
    if lowered.contains("sleep wake failure") || lowered.contains("sleepwakefailure") {
        if !wants(categories, Category::Power) {
            return Some(ParsedReport::Skipped);
        }
        let mut f = Finding::new(
            "file.sleep_wake_failure",
            Severity::High,
            "sleep/wake",
            "Sleep wake failure — the Mac died instead of waking",
        );
        f.detail = "The kernel's sleep/wake transition failed outright (the classic 'closed the \
                    lid, found it dead or burning hot in the bag'). Usually a driver or device \
                    refusing to sleep, or a firmware bug."
            .into();
        f.next_step = Some(
            "Check wake history: `pmset -g log | grep -i 'wake from'`. Suspect USB/Thunderbolt \
             devices, network wake, and any third-party kext in the inventory."
                .into(),
        );
        f.timestamp = ts;
        f.evidence.push(Evidence {
            source: path.display().to_string(),
            excerpt: String::new(),
        });
        return Some(ParsedReport::Finding(f));
    }
    // Other .diag types (disk writes, first-party diagnostics) — ignore quietly.
    Some(ParsedReport::Skipped)
}

fn cpu_resource_finding(path: &Path, app: &str, body: &str, ts: Option<DateTime<Utc>>) -> Finding {
    let cpu_line = body
        .lines()
        .find(|l| l.trim_start().starts_with("CPU:"))
        .map(|l| l.trim().to_string())
        .unwrap_or_default();
    let action = body
        .lines()
        .find(|l| l.trim_start().starts_with("Action taken:"))
        .map(|l| format!(" · {}", l.split_whitespace().collect::<Vec<_>>().join(" ")))
        .unwrap_or_default();
    let cpu_line = format!("{cpu_line}{action}");
    let mut f = Finding::new(
        "file.cpu_resource",
        Severity::Medium,
        "resource_abuse",
        &format!("{app} exceeded its CPU usage limit"),
    );
    f.process = Some(app.to_string());
    f.detail = "macOS noted sustained high CPU from this process and saved a report; the \
                \"Action taken\" line in the evidence says whether anything was done (usually \
                nothing). A one-off report is a busy spell; a process that keeps doing it is \
                degrading performance and battery life."
        .into();
    f.next_step = Some(format!(
        "Watch it live: `top -pid $(pgrep {app})`. Indexing/backup daemons often settle on their \
         own; if it stays hot, see what it's touching: `sudo fs_usage -w -f filesys {app}`."
    ));
    f.timestamp = ts;
    f.evidence.push(Evidence {
        source: path.display().to_string(),
        excerpt: cpu_line,
    });
    f
}

fn wakeups_finding(path: &Path, app: &str, body: &str, ts: Option<DateTime<Utc>>) -> Finding {
    let wakeups_line = body
        .lines()
        .find(|l| l.trim_start().starts_with("Wakeups:"))
        .map(|l| l.trim().to_string())
        .unwrap_or_default();
    let mut f = Finding::new(
        "file.wakeups",
        Severity::Low,
        "resource_abuse",
        &format!("{app} wakes the CPU excessively"),
    );
    f.process = Some(app.to_string());
    f.detail = "This process wakes the CPU far more often than allowed, draining battery and \
                stealing performance headroom even when 'idle'."
        .into();
    f.next_step = Some(format!(
        "Usually fixed by an app update. If {app} keeps tripping the limit, quit it when unused or \
         remove its background helper."
    ));
    f.timestamp = ts;
    f.evidence.push(Evidence {
        source: path.display().to_string(),
        excerpt: wakeups_line,
    });
    f
}

fn text_field(content: &str, key: &str) -> Option<String> {
    content.lines().take(60).find_map(|l| {
        l.strip_prefix(key)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    })
}
