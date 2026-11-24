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
    // Fixture override for unprivileged test runs. Ignored as root, where the
    // caller's environment must not choose what a privileged scan reads.
    if !root {
        if let Some(fixture) = std::env::var_os("MACTRIAGE_REPORTS_DIR") {
            return vec![PathBuf::from(fixture)];
        }
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

// Returned once per report file and consumed at once; boxing would only add
// an allocation per finding.
#[allow(clippy::large_enum_variant)]
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

    let first_line = Some(one_line(&panic_string, 300))
        .filter(|l| !l.is_empty())
        .unwrap_or_else(|| "kernel panic".into());

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
    let pctx = PanicContext::from_panic_string(&panic_string);
    if let Some(kind) = pctx.kind {
        f.detail
            .push_str(&format!(" Panic type: {}.", kind.meaning));
    }
    f.next_step = Some(match pctx.kind.and_then(|k| k.next_step) {
        Some(step) => format!(
            "{step} {} to rule out hardware.",
            crate::util::apple_diagnostics_step()
        ),
        None => format!(
            "If it recurs, note what hardware/apps were in use. Update or remove any third-party \
             kext in the backtrace. {} to rule out hardware.",
            crate::util::apple_diagnostics_step()
        ),
    });
    f.timestamp = ts;
    f.evidence.push(Evidence {
        source: path.display().to_string(),
        excerpt: first_line,
    });
    f.evidence.extend(pctx.evidence());
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

/// What a panic string's well-known lines say. Field layout follows the panic
/// reports macOS writes (`panic(cpu N caller …): reason`, `Panicked task …:
/// pid N: name`, `last started kext at …`, version lines).
#[derive(Debug, Default)]
pub(crate) struct PanicContext {
    pub panicked_process: Option<String>,
    pub watchdog_service: Option<String>,
    pub last_started_kext: Option<String>,
    pub os_version: Option<String>,
    pub kernel_version: Option<String>,
    pub iboot_version: Option<String>,
    pub kind: Option<&'static PanicKind>,
}

/// A recognisable family of panic headline. `meaning` and `next_step` are
/// mactriage's reading of the headline, not Apple text.
#[derive(Debug)]
pub(crate) struct PanicKind {
    pub marker: &'static str,
    pub meaning: &'static str,
    pub next_step: Option<&'static str>,
}

pub(crate) const PANIC_KINDS: &[PanicKind] = &[
    PanicKind {
        marker: "userspace watchdog timeout",
        meaning: "a critical system process stopped checking in with the userspace watchdog, so \
                  the kernel restarted the Mac on purpose. The named service was stuck; the panic \
                  does not say whether on its own code or on something it waited for (graphics, \
                  storage, a kernel extension)",
        next_step: Some(
            "Look for crash, hang, GPU, disk and launchd findings around the panic time, \
             especially for the service named in the evidence.",
        ),
    },
    PanicKind {
        marker: "sleep transition timed out",
        meaning: "the Mac did not finish going to sleep in time (a driver or device refused to sleep)",
        next_step: Some(
            "Disconnect USB/Thunderbolt devices and test sleep; check sleep/wake findings and the \
             kext inventory.",
        ),
    },
    PanicKind {
        marker: "wake transition timed out",
        meaning: "the Mac did not finish waking in time (a driver or device did not come back)",
        next_step: Some(
            "Disconnect USB/Thunderbolt devices and test wake; check sleep/wake findings and the \
             kext inventory.",
        ),
    },
    PanicKind {
        marker: "zone map exhausted",
        meaning: "the kernel ran out of its own memory (a kernel memory leak, usually in a driver)",
        next_step: Some(
            "Remove or update third-party kernel and system extensions first; a leak this size is \
             almost always a driver.",
        ),
    },
    PanicKind {
        marker: "kernel data abort",
        meaning: "kernel code used an invalid memory address (a kernel or driver defect, or bad memory)",
        next_step: None,
    },
    PanicKind {
        marker: "kernel instruction fetch abort",
        meaning: "the kernel jumped to an invalid code address (a kernel or driver defect, or bad memory)",
        next_step: None,
    },
    PanicKind {
        marker: "watchdog timeout",
        meaning: "the kernel watchdog got no check-ins from watchdogd in time: the system was hung \
                  or starved, either in userspace or in the kernel",
        next_step: None,
    },
    PanicKind {
        marker: "kernel trap",
        meaning: "the CPU trapped inside kernel code (Intel; a kernel or driver defect, or bad memory)",
        next_step: None,
    },
];

impl PanicContext {
    pub(crate) fn from_panic_string(ps: &str) -> Self {
        let mut c = PanicContext::default();
        let lines: Vec<String> = ps.lines().map(|l| clean(l).trim().to_string()).collect();
        // Classify from the headline only: the `panic(cpu …)` line and the two
        // lines after it. The backtrace, task list and zone dump below it can
        // mention any of the markers without being the reason for the panic.
        let head_at = lines
            .iter()
            .position(|l| l.to_ascii_lowercase().contains("panic("))
            .or_else(|| lines.iter().position(|l| !l.is_empty()))
            .unwrap_or(0);
        let headline = lines
            .iter()
            .skip(head_at)
            .take(3)
            .map(|l| l.to_ascii_lowercase())
            .collect::<Vec<_>>()
            .join(" ");
        c.kind = PANIC_KINDS.iter().find(|k| headline.contains(k.marker));
        // A value after the label, or (Intel panic format) on the next
        // non-empty line.
        let value = |i: usize, line: &str| -> Option<String> {
            let inline = line.split_once(':').map(|(_, v)| v.trim()).unwrap_or("");
            let v = if inline.is_empty() {
                lines.iter().skip(i + 1).find(|l| !l.is_empty())?.as_str()
            } else {
                inline
            };
            (!v.is_empty() && !v.eq_ignore_ascii_case("not set")).then(|| one_line(v, 160))
        };
        for (i, line) in lines.iter().enumerate() {
            let l = line.to_ascii_lowercase();
            if c.panicked_process.is_none() && l.starts_with("panicked task") {
                // "Panicked task 0x…: 3402 pages, 16 threads: pid 123: WindowServer"
                if let Some(idx) = line.rfind("pid ") {
                    c.panicked_process = line[idx..]
                        .split_once(": ")
                        .map(|(pid, name)| format!("{} ({pid})", name.trim()));
                }
            } else if c.panicked_process.is_none()
                && l.starts_with("bsd process name corresponding to current thread:")
            {
                c.panicked_process = value(i, line);
            } else if c.last_started_kext.is_none() && l.starts_with("last started kext") {
                c.last_started_kext = line
                    .split_once(": ")
                    .and_then(|(_, k)| k.split_whitespace().next())
                    .map(String::from);
            } else if c.os_version.is_none()
                && ["os version:", "mac os version:", "macos version:"]
                    .iter()
                    .any(|p| l.starts_with(p))
            {
                c.os_version = value(i, line);
            } else if c.kernel_version.is_none() && l.starts_with("kernel version:") {
                c.kernel_version = value(i, line);
            } else if c.iboot_version.is_none() && l.starts_with("iboot version:") {
                c.iboot_version = value(i, line);
            }
            if c.watchdog_service.is_none() {
                for marker in ["no successful checkins from ", "no checkins from "] {
                    if let Some(idx) = l.find(marker) {
                        c.watchdog_service = line[idx + marker.len()..]
                            .split([',', ' ', '\t'])
                            .next()
                            .filter(|s| !s.is_empty())
                            .map(String::from);
                        break;
                    }
                }
            }
        }
        c
    }

    fn evidence(&self) -> Vec<Evidence> {
        let mut out = Vec::new();
        let fields = [
            ("panicked process", &self.panicked_process),
            (
                "watchdog service that stopped checking in",
                &self.watchdog_service,
            ),
            (
                "last started kext (not necessarily the cause)",
                &self.last_started_kext,
            ),
            ("os version", &self.os_version),
            ("kernel version", &self.kernel_version),
            ("iBoot version", &self.iboot_version),
        ];
        for (source, value) in fields {
            if let Some(v) = value {
                out.push(Evidence {
                    source: source.into(),
                    excerpt: v.clone(),
                });
            }
        }
        out
    }
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
        .map(|n| one_line(n, 120))
        .unwrap_or_else(|| "unknown".into());
    let exc_type = v
        .pointer("/exception/type")
        .and_then(|t| t.as_str())
        .map(|t| one_line(t, 80))
        .unwrap_or_else(|| "unknown exception".into());
    let signal = v
        .pointer("/exception/signal")
        .and_then(|s| s.as_str())
        .map(|s| one_line(s, 40));
    let term = v
        .pointer("/termination/indicator")
        .and_then(|t| t.as_str())
        .map(|t| one_line(t, 200));

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

    let ctx = CrashContext::from_report(&v);
    // WindowServer draws every window and loginwindow owns the login session;
    // when either dies, macOS ends the session and every open app quits, so
    // the user sees a black screen and the login window: a "soft crash" of
    // the whole Mac without a kernel panic.
    let session = is_session_process(&proc_name, v.get("procPath").and_then(|p| p.as_str()));
    let mut f = Finding::new(
        "file.crash",
        if session {
            Severity::High
        } else {
            Severity::Medium
        },
        "crash",
        &if session {
            format!("{proc_name} crashed ({exc_type}): this normally ends the login session")
        } else {
            format!("{proc_name} crashed ({exc_type})")
        },
    );
    f.process = Some(proc_name.clone());
    f.detail = format!(
        "{proc_name} crashed with {excerpt}. One-off crashes happen; repeated crashes of the same \
         process point at a real defect, a bad update, or corrupted state."
    );
    if session {
        f.detail.push_str(&format!(
            " {proc_name} is the system's own login-session component, so its crash normally \
             logs the user out and quits every open app, without a kernel panic."
        ));
    }
    let reading = ctx.meanings();
    if !reading.is_empty() {
        f.detail.push(' ');
        f.detail.push_str(&reading.join(" "));
    }
    // "Code Signature Invalid" / "Launch Constraint Violation" kills cannot be
    // fixed by reinstalling the app — for system components (Dock, Finder) that
    // advice is impossible on the sealed system volume.
    let signing_kill = excerpt.contains("Code Signature Invalid")
        || excerpt.contains("Launch Constraint Violation");
    f.next_step = Some(if let Some(step) = ctx.next_step(&proc_name) {
        step
    } else if signing_kill {
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
    if !reading.is_empty() {
        // Lets the correlator quote this report's reading without the
        // generic sentences around it.
        f.evidence.push(Evidence {
            source: READING_SOURCE.into(),
            excerpt: reading.join(" "),
        });
    }
    f.evidence.extend(ctx.evidence());
    f.references = ctx.references();
    Some(ParsedReport::Finding(f))
}

/// Evidence source of mactriage's own reading of one crash report.
pub(crate) const READING_SOURCE: &str = "mactriage reading";

/// The system's login-session processes, by name and the folder macOS ships
/// them in, so a third-party binary that shares the name is not mistaken for
/// one. A report without `procPath` is trusted by name.
const SESSION_PROCESSES: &[(&str, &str)] = &[
    (
        "WindowServer",
        "/System/Library/PrivateFrameworks/SkyLight.framework/",
    ),
    (
        "loginwindow",
        "/System/Library/CoreServices/loginwindow.app/",
    ),
];

pub(crate) fn is_session_process(name: &str, path: Option<&str>) -> bool {
    SESSION_PROCESSES
        .iter()
        .any(|(n, prefix)| *n == name && path.is_none_or(|p| p.starts_with(prefix)))
}

/// System libraries whose frames sit on top of the stack in an abort or a
/// raised exception; the code that called them is the useful "crashed in".
const ABORT_PLUMBING: &[&str] = &[
    "libsystem_kernel.dylib",
    "libsystem_pthread.dylib",
    "libsystem_c.dylib",
    "libc++abi.dylib",
    "libobjc.A.dylib",
    "libdyld.dylib",
];

/// The fields of a JSON crash report (bug_type 309) that explain WHY a process
/// died, as laid out in Apple's "Interpreting the JSON format of a crash
/// report". Each one is optional; old or partial reports omit many.
#[derive(Debug, Default)]
pub(crate) struct CrashContext {
    pub exc_type: Option<String>,
    pub signal: Option<String>,
    /// e.g. "KERN_INVALID_ADDRESS at 0x0000000000000000"
    pub subtype: Option<String>,
    pub codes: Option<String>,
    pub term_namespace: Option<String>,
    pub term_code: Option<u64>,
    pub term_indicator: Option<String>,
    pub term_by_proc: Option<String>,
    /// Application Specific Information: messages a library or the process
    /// itself left for the crash report ("abort() called", assertion text).
    pub asi: Vec<String>,
    /// Kernel triage strings: what the kernel saw go wrong (I/O, pagein).
    pub ktriage: Vec<String>,
    /// First line of the VM region summary for the faulting address.
    pub vm_region: Option<String>,
    /// Binary image and symbol at the top of the crashed thread.
    pub crashed_in: Option<String>,
    pub responsible: Option<String>,
    pub translated: bool,
}

impl CrashContext {
    pub(crate) fn from_report(v: &serde_json::Value) -> Self {
        let s = |p: &str| v.pointer(p).and_then(|x| x.as_str()).map(String::from);
        let asi = v
            .get("asi")
            .and_then(|a| a.as_object())
            .map(|m| {
                m.iter()
                    .flat_map(|(lib, msgs)| {
                        let msgs: Vec<String> = match msgs {
                            serde_json::Value::Array(a) => a
                                .iter()
                                .filter_map(|x| x.as_str().map(String::from))
                                .collect(),
                            serde_json::Value::String(x) => vec![x.clone()],
                            _ => Vec::new(),
                        };
                        msgs.into_iter()
                            .map(move |m| format!("{}: {}", clean(lib), one_line(&m, 300)))
                    })
                    .take(8)
                    .collect()
            })
            .unwrap_or_default();
        let ktriage = v
            .get("ktriageinfo")
            .and_then(|k| k.as_str())
            .map(|k| {
                k.lines()
                    .map(|l| one_line(l, 200))
                    .filter(|l| !l.is_empty())
                    .take(8)
                    .collect()
            })
            .unwrap_or_default();
        // Apple's JSON reference names the key `vmregioninfo`; current reports
        // carry both spellings.
        let vm_region = v
            .get("vmregioninfo")
            .or_else(|| v.get("vmRegionInfo"))
            .and_then(|r| r.as_str())
            .and_then(|r| r.lines().next())
            .map(|l| one_line(l, 200));
        fn frame_name<'a>(
            v: &'a serde_json::Value,
            frame: &'a serde_json::Value,
        ) -> Option<(&'a str, Option<&'a str>)> {
            let image = frame
                .get("imageIndex")
                .and_then(|i| i.as_u64())
                .and_then(|i| v.pointer(&format!("/usedImages/{i}/name")))
                .and_then(|n| n.as_str())?;
            Some((image, frame.get("symbol").and_then(|x| x.as_str())))
        }
        // Skip the system frames only for an abort; in a memory fault the top
        // frame is where the fault really happened, even inside a library.
        let aborted = v.pointer("/exception/type").and_then(|t| t.as_str()) == Some("EXC_CRASH");
        let crashed_in = v
            .get("faultingThread")
            .and_then(|t| t.as_u64())
            .and_then(|t| v.pointer(&format!("/threads/{t}/frames")))
            .and_then(|f| f.as_array())
            .and_then(|frames| {
                let named: Vec<(&str, Option<&str>)> = frames
                    .iter()
                    .take(64)
                    .filter_map(|f| frame_name(v, f))
                    .collect();
                named
                    .iter()
                    .find(|(image, _)| !aborted || !ABORT_PLUMBING.contains(image))
                    .or(named.first())
                    .map(|(image, sym)| match sym {
                        Some(sym) => clean(&format!("{image} ({sym})")),
                        None => clean(image),
                    })
            });
        let responsible = s("/responsibleProc")
            .filter(|r| Some(r) != s("/procName").as_ref())
            .map(|r| clean(&r));
        CrashContext {
            exc_type: s("/exception/type").map(|x| clean(&x)),
            signal: s("/exception/signal").map(|x| clean(&x)),
            subtype: s("/exception/subtype").map(|x| one_line(&x, 200)),
            codes: s("/exception/codes").map(|x| one_line(&x, 200)),
            term_namespace: s("/termination/namespace").map(|x| clean(&x)),
            term_code: v.pointer("/termination/code").and_then(|c| c.as_u64()),
            term_indicator: s("/termination/indicator").map(|x| one_line(&x, 200)),
            term_by_proc: s("/termination/byProc").map(|x| clean(&x)),
            asi,
            ktriage,
            vm_region,
            crashed_in,
            responsible,
            translated: v.get("translated").and_then(|t| t.as_bool()) == Some(true),
        }
    }

    /// Faulting address of a memory-access exception, from the subtype
    /// ("KERN_INVALID_ADDRESS at 0x…").
    pub(crate) fn fault_address(&self) -> Option<u64> {
        // "KERN_INVALID_ADDRESS at 0x… -> 0x… (possible pointer
        // authentication failure)": the first run of hex digits only.
        let sub = self.subtype.as_deref()?;
        let (_, rest) = sub.split_once("at 0x")?;
        let hex: String = rest.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
        u64::from_str_radix(&hex, 16).ok()
    }

    fn invalid_address(&self) -> bool {
        self.exc_type.as_deref() == Some("EXC_BAD_ACCESS")
            && self
                .subtype
                .as_deref()
                .is_some_and(|s| s.starts_with("KERN_INVALID_ADDRESS"))
    }

    /// Address 0 exactly: Apple's own example of a NULL pointer.
    pub(crate) fn null_pointer(&self) -> bool {
        self.invalid_address() && self.fault_address() == Some(0)
    }

    /// A nonzero address in the first page: most often a field read through
    /// a NULL pointer, but the address alone does not prove it.
    pub(crate) fn near_null(&self) -> bool {
        self.invalid_address() && self.fault_address().is_some_and(|a| a > 0 && a < 0x1000)
    }

    pub(crate) fn pointer_auth(&self) -> bool {
        self.subtype
            .as_deref()
            .is_some_and(|s| s.contains("pointer authentication"))
    }

    /// The kernel's own triage says a page-in from the file system failed,
    /// so the process died reading its code or a mapped file from storage.
    /// Only explicit failure lines count: KERN_MEMORY_ERROR alone also covers
    /// a mapped file that was truncated or whose network volume went away.
    pub(crate) fn pagein_failure(&self) -> bool {
        self.exc_type.as_deref() == Some("EXC_BAD_ACCESS")
            && self.ktriage.iter().any(|l| {
                let l = l.to_ascii_lowercase();
                (l.contains("pagein") && (l.contains("fail") || l.contains("error")))
                    || l.contains("page has error")
            })
    }

    /// mactriage's reading of the report for the detail text. Apple's own
    /// meaning of each decoded field is in `references`.
    pub(crate) fn meanings(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.pagein_failure() {
            out.push(
                "The kernel's triage says a page-in from the file system failed: the process \
                 died while reading its own code or a mapped file from storage. That points at \
                 a storage read failure (a damaged file, the disk, or its volume) more than at \
                 a defect in the program."
                    .to_string(),
            );
        } else if self.null_pointer() {
            out.push(
                "The faulting address is 0, a NULL pointer dereference: a defect in the code that \
                 crashed."
                    .to_string(),
            );
        } else if self.near_null() {
            out.push(
                "The faulting address is in the first memory page, which most often means a \
                 field was read through a NULL pointer (a defect in the code that crashed)."
                    .to_string(),
            );
        }
        if self.pointer_auth() {
            out.push(
                "The report flags a possible pointer authentication failure: a pointer was \
                 corrupted or forged before it was used."
                    .to_string(),
            );
        }
        if self
            .asi
            .iter()
            .any(|m| m.contains("Terminating app due to uncaught exception"))
        {
            out.push(
                "The application specific information names an uncaught language exception: the \
                 app stopped itself after an error it did not handle, and the exception name and \
                 reason are what the vendor needs."
                    .to_string(),
            );
        }
        out
    }

    /// Specific advice when the report pins the cause; None = generic advice.
    pub(crate) fn next_step(&self, proc_name: &str) -> Option<String> {
        if self.pagein_failure() {
            return Some(format!(
                "Treat this as a likely disk read problem before a {proc_name} bug: back up, run \
                 Disk Utility First Aid on the volume that holds {proc_name} (and on the startup \
                 volume), and check this report for disk I/O or APFS errors. If {proc_name} lives \
                 on an external or network disk, check that disk and its cable first. \
                 Reinstalling {proc_name} only helps if the damaged file is the app itself."
            ));
        }
        let ns = self.term_namespace.as_deref()?;
        let code = self.term_code?;
        crate::apple_docs::termination(ns, code).and_then(|d| d.next_step.map(String::from))
    }

    pub(crate) fn evidence(&self) -> Vec<Evidence> {
        let mut out = Vec::new();
        let mut push = |source: &str, excerpt: String| {
            out.push(Evidence {
                source: source.into(),
                excerpt,
            })
        };
        if let Some(sub) = &self.subtype {
            push("exception subtype", sub.clone());
        }
        if let Some(c) = &self.codes {
            push("exception codes", c.clone());
        }
        if let Some(ns) = &self.term_namespace {
            push(
                "termination",
                format!(
                    "namespace {ns}, code {}{}{}",
                    self.term_code
                        .map(|c| format!("{c:#x}"))
                        .unwrap_or_else(|| "?".into()),
                    self.term_indicator
                        .as_deref()
                        .map(|i| format!(", \"{i}\""))
                        .unwrap_or_default(),
                    self.term_by_proc
                        .as_deref()
                        .map(|p| format!(", by {p}"))
                        .unwrap_or_default()
                ),
            );
        }
        if let Some(c) = &self.crashed_in {
            push("crashed in", c.clone());
        }
        if !self.asi.is_empty() {
            push("application specific information", self.asi.join(" | "));
        }
        if !self.ktriage.is_empty() {
            push("kernel triage", self.ktriage.join(" | "));
        }
        if let Some(r) = &self.vm_region {
            push("faulting address region", r.clone());
        }
        if let Some(r) = &self.responsible {
            push("responsible process", r.clone());
        }
        if self.translated {
            push(
                "translated",
                "ran under Rosetta (Intel code on Apple silicon)".into(),
            );
        }
        out
    }

    /// Report-specific Apple documentation for the decoded fields.
    pub(crate) fn references(&self) -> Vec<crate::report::Reference> {
        use crate::apple_docs as d;
        let mut out = Vec::new();
        // Most specific first: the termination reason, then the subtype.
        let decoded = [
            match (self.term_namespace.as_deref(), self.term_code) {
                (Some(ns), Some(code)) => d::termination(ns, code),
                _ => None,
            },
            self.subtype.as_deref().and_then(d::kern_subtype),
            self.exc_type.as_deref().and_then(d::exception_type),
            self.signal.as_deref().and_then(d::signal),
        ];
        for x in decoded.into_iter().flatten() {
            d::push_unique(&mut out, x.reference());
        }
        let fields = [
            ("asi", !self.asi.is_empty()),
            ("VM Region Info", self.vm_region.is_some()),
            (
                "namespace",
                self.term_namespace
                    .as_deref()
                    .is_some_and(|ns| ns != "SIGNAL"),
            ),
        ];
        for (field, present) in fields {
            if let Some(r) = d::crash_field(field).filter(|_| present) {
                d::push_unique(&mut out, r);
            }
        }
        out
    }
}

/// Report text with every control character (tabs included) turned into a
/// space, so an escape sequence planted in a report file cannot reach the
/// terminal while tab-separated fields stay apart.
fn clean(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// First line of `s` without control characters, cut to `max` characters.
fn one_line(s: &str, max: usize) -> String {
    let first = s.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    let cleaned = clean(first);
    let line = cleaned.trim();
    if line.chars().count() > max {
        format!("{}…", line.chars().take(max).collect::<String>())
    } else {
        line.to_string()
    }
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
