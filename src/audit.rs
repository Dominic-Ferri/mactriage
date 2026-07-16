//! audit.* / posture.* rules — launch items, BTM, kext inventory, security posture,
//! MDM profiles, and install history.

use crate::report::{Category, Evidence, Finding, Severity, Skipped};
use crate::util::{run, run_with_timeout};
use chrono::{DateTime, Utc};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LaunchItem {
    pub label: String,
    pub plist: String,
    pub exec: Option<String>,
    pub exec_missing: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InstallEvent {
    pub name: String,
    pub version: String,
    pub date: DateTime<Utc>,
}

pub struct AuditResult {
    pub findings: Vec<Finding>,
    pub skipped: Vec<Skipped>,
    /// Inventory shared with the correlator and baseline.
    pub launch_items: Vec<LaunchItem>,
    pub loaded_kexts: Vec<String>,
    pub sysexts: Vec<String>,
    pub installs: Vec<InstallEvent>,
}

pub fn scan(
    categories: &HashSet<Category>,
    root: bool,
    window_start: DateTime<Utc>,
) -> AuditResult {
    let mut r = AuditResult {
        findings: Vec::new(),
        skipped: Vec::new(),
        launch_items: Vec::new(),
        loaded_kexts: Vec::new(),
        sysexts: Vec::new(),
        installs: Vec::new(),
    };
    if categories.contains(&Category::LaunchItems) {
        launch_items(&mut r, root);
        btm(&mut r, root);
    }
    if categories.contains(&Category::Kexts) {
        kexts(&mut r);
    }
    if categories.contains(&Category::Posture) {
        posture(&mut r, root);
    }
    if categories.contains(&Category::Updates) {
        install_history(&mut r, window_start);
    }
    r
}

/// Launch item folders outside /System. As root (HOME may be root's), every
/// account's LaunchAgents, plus the invoking user's home if it is elsewhere.
fn launch_dirs(root: bool) -> Vec<PathBuf> {
    let mut dirs = vec![
        PathBuf::from("/Library/LaunchDaemons"),
        PathBuf::from("/Library/LaunchAgents"),
    ];
    let mut homes: Vec<PathBuf> = Vec::new();
    if root {
        if let Ok(users) = std::fs::read_dir("/Users") {
            homes.extend(users.flatten().map(|e| e.path()));
        }
        if let Some(home) = std::env::var("SUDO_USER").ok().and_then(|u| user_home(&u)) {
            homes.push(home);
        }
    } else if let Some(home) = std::env::var_os("HOME") {
        homes.push(PathBuf::from(home));
    }
    homes.sort();
    homes.dedup();
    dirs.extend(homes.into_iter().map(|h| h.join("Library/LaunchAgents")));
    dirs
}

/// Home folder of a local account, from its directory record.
fn user_home(user: &str) -> Option<PathBuf> {
    let out = run(
        "/usr/bin/dscl",
        &[".", "-read", &format!("/Users/{user}"), "NFSHomeDirectory"],
    )?;
    let home = out.trim().strip_prefix("NFSHomeDirectory:")?.trim();
    home.starts_with('/').then(|| PathBuf::from(home))
}

/// Apple's own item: an Apple-labelled job whose program carries Apple's
/// platform signature and is not an interpreter running someone's script.
fn apple_launch_item(item: &LaunchItem) -> bool {
    item.label.starts_with("com.apple.")
        && item.exec.as_deref().is_some_and(|e| {
            crate::security::interpreter_name(e).is_none() && crate::security::verifies_as_apple(e)
        })
}

fn launch_items(r: &mut AuditResult, root: bool) {
    let mut broken: Vec<LaunchItem> = Vec::new();
    let mut total = 0u32;
    for dir in launch_dirs(root) {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e != "plist").unwrap_or(true) {
                continue;
            }
            total += 1;
            let item = parse_launch_plist(&path);
            if let Some(item) = item {
                if item.exec_missing {
                    broken.push(item.clone());
                }
                r.launch_items.push(item);
            }
        }
    }
    if !broken.is_empty() {
        let mut f = Finding::new(
            "audit.launch_broken",
            Severity::Medium,
            "launch_items",
            &format!(
                "{} launch item(s) point at binaries that no longer exist",
                broken.len()
            ),
        );
        f.count = broken.len() as u32;
        f.detail = format!(
            "Leftovers from uninstalled software: launchd retries them forever, they spam the log, \
             and adware/PUPs hide among them. Broken: {}.",
            broken
                .iter()
                .take(6)
                .map(|b| b.label.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        f.next_step = Some(
            "Inspect each plist below; if the parent app is truly gone, move the plist to an \
             Archive folder (don't delete) and `launchctl bootout` the label."
                .into(),
        );
        for b in broken.iter().take(6) {
            f.evidence.push(Evidence {
                source: b.plist.clone(),
                excerpt: format!("{} → missing {}", b.label, b.exec.as_deref().unwrap_or("?")),
            });
        }
        r.findings.push(f);
    }
    // Inventory note (info) so the report shows third-party footprint at a glance.
    // Everything in these folders is third-party unless it verifies as Apple's:
    // a `com.apple.` label alone proves nothing.
    let third_party: Vec<&LaunchItem> = r
        .launch_items
        .iter()
        .filter(|i| !apple_launch_item(i))
        .collect();
    if !third_party.is_empty() {
        let mut f = Finding::new(
            "audit.launch_inventory",
            Severity::Info,
            "launch_items",
            &format!(
                "{} third-party launch item(s) installed ({total} total)",
                third_party.len()
            ),
        );
        f.detail = "Third-party daemons and agents that start automatically. Each one is listed \
                    below with the program it runs."
            .into();
        f.next_step = Some(
            "Anything here you don't recognize deserves a look — this list is where unwanted \
             background software lives."
                .into(),
        );
        f.evidence.extend(third_party.iter().map(|i| Evidence {
            source: i.plist.clone(),
            excerpt: format!(
                "{} → {}",
                i.label,
                i.exec.as_deref().unwrap_or("(no program)")
            ),
        }));
        r.findings.push(f);
    }
}

pub(crate) fn parse_launch_plist(path: &Path) -> Option<LaunchItem> {
    let v: plist::Value = plist::from_file(path).ok()?;
    let dict = v.as_dictionary()?;
    let label = dict
        .get("Label")
        .and_then(|l| l.as_string())
        .unwrap_or("(no label)")
        .to_string();
    let exec = dict
        .get("Program")
        .and_then(|p| p.as_string())
        .map(String::from)
        .or_else(|| {
            dict.get("ProgramArguments")
                .and_then(|a| a.as_array())
                .and_then(|a| a.first())
                .and_then(|p| p.as_string())
                .map(String::from)
        });
    let exec_missing = exec
        .as_deref()
        // Only judge absolute paths; bare names resolve via PATH at launch.
        .map(|e| e.starts_with('/') && !Path::new(e).exists())
        .unwrap_or(false);
    Some(LaunchItem {
        label,
        plist: path.display().to_string(),
        exec,
        exec_missing,
    })
}

fn btm(r: &mut AuditResult, root: bool) {
    // `sfltool dumpbtm` needs root; run as a normal user it HANGS indefinitely
    // (and would take the whole scan with it). Only run it under sudo, and still
    // cap it with a timeout as a safety net.
    if !root {
        r.skipped.push(Skipped {
            what: "Background Task Management database (sfltool dumpbtm)".into(),
            reason: "requires sudo — re-run with sudo to audit login/background items".into(),
        });
        return;
    }
    let (out, timed_out) =
        run_with_timeout("/usr/bin/sfltool", &["dumpbtm"], Duration::from_secs(20));
    if timed_out {
        r.skipped.push(Skipped {
            what: "Background Task Management database (sfltool dumpbtm)".into(),
            reason: "sfltool dumpbtm timed out after 20s — skipped".into(),
        });
        return;
    }
    if out.trim().is_empty() {
        return;
    }
    // Records contain "Name:", "Executable Path:" (or URL); flag entries whose executable is gone.
    let mut cur_name = String::new();
    let mut orphans: Vec<(String, String)> = Vec::new();
    for line in out.lines() {
        let t = line.trim();
        if let Some(v) = t.strip_prefix("Name:") {
            cur_name = v.trim().to_string();
        } else if let Some(v) = t.strip_prefix("Executable Path:") {
            let p = v.trim().trim_start_matches("file://").to_string();
            if p.starts_with('/') && !Path::new(&p).exists() {
                orphans.push((cur_name.clone(), p));
            }
        }
    }
    if !orphans.is_empty() {
        let mut f = Finding::new(
            "audit.btm_orphan",
            Severity::Medium,
            "launch_items",
            &format!(
                "{} background/login item(s) point at missing executables",
                orphans.len()
            ),
        );
        f.count = orphans.len() as u32;
        f.detail = "Entries in the Background Task Management database whose executable no longer \
                    exists — stale login items from removed apps. They clutter Login Items \
                    settings and can trip launch errors."
            .into();
        f.next_step = Some(
            "Remove them in System Settings ▸ General ▸ Login Items, or reset the database as a \
             last resort (`sfltool resetbtm` — resets ALL items, ask first)."
                .into(),
        );
        for (name, p) in orphans.iter().take(6) {
            f.evidence.push(Evidence {
                source: "sfltool dumpbtm".into(),
                excerpt: format!("{name} → missing {p}"),
            });
        }
        r.findings.push(f);
    }
}

fn kexts(r: &mut AuditResult) {
    let out = run("/usr/bin/kmutil", &["showloaded", "--collection", "aux"]).unwrap_or_default();
    for line in out.lines() {
        // "  178    0 0xfff...  com.example.kext.filter (1.0.0) UUID <...>"
        for tok in line.split_whitespace() {
            if tok.contains('.')
                && !tok.starts_with("com.apple.")
                && tok
                    .chars()
                    .next()
                    .map(|c| c.is_alphabetic())
                    .unwrap_or(false)
                && tok.matches('.').count() >= 2
            {
                r.loaded_kexts.push(tok.to_string());
                break;
            }
        }
    }
    let se = run("/usr/bin/systemextensionsctl", &["list"]).unwrap_or_default();
    for line in se.lines() {
        // "* * TEAMID com.vendor.ext (1.0/1) Name [activated enabled]"
        if line.contains("activated") {
            if let Some(bundle) = line
                .split_whitespace()
                .find(|t| t.contains('.') && t.matches('.').count() >= 2)
            {
                if !bundle.starts_with("com.apple.") {
                    r.sysexts.push(bundle.to_string());
                }
            }
        }
    }
    r.loaded_kexts.sort();
    r.loaded_kexts.dedup();
    r.sysexts.sort();
    r.sysexts.dedup();

    if !r.loaded_kexts.is_empty() || !r.sysexts.is_empty() {
        let mut f = Finding::new(
            "audit.kext_inventory",
            Severity::Info,
            "kexts",
            &format!(
                "{} third-party kernel extension(s), {} system extension(s) active",
                r.loaded_kexts.len(),
                r.sysexts.len()
            ),
        );
        f.detail = format!(
            "Third-party kernel code is the #1 panic suspect on any Mac.{}{}",
            if r.loaded_kexts.is_empty() {
                String::new()
            } else {
                format!(" Kexts: {}.", r.loaded_kexts.join(", "))
            },
            if r.sysexts.is_empty() {
                String::new()
            } else {
                format!(" System extensions: {}.", r.sysexts.join(", "))
            }
        );
        f.next_step = Some(
            "Legacy kexts especially: check the vendor for updates. If a panic finding above \
             names one of these, that's your root cause."
                .into(),
        );
        r.findings.push(f);
    }
}

/// A posture check whose tool gave no recognizable answer: say so instead of
/// reporting a clean result.
fn not_verified(r: &mut AuditResult, what: &str) {
    r.skipped.push(Skipped {
        what: what.into(),
        reason: "the command failed or its output was not recognized — NOT verified".into(),
    });
}

fn posture(r: &mut AuditResult, root: bool) {
    // SIP
    let sip = run("/usr/bin/csrutil", &["status"])
        .unwrap_or_default()
        .to_lowercase();
    if !sip.contains("enabled") && !sip.contains("disabled") {
        not_verified(r, "System Integrity Protection status (csrutil status)");
    }
    if sip.contains("disabled") {
        let mut f = Finding::new(
            "posture.sip_disabled",
            Severity::Medium,
            "posture",
            "System Integrity Protection is DISABLED",
        );
        f.detail = "With SIP off, anything running as root can modify system files — weird \
                    behavior and malware persistence both get much easier. Often left over from a \
                    one-time tweak and forgotten."
            .into();
        f.next_step = Some(
            "Re-enable from Recovery: `csrutil enable`, unless there's a documented reason.".into(),
        );
        r.findings.push(f);
    }
    // Gatekeeper
    let gk = run("/usr/sbin/spctl", &["--status"])
        .unwrap_or_default()
        .to_lowercase();
    if !gk.contains("enabled") && !gk.contains("disabled") {
        not_verified(r, "Gatekeeper status (spctl --status)");
    }
    if gk.contains("disabled") {
        let mut f = Finding::new(
            "posture.gatekeeper_off",
            Severity::Medium,
            "posture",
            "Gatekeeper (app assessment) is disabled",
        );
        f.detail = "Unsigned/unnotarized apps run without any check. Fine on a dedicated dev box, \
                    a red flag on a user machine."
            .into();
        f.next_step = Some("Re-enable: `sudo spctl --master-enable`.".into());
        r.findings.push(f);
    }
    // FileVault
    let fv = run("/usr/bin/fdesetup", &["status"]).unwrap_or_default();
    if !fv.contains("FileVault is On") && !fv.contains("FileVault is Off") {
        not_verified(r, "FileVault status (fdesetup status)");
    }
    if fv.contains("FileVault is Off") {
        let mut f = Finding::new(
            "posture.filevault_off",
            Severity::Low,
            "posture",
            "FileVault disk encryption is off",
        );
        f.detail = "Data at rest is unencrypted — anyone with the drive reads everything. Worth \
                    flagging on any portable Mac."
            .into();
        f.next_step = Some(
            "Enable in System Settings ▸ Privacy & Security ▸ FileVault (store the recovery key)."
                .into(),
        );
        r.findings.push(f);
    }
    // Application firewall
    let fw = run(
        "/usr/libexec/ApplicationFirewall/socketfilterfw",
        &["--getglobalstate"],
    )
    .unwrap_or_default();
    if crate::security::parse_firewall_state(&fw) == crate::security::FirewallState::Off {
        let mut f = Finding::new(
            "posture.firewall_off",
            Severity::Medium,
            "posture",
            "Application firewall is off",
        );
        f.detail = "Not fatal on a trusted LAN, but on laptops that roam networks it's free \
                    protection left switched off."
            .into();
        f.next_step = Some("Enable in System Settings ▸ Network ▸ Firewall.".into());
        r.findings.push(f);
    }
    // XProtect staleness — freshest mtime across BOTH delivery paths. Modern
    // macOS ships active protections via XProtect.app (XProtectRemediator);
    // the legacy XProtect.bundle can sit untouched for months on a perfectly
    // healthy Mac (2026-09-08 field report false-flagged 102 days from it).
    let newest_xp = [
        "/Library/Apple/System/Library/CoreServices/XProtect.bundle",
        "/Library/Apple/System/Library/CoreServices/XProtect.app",
    ]
    .iter()
    .filter_map(|p| std::fs::metadata(Path::new(p)).ok()?.modified().ok())
    .max();
    if let Some(modified) = newest_xp {
        {
            let age = (Utc::now() - DateTime::<Utc>::from(modified)).num_days();
            if age > 90 {
                let mut f = Finding::new(
                    "posture.xprotect_stale",
                    Severity::Medium,
                    "posture",
                    &format!("XProtect malware definitions are {age} days old"),
                );
                f.detail = "Apple ships XProtect updates every few weeks in the background. \
                            Months-old definitions usually mean background updates are broken \
                            (MDM block, network filter, or `softwareupdate` disabled)."
                    .into();
                f.next_step = Some(
                    "Force a check: `sudo softwareupdate --background-critical`, and verify \
                     automatic updates are on in System Settings ▸ General ▸ Software Update."
                        .into(),
                );
                r.findings.push(f);
            }
        }
    }
    // MDM / configuration profiles — inventory, because MDM payloads explain 'unfixable' settings.
    // `profiles list` shows user profiles unprivileged; system + MDM payloads appear under sudo.
    let _ = root;
    let profiles = run("/usr/bin/profiles", &["list"]).unwrap_or_default();
    let profile_count = profiles
        .lines()
        .filter(|l| l.contains("profileIdentifier"))
        .count();
    if profile_count > 0 {
        let mut f = Finding::new(
            "posture.mdm_profiles",
            Severity::Info,
            "posture",
            &format!("{profile_count} configuration profile(s) installed"),
        );
        f.detail = "Configuration profiles can pin DNS, proxies, certificates, keychain items, \
                    and update policy. When a setting 'won't stick' or auth behaves strangely, \
                    check here first."
            .into();
        f.next_step =
            Some("Enumerate: `profiles list` (user) / `sudo profiles list` (system + MDM).".into());
        f.evidence.push(Evidence {
            source: "profiles list".into(),
            excerpt: profiles
                .lines()
                .filter(|l| l.contains("profileIdentifier"))
                .take(6)
                .map(|l| l.trim())
                .collect::<Vec<_>>()
                .join(" · "),
        });
        r.findings.push(f);
    }
}

fn install_history(r: &mut AuditResult, window_start: DateTime<Utc>) {
    let v: plist::Value = match plist::from_file("/Library/Receipts/InstallHistory.plist") {
        Ok(v) => v,
        Err(_) => return,
    };
    let Some(arr) = v.as_array() else { return };
    for item in arr {
        let Some(d) = item.as_dictionary() else {
            continue;
        };
        let name = d
            .get("displayName")
            .and_then(|n| n.as_string())
            .unwrap_or("")
            .to_string();
        let version = d
            .get("displayVersion")
            .and_then(|n| n.as_string())
            .unwrap_or("")
            .to_string();
        let date = d.get("date").and_then(|dt| dt.as_date()).map(|dt| {
            let sys: std::time::SystemTime = dt.into();
            DateTime::<Utc>::from(sys)
        });
        if let Some(date) = date {
            if !name.is_empty() {
                r.installs.push(InstallEvent {
                    name,
                    version,
                    date,
                });
            }
        }
    }
    r.installs.sort_by_key(|i| i.date);

    let recent: Vec<&InstallEvent> = r
        .installs
        .iter()
        .filter(|i| i.date >= window_start)
        .collect();
    if !recent.is_empty() {
        let mut f = Finding::new(
            "audit.install_history",
            Severity::Info,
            "updates",
            &format!("{} install(s) in the scan window", recent.len()),
        );
        f.detail = format!(
            "Software installed during the window: {}. \"It broke right after an update\" is the \
             most common root cause there is — the correlator flags findings that started shortly \
             after one of these.",
            // List everything in the window — a truncated list next to a larger
            // count reads as a contradiction ("9 installs" listing 8).
            recent
                .iter()
                .rev()
                .map(|i| format!(
                    "{} {} ({})",
                    i.name,
                    i.version,
                    i.date.with_timezone(&chrono::Local).format("%b %e")
                ))
                .collect::<Vec<_>>()
                .join(", ")
        );
        f.next_step = Some("Full history: `system_profiler SPInstallHistoryDataType` or /Library/Receipts/InstallHistory.plist.".into());
        f.count = recent.len() as u32;
        r.findings.push(f);
    }
}
