//! baseline / diff — capture a known-good inventory, answer "what changed since it worked".

use crate::audit::{InstallEvent, LaunchItem};
use crate::report::Category;
use crate::util::run;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;

#[derive(Serialize, Deserialize)]
pub struct Baseline {
    pub captured_at: DateTime<Utc>,
    pub macos_build: String,
    pub loaded_kexts: Vec<String>,
    pub sysexts: Vec<String>,
    pub launch_items: Vec<LaunchItem>,
    pub install_count: usize,
    pub last_install: Option<InstallEvent>,
    pub disk_pct_full: u32,
    pub snapshot_count: usize,
    pub sip_enabled: bool,
    pub gatekeeper_enabled: bool,
    pub filevault_on: bool,
    /// Hardware wear, so `diff` can show aging since the baseline. Absent in
    /// baselines saved before 0.11 (and on Macs without the data).
    #[serde(default)]
    pub ssd_percent_used: Option<u32>,
    #[serde(default)]
    pub battery_cycles: Option<u32>,
    #[serde(default)]
    pub battery_max_capacity_pct: Option<u32>,
}

pub fn baseline_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    home.join("Library/Application Support/mactriage/baseline.json")
}

pub fn capture(root: bool) -> Baseline {
    let all: HashSet<Category> = Category::ALL.iter().copied().collect();
    let audit = crate::audit::scan(&all, root, Utc::now() - chrono::Duration::days(36500));
    let df = run("df", &["-k", "/"]).unwrap_or_default();
    let disk_pct_full = df
        .lines()
        .nth(1)
        .and_then(|l| l.split_whitespace().nth(4))
        .and_then(|p| p.trim_end_matches('%').parse().ok())
        .unwrap_or(0);
    let snapshot_count = run("tmutil", &["listlocalsnapshots", "/"])
        .map(|o| {
            o.lines()
                .filter(|l| l.contains("com.apple.TimeMachine."))
                .count()
        })
        .unwrap_or(0);
    Baseline {
        captured_at: Utc::now(),
        macos_build: run("sw_vers", &["-buildVersion"])
            .unwrap_or_default()
            .trim()
            .into(),
        loaded_kexts: audit.loaded_kexts,
        sysexts: audit.sysexts,
        launch_items: audit.launch_items,
        install_count: audit.installs.len(),
        last_install: audit.installs.last().cloned(),
        disk_pct_full,
        snapshot_count,
        sip_enabled: !run("csrutil", &["status"])
            .unwrap_or_default()
            .to_lowercase()
            .contains("disabled"),
        gatekeeper_enabled: !run("spctl", &["--status"])
            .unwrap_or_default()
            .to_lowercase()
            .contains("disabled"),
        filevault_on: run("fdesetup", &["status"])
            .unwrap_or_default()
            .contains("FileVault is On"),
        ssd_percent_used: crate::hardware::ssd_check(&crate::host::boot_physical_disk())
            .percentage_used,
        battery_cycles: crate::power::read_battery_ioreg().and_then(|b| b.cycle_count),
        battery_max_capacity_pct: crate::power::read_profiler_battery()
            .and_then(|(_, _, pct)| u32::try_from(pct).ok()),
    }
}

pub fn save(b: &Baseline) -> std::io::Result<PathBuf> {
    let path = baseline_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(b)?)?;
    Ok(path)
}

pub fn diff(root: bool) -> Result<String, String> {
    let path = baseline_path();
    let old: Baseline = serde_json::from_str(&std::fs::read_to_string(&path).map_err(|_| {
        format!(
            "no baseline found at {} — run `mactriage baseline` first",
            path.display()
        )
    })?)
    .map_err(|e| format!("baseline unreadable: {e}"))?;
    let new = capture(root);

    let mut out = String::new();
    out.push_str(&format!(
        "baseline {} → now ({} elapsed)\n\n",
        old.captured_at
            .with_timezone(&chrono::Local)
            .format("%Y-%m-%d %H:%M"),
        crate::util::human_duration((Utc::now() - old.captured_at).num_seconds().max(0) as u64),
    ));

    let mut changes = 0;
    if old.macos_build != new.macos_build {
        out.push_str(&format!(
            "  ~ macOS build: {} → {}\n",
            old.macos_build, new.macos_build
        ));
        changes += 1;
    }
    changes += diff_list(&mut out, "kext", &old.loaded_kexts, &new.loaded_kexts);
    changes += diff_list(&mut out, "system extension", &old.sysexts, &new.sysexts);

    let old_labels: Vec<String> = old.launch_items.iter().map(|i| i.label.clone()).collect();
    let new_labels: Vec<String> = new.launch_items.iter().map(|i| i.label.clone()).collect();
    changes += diff_list(&mut out, "launch item", &old_labels, &new_labels);

    if new.install_count > old.install_count {
        out.push_str(&format!(
            "  + {} new install(s) since baseline{}\n",
            new.install_count - old.install_count,
            new.last_install
                .as_ref()
                .map(|i| format!(" (latest: {} {})", i.name, i.version))
                .unwrap_or_default()
        ));
        changes += 1;
    }
    if new.disk_pct_full.abs_diff(old.disk_pct_full) >= 5 {
        out.push_str(&format!(
            "  ~ disk: {}% → {}% full\n",
            old.disk_pct_full, new.disk_pct_full
        ));
        changes += 1;
    }
    if new.snapshot_count != old.snapshot_count {
        out.push_str(&format!(
            "  ~ local TM snapshots: {} → {}\n",
            old.snapshot_count, new.snapshot_count
        ));
        changes += 1;
    }
    for (name, was, is) in [
        ("SIP", old.sip_enabled, new.sip_enabled),
        ("Gatekeeper", old.gatekeeper_enabled, new.gatekeeper_enabled),
        ("FileVault", old.filevault_on, new.filevault_on),
    ] {
        if was != is {
            out.push_str(&format!(
                "  ! {name}: {} → {}\n",
                if was { "on" } else { "off" },
                if is { "on" } else { "off" }
            ));
            changes += 1;
        }
    }

    for (name, unit, was, is) in [
        ("SSD wear", "%", old.ssd_percent_used, new.ssd_percent_used),
        ("battery cycles", "", old.battery_cycles, new.battery_cycles),
        (
            "battery capacity",
            "%",
            old.battery_max_capacity_pct,
            new.battery_max_capacity_pct,
        ),
    ] {
        if let (Some(was), Some(is)) = (was, is) {
            if was != is {
                out.push_str(&format!("  ~ {name}: {was}{unit} → {is}{unit}\n"));
                changes += 1;
            }
        }
    }

    if changes == 0 {
        out.push_str("  no changes — inventory matches the baseline\n");
    }
    Ok(out)
}

fn diff_list(out: &mut String, kind: &str, old: &[String], new: &[String]) -> usize {
    let old_set: std::collections::HashSet<&String> = old.iter().collect();
    let new_set: std::collections::HashSet<&String> = new.iter().collect();
    let mut n = 0;
    for added in new.iter().filter(|i| !old_set.contains(i)) {
        out.push_str(&format!("  + new {kind}: {added}\n"));
        n += 1;
    }
    for removed in old.iter().filter(|i| !new_set.contains(i)) {
        out.push_str(&format!("  - removed {kind}: {removed}\n"));
        n += 1;
    }
    n
}
