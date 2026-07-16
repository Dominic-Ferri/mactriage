//! Backups & storage bloat — APFS local snapshots, purgeable space, Time Machine staleness.

use crate::report::{Category, Evidence, Finding, Severity};
use crate::util::run;
use chrono::{NaiveDateTime, TimeZone, Utc};
use std::collections::HashSet;

pub fn scan(categories: &HashSet<Category>) -> Vec<Finding> {
    let mut findings = Vec::new();
    if categories.contains(&Category::Disk) {
        apfs_snapshots(&mut findings);
    }
    if categories.contains(&Category::Backups) {
        time_machine(&mut findings);
    }
    findings
}

fn apfs_snapshots(findings: &mut Vec<Finding>) {
    let out = run("tmutil", &["listlocalsnapshots", "/"]).unwrap_or_default();
    // Lines like "com.apple.TimeMachine.2026-07-16-101112.local"
    let snaps: Vec<&str> = out
        .lines()
        .filter(|l| l.contains("com.apple.TimeMachine."))
        .collect();
    if snaps.is_empty() {
        return;
    }
    let oldest_age_days = snaps
        .iter()
        .filter_map(|s| {
            let stamp = s
                .split("com.apple.TimeMachine.")
                .nth(1)?
                .trim_end_matches(".local");
            let nt = NaiveDateTime::parse_from_str(stamp, "%Y-%m-%d-%H%M%S").ok()?;
            let t = chrono::Local.from_local_datetime(&nt).single()?;
            Some((Utc::now() - t.with_timezone(&Utc)).num_days())
        })
        .max()
        .unwrap_or(0);

    // Purgeable space is what these snapshots (and caches) are holding hostage.
    let purgeable = run("diskutil", &["info", "/"])
        .and_then(|o| {
            o.lines()
                .find(|l| l.contains("Purgeable"))
                .map(|l| l.rsplit(':').next().unwrap_or("").trim().to_string())
        })
        .unwrap_or_default();

    // Local snapshots are normal: Time Machine keeps roughly a day of them and
    // thins automatically as space is needed, so a dozen is expected. Only flag
    // as a problem when they coincide with a genuinely full disk — the real
    // "I deleted everything and it's still full" case. Otherwise this is Info.
    let disk_pct: u32 = run("df", &["-k", "/"])
        .and_then(|o| {
            o.lines().nth(1).and_then(|l| {
                l.split_whitespace()
                    .nth(4)
                    .map(|s| s.trim_end_matches('%').to_string())
            })
        })
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let under_pressure = disk_pct >= 85;
    let severity = if under_pressure {
        Severity::Medium
    } else {
        Severity::Info
    };
    let mut f = Finding::new(
        "snap.apfs_snapshots",
        severity,
        "disk",
        &format!(
            "{} local Time Machine snapshot(s) on the boot volume (oldest {oldest_age_days}d)",
            snaps.len()
        ),
    );
    f.count = snaps.len() as u32;
    f.detail = if under_pressure {
        format!(
            "The boot volume is {disk_pct}% full and local APFS snapshots are holding deleted data \
             that Finder can't see — the classic \"I deleted everything and the disk is still full\" \
             case.{} macOS thins these under pressure but sometimes not fast enough.",
            if purgeable.is_empty() {
                String::new()
            } else {
                format!(" Purgeable space right now: {purgeable}.")
            }
        )
    } else {
        format!(
            "Local APFS snapshots are a normal part of Time Machine (about a day's worth, thinned \
             automatically). Nothing to do while the disk has room ({disk_pct}% full).{}",
            if purgeable.is_empty() {
                String::new()
            } else {
                format!(" Purgeable space: {purgeable}.")
            }
        )
    };
    f.next_step = if under_pressure {
        Some(
            "If you need space now, let macOS reclaim it: `tmutil thinlocalsnapshots / 20000000000 4`. \
             These are snapshot copies, not your Time Machine backup — but prefer thinning over \
             deleting individual snapshots."
                .into(),
        )
    } else {
        None
    };
    f.evidence.push(Evidence {
        source: "tmutil listlocalsnapshots /".into(),
        excerpt: snaps.iter().take(5).cloned().collect::<Vec<_>>().join(", "),
    });
    findings.push(f);
}

fn time_machine(findings: &mut Vec<Finding>) {
    let dest = run("tmutil", &["destinationinfo"]).unwrap_or_default();
    if dest.contains("No destinations configured") {
        let mut f = Finding::new(
            "snap.tm_stale",
            Severity::Low,
            "backups",
            "No Time Machine backup destination configured",
        );
        f.detail = "This Mac has no backup destination at all. Not an error, but the first \
                    question after any disk finding is \"where's the backup?\""
            .into();
        f.next_step = Some(
            "Point Time Machine at a disk or NAS: System Settings ▸ General ▸ Time Machine.".into(),
        );
        findings.push(f);
        return;
    }
    if dest.trim().is_empty() {
        return; // tmutil unavailable / no Full Disk Access — stay quiet rather than guess
    }
    let latest = run("tmutil", &["latestbackup"]).unwrap_or_default();
    let stamp = latest
        .trim()
        .rsplit('/')
        .next()
        .unwrap_or("")
        .trim_end_matches(".backup")
        .to_string();
    let latest_time = NaiveDateTime::parse_from_str(&stamp, "%Y-%m-%d-%H%M%S")
        .ok()
        .and_then(|nt| chrono::Local.from_local_datetime(&nt).single());

    match latest_time {
        Some(t) => {
            let age_days = (Utc::now() - t.with_timezone(&Utc)).num_days();
            if age_days >= 7 {
                let sev = if age_days >= 30 {
                    Severity::High
                } else {
                    Severity::Medium
                };
                let mut f = Finding::new(
                    "snap.tm_stale",
                    sev,
                    "backups",
                    &format!("Last completed Time Machine backup is {age_days} days old"),
                );
                f.timestamp = Some(t.with_timezone(&Utc));
                f.detail = "A destination is configured but backups haven't completed recently — \
                            the machine is effectively unprotected and nobody got told."
                    .into();
                f.next_step = Some(
                    "Start one and watch it: `tmutil startbackup --auto`; check errors with \
                     `log show --last 1h --predicate 'process == \"backupd\"' --style compact`."
                        .into(),
                );
                findings.push(f);
            }
        }
        None => {
            let mut f = Finding::new(
                "snap.tm_stale",
                Severity::Medium,
                "backups",
                "Time Machine destination configured but no completed backup found",
            );
            f.detail = "tmutil reports a destination but cannot name a latest backup — either no \
                        backup has ever completed or the destination is unreachable/corrupt."
                .into();
            f.next_step = Some(
                "Check the destination: `tmutil destinationinfo`, mount it, then \
                 `tmutil startbackup --auto`. (If mactriage lacks Full Disk Access this can also \
                 be a permissions false alarm — verify in Terminal.)"
                    .into(),
            );
            f.evidence.push(Evidence {
                source: "tmutil destinationinfo".into(),
                excerpt: dest.lines().take(4).collect::<Vec<_>>().join(" · "),
            });
            findings.push(f);
        }
    }
}
