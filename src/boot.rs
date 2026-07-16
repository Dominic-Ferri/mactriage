//! boot.slow_boot — measure kernel-boot → loginwindow delta for the most recent boot.
//! Cheap: one narrow log query over a 10-minute window around boot, only when the
//! last boot happened inside the scan window.

use crate::report::{Category, Evidence, Finding, Severity};
use crate::util::{run, run_with_timeout};
use chrono::{DateTime, TimeZone, Utc};
use std::collections::HashSet;
use std::time::Duration;

pub fn scan(categories: &HashSet<Category>, window_start: DateTime<Utc>) -> Vec<Finding> {
    let mut findings = Vec::new();
    if !categories.contains(&Category::Boot) {
        return findings;
    }
    let bt = run("sysctl", &["-n", "kern.boottime"]).unwrap_or_default();
    let boot_secs: Option<i64> = bt
        .split("sec =")
        .nth(1)
        .and_then(|s| s.trim().split([',', ' ']).next())
        .and_then(|s| s.parse().ok());
    let Some(boot) = boot_secs.and_then(|s| Utc.timestamp_opt(s, 0).single()) else {
        return findings;
    };
    if boot < window_start {
        return findings; // machine hasn't rebooted inside the window — nothing to measure
    }

    let start = boot
        .with_timezone(&chrono::Local)
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    let end = (boot + chrono::Duration::minutes(10))
        .with_timezone(&chrono::Local)
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    let (out, _) = run_with_timeout(
        "/usr/bin/log",
        &[
            "show",
            "--style",
            "ndjson",
            "--start",
            &start,
            "--end",
            &end,
            "--predicate",
            r#"process == "loginwindow""#,
        ],
        Duration::from_secs(60),
    );
    let first_loginwindow = out.lines().find_map(|l| {
        serde_json::from_str::<serde_json::Value>(l)
            .ok()
            .and_then(|v| {
                v.get("timestamp")
                    .and_then(|t| t.as_str())
                    .and_then(crate::files::parse_report_time)
            })
    });
    let Some(lw) = first_loginwindow else {
        return findings;
    };
    let secs = (lw - boot).num_seconds();
    // The query is bounded to boot..boot+10min, so a loginwindow entry later
    // than that is out-of-range data from a stale/rotated archive (a 4-day-old
    // boot produced a bogus "7h 40m" boot time in the field) — unmeasurable,
    // not slow.
    if secs > 660 {
        return findings;
    }
    if secs > 180 {
        let mut f = Finding::new(
            "boot.slow_boot",
            Severity::Medium,
            "boot",
            &format!(
                "Last boot took {}+ to reach the login window",
                crate::util::human_duration(secs as u64)
            ),
        );
        f.timestamp = Some(boot);
        f.detail = "Kernel boot to loginwindow took unusually long. Common causes: a hung \
                    LaunchDaemon blocking startup, fsck running on a dirty volume, a dying disk, \
                    or a network mount timing out."
            .into();
        f.next_step = Some(
            "Watch the next boot verbosely (hold Cmd-V), or inspect this one: \
             `log show --start '<boot time>' --last-boot --style compact | head -200` and look \
             for multi-second gaps."
                .into(),
        );
        f.evidence.push(Evidence {
            source: "kern.boottime → first loginwindow log entry".into(),
            excerpt: format!("{secs}s"),
        });
        findings.push(f);
    }
    findings
}
