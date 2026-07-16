//! correlate.* — merge related findings into root-cause stories.
//!
//! crash_loop: ≥3 crashes of one process merged and escalated.
//! story: multiple different failure signals from one process merged.
//! panic_kext (v0.2.0): a kext named in a panic backtrace is still loaded.
//! post_update (v0.2.0): finding clusters that started shortly after an install.

use crate::audit::InstallEvent;
use crate::report::{Evidence, Finding, Severity};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use std::collections::HashMap;

/// Earlier of two optional times, ignoring `None` (unlike `Option::min`, which
/// treats `None` as smallest and would erase a real `first_seen`).
fn min_time(a: Option<DateTime<Utc>>, b: Option<DateTime<Utc>>) -> Option<DateTime<Utc>> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, None) => x,
        (None, y) => y,
    }
}

pub fn run(
    findings: Vec<Finding>,
    panic_kexts: &[String],
    loaded_kexts: &[String],
    installs: &[InstallEvent],
) -> Vec<Finding> {
    let mut merged = merge_repeats(findings);
    rate_cpu_limit_reports(&mut merged);
    let mut out = crash_loops_and_stories(merged);
    panic_kext_still_loaded(&mut out, panic_kexts, loaded_kexts);
    spotlight_stack(&mut out);
    post_update(&mut out, installs);
    out
}

/// A wedged Spotlight/knowledge index shows up as several findings across
/// categories — indexer daemons blowing CPU limits, mds error floods, and the
/// knowledge daemons being jetsam-killed on their own caps. Individually each
/// reads as medium noise; together they are one story with one fix, and that
/// story must outrank them (2026-09-08 field report buried it behind three
/// false highs).
const SPOTLIGHT_PROCS: &[&str] = &[
    "mds",
    "mds_stores",
    "mdworker",
    "mdworker_shared",
    "mdsync",
    "mdbulkimport",
    "corespotlightd",
    "spotlightknowledged",
    "knowledgeconstructiond",
    "media-indexer",
    "suggestd",
];

/// More substantive mds errors than this (routine churn is filtered in
/// logscan) suggests the index itself is damaged. Matches log.spotlight's own
/// Medium threshold.
const SPOTLIGHT_ERROR_FLOOD: u32 = 50;

fn spotlight_stack(out: &mut Vec<Finding>) {
    let is_member = |f: &Finding| match f.rule_id.as_str() {
        "log.spotlight" => true,
        "file.cpu_resource" | "file.jetsam" | "correlate.story" => f
            .process
            .as_deref()
            .map(|p| SPOTLIGHT_PROCS.contains(&p))
            .unwrap_or(false),
        _ => false,
    };
    let indexer_cpu = |f: &Finding| {
        f.rule_id == "file.cpu_resource"
            && f.process
                .as_deref()
                .is_some_and(|p| SPOTLIGHT_PROCS.contains(&p))
    };
    let members: Vec<&Finding> = out.iter().filter(|f| is_member(f)).collect();
    let classes: std::collections::HashSet<&str> =
        members.iter().map(|f| f.rule_id.as_str()).collect();
    // Memory kills of the indexer daemons mean the stack is thrashing. A jetsam
    // kill of a daemon that also blew its CPU limit has already been folded
    // into a per-process story ("<proc>: memory kills + runaway CPU").
    let thrashing = members.iter().any(|m| {
        m.rule_id == "file.jetsam"
            || (m.rule_id == "correlate.story" && m.summary.contains(short_kind("file.jetsam")))
    });
    let error_flood = members
        .iter()
        .any(|m| m.rule_id == "log.spotlight" && m.count > SPOTLIGHT_ERROR_FLOOD);
    // Indexers exceeding CPU limits plus some mds errors is scheduled background
    // work. 2026-09-30: spotlightknowledged's 14 reports were ~90 s bursts of one
    // core in KnowledgeGraphKit (the on-device knowledge graph), "Action taken:
    // none", while search tested current and correct. Neither a story nor the
    // old `mdutil -E /` advice fit; a rebuild doesn't even touch that store.
    if classes.len() < 2 || !(thrashing || error_flood) {
        // Info, not Low: the only advice is "no action unless there are
        // symptoms", which is what Info means in the attention list.
        for f in out.iter_mut().filter(|f| indexer_cpu(f)) {
            f.severity = Severity::Info;
            if !f.detail.contains("scheduled bursts") {
                f.detail.push_str(
                    " Apple's Spotlight and knowledge daemons work in scheduled bursts; with no \
                     memory kills or error flood this is expected background work.",
                );
            }
            f.next_step = Some(
                "No action unless Spotlight search is slow or missing results, or this daemon \
                 stays busy for hours while the Mac is idle."
                    .into(),
            );
        }
        return;
    }
    let count: u32 = members.iter().map(|f| f.count.max(1)).sum();
    let first = members
        .iter()
        .filter_map(|f| f.first_seen.or(f.timestamp))
        .min();
    let last = members.iter().filter_map(|f| f.timestamp).max();
    let summaries = members
        .iter()
        .map(|f| f.summary.as_str())
        .collect::<Vec<_>>()
        .join("; ");
    let mut f = if thrashing {
        let mut f = Finding::new(
            "correlate.spotlight_stack",
            Severity::High,
            "story",
            "Spotlight/knowledge indexing stack is degrading this Mac",
        );
        f.detail = format!(
            "Multiple independent signals, including memory kills of the indexer daemons, point \
             at the Spotlight/knowledge index being wedged: {summaries}. A corrupt or thrashing \
             index burns CPU, disk, and memory indefinitely and will not fix itself."
        );
        f.next_step = Some(
            "Rebuild the index: `sudo mdutil -E /` (Spotlight reindexes from scratch; the first \
             hours are busy, then it settles). Verify the daemons calm down in Activity Monitor \
             afterwards."
                .into(),
        );
        f
    } else {
        let mut f = Finding::new(
            "correlate.spotlight_stack",
            Severity::Medium,
            "story",
            "Spotlight index is logging heavy errors",
        );
        f.detail = format!(
            "mds logged a flood of indexer errors (routine client-disconnect and deleted-file \
             messages excluded) alongside indexer CPU reports: {summaries}. A damaged index \
             shows up as missing or stale search results."
        );
        f.next_step = Some(
            "Test search: `mdfind -name <a file you know exists>`. If results are missing or \
             stale, rebuild the index with `sudo mdutil -E /` (hours of reindexing). CPU from \
             spotlightknowledged (the knowledge graph) is not fixed by a rebuild."
                .into(),
        );
        f
    };
    f.count = count;
    f.timestamp = last;
    f.first_seen = first;
    for m in members.iter().take(4) {
        f.evidence.push(Evidence {
            source: format!("member finding · {}", m.rule_id),
            excerpt: m.summary.clone(),
        });
    }
    out.push(f);
    // Keep member rows for JSON evidence, but drop them out of the actionable
    // list — a 2026-09-09 run showed the same `mdutil -E /` advice five times.
    for member in out.iter_mut().filter(|finding| is_member(finding)) {
        member.severity = Severity::Info;
        if !member.detail.contains("Spotlight/knowledge stack") {
            member
                .detail
                .push_str(" Folded into the Spotlight/knowledge stack finding — same fix.");
        }
    }
}

/// A cpu_resource report is macOS noting a busy spell ("Action taken: none");
/// nothing was killed. One or two in the 7-day window are Low; a process that
/// keeps doing it (3 or more) is Medium. 2026-09-30: four one-off reports from
/// days earlier each read as Medium and held the Mac at DEGRADED.
fn rate_cpu_limit_reports(findings: &mut [Finding]) {
    for f in findings
        .iter_mut()
        .filter(|f| f.rule_id == "file.cpu_resource")
    {
        if f.count >= 3 {
            f.severity = Severity::Medium;
            if let Some(p) = &f.process {
                f.summary = format!("{p} exceeded its CPU usage limit {} times", f.count);
            }
        } else {
            f.severity = Severity::Low;
        }
    }
}

/// Collapse repeated (rule, process) file findings into one finding with a count
/// and a first→last range, keeping up to 3 evidence entries.
fn merge_repeats(findings: Vec<Finding>) -> Vec<Finding> {
    let mut groups: HashMap<(String, String), Finding> = HashMap::new();
    let mut out: Vec<Finding> = Vec::new();
    for f in findings {
        let mergeable = f.rule_id.starts_with("file.") && f.rule_id != "file.crash";
        let Some(p) = f.process.clone().filter(|_| mergeable) else {
            out.push(f);
            continue;
        };
        match groups.entry((f.rule_id.clone(), p)) {
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(f);
            }
            std::collections::hash_map::Entry::Occupied(mut e) => {
                let g = e.get_mut();
                let earlier = min_time(g.first_seen.or(g.timestamp), f.first_seen.or(f.timestamp));
                g.count += f.count;
                g.first_seen = earlier;
                g.timestamp = g.timestamp.max(f.timestamp);
                if g.evidence.len() < 3 {
                    g.evidence
                        .extend(f.evidence.into_iter().take(3 - g.evidence.len()));
                }
            }
        }
    }
    out.extend(groups.into_values());
    out
}

fn crash_loops_and_stories(findings: Vec<Finding>) -> Vec<Finding> {
    let mut by_proc: HashMap<String, Vec<Finding>> = HashMap::new();
    let mut passthrough: Vec<Finding> = Vec::new();
    for f in findings {
        match &f.process {
            // Non-fatal fault snapshots are not failures; they must not turn
            // an app's one real crash into a multi-signal "story".
            Some(p) if f.rule_id.starts_with("file.") && f.rule_id != "file.user_fault" => {
                by_proc.entry(p.clone()).or_default().push(f)
            }
            _ => passthrough.push(f),
        }
    }

    let mut merged: Vec<Finding> = Vec::new();
    for (proc_name, group) in by_proc {
        let crashes: Vec<&Finding> = group.iter().filter(|f| f.rule_id == "file.crash").collect();
        let distinct_rules: std::collections::HashSet<&str> =
            group.iter().map(|f| f.rule_id.as_str()).collect();

        // A crash *loop* means a tight burst — ≥3 crashes inside a rolling 60-min
        // window, or ≥5 inside 24 h — not crashes spread across the 7-day file
        // scan. (2026-09-30: jamfRemoteAssistConnector segfaulting every 8 h,
        // 17 times in a week, was reported as "crash-looping in a short window".)
        let mut crash_times: Vec<DateTime<Utc>> =
            crashes.iter().filter_map(|f| f.timestamp).collect();
        crash_times.sort();
        let within = |n: usize, span: ChronoDuration| {
            crash_times.windows(n).any(|w| (w[n - 1] - w[0]) <= span)
        };
        let burst = within(3, ChronoDuration::minutes(60)) || within(5, ChronoDuration::hours(24));

        if crashes.len() >= 3 && burst {
            // Crash loop: merge every crash of this process into one high finding.
            let count = crashes.len() as u32;
            let first = crashes.iter().filter_map(|f| f.timestamp).min();
            let last = crashes.iter().filter_map(|f| f.timestamp).max();
            let mut f = Finding::new(
                "correlate.crash_loop",
                Severity::High,
                "crash_loop",
                &format!("{proc_name} is crash-looping"),
            );
            f.process = Some(proc_name.clone());
            f.count = count;
            f.timestamp = last;
            f.first_seen = first;
            let span = match (first, last) {
                (Some(a), Some(b)) => format!(
                    " between {} and {}",
                    a.with_timezone(&chrono::Local).format("%b %-d %H:%M"),
                    b.with_timezone(&chrono::Local).format("%b %-d %H:%M")
                ),
                _ => String::new(),
            };
            f.detail = format!(
                "{proc_name} crashed {count} times{span}, including a tight burst. A crash loop \
                 actively degrades the system and won't fix itself: check for a bad update, \
                 corrupted preferences, or an incompatible plugin, and consider reinstalling the app."
            );
            f.next_step = Some(format!(
                "Update or reinstall {proc_name}. If it's a background service, find its job: \
                 `launchctl list | grep -i {proc_name}`, then fix or unload its plist."
            ));
            for c in crashes.iter().take(3) {
                f.evidence.extend(c.evidence.iter().cloned());
            }
            // Non-crash findings for the same process ride along as story members.
            let others: Vec<&Finding> =
                group.iter().filter(|g| g.rule_id != "file.crash").collect();
            if !others.is_empty() {
                f.detail.push_str(&format!(
                    " Related signals from the same process: {}.",
                    others
                        .iter()
                        .map(|o| o.summary.as_str())
                        .collect::<Vec<_>>()
                        .join("; ")
                ));
            }
            merged.push(f);
        } else if distinct_rules.len() >= 2 && group.len() >= 2 {
            // Story: different failure modes from one process → one narrative, max severity.
            let severity = group
                .iter()
                .map(|f| f.severity)
                .max()
                .unwrap_or(Severity::Medium);
            let first = group.iter().filter_map(|f| f.timestamp).min();
            let last = group.iter().filter_map(|f| f.timestamp).max();
            let mut f = Finding::new(
                "correlate.story",
                severity,
                "story",
                &format!(
                    "{proc_name}: {}",
                    group
                        .iter()
                        .map(|g| short_kind(&g.rule_id))
                        .collect::<std::collections::BTreeSet<_>>()
                        .into_iter()
                        .collect::<Vec<_>>()
                        .join(" + ")
                ),
            );
            f.process = Some(proc_name.clone());
            f.count = group.len() as u32;
            f.timestamp = last;
            f.first_seen = first;
            f.detail = format!(
                "Multiple different failure signals from {proc_name} in the window — usually one \
                 root cause wearing several hats: {}",
                group
                    .iter()
                    .map(|g| g.summary.as_str())
                    .collect::<Vec<_>>()
                    .join("; ")
            );
            f.next_step = group.iter().find_map(|g| g.next_step.clone());
            for g in group.iter().take(4) {
                f.evidence.extend(g.evidence.iter().cloned());
            }
            merged.push(f);
        } else if crashes.len() >= 2 && distinct_rules.len() == 1 {
            // Repeated crashes of one process that are NOT a tight loop: merge
            // into a single Medium finding instead of leaving three lookalikes.
            let count = crashes.len() as u32;
            let first = crash_times.first().copied();
            let last = crash_times.last().copied();
            let mut f = Finding::new(
                "file.crash",
                Severity::Medium,
                "crash",
                &format!("{proc_name} crashed {count} times (spread out, not a tight loop)"),
            );
            f.process = Some(proc_name.clone());
            f.count = count;
            f.timestamp = last;
            f.first_seen = first;
            f.detail = format!(
                "{proc_name} crashed {count} times across the scan window without a tight burst. \
                 Not an active crash loop, but a recurring failure worth a closer look — a flaky \
                 plugin, a bad update, or corrupted state."
            );
            f.next_step = crashes.iter().find_map(|c| c.next_step.clone());
            for c in crashes.iter().take(3) {
                f.evidence.extend(c.evidence.iter().cloned());
            }
            merged.push(f);
        } else {
            merged.extend(group);
        }
    }
    passthrough.extend(merged);
    passthrough
}

fn short_kind(rule_id: &str) -> &'static str {
    match rule_id {
        "file.crash" => "crashes",
        "file.hang" => "hangs",
        "file.cpu_resource" => "runaway CPU",
        "file.wakeups" => "excessive wakeups",
        "file.jetsam" => "memory kills",
        "file.shutdown_stall" => "shutdown stalls",
        "file.gpu_restart" => "GPU resets",
        _ => "other trouble",
    }
}

/// A kext implicated in a panic backtrace that is STILL loaded is the strongest
/// root-cause signal this tool can produce.
fn panic_kext_still_loaded(
    out: &mut Vec<Finding>,
    panic_kexts: &[String],
    loaded_kexts: &[String],
) {
    if panic_kexts.is_empty() || loaded_kexts.is_empty() {
        return;
    }
    let mut matched: Vec<&String> = panic_kexts
        .iter()
        .filter(|pk| !pk.starts_with("com.apple.") && loaded_kexts.iter().any(|lk| lk == *pk))
        .collect();
    matched.sort();
    matched.dedup();
    if matched.is_empty() {
        return;
    }
    let list = matched
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    let mut f = Finding::new(
        "correlate.panic_kext",
        Severity::High,
        "panic",
        &format!("Third-party kext from a panic backtrace is still loaded: {list}"),
    );
    f.detail = format!(
        "A kernel panic report names {list} in its backtrace, and that extension is loaded right \
         now — the next panic is a matter of time. This is the single most actionable root-cause \
         signal in this report."
    );
    f.next_step = Some(
        "Update the vendor software that ships this kext, or remove it. Verify what loads it: \
         `kmutil showloaded --collection aux`."
            .into(),
    );
    f.evidence.push(Evidence {
        source: "panic backtrace ∩ kmutil showloaded".into(),
        excerpt: list,
    });
    out.push(f);
}

/// Annotate serious findings whose trouble started within 48h after a software
/// install. Apple's silent data updates (XProtect etc.) ship constantly and would
/// tag everything, so they're excluded.
fn post_update(out: &mut [Finding], installs: &[InstallEvent]) {
    let interesting: Vec<&InstallEvent> = installs
        .iter()
        .filter(|i| {
            let n = i.name.trim();
            !(n.starts_with("XProtect")
                || n.starts_with("MRT")
                || n.starts_with("Gatekeeper")
                || n.starts_with("TCC ")
                || n.starts_with("Rosetta"))
        })
        .collect();
    if interesting.is_empty() {
        return;
    }
    for f in out.iter_mut() {
        // Only breakage-class findings earn the annotation — resource nags
        // (cpu_resource, wakeups) fire routinely and would tag every install.
        let breakage = matches!(
            f.rule_id.as_str(),
            "correlate.crash_loop"
                | "correlate.story"
                | "file.kernel_panic"
                | "file.jetsam"
                | "file.gpu_restart"
                | "file.hang"
        ) || (f.rule_id == "file.crash" && f.count >= 2);
        if !breakage {
            continue;
        }
        let Some(started) = f.first_seen.or(f.timestamp) else {
            continue;
        };
        let suspect = interesting
            .iter()
            .rev()
            .find(|i| started >= i.date && started - i.date <= ChronoDuration::hours(48));
        if let Some(i) = suspect {
            let hours = (started - i.date).num_hours();
            let what = if i.version.trim().is_empty() {
                i.name.trim().to_string()
            } else {
                format!("{} {}", i.name.trim(), i.version.trim())
            };
            f.detail.push_str(&format!(
                " ⏱ Started ~{hours}h after \"{what}\" was installed ({}) — possible connection.",
                i.date.with_timezone(&chrono::Local).format("%b %e %H:%M")
            ));
        }
    }
}
