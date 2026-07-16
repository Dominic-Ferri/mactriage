//! watch — a launchd-driven periodic scan that notifies on NEW ≥threshold findings.
//!
//! `watch install` writes a LaunchAgent and loads it (user-level, no sudo needed).
//! `watch run` is what the LaunchAgent executes: fast scan, diff against state, notify.

use crate::report::Severity;
use crate::util::run;
use std::path::PathBuf;

const AGENT_LABEL: &str = "com.mactriage.watch";

fn agent_plist_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    home.join(format!("Library/LaunchAgents/{AGENT_LABEL}.plist"))
}

fn state_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    home.join("Library/Application Support/mactriage/watch-state.json")
}

/// Timestamp of the last `watch run`, read from persisted state (None if never).
pub fn last_run() -> Option<chrono::DateTime<chrono::Utc>> {
    let raw = std::fs::read_to_string(state_path()).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let s = v.get("last_run")?.as_str()?;
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|t| t.with_timezone(&chrono::Utc))
}

/// Minimal XML text escaping for values interpolated into the LaunchAgent plist
/// (an executable path can legitimately contain `&`, `<`, or `>`).
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub fn install(interval: &str, min_severity: Severity) -> Result<String, String> {
    let secs = crate::util::parse_window(interval)
        .ok_or_else(|| format!("bad interval '{interval}' — use e.g. 30m, 6h"))?
        .as_secs();
    if secs < 300 {
        return Err("interval below 5m would burn CPU on log scans — pick something longer".into());
    }
    let exe = xml_escape(
        &std::env::current_exe()
            .map_err(|e| e.to_string())?
            .display()
            .to_string(),
    );
    let sev = format!("{min_severity:?}").to_lowercase();
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>{AGENT_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>watch</string>
        <string>run</string>
        <string>--min-severity</string>
        <string>{sev}</string>
    </array>
    <key>StartInterval</key><integer>{secs}</integer>
    <key>ProcessType</key><string>Background</string>
    <key>LowPriorityIO</key><true/>
    <key>Nice</key><integer>10</integer>
</dict>
</plist>
"#
    );
    let path = agent_plist_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    // Back up an existing LaunchAgent rather than clobbering it.
    if path.exists() {
        let bak = path.with_extension(format!(
            "plist.bak.{}",
            chrono::Local::now().format("%Y%m%d-%H%M%S")
        ));
        std::fs::copy(&path, &bak).map_err(|e| e.to_string())?;
    }
    std::fs::write(&path, plist).map_err(|e| e.to_string())?;
    let uid = unsafe { geteuid_shim() };
    run(
        "launchctl",
        &[
            "bootout",
            &format!("gui/{uid}"),
            path.to_str().unwrap_or_default(),
        ],
    );
    run(
        "launchctl",
        &[
            "bootstrap",
            &format!("gui/{uid}"),
            path.to_str().unwrap_or_default(),
        ],
    )
    .ok_or("launchctl bootstrap failed — try `launchctl load` manually")?;
    Ok(format!(
        "watch installed: every {interval}, notifying on new ≥{sev} findings\nagent: {}",
        path.display()
    ))
}

pub fn uninstall() -> Result<String, String> {
    let path = agent_plist_path();
    if !path.exists() {
        return Ok("watch is not installed".into());
    }
    let uid = unsafe { geteuid_shim() };
    run(
        "launchctl",
        &[
            "bootout",
            &format!("gui/{uid}"),
            path.to_str().unwrap_or_default(),
        ],
    );
    // Archive instead of delete.
    let bak = path.with_extension(format!(
        "plist.removed.{}",
        chrono::Local::now().format("%Y%m%d-%H%M%S")
    ));
    std::fs::rename(&path, &bak).map_err(|e| e.to_string())?;
    Ok(format!(
        "watch removed (LaunchAgent archived at {})",
        bak.display()
    ))
}

pub fn status() -> String {
    let path = agent_plist_path();
    if !path.exists() {
        return "watch: not installed".into();
    }
    let loaded = run("launchctl", &["list"])
        .map(|o| o.contains(AGENT_LABEL))
        .unwrap_or(false);
    let state = std::fs::read_to_string(state_path()).ok();
    let last = state
        .as_deref()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
        .and_then(|v| v.get("last_run").and_then(|t| t.as_str()).map(String::from))
        .unwrap_or_else(|| "never".into());
    format!(
        "watch: installed ({}) · last run {last}\nagent: {}",
        if loaded {
            "loaded"
        } else {
            "NOT loaded — `launchctl bootstrap` it"
        },
        path.display()
    )
}

/// The periodic scan itself: files + snapshot only (no unified log — keep it cheap),
/// notify via Notification Center when a NEW finding at/above threshold appears.
pub fn run_once(min_severity: Severity) -> i32 {
    let report = crate::scan::scan_for_watch();
    let key = |f: &crate::report::Finding| {
        format!("{}|{}", f.rule_id, f.process.as_deref().unwrap_or(""))
    };

    let prev: std::collections::HashSet<String> = std::fs::read_to_string(state_path())
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| {
            v.get("seen").and_then(|s| s.as_array()).map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
        })
        .unwrap_or_default();

    let current: Vec<&crate::report::Finding> = report
        .findings
        .iter()
        .filter(|f| f.severity >= min_severity)
        .collect();
    let fresh: Vec<&&crate::report::Finding> =
        current.iter().filter(|f| !prev.contains(&key(f))).collect();

    if !fresh.is_empty() {
        let title = format!("mactriage: {} new finding(s)", fresh.len());
        let body = fresh
            .iter()
            .take(3)
            .map(|f| f.summary.as_str())
            .collect::<Vec<_>>()
            .join(" · ");
        run(
            "osascript",
            &[
                "-e",
                &format!(
                    "display notification \"{}\" with title \"{}\"",
                    body.replace('"', "'"),
                    title.replace('"', "'")
                ),
            ],
        );
    }

    // Persist state: everything currently visible (so resolved findings can re-alert later).
    let seen: Vec<String> = current.iter().map(|f| key(f)).collect();
    let state = serde_json::json!({
        "last_run": chrono::Utc::now().to_rfc3339(),
        "seen": seen,
        "new_this_run": fresh.len(),
    });
    if let Some(dir) = state_path().parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(
        state_path(),
        serde_json::to_string_pretty(&state).unwrap_or_default(),
    );
    report.exit_code()
}

extern "C" {
    #[link_name = "geteuid"]
    fn geteuid_shim() -> u32;
}
