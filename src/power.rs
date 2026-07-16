//! Battery health, charger adequacy, power assertions (sleep preventers), and
//! dark-wake storms.

use crate::report::{Category, Evidence, Finding, Severity, Vital};
use crate::util::{run, run_with_timeout};
use chrono::{NaiveDateTime, TimeZone, Utc};
use std::collections::HashSet;
use std::time::Duration;

pub struct PowerResult {
    pub vitals: Vec<Vital>,
    pub findings: Vec<Finding>,
}

pub fn scan(categories: &HashSet<Category>) -> PowerResult {
    let mut r = PowerResult {
        vitals: Vec::new(),
        findings: Vec::new(),
    };
    let battery = categories.contains(&Category::Battery);
    // `hardware` is an umbrella for the battery and charger checks, but not for
    // sleep-behaviour checks (assertions, dark wakes).
    if !battery && !categories.contains(&Category::Hardware) {
        return r;
    }
    let ioreg = read_battery_ioreg();
    battery_health(&mut r, ioreg.as_ref());
    charger(&mut r, ioreg.as_ref());
    if battery {
        assertions(&mut r);
        dark_wake_storm(&mut r);
    }
    r
}

/// The AppleSmartBattery registry entry, reduced to what triage uses. The
/// entry also carries `Serial`; it is never read.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct BatteryIoreg {
    pub installed: bool,
    pub cycle_count: Option<u32>,
    pub design_cycles: Option<u32>,
    pub design_mah: Option<u32>,
    pub full_charge_mah: Option<u32>,
    pub external_connected: bool,
    pub raw_external_connected: bool,
    pub is_charging: bool,
    pub fully_charged: bool,
    pub instant_amperage_ma: Option<i64>,
    pub adapter_watts: Option<u32>,
}

/// Parse `ioreg -r -c AppleSmartBattery -a`. None when there is no battery
/// entry (desktop Macs) or the output is unreadable.
pub fn parse_smart_battery(xml: &str) -> Option<BatteryIoreg> {
    let value = plist::Value::from_reader_xml(xml.as_bytes()).ok()?;
    let d = value.as_array()?.first()?.as_dictionary()?;
    let flag =
        |d: &plist::Dictionary, k: &str| d.get(k).and_then(|v| v.as_boolean()).unwrap_or(false);
    // Signed in the XML, but some macOS versions print negative currents as
    // 64-bit two's complement; wrap those back.
    let signed = |d: &plist::Dictionary, k: &str| {
        d.get(k).and_then(|v| {
            v.as_signed_integer()
                .or_else(|| v.as_unsigned_integer().map(|u| u as i64))
        })
    };
    let count = |d: &plist::Dictionary, k: &str| {
        d.get(k)
            .and_then(|v| v.as_unsigned_integer())
            .map(|n| n as u32)
    };
    let data = d.get("BatteryData").and_then(|v| v.as_dictionary());
    let adapter = d.get("AdapterDetails").and_then(|v| v.as_dictionary());
    Some(BatteryIoreg {
        installed: flag(d, "BatteryInstalled"),
        cycle_count: count(d, "CycleCount"),
        design_cycles: count(d, "DesignCycleCount9C"),
        design_mah: data.and_then(|b| count(b, "DesignCapacity")),
        full_charge_mah: data.and_then(|b| count(b, "FullChargeCapacity")),
        external_connected: flag(d, "ExternalConnected"),
        raw_external_connected: flag(d, "AppleRawExternalConnected"),
        is_charging: flag(d, "IsCharging"),
        fully_charged: flag(d, "FullyCharged"),
        instant_amperage_ma: signed(d, "InstantAmperage"),
        adapter_watts: adapter.and_then(|a| count(a, "Watts")),
    })
}

pub fn read_battery_ioreg() -> Option<BatteryIoreg> {
    parse_smart_battery(&run("ioreg", &["-r", "-c", "AppleSmartBattery", "-a"])?)
}

/// Apple's battery figures from `system_profiler SPPowerDataType -json`:
/// (condition, cycle count, Maximum Capacity %). None on desktop Macs. This is
/// the capacity figure System Settings shows, so it — not the raw mAh ratio —
/// drives severity.
pub fn parse_profiler_battery(json: &str) -> Option<(String, i64, i64)> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let items = v.get("SPPowerDataType")?.as_array()?;
    let batt = items
        .iter()
        .find(|i| i.get("sppower_battery_health_info").is_some())?;
    let health = batt
        .pointer("/sppower_battery_health_info/sppower_battery_health")
        .and_then(|h| h.as_str())
        .unwrap_or("unknown")
        .to_string();
    let cycles = batt
        .pointer("/sppower_battery_health_info/sppower_battery_cycle_count")
        .and_then(|c| c.as_i64())
        .unwrap_or(-1);
    let max_cap = batt
        .pointer("/sppower_battery_health_info/sppower_battery_health_maximum_capacity")
        .and_then(|c| c.as_str())
        .map(|s| s.trim_end_matches('%').parse::<i64>().unwrap_or(-1))
        .unwrap_or(-1);
    Some((health, cycles, max_cap))
}

pub fn read_profiler_battery() -> Option<(String, i64, i64)> {
    parse_profiler_battery(&run("system_profiler", &["SPPowerDataType", "-json"])?)
}

fn battery_health(r: &mut PowerResult, ioreg: Option<&BatteryIoreg>) {
    let Some((health, cycles, max_cap)) = read_profiler_battery() else {
        return; // desktop Mac — no battery, nothing to report
    };
    let health = health.as_str();

    let mut flag = None;
    if !health.eq_ignore_ascii_case("good") && health != "unknown" {
        flag = Some(Severity::High);
        let mut f = Finding::new(
            "snap.battery_health",
            Severity::High,
            "battery",
            &format!("Battery condition: {health} — service needed"),
        );
        f.detail = format!(
            "macOS reports the battery as \"{health}\" ({cycles} cycles, {max_cap}% of design \
             capacity). A degraded battery causes throttling, sudden shutdowns, and swelling risk."
        );
        f.next_step =
            Some("Book a battery service; until then avoid full-load work on battery.".into());
        r.findings.push(f);
    } else if in_range(max_cap) {
        flag = Some(Severity::Medium);
        let mut f = Finding::new(
            "snap.battery_health",
            Severity::Medium,
            "battery",
            &format!("Battery capacity down to {max_cap}% of design ({cycles} cycles)"),
        );
        f.detail = "Condition still reads Good, but capacity below 80% means noticeably shorter \
                    runtime and earlier performance management."
            .into();
        f.next_step =
            Some("Plan for battery service; verify runtime complaints against this number.".into());
        r.findings.push(f);
    } else if let Some((count, design)) = past_rated_cycles(ioreg) {
        flag = Some(Severity::Medium);
        let mut f = Finding::new(
            "snap.battery_health",
            Severity::Medium,
            "battery",
            &format!("Battery past its rated cycle count ({count} of {design} cycles)"),
        );
        f.detail = format!(
            "Condition still reads {health} at {max_cap}% capacity, but the battery has been \
             through more charge cycles than it is designed for, so capacity loss and \
             unexpected shutdowns become more likely."
        );
        f.next_step = Some("Plan for battery service, especially if runtime or sudden shutdowns are part of the complaint.".into());
        r.findings.push(f);
    }
    let mut value = if max_cap >= 0 {
        format!("{health} · {max_cap}% capacity")
    } else {
        health.to_string()
    };
    match ioreg.and_then(|b| b.design_cycles.filter(|d| *d > 0)) {
        Some(design) => value.push_str(&format!(" · {cycles}/{design} cycles")),
        None => value.push_str(&format!(" · {cycles} cycles")),
    }
    if let Some((full, design)) = ioreg.and_then(|b| b.full_charge_mah.zip(b.design_mah)) {
        value.push_str(&format!(" · {full}/{design} mAh"));
    }
    r.vitals.push(Vital {
        label: "Battery".into(),
        value,
        flag,
    });
}

/// (cycle count, design cycle count) when the battery has reached its rating.
pub fn past_rated_cycles(ioreg: Option<&BatteryIoreg>) -> Option<(u32, u32)> {
    let b = ioreg?;
    let (count, design) = b.cycle_count.zip(b.design_cycles)?;
    (design > 0 && count >= design).then_some((count, design))
}

/// Discharge current (mA) that counts as "draining" while on external power.
const CHARGER_DRAIN_MA: i64 = -300;

/// Connected to a charger that the macOS power stack also sees, not full, and
/// the battery is still losing charge.
pub fn draining_on_charger(b: &BatteryIoreg) -> bool {
    b.installed
        && b.external_connected
        && b.raw_external_connected
        && !b.fully_charged
        && b.instant_amperage_ma
            .is_some_and(|ma| ma < CHARGER_DRAIN_MA)
}

/// `snap.charger` finding (needs both samples draining — one sample could race
/// a plug/unplug) plus the Charger vital. Nothing for Macs without a battery.
pub fn assess_charger(
    first: &BatteryIoreg,
    second: Option<&BatteryIoreg>,
) -> (Option<Finding>, Option<Vital>) {
    if !first.installed {
        return (None, None);
    }
    let latest = second.unwrap_or(first);
    let draining = draining_on_charger(first) && second.is_some_and(draining_on_charger);
    let watts = latest
        .adapter_watts
        .map(|w| format!("{w} W"))
        .unwrap_or_else(|| "charger".into());
    let state = if !latest.external_connected {
        "on battery".to_string()
    } else if draining {
        format!("{watts} · connected but battery draining")
    } else if latest.fully_charged {
        format!("{watts} · fully charged")
    } else if latest.is_charging {
        format!("{watts} · charging")
    } else {
        format!("{watts} · connected, not charging")
    };
    let flag = draining.then_some(Severity::Medium);
    let vital = Vital {
        label: "Charger".into(),
        value: state,
        flag,
    };
    if !draining {
        return (None, Some(vital));
    }
    let ma = latest.instant_amperage_ma.unwrap_or(0);
    let mut f = Finding::new(
        "snap.charger",
        Severity::Medium,
        "battery",
        &format!("Charger connected but the battery is draining ({watts}, {ma} mA)"),
    );
    f.detail = "The power adapter is connected, yet the battery kept discharging across two \
                readings. The charger or cable can't supply what this Mac is drawing: it is \
                underpowered for this model, a weak USB-C cable or hub is in the path, or the \
                port or adapter is failing. Under very heavy load even the right charger can \
                briefly fall behind."
        .into();
    f.next_step = Some(
        "Plug the Mac's own Apple adapter and cable directly into the Mac (no hub or dock), \
         then recheck; try another USB-C port. If it still drains at light load, test with a \
         known-good charger before suspecting the logic board."
            .into(),
    );
    f.evidence.push(Evidence {
        source: "ioreg AppleSmartBattery (2 samples)".into(),
        excerpt: format!(
            "ExternalConnected={} AppleRawExternalConnected={} FullyCharged={} InstantAmperage={} mA, then {} mA; AdapterDetails.Watts={}",
            first.external_connected,
            first.raw_external_connected,
            first.fully_charged,
            first.instant_amperage_ma.unwrap_or(0),
            ma,
            latest.adapter_watts.map(|w| w.to_string()).unwrap_or_else(|| "?".into())
        ),
    });
    (Some(f), Some(vital))
}

fn charger(r: &mut PowerResult, ioreg: Option<&BatteryIoreg>) {
    let Some(first) = ioreg else {
        return;
    };
    // Only pay for a second sample when the first one looks wrong.
    let second = if draining_on_charger(first) {
        std::thread::sleep(Duration::from_secs(2));
        read_battery_ioreg()
    } else {
        None
    };
    let (finding, vital) = assess_charger(first, second.as_ref());
    r.findings.extend(finding);
    r.vitals.extend(vital);
}

// helper used above to keep the condition readable
fn in_range(max_cap: i64) -> bool {
    (0..80).contains(&max_cap)
}

fn assertions(r: &mut PowerResult) {
    let out = run("pmset", &["-g", "assertions"]).unwrap_or_default();
    // Aggregate section: "   PreventUserIdleSystemSleep     1"
    let active = |name: &str| -> bool {
        out.lines().any(|l| {
            let t = l.trim();
            t.starts_with(name) && t.ends_with('1')
        })
    };
    if !(active("PreventUserIdleSystemSleep") || active("PreventSystemSleep")) {
        return;
    }
    // "Listed by owning process:" lines: pid 123(ProcessName): [...] PreventUserIdleSystemSleep named: "..."
    let mut holders: Vec<String> = Vec::new();
    for line in out.lines() {
        if line.contains("PreventUserIdleSystemSleep") || line.contains("PreventSystemSleep") {
            if let Some(holder) = assertion_holder(line) {
                if !holders.contains(&holder) {
                    holders.push(holder);
                }
            }
        }
    }
    // Apple media daemons hold these constantly during playback; only surface non-obvious holders.
    let interesting: Vec<&String> = holders
        .iter()
        .filter(|h| !matches!(h.as_str(), "powerd" | "coreaudiod" | "sharingd"))
        .collect();
    if interesting.is_empty() {
        return;
    }
    let mut f = Finding::new(
        "snap.power_assertions",
        Severity::Low,
        "battery",
        &format!(
            "Sleep is being prevented by: {}",
            interesting
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    );
    f.detail = "These processes hold power assertions that stop the Mac from sleeping. Legitimate \
                during playback/downloads; a stuck assertion is the classic \"battery died in my \
                bag overnight\" cause."
        .into();
    f.next_step = Some(
        "See details: `pmset -g assertions`. If the holder shouldn't be awake, quit it; if this \
         recurs, check its background helper or update the app."
            .into(),
    );
    f.evidence.push(Evidence {
        source: "pmset -g assertions".into(),
        excerpt: interesting
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", "),
    });
    r.findings.push(f);
}

/// Who is really holding a `pmset -g assertions` line's assertion.
/// runningboardd holds assertions on behalf of apps and services, and the
/// assertion name carries the real client, e.g.
/// `named: "app<application.com.microsoft.teams2.16170346.16172491(501)>427-…"`
/// or `osservice<com.apple.backupd>` (both seen in powerd's log 2026-09-30).
/// Reporting "runningboardd" named nobody useful.
pub fn assertion_holder(line: &str) -> Option<String> {
    let process = line.split('(').nth(1)?.split(')').next()?.trim();
    if process.is_empty() {
        return None;
    }
    if process != "runningboardd" {
        return Some(process.to_string());
    }
    let named = line.split("named: \"").nth(1).unwrap_or("");
    let client = regex::Regex::new(r"(?:app|osservice|daemon|xpcservice|extension)<([^>]+)>")
        .ok()
        .and_then(|re| re.captures(named))
        .map(|c| c[1].to_string());
    Some(match client {
        Some(raw) => {
            // "application.com.microsoft.teams2.16170346.16172491(501)" → "com.microsoft.teams2"
            let raw = raw.split('(').next().unwrap_or(&raw);
            let raw = raw.strip_prefix("application.").unwrap_or(raw);
            let id: Vec<&str> = raw
                .split('.')
                .rev()
                .skip_while(|seg| seg.chars().all(|c| c.is_ascii_digit()))
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            format!("{} (via runningboardd)", id.join("."))
        }
        None => "runningboardd".to_string(),
    })
}

fn dark_wake_storm(r: &mut PowerResult) {
    // pmset -g log is large; give it a bounded read and parse only DarkWake lines.
    let (out, _) = run_with_timeout("pmset", &["-g", "log"], Duration::from_secs(20));
    if out.is_empty() {
        return;
    }
    let now = Utc::now();
    let mut wakes_24h = 0u32;
    let mut last_reason = String::new();
    for line in out.lines() {
        if !line.contains("DarkWake") || !line.contains("due to") {
            continue;
        }
        // "2026-07-16 03:12:44 -0400 DarkWake ... due to <reason>..."
        let ts = line.get(0..19).and_then(|s| {
            NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
                .ok()
                .and_then(|nt| chrono::Local.from_local_datetime(&nt).single())
        });
        if let Some(t) = ts {
            if (now - t.with_timezone(&Utc)).num_hours() < 24 {
                wakes_24h += 1;
                if let Some(reason) = line.split("due to").nth(1) {
                    last_reason = reason.trim().chars().take(80).collect();
                }
            }
        }
    }
    if wakes_24h >= 20 {
        let mut f = Finding::new(
            "snap.darkwake_storm",
            Severity::Medium,
            "battery",
            &format!("{wakes_24h} dark wakes in the last 24h — battery drain while 'asleep'"),
        );
        f.detail = format!(
            "The Mac keeps waking silently instead of staying asleep. Most recent wake reason: \
             {last_reason}. Frequent causes: Power Nap, network wake (Bonjour proxies), a USB \
             device, or a stuck scheduled task."
        );
        f.next_step = Some(
            "Read the pattern: `pmset -g log | grep -i darkwake | tail -30`. If one reason \
             repeats, disable it: Power Nap (`sudo pmset -a powernap 0`), wake for network \
             (`sudo pmset -a womp 0`), or unplug the waking device."
                .into(),
        );
        f.count = wakes_24h;
        r.findings.push(f);
    }
}
