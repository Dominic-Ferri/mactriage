//! Host info, vitals, and snap.* live checks.

use crate::report::{Category, Finding, HostInfo, Severity, Skipped, Vital};
use crate::util::{human_bytes, human_duration, run, run_with_timeout};
use std::collections::HashSet;
use std::time::Duration;

/// Boot instant from kern.boottime, for boot-phase noise detection.
pub fn boot_time() -> Option<chrono::DateTime<chrono::Utc>> {
    let bt = run("sysctl", &["-n", "kern.boottime"])?; // "{ sec = 1752618000, usec = 0 } ..."
    let secs = bt
        .split("sec =")
        .nth(1)?
        .trim()
        .split([',', ' '])
        .next()?
        .parse::<i64>()
        .ok()?;
    chrono::DateTime::from_timestamp(secs, 0)
}

pub fn host_info(root: bool) -> HostInfo {
    let sysctl = |k: &str| {
        run("/usr/sbin/sysctl", &["-n", k])
            .unwrap_or_default()
            .trim()
            .to_string()
    };
    let uptime = {
        let bt = sysctl("kern.boottime"); // "{ sec = 1752618000, usec = 0 } ..."
        let secs = bt
            .split("sec =")
            .nth(1)
            .and_then(|s| s.trim().split([',', ' ']).next())
            .and_then(|s| s.parse::<i64>().ok())
            .map(|boot| (chrono::Utc::now().timestamp() - boot).max(0) as u64)
            .unwrap_or(0);
        human_duration(secs)
    };
    HostInfo {
        model: sysctl("hw.model"),
        chip: sysctl("machdep.cpu.brand_string"),
        memory_gb: sysctl("hw.memsize").parse::<u64>().unwrap_or(0) / 1_073_741_824,
        macos_version: run("/usr/bin/sw_vers", &["-productVersion"])
            .unwrap_or_default()
            .trim()
            .into(),
        macos_build: run("/usr/bin/sw_vers", &["-buildVersion"])
            .unwrap_or_default()
            .trim()
            .into(),
        arch: std::env::consts::ARCH.into(),
        uptime,
        root,
        model_name: run(
            "/usr/sbin/system_profiler",
            &["SPHardwareDataType", "-json"],
        )
        .and_then(|o| serde_json::from_str::<serde_json::Value>(&o).ok())
        .and_then(|v| {
            v.pointer("/SPHardwareDataType/0/machine_name")
                .and_then(|n| n.as_str())
                .map(String::from)
        })
        .unwrap_or_default(),
        storage: run("/usr/sbin/diskutil", &["info", &boot_physical_disk()])
            .map(|o| parse_disk_identity(&o))
            .unwrap_or_default(),
    }
}

/// "APPLE SSD AP0512Z · 500.3 GB" from `diskutil info <whole disk>`.
pub fn parse_disk_identity(info: &str) -> String {
    let field = |name: &str| {
        info.lines()
            .find(|l| l.trim_start().starts_with(name))
            .and_then(|l| l.split_once(':'))
            .map(|(_, v)| v.trim().to_string())
            .unwrap_or_default()
    };
    let media = field("Device / Media Name:");
    // "500.3 GB (500277792768 Bytes) (exactly …)" → "500.3 GB"
    let size = field("Disk Size:")
        .split(" (")
        .next()
        .unwrap_or("")
        .to_string();
    [media, size]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" · ")
}

pub struct SnapshotResult {
    pub vitals: Vec<Vital>,
    pub findings: Vec<Finding>,
    pub skipped: Vec<Skipped>,
}

pub fn scan(categories: &HashSet<Category>, root: bool) -> SnapshotResult {
    let mut r = SnapshotResult {
        vitals: Vec::new(),
        findings: Vec::new(),
        skipped: Vec::new(),
    };
    // Each live check runs when its own category is selected, or under the
    // `snapshot` umbrella. Previously all four were gated on `snapshot` alone,
    // so `--only memory` returned no vitals at all.
    let want = |c: Category| categories.contains(&c) || categories.contains(&Category::Snapshot);
    // `hardware` is a second umbrella covering the live hardware checks.
    let hw = categories.contains(&Category::Hardware);
    if want(Category::Memory) {
        memory(&mut r);
    }
    if want(Category::Thermal) || hw {
        thermal(&mut r, root);
    }
    if want(Category::Disk) || hw {
        disk(&mut r);
    }
    if want(Category::Hardware) {
        match crate::hardware::input_check() {
            Ok((findings, vital)) => {
                r.findings.extend(findings);
                r.vitals.push(vital);
            }
            Err(reason) => r.skipped.push(Skipped {
                what: "keyboard/trackpad check".into(),
                reason,
            }),
        }
    }
    if categories.contains(&Category::Snapshot) {
        load_and_procs(&mut r);
    }
    r
}

fn memory(r: &mut SnapshotResult) {
    let level: u32 = run("sysctl", &["-n", "kern.memorystatus_vm_pressure_level"])
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(1);
    let free_pct = run("memory_pressure", &["-Q"])
        .and_then(|o| {
            o.lines()
                .find(|l| l.contains("free percentage"))
                .and_then(|l| {
                    l.rsplit(':')
                        .next()
                        .map(|p| p.trim().trim_end_matches('%').to_string())
                })
        })
        .unwrap_or_default();
    let swap = run("sysctl", &["-n", "vm.swapusage"]).unwrap_or_default();
    // "total = 4096.00M  used = 2848.75M  free = 1247.25M  (encrypted)"
    let get_mb = |key: &str| -> f64 {
        swap.split(&format!("{key} ="))
            .nth(1)
            .and_then(|s| s.trim().split(['M', 'G', ' ']).next())
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(0.0)
    };
    let (total_mb, used_mb) = (get_mb("total"), get_mb("used"));
    // xnu bsd/sys/event_private.h: NOTE_MEMORYSTATUS_PRESSURE_* are BIT FLAGS
    // (1=normal, 2=warn, 4=critical, 8=low-swap), not an ordinal scale — a
    // combined value like 10 (warn|low-swap) must not read as "normal".
    let critical = level & 4 != 0;
    let warning = level & 2 != 0;
    let low_swap = level & 8 != 0;
    let (pressure_word, flag) = if critical {
        ("pressure critical", Some(Severity::High))
    } else if warning {
        ("pressure warning", Some(Severity::Medium))
    } else {
        ("pressure normal", None)
    };
    let mut value = pressure_word.to_string();
    if low_swap {
        value.push_str(" · low swap");
    }
    if !free_pct.is_empty() {
        value.push_str(&format!(" · {free_pct}% free"));
    }
    if total_mb > 0.0 {
        value.push_str(&format!(
            " · swap {:.1} of {:.1} GB",
            used_mb / 1024.0,
            total_mb / 1024.0
        ));
    }
    r.vitals.push(Vital {
        label: "Memory".into(),
        value,
        flag,
    });

    if critical || warning {
        let sev = if critical {
            Severity::High
        } else {
            Severity::Medium
        };
        let mut f = Finding::new(
            "snap.memory_pressure",
            sev,
            "memory",
            &format!(
                "Live memory pressure is at {} level",
                if level >= 4 { "critical" } else { "warning" }
            ),
        );
        f.detail = "The kernel is actively compressing/paging to keep up right now. Apps will \
                    stutter and jetsam kills become likely."
            .into();
        f.next_step = Some("Find the hog: `top -o mem -n 5 -l 1`, quit or restart it.".into());
        r.findings.push(f);
    }
    if total_mb > 0.0 && used_mb / total_mb > 0.9 {
        let mut f = Finding::new(
            "snap.swap_heavy",
            Severity::Medium,
            "memory",
            &format!(
                "Swap nearly exhausted ({:.1} of {:.1} GB used)",
                used_mb / 1024.0,
                total_mb / 1024.0
            ),
        );
        f.detail = "Swap files are nearly full — the workload doesn't fit in RAM and the system \
                    is paging hard."
            .into();
        f.next_step = Some("Close memory-heavy apps or restart the biggest consumer.".into());
        r.findings.push(f);
    }
}

fn thermal(r: &mut SnapshotResult, root: bool) {
    let therm = run("pmset", &["-g", "therm"]).unwrap_or_default();
    let speed_limit: Option<u32> = therm
        .lines()
        .find(|l| l.contains("CPU_Speed_Limit"))
        .and_then(|l| l.rsplit('=').next())
        .and_then(|v| v.trim().parse().ok());

    let mut value;
    let mut flag = None;
    match speed_limit {
        Some(limit) if limit < 100 => {
            value = format!("CPU speed limited to {limit}%");
            flag = Some(if limit < 70 {
                Severity::High
            } else {
                Severity::Medium
            });
            let mut f = Finding::new(
                "snap.thermal_throttle",
                flag.unwrap(),
                "thermal",
                &format!("CPU is thermally throttled right now ({limit}% speed)"),
            );
            f.detail = "macOS is slowing the CPU for heat as we speak. Everything feels slow \
                        until the machine cools."
                .into();
            f.next_step = Some(
                "Check for a runaway process (`top -o cpu -l 1 -n 5`), clear vents, get the Mac \
                 off soft surfaces."
                    .into(),
            );
            r.findings.push(f);
        }
        Some(_) => value = "no throttling".into(),
        None => value = String::new(),
    }
    if root {
        let (pm, _) = run_with_timeout(
            "powermetrics",
            &["--samplers", "thermal", "-n", "1", "-i", "500"],
            Duration::from_secs(15),
        );
        if let Some(line) = pm.lines().find(|l| l.contains("pressure level")) {
            let level = line.rsplit(':').next().unwrap_or("").trim().to_string();
            if !level.is_empty() {
                if value.is_empty() || value == "no throttling" {
                    value = format!("pressure {level}");
                } else {
                    value.push_str(&format!(" · pressure {level}"));
                }
                // Kernel thermal pressure scale (powermetrics): nominal <
                // moderate < heavy < trapping < sleeping. This is NOT the
                // Foundation NSProcessInfoThermalState scale (nominal/fair/
                // serious/critical) — don't mix them.
                if flag.is_none() {
                    flag = match level.to_ascii_lowercase().as_str() {
                        "nominal" => None,
                        "moderate" => Some(Severity::Medium),
                        "heavy" | "trapping" | "sleeping" => Some(Severity::High),
                        _ => Some(Severity::Medium),
                    };
                }
            }
        }
    } else {
        if value.is_empty() {
            value = "not sampled — run with sudo for live thermal data".into();
        }
        r.skipped.push(Skipped {
            what: "powermetrics thermal sampling".into(),
            reason: "requires sudo — re-run with sudo for live thermal pressure".into(),
        });
    }
    r.vitals.push(Vital {
        label: "Thermal".into(),
        value,
        flag,
    });
}

/// Resolve the boot volume's underlying whole disk for the SMART query, so
/// external-boot and multi-disk Macs check the right device instead of `disk0`.
pub fn boot_physical_disk() -> String {
    let info = run("/usr/sbin/diskutil", &["info", "/"]).unwrap_or_default();
    let store = info
        .lines()
        .find(|l| l.contains("APFS Physical Store"))
        .and_then(|l| l.rsplit(':').next())
        .map(|s| s.trim().to_string())
        .filter(|s| s.starts_with("disk"))
        .or_else(|| {
            info.lines()
                .find(|l| l.trim_start().starts_with("Device Node:"))
                .and_then(|l| l.rsplit('/').next())
                .map(|s| s.trim().to_string())
        });
    match store {
        // "disk0s2" / "disk3s1s1" → whole disk "disk0" / "disk3"
        Some(dev) => {
            if let Some(rest) = dev.strip_prefix("disk") {
                let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                if !num.is_empty() {
                    return format!("disk{num}");
                }
            }
            dev
        }
        None => "disk0".into(),
    }
}

fn disk(r: &mut SnapshotResult) {
    let df = run("df", &["-k", "/"]).unwrap_or_default();
    let mut pct_full = 0u32;
    let mut free_bytes = 0u64;
    if let Some(line) = df.lines().nth(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 5 {
            free_bytes = cols[3].parse::<u64>().unwrap_or(0) * 1024;
            pct_full = cols[4].trim_end_matches('%').parse().unwrap_or(0);
        }
    }
    let whole_disk = boot_physical_disk();
    let smart = run("diskutil", &["info", &whole_disk])
        .and_then(|o| {
            o.lines()
                .find(|l| l.contains("SMART Status"))
                .map(|l| l.rsplit(':').next().unwrap_or("").trim().to_string())
        })
        .unwrap_or_else(|| "unknown".into());

    let mut flag = None;
    if pct_full >= 85 {
        let sev = if pct_full >= 95 {
            Severity::High
        } else {
            Severity::Medium
        };
        flag = Some(sev);
        let mut f = Finding::new(
            "snap.disk_full",
            sev,
            "disk",
            &format!(
                "Boot volume {pct_full}% full ({} free)",
                human_bytes(free_bytes)
            ),
        );
        f.detail = "APFS performance degrades sharply as free space runs out, and updates/swap \
                    can start failing outright."
            .into();
        f.next_step = Some(
            "Check for local Time Machine snapshots first (see the storage findings), then \
             biggest offenders: `du -xh -d 2 ~ | sort -rh | head -20`."
                .into(),
        );
        r.findings.push(f);
    }
    if !smart.eq_ignore_ascii_case("verified")
        && smart != "unknown"
        && !smart.eq_ignore_ascii_case("not supported")
    {
        flag = Some(Severity::High);
        let mut f = Finding::new(
            "snap.smart",
            Severity::High,
            "disk",
            &format!("Drive SMART status: {smart}"),
        );
        f.detail = "The drive is reporting SMART trouble. Failing storage is the one problem \
                    that destroys data — treat as urgent."
            .into();
        f.next_step = Some("Back up immediately, then run Apple Diagnostics.".into());
        r.findings.push(f);
    }
    // SSD wear detail; the "SMART verified" wording above must stay intact —
    // recovery.rs keys its contradiction gate on it.
    let ssd = crate::hardware::ssd_check(&whole_disk);
    if ssd.flag > flag {
        flag = ssd.flag;
    }
    r.findings.extend(ssd.finding);
    r.skipped.extend(ssd.skipped);
    r.vitals.push(Vital {
        label: "Disk".into(),
        value: format!(
            "{pct_full}% full · {} free · SMART {}{}",
            human_bytes(free_bytes),
            smart.to_lowercase(),
            ssd.vital_suffix
        ),
        flag,
    });
}

fn load_and_procs(r: &mut SnapshotResult) {
    let cores: f64 = run("sysctl", &["-n", "hw.ncpu"])
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(1.0);
    let load: f64 = run("sysctl", &["-n", "vm.loadavg"])
        .and_then(|s| {
            s.trim()
                .trim_start_matches('{')
                .split_whitespace()
                .next()
                .and_then(|v| v.parse().ok())
        })
        .unwrap_or(0.0);
    let mut flag = None;
    if load > cores * 2.0 {
        flag = Some(Severity::Low);
        let mut f = Finding::new(
            "snap.load",
            Severity::Low,
            "snapshot",
            &format!("Sustained load {load:.2} far above {cores:.0} cores"),
        );
        f.detail = "Load average is more than double the core count — the machine is queueing \
                    work faster than it can run it."
            .into();
        f.next_step = Some("See the top-processes finding below for the likely culprit.".into());
        r.findings.push(f);
    }
    r.vitals.push(Vital {
        label: "Load".into(),
        value: format!("{load:.2} on {cores:.0} cores"),
        flag,
    });

    // v0.2.0: name the culprit instead of just reporting a number.
    let ps = run("ps", &["-Aceo", "pcpu=,pmem=,comm=", "-r"]).unwrap_or_default();
    let mut top: Vec<(f64, f64, String)> = Vec::new();
    for line in ps.lines().take(8) {
        let mut it = line.split_whitespace();
        let (Some(cpu), Some(mem)) = (it.next(), it.next()) else {
            continue;
        };
        let comm = it.collect::<Vec<_>>().join(" ");
        if let (Ok(c), Ok(m)) = (cpu.parse::<f64>(), mem.parse::<f64>()) {
            top.push((c, m, comm));
        }
    }
    if let Some((cpu, _, name)) = top.first() {
        if *cpu >= 200.0 {
            let mut f = Finding::new(
                "snap.top_procs",
                Severity::Medium,
                "snapshot",
                &format!("{name} is using {cpu:.0}% CPU right now"),
            );
            f.process = Some(name.clone());
            f.detail = format!(
                "Top consumers this instant: {}.",
                top.iter()
                    .take(5)
                    .map(|(c, m, n)| format!("{n} {c:.0}% cpu / {m:.1}% mem"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            f.next_step = Some(format!(
                "Watch it: `top -pid $(pgrep '{name}')`. If it's an indexer/backup daemon give it \
                 an hour; otherwise quit or reinstall it."
            ));
            r.findings.push(f);
        }
    }
    if let Some((cpu, _, _)) = top.iter().find(|(_, _, n)| n == "WindowServer") {
        if *cpu >= 60.0 {
            let mut f = Finding::new(
                "snap.windowserver",
                Severity::Medium,
                "snapshot",
                &format!("WindowServer at {cpu:.0}% CPU — UI lag likely"),
            );
            f.process = Some("WindowServer".into());
            f.detail = "High WindowServer CPU makes the whole UI stutter. Common causes: a \
                        misbehaving app redrawing constantly, too many spaces/displays, or a \
                        screen-capture/overlay utility."
                .into();
            f.next_step = Some(
                "Quit screen-drawing utilities (overlays, screen recorders, wallpaper engines) \
                 one at a time and watch WindowServer's CPU."
                    .into(),
            );
            r.findings.push(f);
        }
    }

    // Name the process holding the most RAM right now — jetsam findings name the
    // historical hog; nothing here named the current one.
    let psm = run("ps", &["-Aceo", "pmem=,comm=", "-m"]).unwrap_or_default();
    if let Some(line) = psm.lines().next() {
        let mut it = line.split_whitespace();
        if let Some(pmem) = it.next() {
            let name = it.collect::<Vec<_>>().join(" ");
            if let Ok(pm) = pmem.parse::<f64>() {
                if pm >= 50.0 && !name.is_empty() {
                    let mut f = Finding::new(
                        "snap.top_mem",
                        Severity::Low,
                        "snapshot",
                        &format!("{name} is using {pm:.0}% of physical RAM right now"),
                    );
                    f.process = Some(name.clone());
                    f.detail = "One process holds a large share of RAM. If the Memory vital shows \
                                pressure, this is the first thing to quit or restart."
                        .into();
                    f.next_step = Some(format!(
                        "Confirm: `top -o mem -n 5 -l 1`. If {name} keeps growing, it's leaking — \
                         restart it."
                    ));
                    r.findings.push(f);
                }
            }
        }
    }
}
