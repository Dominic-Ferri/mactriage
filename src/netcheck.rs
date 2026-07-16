//! Live network health: default route, gateway reachability, DNS, Wi-Fi quality.

use crate::report::{Category, Evidence, Finding, Severity, Skipped, Vital};
use crate::util::{run, run_with_timeout};
use std::collections::HashSet;
use std::time::Duration;

pub struct NetResult {
    pub vitals: Vec<Vital>,
    pub findings: Vec<Finding>,
    pub skipped: Vec<Skipped>,
}

pub fn scan(categories: &HashSet<Category>, root: bool) -> NetResult {
    let mut r = NetResult {
        vitals: Vec::new(),
        findings: Vec::new(),
        skipped: Vec::new(),
    };
    if !categories.contains(&Category::Network) {
        return r;
    }
    let route = run("route", &["-n", "get", "default"]).unwrap_or_default();
    let gateway = route
        .lines()
        .find(|l| l.trim_start().starts_with("gateway:"))
        .map(|l| l.rsplit(':').next().unwrap_or("").trim().to_string());
    let iface = route
        .lines()
        .find(|l| l.trim_start().starts_with("interface:"))
        .map(|l| l.rsplit(':').next().unwrap_or("").trim().to_string())
        .unwrap_or_default();

    let Some(gw) = gateway.filter(|g| !g.is_empty()) else {
        r.vitals.push(Vital {
            label: "Network".into(),
            value: "no default route — offline".into(),
            flag: Some(Severity::Low),
        });
        let mut f = Finding::new(
            "snap.net_offline",
            Severity::Low,
            "network",
            "No default route — this Mac is offline",
        );
        f.detail = "No network path out. Deliberate on an air-gapped box; otherwise the first \
                    thing to fix before anything network-flavored gets diagnosed."
            .into();
        f.next_step = Some("Check link: `ifconfig` (look for status: active), then DHCP on the expected interface.".into());
        r.findings.push(f);
        return r;
    };

    // Gateway reachability: 1 ping, 2s ceiling.
    let (ping_out, _) =
        run_with_timeout("ping", &["-c", "1", "-t", "2", &gw], Duration::from_secs(4));
    let gw_ok = ping_out.contains("1 packets received") || ping_out.contains("1 received");

    // DNS through the system resolver path.
    let (dns_out, _) = run_with_timeout(
        "dscacheutil",
        &["-q", "host", "-a", "name", "apple.com"],
        Duration::from_secs(5),
    );
    let dns_ok = dns_out.contains("ip_address");

    let mut value = format!("gw {gw} via {iface}");
    let mut flag = None;
    match (gw_ok, dns_ok) {
        (true, true) => value.push_str(" · gateway ok · DNS ok"),
        (false, true) => {
            // Gateway ICMP blocked but DNS works — degraded info, not an outage.
            value.push_str(" · gateway not answering ping · DNS ok");
        }
        (true, false) => {
            value.push_str(" · gateway ok · DNS FAILING");
            flag = Some(Severity::High);
            let mut f = Finding::new(
                "snap.dns_failing",
                Severity::High,
                "network",
                "DNS resolution is failing right now (gateway is reachable)",
            );
            f.detail = "The LAN is fine but name lookups don't complete — everything looks \
                        'down' to the user while pings to IPs work. Classic causes: dead \
                        resolver, VPN/filter DNS hijack, bad profile-pinned DNS."
                .into();
            f.next_step = Some(
                "Inspect: `scutil --dns` (which resolver?), test it directly: \
                 `dig @<resolver> apple.com`. Check VPN/filter software and configuration \
                 profiles before touching network settings."
                    .into(),
            );
            f.evidence.push(Evidence {
                source: "dscacheutil -q host -a name apple.com".into(),
                excerpt: dns_out.trim().chars().take(120).collect(),
            });
            r.findings.push(f);
        }
        (false, false) => {
            value.push_str(" · gateway unreachable · DNS failing");
            flag = Some(Severity::Medium);
            let mut f = Finding::new(
                "snap.gateway_down",
                Severity::Medium,
                "network",
                &format!("Default gateway {gw} is unreachable"),
            );
            f.detail = "There's a default route but the gateway doesn't answer and DNS fails — \
                        Wi-Fi may be associated to a dead AP, DHCP stale, or the router is down."
                .into();
            f.next_step = Some(
                "Toggle the interface or renew DHCP; check whether other devices on the same \
                 network are also out (isolates Mac vs. router)."
                    .into(),
            );
            r.findings.push(f);
        }
    }

    // Wi-Fi quality (only when the default route actually rides Wi-Fi; wired
    // Ethernet is also en*, so match the real Wi-Fi device, not the prefix).
    if wifi_device().as_deref() == Some(iface.as_str()) {
        // wdutil info works without sudo on modern macOS (some fields redacted);
        // sudo gets the full picture. Try either way — only report a skip when
        // we couldn't parse signal numbers at all.
        let (wd, _) = run_with_timeout("wdutil", &["info"], Duration::from_secs(10));
        let grab = |key: &str| -> Option<i64> {
            wd.lines()
                .find(|l| l.trim_start().starts_with(key))
                .and_then(|l| l.rsplit(':').next())
                .and_then(|v| v.split_whitespace().next())
                .and_then(|v| v.parse().ok())
        };
        if let (Some(rssi), Some(noise)) = (grab("RSSI"), grab("Noise")) {
            let snr = rssi - noise;
            value.push_str(&format!(" · Wi-Fi {rssi} dBm (SNR {snr})"));
            if rssi < -75 || snr < 15 {
                flag = flag.max(Some(Severity::Medium));
                let mut f = Finding::new(
                    "snap.wifi_quality",
                    Severity::Medium,
                    "network",
                    &format!("Weak Wi-Fi signal: RSSI {rssi} dBm, SNR {snr} dB"),
                );
                f.detail = "At this signal level expect drops, slow roaming, and 'internet is \
                            broken' complaints that are really radio problems."
                    .into();
                f.next_step = Some(
                    "Move closer / reposition the AP, prefer 5 GHz, and check channel \
                     congestion. Full picture: `sudo wdutil info`."
                        .into(),
                );
                r.findings.push(f);
            }
        } else if !root {
            r.skipped.push(Skipped {
                what: "Wi-Fi quality sampling (wdutil info)".into(),
                reason: "no signal numbers without sudo — re-run with sudo for RSSI/noise/channel"
                    .into(),
            });
        }
    }

    r.vitals.push(Vital {
        label: "Network".into(),
        value,
        flag,
    });
    r
}

/// The BSD device name of the Wi-Fi hardware port (e.g. "en0"), or None if this
/// Mac has no Wi-Fi. Used to tell Wi-Fi apart from wired Ethernet (both en*).
fn wifi_device() -> Option<String> {
    let out = run("networksetup", &["-listallhardwareports"]).unwrap_or_default();
    let mut lines = out.lines();
    while let Some(l) = lines.next() {
        if l.trim_start().starts_with("Hardware Port:") && l.to_lowercase().contains("wi-fi") {
            if let Some(dev) = lines.next().and_then(|d| d.trim().strip_prefix("Device:")) {
                return Some(dev.trim().to_string());
            }
        }
    }
    None
}
