//! sec.* rules — security audit beyond the basic posture checks: Wi-Fi
//! encryption, firewall hardening, remote-access listeners, DNS/proxy/hosts
//! redirection, update policy, screen lock, and what the MDM (Jamf) has
//! configured on the Mac. Read-only: every check detects and suggests; nothing
//! here changes a setting.
//!
//! Parsers are pure `&str` functions so they can be tested against fixtures.

use crate::report::{Evidence, Finding, Severity, Skipped, Vital};
use crate::util::{capture, run, run_with_timeout, RUN_TIMEOUT};
use std::path::Path;
use std::time::Duration;

const MANAGED_PREFS: &str = "/Library/Managed Preferences";
const JAMF_BIN: &str = "/usr/local/jamf/bin/jamf";

pub struct SecurityResult {
    pub findings: Vec<Finding>,
    pub vitals: Vec<Vital>,
    pub skipped: Vec<Skipped>,
}

pub fn scan(root: bool) -> SecurityResult {
    let mut r = SecurityResult {
        findings: Vec::new(),
        vitals: Vec::new(),
        skipped: Vec::new(),
    };
    wifi(&mut r);
    firewall(&mut r);
    listeners(&mut r);
    exposed_listeners(&mut r, root);
    internet_sharing(&mut r);
    dns(&mut r);
    proxy(&mut r);
    hosts_file(&mut r);
    updates(&mut r);
    screen_lock(&mut r, root);
    login_window(&mut r);
    mdm(&mut r, root);
    jamf(&mut r, root);
    profiles(&mut r, root);
    managed_restrictions(&mut r);
    trusted_certs(&mut r, root);
    admins(&mut r);
    extensions(&mut r);
    pending_updates(&mut r);
    boot_args(&mut r);
    privileged_launch_writable(&mut r);
    mdm_mismatch(&mut r);
    managed_extensions(&mut r, root);
    firewall_exceptions(&mut r);
    ssh_auth(&mut r, root);
    root_accounts(&mut r);
    jamf_checkin(&mut r);
    r
}

fn finding(id: &str, sev: Severity, summary: &str, detail: &str, next: Option<&str>) -> Finding {
    let mut f = Finding::new(id, sev, "security", summary);
    f.detail = detail.into();
    f.next_step = next.map(String::from);
    f
}

fn vital(r: &mut SecurityResult, label: &str, value: &str, flag: Option<Severity>) {
    r.vitals.push(Vital {
        label: label.into(),
        value: value.into(),
        flag,
    });
}

/// stdout + stderr combined. Some tools (sysadminctl) print their answer on stderr.
/// None when the command could not start or timed out.
fn run_all(cmd: &str, args: &[&str]) -> Option<String> {
    let out = capture(cmd, args, RUN_TIMEOUT)?;
    (!out.timed_out).then(|| out.stdout + &out.stderr)
}

fn plist_dict(path: &str) -> Option<plist::Dictionary> {
    plist::Value::from_file(path).ok()?.into_dictionary()
}

fn plist_bool(d: &plist::Dictionary, key: &str) -> Option<bool> {
    match d.get(key)? {
        plist::Value::Boolean(b) => Some(*b),
        plist::Value::Integer(i) => i.as_signed().map(|v| v != 0),
        plist::Value::String(s) => Some(matches!(s.as_str(), "1" | "true" | "YES" | "yes")),
        _ => None,
    }
}

// ── Wi-Fi ───────────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub enum WifiSecurity {
    NotConnected,
    Open,
    /// Encrypted but broken or weak (WEP, WPA1, TKIP mixed).
    Weak(String),
    /// OWE "Enhanced Open": encrypted, but anyone can join.
    EnhancedOpen(String),
    Secure(String),
    Unknown,
}

/// Parse `ipconfig getsummary <wifi-if>`. The `Security :` line carries the
/// CoreWLAN security type (e.g. `WPA2_PSK`, `FT_8021X`, `NONE`). It is readable
/// without root and without Location permission (unlike the SSID).
pub fn parse_wifi_security(summary: &str) -> WifiSecurity {
    let associated = summary
        .lines()
        .any(|l| l.trim_start().starts_with("SSID :"));
    let sec = summary.lines().find_map(|l| {
        let t = l.trim();
        t.strip_prefix("Security :").map(|v| v.trim().to_string())
    });
    match (associated, sec) {
        (false, None) => WifiSecurity::NotConnected,
        (_, None) => WifiSecurity::Unknown,
        (_, Some(s)) => classify_wifi_security(&s),
    }
}

pub fn classify_wifi_security(raw: &str) -> WifiSecurity {
    let s = raw.to_ascii_uppercase();
    if s.is_empty() {
        return WifiSecurity::Unknown;
    }
    if s == "NONE" || s == "OPEN" {
        return WifiSecurity::Open;
    }
    if s.contains("OWE") {
        return WifiSecurity::EnhancedOpen(raw.into());
    }
    if s.contains("WEP") || s.contains("TKIP") || s.contains("MIXED") {
        return WifiSecurity::Weak(raw.into());
    }
    // WPA1-only: "WPA_PSK", "WPA_PERSONAL", "WPA_ENTERPRISE" — no 2/3 anywhere.
    if s.starts_with("WPA") && !s.contains("WPA2") && !s.contains("WPA3") {
        return WifiSecurity::Weak(raw.into());
    }
    if s.contains("WPA")
        || s.contains("PSK")
        || s.contains("SAE")
        || s.contains("8021X")
        || s.contains("PERSONAL")
        || s.contains("ENTERPRISE")
    {
        return WifiSecurity::Secure(raw.into());
    }
    WifiSecurity::Unknown
}

fn wifi_device() -> Option<String> {
    let out = run("/usr/sbin/networksetup", &["-listallhardwareports"])?;
    let mut lines = out.lines();
    while let Some(l) = lines.next() {
        if l.trim() == "Hardware Port: Wi-Fi" {
            return lines
                .next()
                .and_then(|d| d.trim().strip_prefix("Device:"))
                .map(|d| d.trim().to_string());
        }
    }
    None
}

fn wifi(r: &mut SecurityResult) {
    let Some(dev) = wifi_device() else {
        vital(r, "Wi-Fi security", "no Wi-Fi hardware", None);
        return;
    };
    let (summary, timed_out) = run_with_timeout(
        "/usr/sbin/ipconfig",
        &["getsummary", &dev],
        Duration::from_secs(10),
    );
    let state = if timed_out {
        WifiSecurity::Unknown
    } else {
        parse_wifi_security(&summary)
    };
    match state {
        WifiSecurity::NotConnected => vital(r, "Wi-Fi security", "not connected", None),
        WifiSecurity::Secure(s) => vital(r, "Wi-Fi security", &s, None),
        WifiSecurity::Open => {
            vital(
                r,
                "Wi-Fi security",
                "OPEN (no encryption)",
                Some(Severity::High),
            );
            r.findings.push(finding(
                "sec.wifi_open",
                Severity::High,
                "Connected to an OPEN Wi-Fi network (no encryption)",
                "Everything not wrapped in TLS or a VPN is readable by anyone nearby, and \
                 anyone can impersonate this network. Captive-portal guest networks are \
                 usually open.",
                Some(
                    "Use a VPN your organisation approves on this network, or switch to an \
                      encrypted network such as the organisation's WPA2/WPA3-Enterprise network.",
                ),
            ));
        }
        WifiSecurity::Weak(s) => {
            vital(
                r,
                "Wi-Fi security",
                &format!("{s} (weak)"),
                Some(Severity::Medium),
            );
            r.findings.push(finding(
                "sec.wifi_weak",
                Severity::Medium,
                &format!("Wi-Fi uses weak security: {s}"),
                "WEP and WPA1/TKIP can be cracked with off-the-shelf tools; mixed mode \
                 lets clients fall back to them.",
                Some("Ask the network owner to move to WPA2-AES or WPA3; use a VPN until then."),
            ));
        }
        WifiSecurity::EnhancedOpen(s) => {
            vital(
                r,
                "Wi-Fi security",
                &format!("{s} (enhanced open)"),
                Some(Severity::Low),
            );
            r.findings.push(finding(
                "sec.wifi_weak",
                Severity::Low,
                &format!("Wi-Fi is Enhanced Open ({s}): encrypted but unauthenticated"),
                "OWE encrypts traffic but anyone can join, so the network itself can't be \
                 trusted.",
                Some("Treat it like public Wi-Fi: use a VPN."),
            ));
        }
        WifiSecurity::Unknown => {
            vital(r, "Wi-Fi security", "unknown", Some(Severity::Info));
            r.findings.push(finding(
                "sec.wifi_unknown",
                Severity::Info,
                "Wi-Fi security type could not be read",
                "Wi-Fi is up but `ipconfig getsummary` did not report a security type. This is \
                 NOT a pass — the encryption is unverified.",
                Some("Check System Settings ▸ Wi-Fi ▸ Details ▸ Security, or `sudo wdutil info`."),
            ));
        }
    }
}

// ── firewall hardening (on/off itself is posture.firewall_off) ──────────────

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum FirewallState {
    On,
    Off,
    Unknown,
}

/// `socketfilterfw --getglobalstate`: "Firewall is enabled. (State = 1)",
/// "… (State = 2)" (block all), or "Firewall is disabled. (State = 0)".
/// Anything else is Unknown — never treated as on.
pub fn parse_firewall_state(out: &str) -> FirewallState {
    let l = out.to_lowercase();
    if l.contains("is disabled") || l.contains("state = 0") {
        FirewallState::Off
    } else if l.contains("is enabled") {
        FirewallState::On
    } else {
        FirewallState::Unknown
    }
}

/// `socketfilterfw --getstealthmode`: "Firewall stealth mode is on|off"
/// (older builds: "Stealth mode enabled|disabled"). None = unreadable.
pub fn parse_stealth(out: &str) -> Option<bool> {
    let l = out.to_lowercase();
    if l.contains("mode is on") || l.contains("mode enabled") {
        Some(true)
    } else if l.contains("mode is off") || l.contains("mode disabled") {
        Some(false)
    } else {
        None
    }
}

fn firewall(r: &mut SecurityResult) {
    let fw = "/usr/libexec/ApplicationFirewall/socketfilterfw";
    let state = parse_firewall_state(&run(fw, &["--getglobalstate"]).unwrap_or_default());
    let managed = Path::new(MANAGED_PREFS)
        .join("com.apple.security.firewall.plist")
        .exists();
    let (label, flag) = match state {
        FirewallState::On => ("on", None),
        FirewallState::Off => ("OFF", Some(Severity::Medium)),
        FirewallState::Unknown => ("unknown", Some(Severity::Info)),
    };
    let label = if managed {
        format!("{label} (MDM-managed)")
    } else {
        label.to_string()
    };
    vital(r, "Firewall", &label, flag);
    match state {
        // posture.firewall_off reports it; stealth is moot (macOS drops it too).
        FirewallState::Off => return,
        FirewallState::Unknown => {
            r.skipped.push(Skipped {
                what: "application firewall state".into(),
                reason: "socketfilterfw output unrecognized — firewall NOT verified".into(),
            });
            return;
        }
        FirewallState::On => {}
    }
    match parse_stealth(&run(fw, &["--getstealthmode"]).unwrap_or_default()) {
        Some(true) => vital(r, "Stealth mode", "on", None),
        Some(false) => {
            vital(r, "Stealth mode", "OFF", Some(Severity::Low));
            r.findings.push(finding(
                "sec.firewall_stealth_off",
                Severity::Low,
                "Firewall stealth mode is off",
                "The Mac answers pings and probes to closed ports, so it is easy to find on \
                 untrusted networks.",
                Some("System Settings ▸ Network ▸ Firewall ▸ Options ▸ Enable stealth mode."),
            ));
        }
        None => vital(r, "Stealth mode", "unknown", Some(Severity::Info)),
    }
    let signed = run(fw, &["--getallowsigned"]).unwrap_or_default();
    if signed.contains("downloaded signed software ENABLED") {
        let mut f = finding(
            "sec.firewall_allow_signed",
            Severity::Info,
            "Firewall auto-allows any downloaded signed app",
            "Any app signed with a Developer ID can accept incoming connections without a \
             prompt. This is Apple's default; stricter setups turn it off.",
            Some("Firewall ▸ Options ▸ untick 'Automatically allow downloaded signed software'."),
        );
        f.evidence.push(Evidence {
            source: "socketfilterfw --getallowsigned".into(),
            excerpt: signed.trim().replace('\n', " · "),
        });
        r.findings.push(f);
    }
}

// ── remote-access listeners ─────────────────────────────────────────────────

/// Remote-access services: (launchd label, port, name).
const REMOTE_SERVICES: &[(&str, u16, &str)] = &[
    ("com.openssh.sshd", 22, "Remote Login (SSH)"),
    ("com.apple.screensharing", 5900, "Screen Sharing / VNC"),
    ("com.apple.smbd", 445, "File Sharing (SMB)"),
    ("com.apple.AEServer", 3031, "Remote Apple Events"),
];

/// Labels explicitly `=> enabled` in `launchctl print-disabled system`. These
/// services are socket-activated (not running until someone connects), so the
/// enabled flag is the setting itself — what the Sharing pane toggles.
pub fn parse_enabled_services(out: &str) -> Vec<String> {
    out.lines()
        .filter_map(|l| {
            let (label, state) = l.trim().split_once("=>")?;
            (state.trim() == "enabled").then(|| label.trim().trim_matches('"').to_string())
        })
        .collect()
}

/// Ports with a LISTEN socket bound to all interfaces (`*.port`), from
/// `netstat -an`. Loopback-only listeners are not remote access.
pub fn parse_listen_ports(netstat: &str) -> Vec<u16> {
    let mut ports: Vec<u16> = netstat
        .lines()
        .filter(|l| l.starts_with("tcp") && l.contains("LISTEN"))
        .filter_map(|l| l.split_whitespace().nth(3))
        .filter(|addr| addr.starts_with("*.") || addr.starts_with("*:"))
        .filter_map(|addr| addr.rsplit(['.', ':']).next()?.parse().ok())
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}

fn listeners(r: &mut SecurityResult) {
    let Some(disabled) = run("/bin/launchctl", &["print-disabled", "system"]) else {
        vital(r, "Remote access open", "unknown", Some(Severity::Info));
        r.skipped.push(Skipped {
            what: "remote-access services (launchctl print-disabled)".into(),
            reason: "launchctl returned nothing".into(),
        });
        return;
    };
    let enabled = parse_enabled_services(&disabled);
    // Supporting evidence only: macOS hides netstat's socket table from some
    // callers (0 tcp rows), so an empty port list proves nothing.
    let ports = parse_listen_ports(&run("/usr/sbin/netstat", &["-an"]).unwrap_or_default());
    let screen_mdm = Path::new(MANAGED_PREFS)
        .join("com.apple.screensharingserver.plist")
        .exists();
    let ard = run("/usr/bin/pgrep", &["-x", "ARDAgent"]).is_some_and(|o| !o.trim().is_empty());
    let mut names = Vec::new();
    let mut services: Vec<(&str, Option<u16>, &str)> = REMOTE_SERVICES
        .iter()
        .filter(|(label, _, _)| enabled.iter().any(|e| e == label))
        .map(|(l, p, n)| (*l, Some(*p), *n))
        .collect();
    if ard {
        services.push(("ARDAgent", Some(3283), "Remote Management (ARD)"));
    }
    for (label, port, name) in services {
        names.push(name);
        let mut detail = format!(
            "{name} is switched on, so it can be reached from any network this Mac joins \
             (subject to the firewall and account passwords)."
        );
        if port == Some(22) && jamf_log_mentions("startssh") {
            detail.push_str(
                " jamf.log shows a Jamf `startssh` task, so a Jamf policy turned SSH on.",
            );
        }
        if (port == Some(5900) || label == "ARDAgent") && screen_mdm {
            detail.push_str(
                " A Screen Sharing configuration profile is installed, so the MDM (Jamf) \
                 most likely turned this on for remote support.",
            );
        }
        let mut f = finding(
            "sec.remote_access",
            Severity::Medium,
            &format!("{name} is enabled"),
            &detail,
            Some(
                "If you don't use it: System Settings ▸ General ▸ Sharing ▸ turn it off. If \
                  the MDM enabled it, raise it with the Jamf admin instead of fighting the \
                  policy.",
            ),
        );
        f.process = Some(name.to_string());
        f.evidence.push(Evidence {
            source: "launchctl print-disabled system".into(),
            excerpt: format!("\"{label}\" => enabled"),
        });
        if let Some(p) = port.filter(|p| ports.contains(p)) {
            f.evidence.push(Evidence {
                source: "netstat -an".into(),
                excerpt: format!("*.{p} LISTEN"),
            });
        }
        r.findings.push(f);
    }
    let v = if names.is_empty() {
        "none".to_string()
    } else {
        names.join(", ")
    };
    let flag = (!names.is_empty()).then_some(Severity::Medium);
    vital(r, "Remote access open", &v, flag);
}

// ── every listener reachable from the network ───────────────────────────────

/// One LISTEN socket from `lsof -nP -iTCP -sTCP:LISTEN -F pcn`.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Listener {
    pub pid: u32,
    pub command: String,
    pub port: u16,
    /// Bound to a non-loopback address (`*`, or one LAN/VPN address), so other
    /// machines can connect.
    pub exposed: bool,
}

/// Loopback binds (`127.x.x.x`, `[::1]`, `[::ffff:127.0.0.1]`) are local-only.
/// `*` and every other address face a network; so does anything unparseable.
fn bind_is_exposed(addr: &str) -> bool {
    let ip = addr.trim_start_matches('[').trim_end_matches(']');
    match ip
        .split('%')
        .next()
        .unwrap_or(ip)
        .parse::<std::net::IpAddr>()
    {
        Ok(std::net::IpAddr::V4(v4)) => !v4.is_loopback(),
        Ok(std::net::IpAddr::V6(v6)) => {
            !(v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()))
        }
        Err(_) => true,
    }
}

/// Parse lsof field output: `p<pid>` starts a process, `c<command>` names it,
/// `n<addr>:<port>` is one socket (`*:7000`, `127.0.0.1:48000`, `[::1]:9877`).
/// Rows with the same (pid, port) (IPv4 + IPv6 sockets) collapse to one, which
/// is exposed if any of its sockets is.
pub fn parse_lsof_listeners(out: &str) -> Vec<Listener> {
    let mut found: Vec<Listener> = Vec::new();
    let (mut pid, mut command) = (0u32, String::new());
    for l in out.lines() {
        let mut chars = l.chars();
        let Some(tag) = chars.next() else { continue };
        let val = chars.as_str().trim();
        match tag {
            'p' => {
                pid = val.parse().unwrap_or(0);
                command.clear();
            }
            'c' => command = val.to_string(),
            'n' if pid > 0 => {
                let Some((addr, port)) = val.rsplit_once(':') else {
                    continue;
                };
                let Ok(port) = port.parse::<u16>() else {
                    continue;
                };
                let exposed = bind_is_exposed(addr);
                match found.iter_mut().find(|f| f.pid == pid && f.port == port) {
                    Some(f) => f.exposed |= exposed,
                    None => found.push(Listener {
                        pid,
                        command: command.clone(),
                        port,
                        exposed,
                    }),
                }
            }
            _ => {}
        }
    }
    found
}

/// Apple platform binaries carry `Authority=Software Signing` (older) or
/// `Authority=macOS Software Signing`. Mac App Store apps and Developer ID
/// apps do not — they are third-party even though Apple co-signs them.
pub fn apple_platform_signed(codesign_out: &str) -> bool {
    codesign_out.lines().any(|l| {
        matches!(
            l.trim(),
            "Authority=Software Signing" | "Authority=macOS Software Signing"
        )
    })
}

/// Human label for who signed a binary, from `codesign -dv --verbose=2`.
pub fn signer_label(codesign_out: &str) -> String {
    if codesign_out.contains("code object is not signed") {
        return "unsigned".into();
    }
    if apple_platform_signed(codesign_out) {
        return "Apple".into();
    }
    for l in codesign_out.lines() {
        let l = l.trim();
        if let Some(dev) = l.strip_prefix("Authority=Developer ID Application: ") {
            return format!("Developer ID: {dev}");
        }
        if l == "Authority=Apple Mac OS Application Signing" {
            return "Mac App Store".into();
        }
    }
    if codesign_out.lines().any(|l| l.trim() == "Signature=adhoc") {
        return "ad-hoc signed (no identity)".into();
    }
    "unknown signer".into()
}

/// Ports the socket-activated sharing services own; `sec.remote_access`
/// already reports those by their launchd setting.
fn sharing_port(port: u16) -> bool {
    REMOTE_SERVICES.iter().any(|(_, p, _)| *p == port) || port == 3283
}

/// Ports worth reporting for one process. A sharing-service port is left to
/// `sec.remote_access` only when launchd (pid 1) or an Apple binary holds it.
/// Anything else on 22, 445, 5900, 3031 or 3283 is a third-party server.
pub fn reportable_ports(pid: u32, apple: bool, ports: &[u16]) -> Vec<u16> {
    ports
        .iter()
        .copied()
        .filter(|&p| !(sharing_port(p) && (pid == 1 || apple)))
        .collect()
}

/// Does the file carry Apple's own platform signature? A code requirement
/// also validates the signature, unlike reading `codesign -dv` text.
pub(crate) fn verifies_as_apple(path: &str) -> bool {
    capture(
        "/usr/bin/codesign",
        &["--verify", "--deep", "-R=anchor apple", "--", path],
        RUN_TIMEOUT,
    )
    .is_some_and(|out| out.success)
}

/// One process with network-facing sockets.
struct ListenerProc {
    command: String,
    path: Option<String>,
    signer: String,
    apple: bool,
    ports: Vec<u16>,
}

impl ListenerProc {
    fn ports(&self) -> String {
        let ports: Vec<String> = self.ports.iter().map(|p| p.to_string()).collect();
        ports.join(", ")
    }

    fn describe(&self) -> String {
        format!(
            "{} ({}) — port {} — {}",
            self.command,
            self.path.as_deref().unwrap_or("path unreadable"),
            self.ports(),
            self.signer
        )
    }
}

const LISTENING: &str = "Listening on the network";

fn exposed_listeners(r: &mut SecurityResult, root: bool) {
    if !root {
        r.skipped.push(Skipped {
            what: "listeners owned by other users (lsof)".into(),
            reason: "requires sudo — only this user's processes were inspected".into(),
        });
    }
    let (out, timed_out) = run_with_timeout(
        "/usr/sbin/lsof",
        &["-nP", "-iTCP", "-sTCP:LISTEN", "-F", "pcn"],
        Duration::from_secs(20),
    );
    let all = parse_lsof_listeners(&out);
    if all.is_empty() {
        vital(r, LISTENING, "unknown", Some(Severity::Info));
        r.skipped.push(Skipped {
            what: "network-facing listeners (lsof)".into(),
            reason: if timed_out {
                "lsof timed out after 20s".into()
            } else {
                "lsof listed no LISTEN sockets — not verified".into()
            },
        });
        return;
    }
    // Group exposed sockets by pid, then resolve each process once: the real
    // executable from the kernel (a process can rewrite argv[0]), Apple or not from a
    // code requirement, and a signer label from codesign (printed on stderr).
    let mut by_pid: std::collections::BTreeMap<u32, (String, Vec<u16>)> = Default::default();
    for l in all.iter().filter(|l| l.exposed) {
        by_pid
            .entry(l.pid)
            .or_insert_with(|| (l.command.clone(), Vec::new()))
            .1
            .push(l.port);
    }
    let procs: Vec<ListenerProc> = by_pid
        .into_iter()
        .filter_map(|(pid, (command, ports))| {
            let path = crate::util::pid_path(pid);
            let apple = path.as_deref().is_some_and(verifies_as_apple);
            let ports = reportable_ports(pid, apple, &ports);
            if ports.is_empty() {
                return None;
            }
            let signer = match path.as_deref() {
                _ if apple => "Apple".into(),
                Some(p) => signer_label(
                    &run_all("/usr/bin/codesign", &["-dv", "--verbose=2", "--", p])
                        .unwrap_or_default(),
                ),
                None => "signer unknown".into(),
            };
            Some(ListenerProc {
                command,
                path,
                signer,
                apple,
                ports,
            })
        })
        .collect();
    if procs.is_empty() {
        // Unprivileged, other users' processes were invisible: not a clean result.
        if root {
            vital(r, LISTENING, "none beyond sharing services", None);
        } else {
            vital(
                r,
                LISTENING,
                "unknown (only this user's processes checked)",
                Some(Severity::Info),
            );
        }
        return;
    }
    let (apple, third): (Vec<&ListenerProc>, Vec<&ListenerProc>) =
        procs.iter().partition(|p| p.apple);
    let summary: Vec<String> = procs
        .iter()
        .map(|p| format!("{}:{}", p.command, p.ports().replace(", ", "/")))
        .collect();
    let flag = (!third.is_empty()).then_some(Severity::Medium);
    vital(r, LISTENING, &summary.join(", "), flag);
    if !third.is_empty() {
        let mut f = finding(
            "sec.listener_exposed",
            Severity::Medium,
            &format!(
                "{} third-party program(s) accept connections from the network",
                third.len()
            ),
            "These processes hold a TCP port open on a network-facing address (every \
             interface, or one LAN or VPN address), not just localhost, so other machines on \
             that network can talk to them (unless the firewall blocks the app). Dev servers \
             and remote-control tools often bind this way by default; so does malware. A \
             program on a sharing port (SSH, SMB, Screen Sharing) that is not Apple's own \
             service is listed here too.",
            Some(
                "If a program only needs local access, bind it to 127.0.0.1. If you don't \
                  recognise one, quit it and check where it came from: \
                  `lsof -nP -iTCP -sTCP:LISTEN`.",
            ),
        );
        for p in &third {
            f.evidence.push(Evidence {
                source: "lsof + codesign".into(),
                excerpt: p.describe(),
            });
        }
        r.findings.push(f);
    }
    if !apple.is_empty() {
        let mut f = finding(
            "sec.listener_apple",
            Severity::Info,
            &format!("{} Apple service(s) listening on the network", apple.len()),
            "Apple's own daemons (AirPlay receiver in Control Center, rapportd for Continuity, \
             etc.) listen for nearby devices. Normal on a personal Mac; on an untrusted \
             network each is still a reachable service.",
            Some(
                "To shrink the surface: System Settings ▸ General ▸ AirDrop & Handoff (turn \
                  off AirPlay Receiver / Handoff), and keep the firewall on.",
            ),
        );
        for p in &apple {
            f.evidence.push(Evidence {
                source: "lsof + codesign".into(),
                excerpt: p.describe(),
            });
        }
        r.findings.push(f);
    }
}

fn internet_sharing(r: &mut SecurityResult) {
    let Some(d) = plist_dict("/Library/Preferences/SystemConfiguration/com.apple.nat.plist") else {
        return;
    };
    let on = d
        .get("NAT")
        .and_then(|n| n.as_dictionary())
        .and_then(|n| plist_bool(n, "Enabled"))
        .unwrap_or(false);
    if on {
        r.findings.push(finding(
            "sec.internet_sharing",
            Severity::Medium,
            "Internet Sharing is on",
            "This Mac is acting as a router/hotspot for other devices, bridging them onto \
             whatever network it is connected to.",
            Some("System Settings ▸ General ▸ Sharing ▸ Internet Sharing ▸ off."),
        ));
    }
}

// ── DNS / proxy / hosts ─────────────────────────────────────────────────────

/// Nameservers of the default resolver (`resolver #1`) in `scutil --dns`.
pub fn parse_default_nameservers(scutil_dns: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_first = false;
    for l in scutil_dns.lines() {
        let t = l.trim();
        if t.starts_with("resolver #") {
            if in_first {
                break;
            }
            in_first = t == "resolver #1";
            continue;
        }
        if in_first {
            if let Some(ns) = t.strip_prefix("nameserver[") {
                if let Some((_, v)) = ns.split_once(':') {
                    out.push(v.trim().to_string());
                }
            }
        }
    }
    out
}

/// Private, loopback, CGNAT (Tailscale's 100.100.100.100) and ULA/link-local v6.
pub fn is_private_ip(ip: &str) -> bool {
    if let Ok(v4) = ip.parse::<std::net::Ipv4Addr>() {
        let o = v4.octets();
        return v4.is_private()
            || v4.is_loopback()
            || v4.is_link_local()
            || (o[0] == 100 && (64..128).contains(&o[1]));
    }
    let base = ip.split('%').next().unwrap_or(ip);
    if let Ok(v6) = base.parse::<std::net::Ipv6Addr>() {
        let s = v6.segments()[0];
        return v6.is_loopback() || (s & 0xfe00) == 0xfc00 || (s & 0xffc0) == 0xfe80;
    }
    false
}

/// Public resolvers run by a known operator. Anything public and not here is
/// "unrecognized" — the shape a DNS hijack takes.
const KNOWN_RESOLVERS: &[(&str, &str)] = &[
    ("1.1.1.1", "Cloudflare"),
    ("1.0.0.1", "Cloudflare"),
    ("1.1.1.2", "Cloudflare"),
    ("1.0.0.2", "Cloudflare"),
    ("1.1.1.3", "Cloudflare"),
    ("1.0.0.3", "Cloudflare"),
    ("2606:4700:4700::1111", "Cloudflare"),
    ("2606:4700:4700::1001", "Cloudflare"),
    ("2606:4700:4700::1112", "Cloudflare"),
    ("2606:4700:4700::1002", "Cloudflare"),
    ("2606:4700:4700::1113", "Cloudflare"),
    ("2606:4700:4700::1003", "Cloudflare"),
    ("8.8.8.8", "Google"),
    ("8.8.4.4", "Google"),
    ("2001:4860:4860::8888", "Google"),
    ("2001:4860:4860::8844", "Google"),
    ("9.9.9.9", "Quad9"),
    ("149.112.112.112", "Quad9"),
    ("9.9.9.10", "Quad9"),
    ("149.112.112.10", "Quad9"),
    ("9.9.9.11", "Quad9"),
    ("149.112.112.11", "Quad9"),
    ("2620:fe::fe", "Quad9"),
    ("2620:fe::9", "Quad9"),
    ("2620:fe::10", "Quad9"),
    ("2620:fe::11", "Quad9"),
    ("208.67.222.222", "OpenDNS"),
    ("208.67.220.220", "OpenDNS"),
    ("208.67.222.123", "OpenDNS"),
    ("208.67.220.123", "OpenDNS"),
    ("2620:119:35::35", "OpenDNS"),
    ("2620:119:53::53", "OpenDNS"),
    ("94.140.14.14", "AdGuard"),
    ("94.140.15.15", "AdGuard"),
    ("94.140.14.15", "AdGuard"),
    ("94.140.15.16", "AdGuard"),
    ("2a10:50c0::ad1:ff", "AdGuard"),
    ("2a10:50c0::ad2:ff", "AdGuard"),
    ("76.76.2.0", "Control D"),
    ("76.76.10.0", "Control D"),
    ("185.228.168.9", "CleanBrowsing"),
    ("185.228.169.9", "CleanBrowsing"),
    ("4.2.2.1", "Level 3"),
    ("4.2.2.2", "Level 3"),
    ("4.2.2.3", "Level 3"),
    ("4.2.2.4", "Level 3"),
    ("75.75.75.75", "Comcast/Xfinity"),
    ("75.75.76.76", "Comcast/Xfinity"),
    ("2001:558:feed::1", "Comcast/Xfinity"),
    ("2001:558:feed::2", "Comcast/Xfinity"),
    ("71.252.0.12", "Verizon"),
    ("68.237.161.12", "Verizon"),
    ("68.94.156.1", "AT&T"),
    ("68.94.157.1", "AT&T"),
    ("209.18.47.61", "Spectrum"),
    ("209.18.47.62", "Spectrum"),
];

/// Operator name for a well-known public resolver. Addresses are compared
/// parsed, so `2606:4700:4700:0:0:0:0:1111` matches `2606:4700:4700::1111`.
pub fn known_public_resolver(ip: &str) -> Option<&'static str> {
    let ip: std::net::IpAddr = ip.split('%').next()?.parse().ok()?;
    KNOWN_RESOLVERS
        .iter()
        .find(|(k, _)| k.parse() == Ok(ip))
        .map(|(_, who)| *who)
}

/// Public resolvers as (known provider, unrecognized); private ones are dropped.
pub fn split_public_resolvers(ns: &[String]) -> (Vec<&String>, Vec<&String>) {
    ns.iter()
        .filter(|n| !is_private_ip(n))
        .partition(|n| known_public_resolver(n).is_some())
}

fn dns(r: &mut SecurityResult) {
    let dns = run("/usr/sbin/scutil", &["--dns"]).unwrap_or_default();
    if !dns.contains("resolver #") {
        vital(r, "DNS servers", "unknown", Some(Severity::Info));
        r.skipped.push(Skipped {
            what: "DNS resolver configuration (scutil --dns)".into(),
            reason: "scutil returned no resolver list — DNS not verified".into(),
        });
        return;
    }
    let ns = parse_default_nameservers(&dns);
    vital(
        r,
        "DNS servers",
        &if ns.is_empty() {
            "none".into()
        } else {
            ns.join(", ")
        },
        None,
    );
    let (known, unknown) = split_public_resolvers(&ns);
    if !unknown.is_empty() {
        let mut f = finding(
            "sec.dns_public",
            Severity::Medium,
            &format!(
                "DNS goes to an unrecognized public resolver: {}",
                unknown
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            "This resolver is not a known provider (Cloudflare, Google, Quad9, OpenDNS, \
             AdGuard, the major US ISPs). Whoever runs it sees every domain this Mac looks up \
             and can answer with the wrong address. If you did not set it, suspect a \
             planted network setting, a profile, or malware.",
            Some(
                "Check who set it: System Settings ▸ Network ▸ <interface> ▸ Details ▸ DNS, \
                  the router's DHCP settings, and installed profiles for a DNS Settings \
                  payload. Replace it with your ISP's or a known resolver if unexplained.",
            ),
        );
        f.evidence.push(Evidence {
            source: "scutil --dns (resolver #1)".into(),
            excerpt: ns.join(", "),
        });
        r.findings.push(f);
    }
    if !known.is_empty() {
        let who: Vec<String> = known
            .iter()
            .map(|n| format!("{n} ({})", known_public_resolver(n).unwrap_or("?")))
            .collect();
        let mut f = finding(
            "sec.dns_public",
            Severity::Info,
            &format!("DNS goes to a known public resolver: {}", who.join(", ")),
            "A recognized provider. Fine if you (or your ISP's DHCP) chose it; it just means \
             DNS queries leave the local network in the clear.",
            Some("Nothing to do unless you expected a different resolver."),
        );
        f.evidence.push(Evidence {
            source: "scutil --dns (resolver #1)".into(),
            excerpt: ns.join(", "),
        });
        r.findings.push(f);
    }
}

fn proxy(r: &mut SecurityResult) {
    let proxy = run("/usr/sbin/scutil", &["--proxy"]).unwrap_or_default();
    let enabled: Vec<&str> = [
        "HTTPEnable",
        "HTTPSEnable",
        "SOCKSEnable",
        "ProxyAutoConfigEnable",
    ]
    .into_iter()
    .filter(|k| proxy.lines().any(|l| l.trim() == format!("{k} : 1")))
    .collect();
    if !enabled.is_empty() {
        let mut f = finding(
            "sec.proxy_set",
            Severity::Low,
            "A system web proxy is configured",
            "All web traffic is routed through a proxy. Legitimate on managed networks; \
             adware and TLS-interception tools also do this.",
            Some(
                "Check System Settings ▸ Network ▸ <interface> ▸ Details ▸ Proxies, and \
                  which profile set it (`sudo profiles show`).",
            ),
        );
        f.evidence.push(Evidence {
            source: "scutil --proxy".into(),
            excerpt: proxy
                .lines()
                .map(str::trim)
                .filter(|l| {
                    enabled.iter().any(|k| l.starts_with(k))
                        || l.contains("Proxy :")
                        || l.contains("URLString")
                })
                .collect::<Vec<_>>()
                .join(" · "),
        });
        r.findings.push(f);
    }
}

/// Non-stock /etc/hosts entries as (ip, hostname), de-duplicated.
pub fn parse_hosts_overrides(hosts: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for l in hosts.lines() {
        let l = l.split('#').next().unwrap_or("").trim();
        let mut parts = l.split_whitespace();
        let Some(ip) = parts.next() else { continue };
        for host in parts {
            let stock = matches!(
                (ip, host),
                ("127.0.0.1", "localhost")
                    | ("::1", "localhost")
                    | ("fe80::1%lo0", "localhost")
                    | ("255.255.255.255", "broadcasthost")
            );
            let pair = (ip.to_string(), host.to_string());
            if !stock && !out.contains(&pair) {
                out.push(pair);
            }
        }
    }
    out
}

/// Domains where a hosts-file override is dangerous rather than merely odd:
/// Apple's update / notarization / revocation hosts, package registries, and
/// sign-in providers. Suffix match on a label boundary.
const SENSITIVE_HOSTS: &[(&str, &str)] = &[
    ("apple.com", "Apple update/security"),
    ("icloud.com", "Apple sign-in"),
    ("apple-cloudkit.com", "Apple sign-in"),
    ("github.com", "package registry"),
    ("githubusercontent.com", "package registry"),
    ("npmjs.org", "package registry"),
    ("npmjs.com", "package registry"),
    ("pypi.org", "package registry"),
    ("pythonhosted.org", "package registry"),
    ("rubygems.org", "package registry"),
    ("crates.io", "package registry"),
    ("brew.sh", "package registry"),
    ("microsoftonline.com", "sign-in"),
    ("live.com", "sign-in"),
    ("office.com", "sign-in"),
    ("google.com", "sign-in"),
    ("googleapis.com", "sign-in"),
    ("okta.com", "sign-in"),
    ("duosecurity.com", "sign-in"),
    ("paypal.com", "sign-in"),
    ("amazon.com", "sign-in"),
];

/// `host` is `suffix` or a subdomain of it (label boundary, so not `notapple.com`).
fn host_in(host: &str, suffix: &str) -> bool {
    host == suffix || host.ends_with(&format!(".{suffix}"))
}

/// Why a hostname is sensitive to override, or None.
pub fn sensitive_host(host: &str) -> Option<&'static str> {
    let h = host.to_ascii_lowercase();
    for (suffix, why) in SENSITIVE_HOSTS {
        if host_in(&h, suffix) {
            return Some(why);
        }
    }
    // Any host whose first label says "sign-in" is a sign-in page.
    let first = h.split('.').next().unwrap_or("");
    matches!(
        first,
        "login" | "auth" | "sso" | "signin" | "id" | "accounts" | "idp"
    )
    .then_some("sign-in")
}

/// Apple hosts that deliver software updates and XProtect data, certificate
/// revocation (OCSP/CRL) and notarization tickets. Suffix match. Telemetry
/// hosts such as xp.apple.com are deliberately absent.
const APPLE_SECURITY_HOSTS: &[&str] = &[
    "swscan.apple.com",
    "swdist.apple.com",
    "swcdn.apple.com",
    "mesu.apple.com",
    "gdmf.apple.com",
    "cdn-apple.com",
    "updates.cdn-apple.com",
    "ocsp.apple.com",
    "ocsp2.apple.com",
    "crl.apple.com",
    "valid.apple.com",
    "api.apple-cloudkit.com",
];

/// Severity of blocking `host` in /etc/hosts: High for an Apple update,
/// revocation or notarization host, Medium for any other `*.apple.com`
/// name, None for a non-Apple name.
pub fn apple_block_severity(host: &str) -> Option<Severity> {
    let h = host.to_ascii_lowercase();
    if APPLE_SECURITY_HOSTS.iter().any(|s| host_in(&h, s)) {
        Some(Severity::High)
    } else if host_in(&h, "apple.com") {
        Some(Severity::Medium)
    } else {
        None
    }
}

fn hosts_file(r: &mut SecurityResult) {
    let Ok(text) = std::fs::read_to_string("/etc/hosts") else {
        return;
    };
    let entries = parse_hosts_overrides(&text);
    let (blocks, redirects): (Vec<_>, Vec<_>) = entries
        .iter()
        .partition(|(ip, _)| matches!(ip.as_str(), "127.0.0.1" | "0.0.0.0" | "::1" | "::"));
    if !redirects.is_empty() {
        let sensitive: Vec<String> = redirects
            .iter()
            .filter_map(|(ip, h)| sensitive_host(h).map(|why| format!("{h} → {ip} ({why})")))
            .collect();
        let (sev, summary) = if sensitive.is_empty() {
            (
                Severity::Low,
                format!(
                    "/etc/hosts redirects {} hostname(s) to fixed IPs",
                    redirects.len()
                ),
            )
        } else {
            (
                Severity::Medium,
                format!(
                    "/etc/hosts redirects {} sensitive hostname(s) (Apple, package registry, \
                     or sign-in) to fixed IPs",
                    sensitive.len()
                ),
            )
        };
        let mut f = finding(
            "sec.hosts_redirect",
            sev,
            &summary,
            "These names skip DNS and always go to the listed address. If the entry is stale \
             or was planted, traffic silently goes to the wrong server (package registries \
             and login pages are the dangerous ones).",
            Some(
                "Confirm each line is yours; remove stale ones with `sudo nano /etc/hosts` \
                  (back it up first).",
            ),
        );
        if !sensitive.is_empty() {
            f.evidence.push(Evidence {
                source: "/etc/hosts (sensitive)".into(),
                excerpt: sensitive.join(" · "),
            });
        }
        f.evidence.push(Evidence {
            source: "/etc/hosts".into(),
            excerpt: redirects
                .iter()
                .map(|(ip, h)| format!("{h} → {ip}"))
                .collect::<Vec<_>>()
                .join(" · "),
        });
        r.findings.push(f);
    }
    if !blocks.is_empty() {
        let apple: Vec<(&str, Severity)> = blocks
            .iter()
            .filter_map(|(_, h)| apple_block_severity(h).map(|s| (h.as_str(), s)))
            .collect();
        let names: Vec<&str> = apple.iter().map(|(h, _)| *h).collect();
        let mut f = match apple.iter().map(|(_, s)| *s).max() {
            None => finding(
                "sec.hosts_block",
                Severity::Info,
                &format!("/etc/hosts blocks {} hostname(s)", blocks.len()),
                "Names pointed at localhost are blocked. Usually deliberate (ad/telemetry \
                 blocking); malware sometimes blocks security-update hosts the same way.",
                None,
            ),
            Some(Severity::High) => finding(
                "sec.hosts_block",
                Severity::High,
                &format!(
                    "/etc/hosts blocks Apple update or security host(s): {}",
                    names.join(", ")
                ),
                "These Apple hosts carry software updates, XProtect definitions, notarization \
                 checks and certificate revocation. Blocking them is how malware keeps the Mac \
                 from updating or from learning that its code signature was revoked. There is \
                 almost no legitimate reason for this on a personal or managed Mac.",
                Some(
                    "Remove the lines (`sudo nano /etc/hosts`, back it up first), then run \
                      Software Update. If you didn't add them, treat the Mac as compromised \
                      and look at who else can write that file.",
                ),
            ),
            Some(sev) => finding(
                "sec.hosts_block",
                sev,
                &format!("/etc/hosts blocks Apple host(s): {}", names.join(", ")),
                "None of these is a known update, revocation or notarization host, so this is \
                 most likely telemetry or ad blocking. Blocking Apple names can still break \
                 Apple services, and malware blocks Apple hosts to stay hidden.",
                Some(
                    "Confirm each line is yours; remove the ones you don't recognise with \
                      `sudo nano /etc/hosts` (back it up first).",
                ),
            ),
        };
        f.evidence.push(Evidence {
            source: "/etc/hosts".into(),
            excerpt: blocks
                .iter()
                .map(|(_, h)| h.as_str())
                .collect::<Vec<_>>()
                .join(" · "),
        });
        r.findings.push(f);
    }
}

// ── software update policy ──────────────────────────────────────────────────

fn updates(r: &mut SecurityResult) {
    let local =
        plist_dict("/Library/Preferences/com.apple.SoftwareUpdate.plist").unwrap_or_default();
    let managed = plist_dict(&format!("{MANAGED_PREFS}/com.apple.SoftwareUpdate.plist"));
    // A managed value wins over the local one.
    let get = |k: &str| {
        managed
            .as_ref()
            .and_then(|m| plist_bool(m, k))
            .or_else(|| plist_bool(&local, k))
    };
    let mut off = Vec::new();
    for (key, what) in [
        ("AutomaticCheckEnabled", "check for updates"),
        (
            "CriticalUpdateInstall",
            "install security responses & system files",
        ),
        ("ConfigDataInstall", "install XProtect/malware definitions"),
    ] {
        if get(key) == Some(false) {
            off.push(what);
        }
    }
    let src = if managed.is_some() {
        " (MDM-managed)"
    } else {
        ""
    };
    if off.is_empty() {
        vital(r, "Security updates", &format!("automatic{src}"), None);
    } else {
        vital(
            r,
            "Security updates",
            &format!("OFF: {}{src}", off.join(", ")),
            Some(Severity::Medium),
        );
        r.findings.push(finding(
            "sec.auto_updates_off",
            Severity::Medium,
            &format!("Automatic security updates are off: {}", off.join(", ")),
            &format!(
                "Apple ships XProtect definitions and Rapid Security Responses silently in the \
                 background; with these off the Mac falls behind on malware protection.{}",
                if managed.is_some() {
                    " A managed SoftwareUpdate profile is present, so the MDM may be enforcing this."
                } else {
                    ""
                }
            ),
            Some("System Settings ▸ General ▸ Software Update ▸ Automatic Updates ▸ turn on \
                  'Install Security Responses and system files'."),
        ));
    }
    if let Some(aa) = plist_dict(&format!(
        "{MANAGED_PREFS}/com.apple.applicationaccess.plist"
    )) {
        let forced = plist_bool(&aa, "forceDelayedSoftwareUpdates").unwrap_or(false)
            || plist_bool(&aa, "forceDelayedMajorSoftwareUpdates").unwrap_or(false);
        if forced {
            let days = aa
                .get("enforcedSoftwareUpdateDelay")
                .and_then(|v| v.as_signed_integer())
                .map(|d| format!("{d} days"))
                .unwrap_or_else(|| "an MDM-set delay".into());
            r.findings.push(finding(
                "sec.update_deferred",
                Severity::Info,
                &format!("MDM is deferring software updates ({days})"),
                "The MDM restriction profile hides new macOS updates for a period after \
                 release. This explains 'my Mac says it's up to date but it isn't'.",
                Some("Nothing to fix locally — ask the Jamf admin if you need an update sooner."),
            ));
        }
    }
}

// ── screen lock / login window ──────────────────────────────────────────────

/// Parse `sysadminctl -screenLock status` (printed on stderr): "screenLock delay
/// is immediate", "screenLock delay is 300 seconds", or "screenLock is off".
/// Returns Some(delay seconds), None for off, Err for unparseable.
pub fn parse_screen_lock(out: &str) -> Result<Option<u64>, ()> {
    let l = out.to_lowercase();
    if l.contains("screenlock is off") {
        return Ok(None);
    }
    if l.contains("delay is immediate") {
        return Ok(Some(0));
    }
    if let Some(rest) = l.split("delay is ").nth(1) {
        if let Some(n) = rest.split_whitespace().next().and_then(|n| n.parse().ok()) {
            return Ok(Some(n));
        }
    }
    Err(())
}

fn screen_lock(r: &mut SecurityResult, root: bool) {
    // The setting is per-user; under sudo, ask for the invoking user.
    let sudo_user = std::env::var("SUDO_USER").ok();
    let out = match (root, sudo_user.as_deref()) {
        (true, Some(u)) => run_all(
            "/usr/bin/sudo",
            &["-u", u, "/usr/sbin/sysadminctl", "-screenLock", "status"],
        ),
        _ => run_all("/usr/sbin/sysadminctl", &["-screenLock", "status"]),
    }
    .unwrap_or_default();
    match parse_screen_lock(&out) {
        Ok(Some(0)) => vital(r, "Screen lock", "password immediately", None),
        Ok(Some(s)) if s <= 300 => vital(r, "Screen lock", &format!("password after {s}s"), None),
        Ok(Some(s)) => {
            vital(
                r,
                "Screen lock",
                &format!("password after {s}s"),
                Some(Severity::Low),
            );
            r.findings.push(finding(
                "sec.screen_lock_weak",
                Severity::Low,
                &format!(
                    "Screen lock waits {} before requiring a password",
                    crate::util::human_duration(s)
                ),
                "Anyone who opens the lid within that window gets in without a password.",
                Some(
                    "System Settings ▸ Lock Screen ▸ 'Require password after screen saver \
                      begins or display is turned off' ▸ Immediately.",
                ),
            ));
        }
        Ok(None) => {
            vital(r, "Screen lock", "OFF", Some(Severity::Medium));
            r.findings.push(finding(
                "sec.screen_lock_weak",
                Severity::Medium,
                "No password is required to wake the Mac",
                "Waking from sleep or the screen saver goes straight to the desktop.",
                Some("System Settings ▸ Lock Screen ▸ require password Immediately."),
            ));
        }
        Err(()) => vital(r, "Screen lock", "unknown", Some(Severity::Info)),
    }
}

fn login_window(r: &mut SecurityResult) {
    let d = plist_dict("/Library/Preferences/com.apple.loginwindow.plist").unwrap_or_default();
    if let Some(user) = d.get("autoLoginUser").and_then(|v| v.as_string()) {
        r.findings.push(finding(
            "sec.autologin_on",
            Severity::High,
            &format!("Automatic login is ON (user: {user})"),
            "Anyone who powers on the Mac lands in this account with no password. It also \
             means FileVault is off or bypassed at boot.",
            Some("System Settings ▸ Users & Groups ▸ Automatically log in as ▸ Off."),
        ));
    }
    if plist_bool(&d, "GuestEnabled") == Some(true) {
        r.findings.push(finding(
            "sec.guest_enabled",
            Severity::Low,
            "Guest account is enabled",
            "Anyone can log in as Guest without a password.",
            Some("System Settings ▸ Users & Groups ▸ Guest User ▸ off."),
        ));
    }
}

// ── MDM / Jamf ──────────────────────────────────────────────────────────────

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Enrollment {
    pub enrolled: Option<bool>,
    pub user_approved: bool,
    pub dep: Option<bool>,
    pub server: Option<String>,
}

/// Parse `profiles status -type enrollment`.
pub fn parse_enrollment(out: &str) -> Enrollment {
    let mut e = Enrollment::default();
    for l in out.lines() {
        let Some((k, v)) = l.split_once(':') else {
            continue;
        };
        let v = v.trim();
        match k.trim() {
            "MDM enrollment" => {
                e.enrolled = Some(v.starts_with("Yes"));
                e.user_approved = v.contains("User Approved");
            }
            "Enrolled via DEP" => e.dep = Some(v.starts_with("Yes")),
            "MDM server" => e.server = Some(v.to_string()),
            _ => {}
        }
    }
    e
}

fn mdm(r: &mut SecurityResult, root: bool) {
    let (out, timed_out) = run_with_timeout(
        "/usr/bin/profiles",
        &["status", "-type", "enrollment"],
        Duration::from_secs(20),
    );
    let e = parse_enrollment(&out);
    match e.enrolled {
        None => {
            vital(r, "MDM", "unknown", Some(Severity::Info));
            r.skipped.push(Skipped {
                what: "MDM enrollment status".into(),
                reason: if timed_out {
                    "profiles timed out".into()
                } else {
                    "unreadable output".into()
                },
            });
        }
        Some(false) => vital(r, "MDM", "not enrolled", None),
        Some(true) => {
            let host = e
                .server
                .as_deref()
                .and_then(|s| s.split("//").nth(1))
                .and_then(|s| s.split(['/', ':']).next())
                .unwrap_or("unknown server");
            let mode = match (e.dep, e.user_approved) {
                (Some(true), _) => "DEP",
                (_, true) => "user-approved",
                _ => "NOT user-approved",
            };
            let flag = (!e.user_approved && e.dep != Some(true)).then_some(Severity::Medium);
            vital(r, "MDM", &format!("{host} ({mode})"), flag);
            if flag.is_some() {
                r.findings.push(finding(
                    "sec.mdm_not_approved",
                    Severity::Medium,
                    "MDM enrollment is not user-approved",
                    "Without user approval macOS silently ignores kernel/system-extension, \
                     PPPC (privacy) and several security payloads — so settings the Jamf admin \
                     thinks are applied may not be.",
                    Some(
                        "System Settings ▸ Privacy & Security ▸ Profiles ▸ approve the MDM \
                          profile, or ask the Jamf admin to re-enroll.",
                    ),
                ));
            }
        }
    }
    if e.enrolled != Some(true) {
        return;
    }
    if !root {
        r.skipped.push(Skipped {
            what: "Bootstrap Token escrow".into(),
            reason: "requires sudo".into(),
        });
        return;
    }
    let (bt, timed_out) = run_with_timeout(
        "/usr/bin/profiles",
        &["status", "-type", "bootstraptoken"],
        Duration::from_secs(20),
    );
    if bt.contains("escrowed to server: NO") {
        vital(r, "Bootstrap Token", "NOT escrowed", Some(Severity::Medium));
        r.findings.push(finding(
            "sec.bootstrap_token",
            Severity::Medium,
            "Bootstrap Token is not escrowed to the MDM",
            "The MDM can't grant SecureTokens to new accounts, authorize OS updates on Apple \
             silicon, or install kernel extensions without a user at the keyboard.",
            Some(
                "Log in once as a SecureToken admin, then `sudo profiles install -type \
                  bootstraptoken`.",
            ),
        ));
    } else if bt.contains("escrowed to server: YES") {
        vital(r, "Bootstrap Token", "escrowed", None);
    } else {
        vital(r, "Bootstrap Token", "unknown", Some(Severity::Info));
        r.skipped.push(Skipped {
            what: "Bootstrap Token escrow".into(),
            reason: if timed_out {
                "profiles timed out".into()
            } else {
                "unreadable output".into()
            },
        });
    }
}

fn jamf(r: &mut SecurityResult, root: bool) {
    let daemons: Vec<_> = std::fs::read_dir("/Library/LaunchDaemons")
        .map(|d| d.flatten().map(|e| e.path()).collect())
        .unwrap_or_else(|_| Vec::new())
        .into_iter()
        .filter(|p: &std::path::PathBuf| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("com.jamf"))
        })
        .collect();
    let has_bin = Path::new(JAMF_BIN).exists();
    if daemons.is_empty() && !has_bin {
        return; // not a Jamf Mac
    }
    let broken: Vec<String> = daemons
        .iter()
        .filter_map(|p| crate::audit::parse_launch_plist(p))
        .filter(|i| i.exec_missing)
        .map(|i| format!("{} → {}", i.label, i.exec.unwrap_or_default()))
        .collect();
    if !has_bin || !broken.is_empty() {
        let mut f = finding(
            "sec.jamf_broken",
            Severity::Medium,
            "Jamf management framework is damaged",
            "Jamf LaunchDaemons are present but the jamf binary or the programs they launch \
             are missing, so policies, inventory and self-service are silently failing.",
            Some(
                "Re-enroll from the Jamf enrollment URL, or ask the Jamf admin to push \
                  `jamf manage` / reinstall the framework.",
            ),
        );
        if !has_bin {
            f.evidence.push(Evidence {
                source: JAMF_BIN.into(),
                excerpt: "missing".into(),
            });
        }
        for b in &broken {
            f.evidence.push(Evidence {
                source: "LaunchDaemon".into(),
                excerpt: b.clone(),
            });
        }
        r.findings.push(f);
    }
    if !has_bin {
        vital(r, "Jamf framework", "MISSING", Some(Severity::Medium));
        return;
    }
    if !root {
        vital(
            r,
            "Jamf framework",
            "installed (server check needs sudo)",
            None,
        );
        r.skipped.push(Skipped {
            what: "Jamf server connectivity (jamf checkJSSConnection)".into(),
            reason: "requires sudo".into(),
        });
        return;
    }
    let (out, timed_out) = run_with_timeout(
        JAMF_BIN,
        &["checkJSSConnection", "-retry", "0"],
        Duration::from_secs(25),
    );
    if out.contains("is available") {
        vital(r, "Jamf framework", "installed, server reachable", None);
    } else {
        vital(
            r,
            "Jamf framework",
            "server UNREACHABLE",
            Some(Severity::Low),
        );
        let mut f = finding(
            "sec.jamf_unreachable",
            Severity::Low,
            "Jamf framework can't reach its server",
            "Policies and inventory won't run until it can. Normal off the corporate network \
             without VPN if the Jamf server is internal-only.",
            Some("Retry on the organisation's network or VPN: `sudo jamf checkJSSConnection`."),
        );
        f.evidence.push(Evidence {
            source: "jamf checkJSSConnection".into(),
            excerpt: if timed_out {
                "timed out after 25s".into()
            } else {
                out.lines().last().unwrap_or("").trim().to_string()
            },
        });
        r.findings.push(f);
    }
}

/// Payload types worth calling out: these are the ones that explain "a setting
/// won't stick", a privacy prompt that never appears, or traffic going somewhere
/// unexpected.
const NOTABLE_PAYLOADS: &[(&str, &str)] = &[
    (
        "com.apple.TCC.configuration-profile-policy",
        "privacy (PPPC) grants",
    ),
    ("com.apple.system-extension-policy", "system extensions"),
    ("com.apple.webcontent-filter", "content filter"),
    ("com.apple.dnsSettings.managed", "DNS settings"),
    ("com.apple.wifi.managed", "Wi-Fi"),
    ("com.apple.security.firewall", "firewall"),
    ("com.apple.security.root", "root certificate"),
    ("com.apple.security.pkcs1", "certificate"),
    ("com.apple.security.pkcs12", "identity certificate"),
    ("com.apple.vpn.managed", "VPN"),
    ("com.apple.proxy.http.global", "global proxy"),
    ("com.apple.applicationaccess", "restrictions"),
    ("com.apple.servicemanagement", "managed login items"),
    ("com.apple.screensharing", "screen sharing"),
    ("com.apple.SoftwareUpdate", "software update"),
    ("com.apple.MCX.FileVault2", "FileVault"),
    ("com.apple.loginwindow", "login window"),
];

#[derive(Debug, PartialEq, Eq)]
pub struct ProfileInfo {
    pub scope: String,
    pub name: String,
    pub payload_types: Vec<String>,
}

/// Parse `profiles show -output stdout-xml`: {scope: [ {ProfileDisplayName,
/// ProfileItems: [{PayloadType}]} ]}. Scope is a username or `_computerlevel`.
pub fn parse_profiles_xml(xml: &str) -> Vec<ProfileInfo> {
    let Ok(v) = plist::Value::from_reader_xml(xml.as_bytes()) else {
        return Vec::new();
    };
    let Some(top) = v.as_dictionary() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (scope, list) in top {
        for p in list.as_array().map(|a| a.as_slice()).unwrap_or(&[]) {
            let Some(d) = p.as_dictionary() else { continue };
            let name = d
                .get("ProfileDisplayName")
                .and_then(|n| n.as_string())
                .unwrap_or("(unnamed)")
                .to_string();
            let payload_types = d
                .get("ProfileItems")
                .and_then(|i| i.as_array())
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|i| i.as_dictionary()?.get("PayloadType")?.as_string())
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();
            out.push(ProfileInfo {
                scope: scope.clone(),
                name,
                payload_types,
            });
        }
    }
    out
}

fn profiles(r: &mut SecurityResult, root: bool) {
    let (xml, timed_out) = profiles_show();
    let (xml, timed_out) = (xml.as_str(), *timed_out);
    let list = parse_profiles_xml(xml);
    if !root {
        r.skipped.push(Skipped {
            what: "computer-level configuration profiles".into(),
            reason: "requires sudo — only this user's profiles were read".into(),
        });
    }
    if list.is_empty() {
        if timed_out {
            r.skipped.push(Skipped {
                what: "configuration profile inventory".into(),
                reason: "profiles timed out".into(),
            });
        }
        return;
    }
    let mut notable: Vec<&str> = Vec::new();
    for p in &list {
        for t in &p.payload_types {
            for (prefix, label) in NOTABLE_PAYLOADS {
                if t.starts_with(prefix) && !notable.contains(label) {
                    notable.push(label);
                }
            }
        }
    }
    let mut f = finding(
        "sec.profile_inventory",
        Severity::Info,
        &format!(
            "{} configuration profile(s) installed{}",
            list.len(),
            if notable.is_empty() {
                String::new()
            } else {
                format!(" — they control: {}", notable.join(", "))
            }
        ),
        "Every setting a profile controls is locked: changing it locally either fails or is \
         reverted on the next MDM check-in. When something 'won't stick', look here first.",
        Some(
            "Full contents: `sudo profiles show -output stdout-xml`, or System Settings ▸ \
              General ▸ Device Management.",
        ),
    );
    for p in &list {
        f.evidence.push(Evidence {
            source: format!("profile ({})", p.scope),
            excerpt: format!("{}: {}", p.name, p.payload_types.join(", ")),
        });
    }
    r.findings.push(f);
}

/// `allow*` restriction keys the MDM set to false, from the managed
/// com.apple.applicationaccess preferences (readable without root).
pub fn disabled_restrictions(d: &plist::Dictionary) -> Vec<String> {
    let mut out: Vec<String> = d
        .keys()
        .filter(|k| k.starts_with("allow") && plist_bool(d, k) == Some(false))
        .map(|k| k.trim_start_matches("allow").to_string())
        .collect();
    out.sort();
    out
}

fn managed_restrictions(r: &mut SecurityResult) {
    let Ok(dir) = std::fs::read_dir(MANAGED_PREFS) else {
        return;
    };
    let mut domains: Vec<String> = dir
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            n.strip_suffix(".plist").map(String::from)
        })
        .collect();
    domains.sort();
    if domains.is_empty() {
        return;
    }
    let mut f = finding(
        "sec.managed_prefs",
        Severity::Info,
        &format!("MDM is enforcing {} preference domain(s)", domains.len()),
        "These are the settings the MDM has actually applied on this Mac (from /Library/Managed \
         Preferences). Anything listed here overrides what you set in System Settings.",
        None,
    );
    f.evidence.push(Evidence {
        source: MANAGED_PREFS.into(),
        excerpt: domains.join(", "),
    });
    if let Some(aa) = plist_dict(&format!(
        "{MANAGED_PREFS}/com.apple.applicationaccess.plist"
    )) {
        let off = disabled_restrictions(&aa);
        if !off.is_empty() {
            f.evidence.push(Evidence {
                source: "restrictions (allow* = false)".into(),
                excerpt: off.join(", "),
            });
        }
    }
    if let Some(tcc) = plist_dict(&format!(
        "{MANAGED_PREFS}/com.apple.TCC.configuration-profile-policy.plist"
    )) {
        let services = tcc_services(&tcc);
        if !services.is_empty() {
            f.evidence.push(Evidence {
                source: "PPPC privacy grants (service × apps)".into(),
                excerpt: services.join(", "),
            });
        }
    }
    r.findings.push(f);
}

/// Count PPPC entries per TCC service in the managed TCC policy plist.
fn tcc_services(d: &plist::Dictionary) -> Vec<String> {
    let mut counts: std::collections::BTreeMap<String, usize> = Default::default();
    fn walk(v: &plist::Value, counts: &mut std::collections::BTreeMap<String, usize>) {
        match v {
            plist::Value::Dictionary(d) => {
                if let Some(svc) = d.get("Services").and_then(|s| s.as_dictionary()) {
                    for (name, apps) in svc {
                        *counts.entry(name.clone()).or_default() +=
                            apps.as_array().map(|a| a.len()).unwrap_or(1);
                    }
                }
                for (_, child) in d {
                    walk(child, counts);
                }
            }
            plist::Value::Array(a) => a.iter().for_each(|c| walk(c, counts)),
            _ => {}
        }
    }
    walk(&plist::Value::Dictionary(d.clone()), &mut counts);
    counts
        .into_iter()
        .map(|(k, n)| format!("{k} ×{n}"))
        .collect()
}

// ── certificates, admins, extensions ────────────────────────────────────────

/// Certificate names from `security dump-trust-settings -d` (admin domain):
/// certificates whose trust an administrator or profile explicitly set.
pub fn parse_trust_settings(out: &str) -> Vec<String> {
    out.lines()
        .filter_map(|l| {
            let t = l.trim();
            let rest = t.strip_prefix("Cert ")?;
            let (idx, name) = rest.split_once(':')?;
            idx.trim().parse::<u32>().ok()?;
            Some(name.trim().to_string())
        })
        .collect()
}

/// Is this admin-trusted certificate the Jamf built-in CA? Jamf names it
/// "<Org> JSS Built-in Certificate Authority" — the whole phrase, not merely
/// "jamf" or "JSS" somewhere in the name — and it only counts on a Mac that
/// actually carries the Jamf framework.
pub fn jamf_ca_expected(name: &str, jamf_present: bool) -> bool {
    jamf_present && name.trim().ends_with("JSS Built-in Certificate Authority")
}

/// Decode one PEM certificate block (as `security find-certificate -p` prints
/// it) to DER bytes. Returns None when there is no block or the base64 is bad.
pub fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    let mut inside = false;
    let mut bits: u32 = 0;
    let mut nbits = 0;
    let mut out = Vec::new();
    let mut saw_block = false;
    for l in pem.lines() {
        let l = l.trim();
        if l.starts_with("-----BEGIN") {
            inside = true;
            saw_block = true;
            continue;
        }
        if l.starts_with("-----END") {
            break;
        }
        if !inside {
            continue;
        }
        for c in l.bytes() {
            let v = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' => break,
                _ => return None,
            };
            bits = (bits << 6) | v as u32;
            nbits += 6;
            if nbits >= 8 {
                nbits -= 8;
                out.push((bits >> nbits) as u8);
                bits &= (1 << nbits) - 1;
            }
        }
    }
    (saw_block && !out.is_empty()).then_some(out)
}

/// DER bytes of every certificate payload in `profiles show -output stdout-xml`
/// (root / pkcs1 / pem payloads carry the certificate in PayloadContent).
pub fn profile_cert_ders(xml: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let Ok(v) = plist::Value::from_reader_xml(xml.as_bytes()) else {
        return out;
    };
    fn walk(v: &plist::Value, out: &mut Vec<Vec<u8>>) {
        match v {
            plist::Value::Dictionary(d) => {
                let ty = d
                    .get("PayloadType")
                    .and_then(|t| t.as_string())
                    .unwrap_or("");
                if ty.starts_with("com.apple.security.root")
                    || ty.starts_with("com.apple.security.pkcs1")
                    || ty.starts_with("com.apple.security.pem")
                {
                    match d.get("PayloadContent") {
                        Some(plist::Value::Data(b)) => out.push(b.clone()),
                        Some(plist::Value::String(s)) => {
                            if let Some(der) = pem_to_der(s) {
                                out.push(der);
                            }
                        }
                        _ => {}
                    }
                }
                d.values().for_each(|c| walk(c, out));
            }
            plist::Value::Array(a) => a.iter().for_each(|c| walk(c, out)),
            _ => {}
        }
    }
    walk(&v, &mut out);
    out
}

/// (SHA-256, DER) of every certificate in `security find-certificate -a -Z -p`
/// output, where a `SHA-256 hash:` line precedes each PEM block.
pub fn parse_keychain_certs(out: &str) -> Vec<(String, Vec<u8>)> {
    let mut certs = Vec::new();
    let (mut sha, mut pem) = (String::new(), String::new());
    for l in out.lines() {
        if let Some(h) = l.strip_prefix("SHA-256 hash:") {
            sha = h.trim().to_string();
        } else if l.starts_with("-----BEGIN") || !pem.is_empty() {
            pem.push_str(l);
            pem.push('\n');
            if l.starts_with("-----END") {
                if let Some(der) = pem_to_der(&pem) {
                    certs.push((std::mem::take(&mut sha), der));
                }
                pem.clear();
            }
        }
    }
    certs
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AdminTrust {
    /// Named like the Jamf CA, and every System keychain certificate found by
    /// that name is one an installed profile delivered.
    JamfVerified,
    /// Named like the Jamf CA, but not shown to come from a profile.
    JamfUnverified,
    /// Any other certificate: a possible TLS-inspection root.
    Other,
}

/// Classify one admin-trusted certificate. `keychain_ders` are the System
/// keychain certificates matching its name (a substring search, so all of
/// them must match). With no profile certificates to compare, a Jamf-named
/// certificate stays unverified.
pub fn classify_admin_cert(
    name: &str,
    jamf_present: bool,
    keychain_ders: &[Vec<u8>],
    profile_ders: &[Vec<u8>],
) -> AdminTrust {
    if !jamf_ca_expected(name, jamf_present) {
        AdminTrust::Other
    } else if !keychain_ders.is_empty() && keychain_ders.iter().all(|d| profile_ders.contains(d)) {
        AdminTrust::JamfVerified
    } else {
        AdminTrust::JamfUnverified
    }
}

/// Certificate names from `security dump-trust-settings` output, or None when
/// the command failed. "No Trust Settings were found" is an empty list.
pub fn parse_trust_output(out: &str) -> Option<Vec<String>> {
    if out.contains("Number of trusted certs") {
        Some(parse_trust_settings(out))
    } else if out.contains("No Trust Settings were found") {
        Some(Vec::new())
    } else {
        None
    }
}

fn trust_unknown(r: &mut SecurityResult, label: &str, what: &str) {
    vital(r, label, "unknown", Some(Severity::Info));
    r.skipped.push(Skipped {
        what: what.into(),
        reason: "security dump-trust-settings failed — trust NOT verified".into(),
    });
}

fn trusted_certs(r: &mut SecurityResult, root: bool) {
    let out = run_all("/usr/bin/security", &["dump-trust-settings", "-d"]);
    match out.as_deref().and_then(parse_trust_output) {
        None => trust_unknown(r, "Admin-trusted certs", "admin-domain certificate trust"),
        Some(certs) if certs.is_empty() => vital(r, "Admin-trusted certs", "none", None),
        Some(certs) => admin_trust(r, root, &certs),
    }
    user_trust(r, root);
}

fn admin_trust(r: &mut SecurityResult, root: bool, certs: &[String]) {
    // The Jamf built-in CA is required for Jamf itself; anything else can be
    // a TLS-inspection root that can read HTTPS traffic. A cert is only
    // "the Jamf CA" by Jamf's exact naming on a Jamf-enrolled Mac, and it
    // must also be the certificate an installed profile delivered.
    let jamf_present = Path::new(JAMF_BIN).exists();
    let profile_ders = if root {
        profile_cert_ders(profiles_xml())
    } else {
        Vec::new()
    };
    let mut jamf: Vec<String> = Vec::new();
    let mut unverified: Vec<String> = Vec::new();
    let mut other: Vec<String> = Vec::new();
    for c in certs {
        let keychain = if profile_ders.is_empty() || !jamf_ca_expected(c, jamf_present) {
            Vec::new()
        } else {
            system_keychain_certs(c)
        };
        let ders: Vec<Vec<u8>> = keychain.iter().map(|(_, d)| d.clone()).collect();
        match classify_admin_cert(c, jamf_present, &ders, &profile_ders) {
            AdminTrust::JamfVerified => jamf.push(c.clone()),
            AdminTrust::JamfUnverified => {
                let hashes: Vec<&str> = keychain
                    .iter()
                    .filter(|(_, d)| !profile_ders.contains(d))
                    .map(|(h, _)| h.as_str())
                    .collect();
                unverified.push(if hashes.is_empty() {
                    c.clone()
                } else {
                    format!("{c} (SHA-256 {})", hashes.join(", "))
                });
            }
            AdminTrust::Other => other.push(c.clone()),
        }
    }
    let jamf_label = "expected (Jamf CA, matches an installed profile's certificate payload)";
    let unverified_label = if !root {
        "Jamf-named, not matched to a profile (needs sudo)"
    } else if profile_ders.is_empty() {
        "Jamf-named, no installed profile delivers a certificate"
    } else {
        "Jamf-named, NOT in any profile payload"
    };
    vital(r, "Admin-trusted certs", &certs.join(", "), None);
    let sev = if !other.is_empty() {
        Severity::Medium
    } else if !unverified.is_empty() {
        Severity::Low
    } else {
        Severity::Info
    };
    let mut f = finding(
        "sec.custom_trust",
        sev,
        &format!("{} certificate(s) have admin-set trust", certs.len()),
        &format!(
            "Certificates trusted outside Apple's store can sign ANY website's certificate, \
                 so whoever holds the key can read this Mac's HTTPS traffic. {}{}{}",
            if jamf.is_empty() {
                ""
            } else {
                "The Jamf (JSS) CA is expected on a Jamf-managed Mac. "
            },
            match (unverified.is_empty(), root) {
                (true, _) => "",
                (false, true) => {
                    "A certificate is named like the Jamf CA but does not match any \
                         certificate an installed profile delivered — confirm it with the Jamf \
                         admin. "
                }
                (false, false) => {
                    "A certificate is named like the Jamf CA; without sudo it can't be \
                         matched to the certificate an installed profile delivered. "
                }
            },
            if other.is_empty() {
                ""
            } else {
                "The others need an owner: a corporate firewall's TLS-inspection CA is \
                     legitimate on managed networks; an unknown one is a red flag."
            }
        ),
        Some(
            "Inspect in Keychain Access ▸ System ▸ Certificates (look for the blue '+' \
                  trust icon). Don't delete MDM-installed certs — Jamf will break.",
        ),
    );
    f.evidence.push(Evidence {
        source: "security dump-trust-settings -d".into(),
        excerpt: certs.join(" · "),
    });
    for (label, list) in [
        (jamf_label, &jamf),
        (unverified_label, &unverified),
        ("needs an owner", &other),
    ] {
        if !list.is_empty() {
            f.evidence.push(Evidence {
                source: label.into(),
                excerpt: list.join(" · "),
            });
        }
    }
    if !root {
        f.evidence.push(Evidence {
            source: "note".into(),
            excerpt: "run with sudo to match the Jamf CA against the installed profile".into(),
        });
    }
    r.findings.push(f);
}

/// System keychain certificates whose name contains `name` (the search is a
/// substring match), as (SHA-256, DER).
fn system_keychain_certs(name: &str) -> Vec<(String, Vec<u8>)> {
    let out = run(
        "/usr/bin/security",
        &[
            "find-certificate",
            "-a",
            "-Z",
            "-p",
            "-c",
            name,
            "/Library/Keychains/System.keychain",
        ],
    );
    parse_keychain_certs(&out.unwrap_or_default())
}

fn user_trust(r: &mut SecurityResult, root: bool) {
    // User domain: trust the user set by clicking "Always Trust". Per-user,
    // so under sudo ask for the invoking user, not root.
    let sudo_user = std::env::var("SUDO_USER").ok();
    let (user_out, who) = match (root, sudo_user.as_deref()) {
        (true, Some(u)) => (
            run_all(
                "/usr/bin/sudo",
                &["-u", u, "/usr/bin/security", "dump-trust-settings"],
            ),
            u.to_string(),
        ),
        _ => (
            run_all("/usr/bin/security", &["dump-trust-settings"]),
            std::env::var("USER").unwrap_or_else(|_| "this user".into()),
        ),
    };
    let Some(user_certs) = user_out.as_deref().and_then(parse_trust_output) else {
        trust_unknown(r, "User-trusted certs", "user-domain certificate trust");
        return;
    };
    if user_certs.is_empty() {
        vital(r, "User-trusted certs", "none", None);
        return;
    }
    vital(
        r,
        "User-trusted certs",
        &user_certs.join(", "),
        Some(Severity::Low),
    );
    let mut f = finding(
        "sec.custom_trust",
        Severity::Low,
        &format!(
            "{} certificate(s) have user-set trust ({who})",
            user_certs.len()
        ),
        "These were trusted from this account's login keychain (an 'Always Trust' click or a \
         tool that wrote trust settings). A trusted leaf certificate only vouches for one \
         server; a trusted CA lets its owner impersonate any site for this user. Both are \
         invisible to the admin-domain check above.",
        Some(
            "Keychain Access ▸ login ▸ Certificates: open each one, expand Trust. Set a \
              certificate you don't recognise back to 'Use System Defaults'.",
        ),
    );
    f.evidence.push(Evidence {
        source: "security dump-trust-settings (user domain)".into(),
        excerpt: user_certs.join(" · "),
    });
    r.findings.push(f);
}

/// `profiles show -output stdout-xml`, fetched once per run. Empty when it
/// timed out or ran unprivileged on a Mac with only computer-level profiles.
fn profiles_xml() -> &'static str {
    &profiles_show().0
}

/// (xml, timed_out) from one `profiles show` per run; three checks read it.
fn profiles_show() -> &'static (String, bool) {
    static XML: std::sync::OnceLock<(String, bool)> = std::sync::OnceLock::new();
    XML.get_or_init(|| {
        run_with_timeout(
            "/usr/bin/profiles",
            &["show", "-output", "stdout-xml"],
            Duration::from_secs(30),
        )
    })
}

fn admins(r: &mut SecurityResult) {
    let out = run(
        "/usr/bin/dscl",
        &[".", "-read", "/Groups/admin", "GroupMembership"],
    )
    .unwrap_or_default();
    let members: Vec<String> = out
        .split_whitespace()
        .skip(1) // "GroupMembership:"
        .filter(|m| *m != "root")
        .map(String::from)
        .collect();
    if members.is_empty() {
        return;
    }
    let mut hidden = Vec::new();
    for m in &members {
        let rec = run(
            "/usr/bin/dscl",
            &[".", "-read", &format!("/Users/{m}"), "UniqueID", "IsHidden"],
        )
        .unwrap_or_default();
        let uid: Option<u32> = rec
            .lines()
            .find_map(|l| l.strip_prefix("UniqueID:"))
            .and_then(|v| v.trim().parse().ok());
        let is_hidden = rec.lines().any(|l| l.trim() == "IsHidden: 1");
        if is_hidden || uid.is_some_and(|u| u < 500) {
            hidden.push(m.clone());
        }
    }
    vital(r, "Admin accounts", &members.join(", "), None);
    let mut f = finding(
        "sec.admin_accounts",
        Severity::Info,
        &format!("{} admin account(s): {}", members.len(), members.join(", ")),
        &format!(
            "Every admin can install software, change security settings, and read other \
             users' files with sudo.{}",
            if hidden.is_empty() {
                String::new()
            } else {
                format!(
                    " Hidden admin(s): {} — a hidden `jamf`/management account is normal for \
                     Jamf; any other hidden admin should be explained.",
                    hidden.join(", ")
                )
            }
        ),
        None,
    );
    if hidden
        .iter()
        .any(|h| !h.to_lowercase().contains("jamf") && !h.starts_with('_'))
    {
        f.severity = Severity::Low;
    }
    r.findings.push(f);
}

/// Active network / endpoint-security system extensions from
/// `systemextensionsctl list`, as "name (team)".
pub fn parse_sysext_security(out: &str) -> Vec<String> {
    let mut section_relevant = false;
    let mut found = Vec::new();
    for l in out.lines() {
        if l.starts_with("--- ") {
            section_relevant = l.contains("network_extension") || l.contains("endpoint_security");
            continue;
        }
        if !section_relevant || !l.contains("[activated enabled]") {
            continue;
        }
        let cols: Vec<&str> = l.split('\t').collect();
        if cols.len() >= 6 {
            let name = cols[4].trim();
            found.push(format!("{name} ({})", cols[2].trim()));
        }
    }
    found
}

fn extensions(r: &mut SecurityResult) {
    let (out, _) = run_with_timeout(
        "/usr/bin/systemextensionsctl",
        &["list"],
        Duration::from_secs(15),
    );
    let found = parse_sysext_security(&out);
    if found.is_empty() {
        return;
    }
    let mut f = finding(
        "sec.traffic_extensions",
        Severity::Info,
        &format!(
            "{} network/endpoint-security extension(s) active",
            found.len()
        ),
        "These can see or redirect network traffic (VPNs, proxies, content filters) or watch \
         every process (EDR/antivirus). Expected ones are fine; they are also the usual cause \
         of 'internet broken only on this Mac' and of crash-looping security agents.",
        Some(
            "Review in System Settings ▸ General ▸ Login Items & Extensions ▸ Network / \
              Endpoint Security Extensions.",
        ),
    );
    f.evidence.push(Evidence {
        source: "systemextensionsctl list".into(),
        excerpt: found.join(" · "),
    });
    r.findings.push(f);
}

/// `sec.profile_inventory` lists every profile and its payloads, so the older
/// `posture.mdm_profiles` count is redundant when both ran.
pub fn supersede_profile_count(existing: &mut Vec<Finding>, new: &[Finding]) {
    if new.iter().any(|f| f.rule_id == "sec.profile_inventory") {
        existing.retain(|f| f.rule_id != "posture.mdm_profiles");
    }
}

// ── updates, boot arguments, launch daemons, MDM drift, SSH, Jamf check-in ──

const JAMF_LOG: &str = "/var/log/jamf.log";
/// jamf.log grows without bound; the newest 2 MB covers weeks of check-ins.
const JAMF_LOG_TAIL: u64 = 2 << 20;

/// The tail of jamf.log, read once per run. None when absent or unreadable.
fn jamf_log() -> Option<&'static str> {
    static LOG: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    LOG.get_or_init(|| {
        use std::io::{Read, Seek, SeekFrom};
        let mut f = std::fs::File::open(JAMF_LOG).ok()?;
        let start = f.metadata().ok()?.len().saturating_sub(JAMF_LOG_TAIL);
        f.seek(SeekFrom::Start(start)).ok()?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).ok()?;
        let text = String::from_utf8_lossy(&buf).into_owned();
        // Drop the partial first line when the read started mid-file.
        Some(match (start > 0, text.split_once('\n')) {
            (true, Some((_, rest))) => rest.to_string(),
            _ => text,
        })
    })
    .as_deref()
}

fn jamf_log_mentions(needle: &str) -> bool {
    jamf_log().is_some_and(|t| t.contains(needle))
}

fn age_days(d: plist::Date) -> i64 {
    let t: std::time::SystemTime = d.into();
    (chrono::Utc::now() - chrono::DateTime::<chrono::Utc>::from(t)).num_days()
}

/// Pending updates from the Software Update cache. An empty list only counts
/// as "patched" when the last successful scan is recent.
fn pending_updates(r: &mut SecurityResult) {
    let Some(d) = plist_dict("/Library/Preferences/com.apple.SoftwareUpdate.plist") else {
        r.skipped.push(Skipped {
            what: "pending software updates".into(),
            reason: "com.apple.SoftwareUpdate.plist unreadable".into(),
        });
        return;
    };
    let scan_age = d
        .get("LastSuccessfulDate")
        .or_else(|| d.get("LastFullSuccessfulDate"))
        .and_then(|v| v.as_date())
        .map(age_days);
    let offers = d
        .get("FirstOfferDateDictionary")
        .and_then(|v| v.as_dictionary());
    let pending: Vec<(String, Option<i64>)> = d
        .get("RecommendedUpdates")
        .and_then(|v| v.as_array())
        .map(|a| a.as_slice())
        .unwrap_or(&[])
        .iter()
        .filter_map(|u| {
            let u = u.as_dictionary()?;
            let name = u
                .get("Display Name")
                .or_else(|| u.get("Identifier"))
                .and_then(|v| v.as_string())
                .unwrap_or("(unnamed update)");
            let ver = u
                .get("Display Version")
                .and_then(|v| v.as_string())
                .unwrap_or("");
            let key = u.get("Product Key").and_then(|v| v.as_string());
            let offered = key.and_then(|k| offers?.get(k)?.as_date()).map(age_days);
            Some((format!("{name} {ver}").trim().to_string(), offered))
        })
        .collect();

    match scan_age {
        Some(a) if a > 14 => {
            vital(
                r,
                "Update scan",
                &format!("last success {a} days ago"),
                Some(Severity::Medium),
            );
            r.findings.push(finding(
                "sec.update_scan_stale",
                Severity::Medium,
                &format!("Software Update hasn't completed a scan in {a} days"),
                "With no recent scan, 'no updates pending' proves nothing — the Mac may be \
                 missing security fixes it simply hasn't heard about.",
                Some(
                    "System Settings ▸ General ▸ Software Update (forces a scan). If it fails, \
                      check network filters / MDM update restrictions.",
                ),
            ));
        }
        Some(a) => vital(r, "Update scan", &format!("last success {a}d ago"), None),
        None => vital(
            r,
            "Update scan",
            "never succeeded / unknown",
            Some(Severity::Info),
        ),
    }
    if pending.is_empty() {
        return;
    }
    let oldest = pending.iter().filter_map(|(_, a)| *a).max();
    let sev = if oldest.is_some_and(|a| a > 30) {
        Severity::High
    } else {
        Severity::Medium
    };
    vital(r, "Updates pending", &pending.len().to_string(), Some(sev));
    let mut f = finding(
        "sec.updates_pending",
        sev,
        &format!(
            "{} software update(s) waiting to install{}",
            pending.len(),
            oldest
                .map(|a| format!(" (oldest offered {a} days ago)"))
                .unwrap_or_default()
        ),
        "Automatic updates being ON doesn't mean the Mac is patched: these were found but \
         never installed (deferred by MDM, failed, or waiting on a restart).",
        Some("System Settings ▸ General ▸ Software Update ▸ Update Now (save work — it restarts)."),
    );
    f.evidence.push(Evidence {
        source: "SoftwareUpdate RecommendedUpdates".into(),
        excerpt: pending
            .iter()
            .map(|(n, _)| n.as_str())
            .collect::<Vec<_>>()
            .join(" · "),
    });
    r.findings.push(f);
}

/// Boot arguments that switch off code-signing / AMFI / kernel protections.
const DANGEROUS_BOOT_ARGS: &[&str] = &[
    "amfi_get_out_of_my_way",
    "amfi_allow_any_signature",
    "amfi_unrestrict_task_for_pid",
    "cs_enforcement_disable",
    "cs_debug",
    "amfi=",
    "rootless=0",
    "ipc_control_port_options=0",
    "PE_i_can_has_debugger",
];

pub fn dangerous_boot_args(args: &str) -> Vec<String> {
    args.split_whitespace()
        .filter(|a| DANGEROUS_BOOT_ARGS.iter().any(|d| a.starts_with(d)))
        .map(String::from)
        .collect()
}

fn boot_args(r: &mut SecurityResult) {
    let effective = run("/usr/sbin/sysctl", &["-n", "kern.bootargs"]).unwrap_or_default();
    // `nvram boot-args` prints "boot-args\t<value>" or an error when unset.
    let stored = run("/usr/sbin/nvram", &["boot-args"])
        .unwrap_or_default()
        .split_once('\t')
        .map(|(_, v)| v.trim().to_string())
        .unwrap_or_default();
    let live = dangerous_boot_args(&effective);
    let pending: Vec<String> = dangerous_boot_args(&stored)
        .into_iter()
        .filter(|a| !live.contains(a))
        .collect();
    if live.is_empty() && pending.is_empty() {
        return;
    }
    let (sev, what) = if live.is_empty() {
        (Severity::Medium, "stored in NVRAM (not active this boot)")
    } else {
        (Severity::High, "ACTIVE this boot")
    };
    let mut f = finding(
        "sec.boot_args",
        sev,
        &format!("Security-disabling boot arguments {what}"),
        "These switch off code-signing enforcement (AMFI) or kernel protections, so \
         Gatekeeper and SIP can look healthy while unsigned code runs freely. Legit only on \
         a kernel/driver developer's test machine.",
        Some(
            "From Recovery: `nvram -d boot-args`, then restore Full Security in Startup \
              Security Utility.",
        ),
    );
    f.evidence.push(Evidence {
        source: "kern.bootargs / nvram boot-args".into(),
        excerpt: live
            .iter()
            .chain(pending.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join(" "),
    });
    r.findings.push(f);
}

/// Why a root-run path is tamperable by a non-root user, or None if it's safe.
/// Group write by wheel(0)/admin(80) is not flagged: admins can sudo anyway.
pub fn unsafe_owner_mode(uid: u32, gid: u32, mode: u32) -> Option<String> {
    if mode & 0o002 != 0 {
        return Some("world-writable".into());
    }
    if mode & 0o020 != 0 && gid != 0 && gid != 80 {
        return Some(format!("group-writable (gid {gid})"));
    }
    if uid != 0 {
        return Some(format!("owned by uid {uid}"));
    }
    None
}

fn path_problem(p: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(p).ok()?;
    unsafe_owner_mode(m.uid(), m.gid(), m.mode()).map(|why| format!("{} — {why}", p.display()))
}

/// Programs that run whatever file follows them on the command line.
const INTERPRETERS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "ksh",
    "dash",
    "fish",
    "env",
    "python",
    "perl",
    "ruby",
    "node",
    "php",
    "osascript",
    "expect",
    "tclsh",
    "lua",
    "swift",
];

pub(crate) fn interpreter_name(path: &str) -> Option<&str> {
    let base = Path::new(path).file_name()?.to_str()?;
    // "python3.12" → "python", "sh" → "sh".
    let name = base.split(|c: char| !c.is_ascii_alphabetic()).next()?;
    INTERPRETERS.contains(&name).then_some(name)
}

/// What one interpreter argument is.
enum Arg {
    /// The code follows inline (`sh -c`, `python -m`): there is no script file.
    Inline,
    /// An option that consumes the next word (`python -W x`, `bash -o opt`).
    TakesValue,
    Flag,
    /// A script path, or (for env) the program or a VAR=value setting.
    Operand,
}

fn classify_arg(interp: &str, a: &str) -> Arg {
    let shell = matches!(interp, "sh" | "bash" | "zsh" | "ksh" | "dash" | "fish");
    if !a.starts_with('-') && !(shell && a.starts_with('+')) {
        return Arg::Operand;
    }
    let inline = matches!(a, "-c" | "-e" | "--eval")
        || matches!(
            (interp, a),
            ("node", "-p" | "--print") | ("python", "-m") | ("perl", "-E") | ("php", "-r")
        );
    let takes_value = match interp {
        "python" => matches!(a, "-W" | "-X" | "-Q"),
        "perl" => a == "-I",
        "ruby" => matches!(a, "-I" | "-r" | "-C" | "-E"),
        "osascript" => matches!(a, "-l" | "-s"),
        "node" => matches!(a, "-r" | "--require" | "--import"),
        "php" => matches!(a, "-c" | "-d" | "-z"),
        "env" => matches!(a, "-u" | "-P" | "-S"),
        _ => shell && matches!(a, "-o" | "+o" | "-O" | "+O"),
    };
    if inline {
        Arg::Inline
    } else if takes_value {
        Arg::TakesValue
    } else {
        Arg::Flag
    }
}

/// For a daemon that runs a script through an interpreter
/// (`/bin/sh /path/x.sh`, `/usr/bin/env python3 /path/x.py`), the script is the
/// real program; for `env /abs/prog` it is that program. Returns its absolute
/// path, or None when the program is a normal binary, the code is inline
/// (`-c` / `-e`), or the path is relative.
pub fn interpreter_script(args: &[String]) -> Option<String> {
    let mut rest = args.iter().skip(1);
    let mut name = interpreter_name(args.first()?)?;
    if name == "env" {
        // Skip env's options (and their values) and VAR=value settings.
        let prog = loop {
            let a = rest.next()?;
            match classify_arg("env", a) {
                Arg::TakesValue => {
                    rest.next();
                }
                Arg::Operand if !a.contains('=') => break a,
                _ => {}
            }
        };
        match interpreter_name(prog) {
            Some("env") => return None,
            Some(interp) => name = interp,
            None => return prog.starts_with('/').then(|| prog.clone()),
        }
    }
    while let Some(a) = rest.next() {
        match classify_arg(name, a) {
            Arg::Inline => return None,
            Arg::TakesValue => {
                rest.next();
            }
            Arg::Flag => {}
            Arg::Operand => return a.starts_with('/').then(|| a.clone()),
        }
    }
    None
}

fn privileged_launch_writable(r: &mut SecurityResult) {
    let Ok(dir) = std::fs::read_dir("/Library/LaunchDaemons") else {
        return;
    };
    let mut high = Vec::new();
    let mut owned = Vec::new();
    for e in dir.flatten() {
        let plist_path = e.path();
        if plist_path.extension().and_then(|x| x.to_str()) != Some("plist") {
            continue;
        }
        let dict = plist_dict(&plist_path.to_string_lossy());
        let runs_as_root = dict
            .as_ref()
            .and_then(|d| {
                d.get("UserName")
                    .and_then(|u| u.as_string())
                    .map(String::from)
            })
            .is_none_or(|u| u == "root");
        if !runs_as_root {
            continue;
        }
        let args: Vec<String> = dict
            .as_ref()
            .and_then(|d| d.get("ProgramArguments"))
            .and_then(|a| a.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_string().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let mut problems: Vec<String> = path_problem(&plist_path).into_iter().collect();
        // The program, plus — when the program is an interpreter — the script
        // it runs, which is the file an attacker would actually edit.
        let mut targets: Vec<String> = Vec::new();
        if let Some(exec) = crate::audit::parse_launch_plist(&plist_path).and_then(|i| i.exec) {
            targets.push(exec);
        }
        if let Some(script) = interpreter_script(&args) {
            targets.push(script);
        }
        for t in &targets {
            let exec = Path::new(t);
            if exec.is_absolute() && exec.exists() {
                // The file itself (and its symlink target), then every parent dir.
                let real = std::fs::canonicalize(exec).unwrap_or_else(|_| exec.to_path_buf());
                problems.extend(path_problem(exec));
                if real != exec {
                    problems.extend(path_problem(&real));
                }
                problems.extend(real.ancestors().skip(1).filter_map(path_problem));
            } else if exec.is_absolute() {
                // A missing program is an open slot: whoever can create it gets
                // root the next time launchd starts the job.
                if let Some(dir) = exec.ancestors().skip(1).find(|a| a.exists()) {
                    let real = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
                    problems.extend(real.ancestors().filter_map(path_problem).map(|p| {
                        format!("{} is missing and can be created via {p}", exec.display())
                    }));
                }
            }
        }
        problems.sort();
        problems.dedup();
        let label = plist_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        for p in problems {
            let line = format!("{label}: {p}");
            if p.contains("owned by uid") {
                owned.push(line);
            } else {
                high.push(line);
            }
        }
    }
    let next = "Fix ownership/permissions to root:wheel, no group/other write: \
                `sudo chown root:wheel <path>` and `sudo chmod go-w <path>` (back up first), \
                or reinstall the vendor's package.";
    if !high.is_empty() {
        let mut f = finding(
            "sec.privileged_launch_writable",
            Severity::High,
            &format!(
                "{} root LaunchDaemon file(s) are writable by non-admins",
                high.len()
            ),
            "A LaunchDaemon runs as root at every boot. If any user or process can edit its \
             plist, program, or a folder above the program, it can make the Mac run its own \
             code as root — a direct privilege escalation.",
            Some(next),
        );
        f.evidence.extend(high.iter().take(12).map(|h| Evidence {
            source: "stat".into(),
            excerpt: h.clone(),
        }));
        r.findings.push(f);
    }
    if !owned.is_empty() {
        let mut f = finding(
            "sec.privileged_launch_writable",
            Severity::Medium,
            &format!(
                "{} root LaunchDaemon path(s) are owned by a regular user",
                owned.len()
            ),
            "The program runs as root but a normal account owns it (typical of apps dragged \
             into /Applications). macOS App Management protection blunts this for signed apps, \
             but user-level malware that gets past it can escalate to root.",
            Some(next),
        );
        f.evidence.extend(owned.iter().take(12).map(|h| Evidence {
            source: "stat".into(),
            excerpt: h.clone(),
        }));
        r.findings.push(f);
    }
}

/// Settings a profile REQUIRES vs what the Mac is actually doing. A mismatch
/// means a failed, stale, or conflicting MDM deployment.
fn mdm_mismatch(r: &mut SecurityResult) {
    let mp = |d: &str| plist_dict(&format!("{MANAGED_PREFS}/{d}.plist"));
    let mut bad: Vec<String> = Vec::new();
    if let Some(fw) = mp("com.apple.security.firewall") {
        let want = plist_bool(&fw, "EnableFirewall");
        let state = run(
            "/usr/libexec/ApplicationFirewall/socketfilterfw",
            &["--getglobalstate"],
        )
        .unwrap_or_default();
        if want == Some(true) && parse_firewall_state(&state) == FirewallState::Off {
            bad.push("Firewall: profile requires ON, firewall is OFF".into());
        }
        if plist_bool(&fw, "EnableStealthMode") == Some(true) {
            let st = run(
                "/usr/libexec/ApplicationFirewall/socketfilterfw",
                &["--getstealthmode"],
            )
            .unwrap_or_default();
            if parse_stealth(&st) == Some(false) {
                bad.push("Firewall stealth: profile requires ON, stealth is OFF".into());
            }
        }
    }
    if let Some(gk) = mp("com.apple.systempolicy.control") {
        let st = run("/usr/sbin/spctl", &["--status"]).unwrap_or_default();
        if plist_bool(&gk, "EnableAssessment") == Some(true) && st.contains("disabled") {
            bad.push("Gatekeeper: profile requires ON, Gatekeeper is OFF".into());
        }
    }
    if let Some(ss) = mp("com.apple.screensaver") {
        let delay_req = ss
            .get("askForPasswordDelay")
            .and_then(|v| v.as_signed_integer());
        if plist_bool(&ss, "askForPassword") == Some(true) || delay_req.is_some() {
            let out =
                run_all("/usr/sbin/sysadminctl", &["-screenLock", "status"]).unwrap_or_default();
            match (parse_screen_lock(&out), delay_req) {
                (Ok(None), _) => {
                    bad.push("Screen lock: profile requires a password, lock is OFF".into())
                }
                (Ok(Some(actual)), Some(req)) if actual as i64 > req => bad.push(format!(
                    "Screen lock: profile requires ≤{req}s, actual {actual}s"
                )),
                _ => {}
            }
        }
    }
    if let Some(mcx) = mp("com.apple.MCX") {
        if plist_bool(&mcx, "dontAllowFDEDisable") == Some(true)
            && run("/usr/bin/fdesetup", &["status"])
                .unwrap_or_default()
                .contains("FileVault is Off")
        {
            bad.push("FileVault: profile forbids disabling it, FileVault is OFF".into());
        }
    }
    if bad.is_empty() {
        return;
    }
    let mut f = finding(
        "sec.mdm_mismatch",
        Severity::Medium,
        &format!("{} MDM-required setting(s) are not in effect", bad.len()),
        "A configuration profile demands these protections but the Mac isn't applying them — \
         a failed or conflicting Jamf deployment, a pending restart, or local tampering.",
        Some(
            "Tell the Jamf admin which profile didn't apply (System Settings ▸ General ▸ \
              Device Management shows it); a restart fixes pending ones.",
        ),
    );
    f.evidence.extend(bad.into_iter().map(|b| Evidence {
        source: MANAGED_PREFS.into(),
        excerpt: b,
    }));
    r.findings.push(f);
}

/// Extension bundle IDs a profile names explicitly: (bundle id, why, required).
/// `required` = a content filter / DNS proxy provider that must be running;
/// otherwise it is only on the system-extension allow-list.
pub fn profile_extension_ids(xml: &str) -> Vec<(String, String, bool)> {
    let mut out: Vec<(String, String, bool)> = Vec::new();
    let Ok(v) = plist::Value::from_reader_xml(xml.as_bytes()) else {
        return out;
    };
    fn items(v: &plist::Value, acc: &mut Vec<plist::Dictionary>) {
        match v {
            plist::Value::Dictionary(d) => {
                if d.contains_key("PayloadType") {
                    acc.push(d.clone());
                }
                d.values().for_each(|c| items(c, acc));
            }
            plist::Value::Array(a) => a.iter().for_each(|c| items(c, acc)),
            _ => {}
        }
    }
    let mut payloads = Vec::new();
    items(&v, &mut payloads);
    for p in payloads {
        let ty = p
            .get("PayloadType")
            .and_then(|t| t.as_string())
            .unwrap_or("");
        let content = p
            .get("PayloadContent")
            .and_then(|c| c.as_dictionary())
            .unwrap_or(&p);
        if ty == "com.apple.system-extension-policy" {
            for key in ["AllowedSystemExtensions", "NonRemovableSystemExtensions"] {
                if let Some(teams) = content.get(key).and_then(|x| x.as_dictionary()) {
                    for ids in teams.values() {
                        for id in ids.as_array().map(|a| a.as_slice()).unwrap_or(&[]) {
                            if let Some(id) = id.as_string() {
                                if !out.iter().any(|(i, _, _)| i == id) {
                                    out.push((
                                        id.into(),
                                        "system-extension allow-list".into(),
                                        false,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
        if ty == "com.apple.webcontent-filter" || ty == "com.apple.dnsProxy.managed" {
            for key in [
                "FilterDataProviderBundleIdentifier",
                "FilterPacketProviderBundleIdentifier",
                "ProviderBundleIdentifier",
            ] {
                if let Some(id) = content.get(key).and_then(|x| x.as_string()) {
                    out.retain(|(i, _, _)| i != id);
                    out.push((id.into(), format!("{ty} provider"), true));
                }
            }
        }
    }
    out
}

/// Bundle IDs of `[activated enabled]` extensions in `systemextensionsctl list`.
pub fn active_extension_ids(out: &str) -> Vec<String> {
    out.lines()
        .filter(|l| l.contains("[activated enabled]"))
        .filter_map(|l| l.split('\t').nth(3))
        .map(|c| c.split(" (").next().unwrap_or(c).trim().to_string())
        .collect()
}

fn managed_extensions(r: &mut SecurityResult, root: bool) {
    if !root {
        r.skipped.push(Skipped {
            what: "MDM-required extensions running (system-extension / content-filter payloads)"
                .into(),
            reason: "requires sudo — computer-level profiles are not readable".into(),
        });
        return;
    }
    let wanted = profile_extension_ids(profiles_xml());
    if wanted.is_empty() {
        return;
    }
    let (list, _) = run_with_timeout(
        "/usr/bin/systemextensionsctl",
        &["list"],
        Duration::from_secs(15),
    );
    let active = active_extension_ids(&list);
    let missing: Vec<&(String, String, bool)> = wanted
        .iter()
        .filter(|(id, _, _)| !active.contains(id))
        .collect();
    if missing.is_empty() {
        return;
    }
    let required = missing.iter().any(|(_, _, req)| *req);
    let mut f = finding(
        "sec.managed_extension_inactive",
        if required {
            Severity::Medium
        } else {
            Severity::Low
        },
        &format!(
            "{} extension(s) named by MDM profiles are not running",
            missing.len()
        ),
        "Jamf configured these extensions, but none of them is active. A content filter or DNS \
         proxy that isn't running means the protection is silently absent; an allow-listed EDR \
         that never activated means the Mac isn't being monitored. (An allow-list entry alone \
         doesn't prove the product is supposed to be installed.)",
        Some(
            "Check the vendor app is installed and approved in System Settings ▸ General ▸ \
              Login Items & Extensions; a reboot activates pending ones.",
        ),
    );
    f.evidence
        .extend(missing.iter().map(|(id, why, _)| Evidence {
            source: why.clone(),
            excerpt: id.clone(),
        }));
    r.findings.push(f);
}

/// (path, allowed) pairs from `socketfilterfw --listapps`.
pub fn parse_firewall_apps(out: &str) -> Vec<(String, bool)> {
    let mut apps = Vec::new();
    let mut lines = out.lines().peekable();
    while let Some(l) = lines.next() {
        let Some((n, path)) = l.split_once(" : ") else {
            continue;
        };
        if n.trim().parse::<u32>().is_err() {
            continue;
        }
        let allowed = lines
            .peek()
            .map(|nx| nx.contains("Allow incoming"))
            .unwrap_or(false);
        apps.push((path.trim().to_string(), allowed));
    }
    apps
}

fn firewall_exceptions(r: &mut SecurityResult) {
    let out = run(
        "/usr/libexec/ApplicationFirewall/socketfilterfw",
        &["--listapps"],
    )
    .unwrap_or_default();
    let apps = parse_firewall_apps(&out);
    let allowed: Vec<&String> = apps.iter().filter(|(_, a)| *a).map(|(p, _)| p).collect();
    if allowed.is_empty() {
        return;
    }
    vital(
        r,
        "Firewall exceptions",
        &format!("{} apps allowed inbound", allowed.len()),
        None,
    );
    let risky_dirs = [
        "/Users/",
        "/tmp/",
        "/private/tmp/",
        "/private/var/folders/",
        "/Volumes/",
    ];
    let (missing, present): (Vec<&String>, Vec<&String>) = allowed
        .iter()
        .partition(|p| !Path::new(p.as_str()).exists());
    let risky: Vec<&&String> = present
        .iter()
        .filter(|p| risky_dirs.iter().any(|d| p.starts_with(d)) || p.contains("/Downloads/"))
        .collect();
    if !risky.is_empty() {
        let mut f = finding(
            "sec.firewall_exception_risky",
            Severity::Medium,
            &format!(
                "{} firewall exception(s) point into user-writable folders",
                risky.len()
            ),
            "These programs may accept inbound connections, and they live somewhere any \
             process running as you can replace them (home folder, Downloads, temp, external \
             drives). Swap the file and the exception comes with it.",
            Some(
                "Remove unneeded ones: System Settings ▸ Network ▸ Firewall ▸ Options ▸ select ▸ \
                  '−'. Move real apps into /Applications.",
            ),
        );
        f.evidence.extend(risky.iter().take(12).map(|p| Evidence {
            source: "socketfilterfw --listapps".into(),
            excerpt: p.to_string(),
        }));
        r.findings.push(f);
    }
    if !missing.is_empty() {
        let mut f = finding(
            "sec.firewall_exception_stale",
            Severity::Low,
            &format!(
                "{} firewall exception(s) point at apps that no longer exist",
                missing.len()
            ),
            "Leftovers from uninstalled apps. Harmless until something new is installed at the \
             same path — then it inherits inbound access without a prompt.",
            Some("System Settings ▸ Network ▸ Firewall ▸ Options ▸ remove the missing entries."),
        );
        f.evidence.extend(missing.iter().take(12).map(|p| Evidence {
            source: "socketfilterfw --listapps".into(),
            excerpt: p.to_string(),
        }));
        r.findings.push(f);
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct SshAuth {
    pub password: bool,
    pub kbd_interactive: bool,
    pub permit_root: String,
}

/// Effective auth settings from sshd_config text (first value wins, like sshd;
/// `Match` blocks are ignored — they only narrow the global defaults).
/// Defaults are OpenSSH's: password + keyboard-interactive on, root key-only.
pub fn parse_sshd_config(text: &str) -> SshAuth {
    let mut password: Option<bool> = None;
    let mut kbd: Option<bool> = None;
    let mut root: Option<String> = None;
    for l in text.lines() {
        let l = l.split('#').next().unwrap_or("").trim();
        let mut it = l.split_whitespace();
        let (Some(k), Some(v)) = (it.next(), it.next()) else {
            continue;
        };
        let k = k.to_ascii_lowercase();
        if k == "match" {
            break;
        }
        let yes = v.eq_ignore_ascii_case("yes");
        match k.as_str() {
            "passwordauthentication" if password.is_none() => password = Some(yes),
            "kbdinteractiveauthentication" | "challengeresponseauthentication" if kbd.is_none() => {
                kbd = Some(yes)
            }
            "permitrootlogin" if root.is_none() => root = Some(v.to_ascii_lowercase()),
            _ => {}
        }
    }
    SshAuth {
        password: password.unwrap_or(true),
        kbd_interactive: kbd.unwrap_or(true),
        permit_root: root.unwrap_or_else(|| "prohibit-password".into()),
    }
}

fn sshd_config_text() -> String {
    let mut text = String::new();
    // Includes first: macOS's sshd_config pulls sshd_config.d/* in at the top.
    if let Ok(dir) = std::fs::read_dir("/etc/ssh/sshd_config.d") {
        let mut files: Vec<_> = dir.flatten().map(|e| e.path()).collect();
        files.sort();
        for f in files {
            text.push_str(&std::fs::read_to_string(f).unwrap_or_default());
            text.push('\n');
        }
    }
    text.push_str(&std::fs::read_to_string("/etc/ssh/sshd_config").unwrap_or_default());
    text
}

fn ssh_auth(r: &mut SecurityResult, root: bool) {
    let enabled = run("/bin/launchctl", &["print-disabled", "system"])
        .map(|o| {
            parse_enabled_services(&o)
                .iter()
                .any(|s| s == "com.openssh.sshd")
        })
        .unwrap_or(false);
    if !enabled {
        return;
    }
    // Under root, `sshd -T` prints the real effective config; else parse the files.
    let (auth, source) = if root {
        let (t, _) = run_with_timeout("/usr/sbin/sshd", &["-T"], Duration::from_secs(10));
        if t.contains("passwordauthentication") {
            (parse_sshd_config(&t), "sshd -T")
        } else {
            (parse_sshd_config(&sshd_config_text()), "sshd_config")
        }
    } else {
        (parse_sshd_config(&sshd_config_text()), "sshd_config")
    };
    if auth.permit_root == "yes" {
        r.findings.push(finding(
            "sec.ssh_weak_auth",
            Severity::High,
            "SSH allows root to log in with a password",
            "`PermitRootLogin yes` exposes the most powerful account to password guessing from \
             any network that can reach port 22.",
            Some("Set `PermitRootLogin no` in /etc/ssh/sshd_config.d/ (back up first)."),
        ));
    }
    if auth.password || auth.kbd_interactive {
        let mut f = finding(
            "sec.ssh_weak_auth",
            Severity::Medium,
            "SSH accepts passwords (not just keys)",
            "Anyone who can reach port 22 can try to guess account passwords. macOS's default; \
             key-only SSH removes the risk entirely.",
            Some(
                "If you use SSH keys: add `PasswordAuthentication no` and \
                  `KbdInteractiveAuthentication no` to /etc/ssh/sshd_config.d/100-local.conf. \
                  If Jamf enabled SSH, ask the Jamf admin first.",
            ),
        );
        f.evidence.push(Evidence {
            source: source.into(),
            excerpt: format!(
                "password={} kbd-interactive={} permitrootlogin={}",
                auth.password, auth.kbd_interactive, auth.permit_root
            ),
        });
        r.findings.push(f);
    }
}

/// Non-root accounts with UID 0 from `dscl . -list /Users UniqueID`.
pub fn extra_uid0(out: &str) -> Vec<String> {
    out.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let (name, uid) = (it.next()?, it.next()?);
            (uid == "0" && name != "root").then(|| name.to_string())
        })
        .collect()
}

fn root_accounts(r: &mut SecurityResult) {
    let list = run("/usr/bin/dscl", &[".", "-list", "/Users", "UniqueID"]).unwrap_or_default();
    let extra = extra_uid0(&list);
    if !extra.is_empty() {
        r.findings.push(finding(
            "sec.uid0_extra",
            Severity::High,
            &format!("Extra account(s) with root's user ID: {}", extra.join(", ")),
            "UID 0 is root. A second account with UID 0 is a full root backdoor that doesn't \
             show up as 'root' — a classic persistence trick.",
            Some(
                "Investigate who created it; remove with `sudo dscl . -delete /Users/<name>` \
                  once confirmed (back up first).",
            ),
        ));
    }
    let rec = run_all(
        "/usr/bin/dscl",
        &[
            ".",
            "-read",
            "/Users/root",
            "AuthenticationAuthority",
            "Password",
        ],
    )
    .unwrap_or_default();
    let has_auth = rec
        .lines()
        .any(|l| l.starts_with("AuthenticationAuthority:"));
    let disabled = rec.contains("DisabledUser");
    if has_auth && !disabled {
        r.findings.push(finding(
            "sec.root_enabled",
            Severity::Medium,
            "The root account is enabled",
            "macOS ships with root disabled; admins use sudo. An enabled root account is an \
             extra password to guess and usually a leftover from old troubleshooting.",
            Some("Directory Utility ▸ Edit ▸ Disable Root User, or `dsenableroot -d`."),
        ));
    }
}

/// Parse a jamf.log line time ("Thu Sep 24 08:01:58 host jamf[1]: ..."), local
/// time, current year (rolled back a year if that would be in the future).
pub fn parse_jamf_time(
    line: &str,
    now: chrono::DateTime<chrono::Local>,
) -> Option<chrono::DateTime<chrono::Local>> {
    use chrono::{Datelike, TimeZone};
    let stamp: String = line
        .split_whitespace()
        .skip(1)
        .take(3)
        .collect::<Vec<_>>()
        .join(" ");
    let parse = |y: i32| {
        chrono::NaiveDateTime::parse_from_str(&format!("{y} {stamp}"), "%Y %b %d %H:%M:%S")
            .ok()
            .and_then(|n| chrono::Local.from_local_datetime(&n).single())
    };
    let t = parse(now.year())?;
    if t > now + chrono::Duration::days(1) {
        parse(now.year() - 1)
    } else {
        Some(t)
    }
}

fn jamf_checkin(r: &mut SecurityResult) {
    let Some(log) = jamf_log() else {
        return; // not a Jamf Mac (or unreadable — jamf() already covers a broken framework)
    };
    let now = chrono::Local::now();
    let lines: Vec<&str> = log.lines().collect();
    let last_idx = lines
        .iter()
        .rposition(|l| l.contains("\"recurring check-in\""));
    let failures_after = lines[last_idx.map(|i| i + 1).unwrap_or(0)..]
        .iter()
        .filter(|l| l.contains("Could not connect to the JSS"))
        .count();
    let Some(i) = last_idx else {
        vital(r, "Jamf check-in", "none in jamf.log", Some(Severity::Low));
        r.findings.push(finding(
            "sec.jamf_checkin_stale",
            Severity::Low,
            "jamf.log has no recurring check-in on record",
            "The Jamf framework logs every scheduled check-in; none in the newest 2 MB of the \
             log means policies and inventory aren't running on schedule (or the log was just \
             rotated).",
            Some(
                "`sudo jamf policy -verbose` on the organisation's network, or ask the Jamf \
                  admin.",
            ),
        ));
        return;
    };
    let Some(t) = parse_jamf_time(lines[i], now) else {
        return;
    };
    let hours = (now - t).num_hours();
    let age = crate::util::human_duration((now - t).num_seconds().max(0) as u64);
    let sev = match hours {
        h if h > 72 => Some(Severity::Medium),
        h if h > 24 => Some(Severity::Low),
        _ => None,
    };
    vital(
        r,
        "Jamf check-in",
        &format!(
            "last {age} ago{}",
            if failures_after > 0 {
                format!(" · {failures_after} failed since")
            } else {
                String::new()
            }
        ),
        sev,
    );
    if let Some(sev) = sev {
        let mut f = finding(
            "sec.jamf_checkin_stale",
            sev,
            &format!("Last Jamf check-in was {age} ago"),
            "Jamf normally checks in every 15–60 minutes. Without check-ins, security \
             policies, patches and inventory stop — even though the framework itself looks \
             installed. Normal for a Mac that was off, or off the corporate network without \
             VPN.",
            Some(
                "Connect to the organisation's network or VPN and run `sudo jamf policy`; if \
                  it still can't connect, tell the Jamf admin.",
            ),
        );
        f.evidence.push(Evidence {
            source: JAMF_LOG.into(),
            excerpt: lines[i].trim().to_string(),
        });
        if failures_after > 0 {
            f.evidence.push(Evidence {
                source: JAMF_LOG.into(),
                excerpt: format!("{failures_after}× 'Could not connect to the JSS' since"),
            });
        }
        r.findings.push(f);
    }
}
