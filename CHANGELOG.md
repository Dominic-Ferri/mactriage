# Changelog

## 0.12.0 (2026-10-10, hardened 2026-10-21)

- `mactriage security` adds the launch-item and kext audits, every network
  listener with its real path and signer (`sec.listener_exposed`,
  `sec.listener_apple`), user-domain certificate trust, and a check of the
  script behind interpreter daemons.
- DNS resolvers are rated by operator: a known provider is Info, an
  unrecognized one is Medium. Blocking an Apple update, revocation, or
  notarization host in `/etc/hosts` is High. Blocking any other Apple host is
  Medium.
- The Jamf CA counts as expected only when its exact name matches and every
  System keychain certificate with that name came from an installed profile.
  Otherwise it is Low, including runs without sudo.
- MacSecurity.app writes reports to `~/Library/Logs/MacSecurity/` (folder 0700,
  files 0600). Root never writes there. `--html` creates a new file only and
  refuses an existing path or a symbolic link.
- Both apps verify their own signature before asking for a password, fall back
  to reduced coverage on Ctrl-C, run the root process with a fixed PATH, and
  clear cached sudo credentials on exit.
- Listener paths come from the kernel, not the process name, which a program
  can fake. Every
  system tool runs by absolute path with a time limit. A tool that fails is
  reported as Skipped, never as a pass.

## Documentation (2026-10-01)

The README now explains how a scan reaches its answers: the scan stages, the
correlation order, the condition table and the recovery gates. No code changes.

## 0.11.5 (2026-09-30)

Background Spotlight indexing is no longer reported as a problem. Two routine
indexer messages are ignored. The Spotlight story now needs indexer memory
kills (High) or more than 50 real errors (Medium). Without that evidence, CPU
reports from Apple's indexing daemons are Info.

## 0.11.4 (2026-09-30)

Sleep blockers held through `runningboardd` now name the real app. Bluetooth
retries to a single device are Low instead of Medium. One-off CPU-limit reports
are Low unless the same process has three or more.

## 0.11.3 (2026-09-30)

Thermal throttling counts episodes of rising pressure, not every log line that
mentions it. Severity follows the number of episodes and any real CPU speed
limit. Time Machine scheduling deferrals no longer count as errors.

## 0.11.2 (2026-09-30)

The default unified-log time limit rose from 240 s to 600 s, so a 6-hour pass
is no longer cut short. `log show` emits the oldest events first, so a cut pass
lost the newest ones. The timeout note now says so.

## 0.11.1 (2026-09-30)

- Fault snapshots (`ExcUserFault_*.ips`) are Info and never count as crashes.
- A crash loop needs 3 crashes in 60 minutes or 5 in 24 hours. Crashes spread
  further apart are a Medium recurring crash.
- The Spotlight story is High only when indexer daemons are memory-killed.
- Gatekeeper ignores QUIC flow-control counters. Keychain severity counts only
  real authentication failures.

## 0.11.0 (2026-09-30)

- `snap.ssd_wear` reads the NVMe health log through `smartctl`. MacTriage.app
  bundles a universal smartctl 7.5 built from pinned source (GPL-2.0).
- New checks for a charger that cannot keep up, battery cycles against the
  design rating, missing built-in keyboards and trackpads, and low-battery
  Bluetooth input devices.
- Kernel panics are classed as likely hardware, firmware, or software. A
  hardware-class panic points the recovery assessment at hardware first.
- Report headers show the model name and boot drive. Baseline and diff record
  SSD wear and battery data. Apple Diagnostics advice matches the Mac's chip.

## 0.10.1 (2026-09-24)

`posture.firewall_off` rose from Low to Medium. The firewall and stealth checks
share tested parsers. Unreadable firewall output is reported as not verified.

## 0.10.0 (2026-09-24)

Twelve new security rules: pending updates and stale update scans,
security-disabling boot arguments, writable root LaunchDaemons, MDM settings
that are not in effect, inactive MDM-required extensions, risky or stale
firewall exceptions, SSH password login, extra UID 0 accounts, an enabled root
account, and stale Jamf check-ins.

## 0.9.0 (2026-09-24)

- New `mactriage security`: a read-only audit of Wi-Fi encryption, firewall
  hardening, sharing services, DNS, proxies, `/etc/hosts`, update policy,
  screen lock, and the login window.
- It also covers MDM enrollment, Jamf health, configuration profiles, managed
  preferences, trusted certificates, admin accounts, and network extensions.
- `./build-app.sh security` builds MacSecurity.app, which runs the audit and
  opens the HTML report.
- Remote-access detection reads the launchd sharing switches, because `netstat`
  output is unreliable for child processes on recent macOS.

## 0.8.0 (2026-09-09)

- Tables and matchers were checked against Apple's own sources and man pages.
- The memory-pressure value is read as a bitmask. The shutdown-cause table was
  corrected and extended.
- New report types: sleep/wake failure, boot reset count, userspace watchdog,
  and forced reset.
- Jetsam kill reasons were verified against xnu. CPU and wakeup reports moved
  to their own `resourceabuse` category.

## 0.7.4 (2026-09-09)

The Spotlight story now appears once instead of five times. More reconnect and
backup noise is filtered. Locked-keychain errors alone stay Low.

## 0.7.3 (2026-09-09)

`log.io_errors` no longer treats routine APFS "invalidating" messages as
corruption.

## 0.7.2 (2026-09-09)

The dashboard saves the JSON and HTML report when a scan completes.
`log.io_errors` ignores sandbox denials, keybag churn, and failed mounts of
locked volumes. A routine Time Machine snapshot probe is ignored.

## 0.7.1 (2026-09-09)

Idle-exit reclaims no longer count as memory-pressure kills. Wi-Fi telemetry
dumps no longer match link events. Out-of-range boot timings are discarded.

## 0.7.0 (2026-09-08)

- Noise filters for Wi-Fi, watchdog, thermal, and USB rules.
- Jetsam findings separate a process over its own limit from a system out of
  memory.
- Log-only disk errors no longer push recovery to hardware when SMART is
  verified.
- Findings from the first 2 minutes after boot drop one severity level.
- Spotlight symptoms join into one story, and XProtect age uses the newest
  definitions.

## 0.6.0 (2026-09-08)

JSON reports carry `log_events`, every unified-log line that matched a rule.
Core Data metadata and successful `fsck_apfs` runs no longer count as disk
failure.

## 0.5.1 (2026-08-24)

The results summary lists every Fatal, High, Medium, and Low finding with its
next step. Reports share one overall condition scale, from HEALTHY to CRITICAL,
plus UNKNOWN for incomplete scans.

## 0.5.0 (2026-08-24)

New `mactriage ui`, a keyboard-driven Ratatui dashboard with live progress,
safe cancellation, and export that never overwrites. Only a private scan worker
runs as root. The dashboard stays with the logged-in user.

## 0.4.0 (2026-08-24)

Full scans end with a recovery assessment. A clean install is recommended only
after five explicit gates pass, and incomplete scans block it. New
`log.software_update` rule.

## 0.3.0 (2026-07-23)

- A failed or partial scan never looks healthy. Log failures, timeouts, and
  unreadable report folders mark the scan incomplete.
- The log streamer no longer drops the newest events.
- Crash loops need a real burst. SMART status checks the actual boot disk.
- New `snap.top_mem` rule, and a repeatable `build-app.sh` for the app.

## 0.2.0 (2026-07-16)

- Full rewrite after the 0.1.0 source was lost. Rule IDs, flags, and exit codes
  are unchanged.
- New audits: launch items, Background Task Management, kexts, install history,
  security posture, snapshots, Time Machine, battery, sleep, and network.
- New `baseline`, `diff`, `watch`, and `--html`.
- Live progress bar, and a streamed unified-log pass.

## 0.1.0 (2026-07)

Original release: report-file, unified-log, and live-vitals scanners, a
correlator, and a severity-ranked report with JSON schema 1.
