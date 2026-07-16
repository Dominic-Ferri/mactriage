# mactriage

mactriage is a command-line tool for Mac support work. It reads the evidence
that macOS already keeps: crash reports, kernel panic records, the unified log,
and live system state. It turns that evidence into one list of problems, sorted
by how serious they are. Each problem has a plain explanation and a next step.

It answers the questions a support technician asks first:

- Did anything crash, panic, hang, or run out of memory?
- Is the problem one app, or the whole system?
- Did the trouble start right after something was installed?
- Is the hardware healthy (SSD, battery, charger, keyboard, trackpad)?
- Is something keeping the Mac awake, filling the disk, or blocking backups?
- What is the security posture (firewall, sharing, MDM, certificates)?
- Does this Mac need an erase and reinstall, or not?

mactriage only reads. It does not delete files, change settings, start
Recovery, or touch firmware. The only thing it writes is its own state
(a baseline file, watch state, and the reports you ask for).

## Quick start

```
mactriage                 # full scan: 6h of unified log, 7d of reports, live vitals, audits
sudo mactriage            # same scan with full coverage (see "Running as root")
mactriage ui              # interactive dashboard in Terminal
mactriage snapshot        # live vitals only, finishes in seconds
mactriage --no-log        # fast mode: skip the unified log
mactriage --html r.html   # also write a self-contained HTML report (new file, mode 0600)
mactriage --json          # machine-readable output (schema_version 2)
```

More commands:

```
mactriage --only hardware --no-log   # SSD wear, battery and charger, keyboard and trackpad
mactriage security                   # read-only security audit
mactriage rules                      # list every detection rule
mactriage baseline                   # save an inventory of this Mac while it works
mactriage diff                       # show what changed since the baseline
mactriage watch install              # scan every 6h in the background, notify on new problems
```

Useful options:

| Option | What it does |
|---|---|
| `--last 24h` | How much of the unified log to read. Default `6h`. |
| `--files-last 14d` | How far back to read crash and panic reports. Default `7d`. |
| `--from "2026-07-01 08:30" --to ...` | Scan a fixed time range instead. |
| `--only <cat>` / `--skip <cat>` | Limit the scan to some categories, or leave some out. |
| `--min-severity medium` | Hide findings below this level. |
| `--timeout 900` | Upper limit in seconds for the unified-log pass. Default `600`. |
| `--full` | Show every finding. The terminal report shows 10 per category by default. |
| `-v` / `-vv` | Show evidence lines / show timing and skipped checks on stderr. |

Run `mactriage --help` for the full list of categories and options.

## How a scan works

A full scan runs in five stages. The progress bar follows them, and for the log
stage it shows how much of the time window has actually been read.

### 1. Diagnostic report files

mactriage reads `/Library/Logs/DiagnosticReports`, your own
`~/Library/Logs/DiagnosticReports`, and the `Retired` folders inside them. As
root it also reads every user's folder. It parses each report by its type:

| Report | What mactriage takes from it |
|---|---|
| Kernel panic (`.panic`, `.ips` type 210) | The panic string, the kernel extensions in the backtrace, and a cause class: hardware, firmware/coprocessor, or software |
| App crash (`.ips` type 309, `.crash`) | Process, exception type, signal, termination reason |
| Hang (`.hang`, `.spin`, `.ips` type 288) | Which app stopped responding |
| Jetsam (`.ips` type 298) | Which processes the kernel killed to free memory |
| CPU and wakeup limits (`.diag`) | Processes that ran too hot or woke the CPU too often |
| GPU restart, shutdown stall | Driver resets, processes that held up shutdown |

Some reports are not failures. An `ExcUserFault_*.ips` file is a fault snapshot
from a process that kept running. mactriage lists it as Info and never counts
it as a crash.

### 2. The unified log

This is the slow stage. mactriage runs `/usr/bin/log show` once, with one
combined predicate that covers every log rule, and streams the output as JSON
lines. One pass is about ten times faster than one query per rule. On a busy Mac
a 6-hour window takes 2 to 5 minutes.

Each matching line goes to a classifier in Rust. The classifier filters known
noise first. Examples are thermal messages that report the all-clear and
Spotlight errors for files that were deleted mid-read. Time Machine "backup
delayed" messages and the lines that `log show` itself creates are noise too.
What remains is
counted per rule, and the count sets the severity. Five thermal episodes are
Low. Thirty are High.

The log rules cover shutdown causes, watchdog timeouts, thermal throttling,
disk and APFS errors, GPU resets, launchd service crashes, and Spotlight errors.
They also cover kernel extension load failures, USB and Thunderbolt
over-current, sleep and wake failures, and Wi-Fi disconnects. Bluetooth
retries, Software Update failures, and Time Machine errors complete the list.

If the pass reaches `--timeout`, mactriage stops it and keeps what it read. It
then marks the scan incomplete (see "When a scan is incomplete").

### 3. Live checks

These read the current state of the Mac. Most finish in under a second each.

- **Vitals:** memory pressure and swap, the top memory user, CPU load, disk
  free space, uptime.
- **Hardware:** SSD wear from the NVMe health log (through `smartctl`), and
  battery capacity and cycle count against the design rating. It also checks
  for a charger that cannot keep up (connected, but the battery drains in two
  samples), and for the built-in keyboard and trackpad. A laptop whose keyboard or trackpad is missing
  from the I/O registry gets a finding. This check does not run with the lid
  closed. Bluetooth keyboards, mice, and trackpads at 10% battery or less are
  also flagged.
- **Power:** sleep preventers from `pmset -g assertions`. When `runningboardd`
  holds an assertion for an app, mactriage names the app, not `runningboardd`.
- **Network:** default route, gateway reachability, DNS, and Wi-Fi signal
  quality on the real Wi-Fi port.
- **Storage and backups:** APFS local snapshots, purgeable space, and the age
  of the last Time Machine backup.

### 4. Audits

- **Launch items:** LaunchAgents and LaunchDaemons that point to a missing
  program. As root, also the background items in macOS's Background Task
  Management database that no longer have an owner. Every third-party item is listed with
  the program it runs. An item counts as Apple's only when its program carries
  Apple's own signature. As root, every user's LaunchAgents folder is read.
- **Kernel extensions:** the loaded third-party kexts. This list is kept for
  the next stage.
- **Install history:** what was installed and when.
- **Posture:** SIP, Gatekeeper, FileVault, the firewall, XProtect updates, and MDM profiles.
- **Security:** the firewall and its app exceptions, Wi-Fi encryption, sharing
  services, network listeners, SSH password login, and DNS and `/etc/hosts`
  changes. Also pending updates, screen lock, MDM and Jamf state, trusted
  certificates, boot arguments, writable root daemons, and extra UID 0 accounts.
  `mactriage security` runs this part alone (see "The security audit").

### 5. Correlation

A raw list of findings is hard to read. One broken app can produce twenty lines.
The correlator joins related findings into one, in this order:

1. **Repeats:** the same rule from the same process becomes one finding with a
   count and a first and last time.
2. **Crash loop:** a process that crashed 3 or more times in 60 minutes, or 5
   or more times in 24 hours, becomes one High finding.
3. **Story:** two or more failure signals from one process (for
   example a crash, a hang, and a launchd restart) become one finding with one
   fix.
4. **Panic kext:** a kernel extension named in a panic backtrace that is still
   loaded now. This is the strongest single cause mactriage can identify.
5. **After an update:** a group of findings that started shortly after an
   install is linked to that install.

Then a boot filter runs. A log finding whose events all fall in the first
2 minutes after boot is usually normal startup work, so its severity drops one
level. Fatal findings never drop.

## Reading the report

Each finding has one of five levels:

| Level | Meaning |
|---|---|
| Fatal | The machine itself went down: kernel panic, watchdog, thermal, or power shutdown |
| High | Something important is broken or close to failing |
| Medium | A real problem that affects use |
| Low | Worth knowing about, usually not urgent |
| Info | Context. Not counted against the Mac |

The report also gives the whole Mac one overall condition:

| Condition | Rule |
|---|---|
| CRITICAL | At least one Fatal finding |
| SERIOUS | At least one High finding |
| DEGRADED | At least one Medium finding |
| MINOR | Only Low findings |
| HEALTHY | A complete scan with no findings above Info |
| UNKNOWN | An incomplete scan with no findings above Info |

The exit code follows the worst finding: `0` healthy, `10` low, `20` medium,
`30` high, `40` fatal, `2` usage error, `70` internal error. Scripts can use it
without parsing the output.

### When a scan is incomplete

A scan with zero findings is only good news if every source was read. mactriage
marks the scan incomplete when any of these happen:

- `log show` fails, exits with an error, or reaches the timeout.
- A multi-hour log window returns zero lines.
- A report folder cannot be read (usually missing Full Disk Access).

An incomplete scan shows a note in the terminal and HTML reports and sets
`"complete": false` in JSON. Its condition is UNKNOWN, never HEALTHY.

## The recovery assessment

Full scans end with a recovery assessment. It answers one question: does the
evidence support erasing this Mac? A clean install loses data and time, so the
answer is never based on a severity score. The assessment checks the evidence
in this order and stops at the first match:

| Order | Evidence | Recommendation |
|---|---|---|
| 1 | A panic that names a hardware fault (CATERR, machine check, ECC) or a firmware path (SEP, BridgeOS, SMC, ANS, DCP, AOP, RTKit). A failing SSD health log. Heavy disk I/O errors that SMART does not contradict. A shutdown caused by power or thermal hardware. | Firmware or hardware first. Back up, run Apple Diagnostics, then a DFU Revive. Erasing cannot fix this. |
| 2 | A loaded third-party kext that appears in a panic backtrace | Repair software first. Update or remove that product, then retest. |
| 3 | Two or more kernel panics | Firmware or hardware first. Clean install is not yet justified. |
| 4 | An incomplete scan, or a scan without root, the unified log, or all categories | Collect more evidence. Clean install is blocked. |
| 5 | A crash loop, a multi-signal story, a broken launch item, or a failing service | Repair software first. Fix the named component and test in Safe Mode and a new user account. |
| 6 | Software Update failures, one kernel panic, or a system-wide watchdog, GPU, boot, or storage failure | Reinstall macOS without erasing. Clean install is not yet justified. |
| 7 | None of the above | No erase needed. |

Every assessment lists the five gates that must all be true before anyone
should consider an erase:

1. A current full backup was read back or test-restored.
2. Apple Diagnostics passes, or the hardware fault was repaired.
3. The problem happens in Safe Mode.
4. The problem happens in a new user account.
5. A macOS reinstall without erasing was done, and the problem is still there.

A missing or old backup is a reason to stop. It is never a reason to go ahead.
Snapshot and watch reports leave this section out, because they do not read
enough history to support the decision.

## Running as root

Without sudo, mactriage still runs every check it can and lists the rest as
Skipped. With sudo it adds:

- every user's crash and panic reports, not only yours
- the full kernel panic record
- `powermetrics` thermal sampling
- full Wi-Fi details
- the Background Task Management audit (`sfltool dumpbtm`, which hangs
  without root, so mactriage never runs it as a normal user)

The recovery assessment needs root and the full log pass. Without them it
returns "collect more evidence".

Give your terminal app Full Disk Access too (System Settings > Privacy &
Security > Full Disk Access). Without it, some report folders and `tmutil` are
hidden, and the scan is marked incomplete.

## The security audit

`mactriage security` checks settings only. It reads no logs and no report
files, and it finishes in seconds. Some details of how it decides:

- **Network listeners:** a program counts as exposed when it listens on any
  address other than loopback. The real program path comes from the kernel,
  not from the process name, so a renamed process cannot pass as Apple's.
  Apple's own services are checked with `codesign` against Apple's signature.
- **Sharing ports:** ports 22, 445, 5900, 3031, and 3283 are left to the
  sharing check only when launchd or an Apple binary holds them.
- **Certificates:** a certificate named like the Jamf CA is Info only when it
  matches a certificate that an installed profile delivered. Without that
  match it is Low.
- **`/etc/hosts`:** blocking an Apple update, revocation, or notarization host
  is High. Blocking any other Apple host is Medium.
- **Failed tools:** when a tool such as `csrutil` or `security` gives no usable
  answer, the check is listed as Skipped. It is never shown as a pass.

Every system tool runs by its full path, and each one has a time limit.

### MacSecurity.app

`MacSecurity.app` opens Terminal and runs the audit from the binary inside the
bundle. It writes the HTML report to `~/Library/Logs/MacSecurity/`. The folder
is private to your account (mode 0700), and each report is mode 0600.

The app asks for your administrator password first. With the password, the
audit runs as root and adds computer-level profiles, the Bootstrap Token, and
the Jamf server check. Press Ctrl-C at the password prompt to skip it. The
audit then runs as your user with reduced coverage.

Before it asks for the password, the app checks its own code signature. If the
check fails, it does not ask and runs the reduced audit instead. Under sudo,
root writes the report to a private temporary folder. Your own account then
copies it to the Logs folder, so root never writes into your home folder. The
app clears the cached sudo password when it finishes.

`mactriage --html` creates a new file only. It refuses a path that already
exists, and it never follows a symbolic link.

## The dashboard

`mactriage ui` opens a terminal dashboard built with Ratatui. You pick a
profile (Full, Fast, or Snapshot), watch the progress, and cancel safely at any
time. The results have tabs for Summary, Findings, Recovery, Vitals, and
Coverage, plus the full rule list. Page Up and Page Down scroll long panels.
Export writes HTML or JSON and never overwrites an existing file.

The first results screen lists every Fatal, High, Medium, and Low finding with
its next step. The dashboard does not cap findings per category. Info findings
stay in the Findings tab.

The dashboard itself runs as you. When it needs root, it starts a separate scan
worker with sudo and talks to it over a private JSON-lines channel on stdin and
stdout. Only the read-only scanner runs as root. The dashboard and the files it
exports stay owned by your user.

## Baseline, diff, and watch

`mactriage baseline` saves an inventory of the Mac to
`~/Library/Application Support/mactriage/baseline.json`: loaded kexts, launch
items, security posture, disk use, and hardware wear. Save one while the Mac
works. When it breaks later, `mactriage diff` shows what changed since then.

`mactriage watch install` adds a LaunchAgent for your user (no sudo). Every 6
hours by default it runs a fast scan of report files and live vitals. It
compares the result with the last run and sends a notification for any new
finding at or above High. Change both with `--interval` and `--min-severity`.
`mactriage watch status` shows whether it is loaded and when it last ran.
`mactriage watch uninstall` unloads it and archives the plist.

## Output formats

- **Terminal:** color when the output is a TTY. `--no-color` and `NO_COLOR`
  turn it off.
- **HTML:** one self-contained file with no external assets, ready to attach
  to a ticket.
- **JSON:** `schema_version` 2. Includes the tool version, the scanned time
  window, the `complete` flag, and every finding with its evidence. It also
  holds the recovery assessment and `log_events` (every log line that matched a
  rule).
  New fields are only ever added, so older consumers keep working.

Reports never include serial numbers. mactriage does not read them from the
battery, the SSD, or the system.

## Build

Requires Rust (stable) and the Xcode command-line tools.

```
cargo build --release          # native build
./build-universal.sh           # arm64 + x86_64 binary → target/universal/mactriage
cargo install --path .         # installs to ~/.cargo/bin/mactriage
cargo test                     # unit and fixture tests
./build-app.sh                 # dist/build/MacTriage.app
./build-app.sh security        # dist/build/MacSecurity.app: runs `mactriage security`
./build-app.sh security ~/Apps # same app, built into another folder
```

`MacTriage.app` is an AppleScript launcher. It opens Terminal, asks for your
password with `sudo -v`, and starts the dashboard from the universal binary
inside the bundle. Ctrl-C or three wrong passwords start it with reduced
coverage instead. Like `MacSecurity.app`, it checks its own signature before it
asks for a password.

The build signs the app ad hoc. For a signature that stays the same between
builds, create a self-signed code-signing certificate named "MacTriage Dev" in
Keychain Access. You do not need a paid Apple Developer account. A copy moved
to another Mac needs one right-click > Open the first time.

### smartctl

The SSD wear check needs `smartctl` from smartmontools. `MacTriage.app`
includes a universal copy (macOS 12 and later) that `dist/build-smartctl.sh`
builds from smartmontools 7.5 source with a pinned SHA-256 (GPL-2.0). The
command-line tool looks for it in this order and never searches `PATH`:

1. `MACTRIAGE_SMARTCTL=/path/to/smartctl`
2. next to the mactriage binary
3. `/opt/homebrew/bin`, then `/usr/local/bin`

If none is found, the check shows as Skipped.

## Testing against saved reports

Set `MACTRIAGE_REPORTS_DIR` to a folder of sample reports, and mactriage reads
that folder instead of the system ones. The test suite uses this for its
fixtures.

## Source layout

| File | Job |
|---|---|
| `main.rs` | Command-line parsing |
| `scan.rs` | Runs the stages for full, snapshot, security, and watch scans |
| `files.rs` | Crash, panic, hang, and jetsam report parsing |
| `logscan.rs` | The unified-log pass and its classifiers |
| `host.rs`, `power.rs`, `hardware.rs` | Vitals, battery, charger, sleep blockers, SSD, input devices |
| `netcheck.rs`, `storage.rs` | Network health, snapshots, Time Machine |
| `audit.rs`, `security.rs` | Launch items, kexts, install history, posture, security audit |
| `correlate.rs` | Joins findings into crash loops, stories, and root causes |
| `recovery.rs` | The recovery assessment |
| `render.rs`, `html.rs`, `report.rs` | Terminal, HTML, and JSON output |
| `baseline.rs`, `watch.rs` | Baseline and diff, background watch |
| `protocol.rs`, `progress.rs` | Dashboard-to-worker channel, progress reporting |
| `rules.rs` | The rule catalog shown by `mactriage rules` |

There are 110 rules: 14 report-file (`file.*`), 19 unified-log (`log.*`),
21 live (`snap.*`), 5 audit, 6 posture, 39 security, 1 boot, and 5 correlation.

## History

The v0.1.0 source was lost. v0.2.0 is a full rewrite that kept the same rule IDs
and command line. v0.3.0 fixed trust and correctness problems. Later versions
added the dashboard, the recovery assessment, the security audit, and hardware
checks. Since 0.11.1, most changes tune rules that raised false alarms on real
Macs. Version 0.12.0 hardened the security audit and the app launchers. See
`CHANGELOG.md` for the reasons behind each change.
