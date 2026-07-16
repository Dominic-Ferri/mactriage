# dist: the app wrappers

`MacTriage.app` is an AppleScript applet (source: `applet-source.applescript`)
that opens Terminal and runs the bundled Ratatui interface at
`Contents/Resources/mactriage`. The launcher checks the app's signature, then
runs `sudo -v` before the TUI. With the password, a private privileged scan
worker gives full coverage. Ctrl-C or 3 wrong passwords select reduced
coverage. The TUI and exported reports remain owned by the logged-in user.
Terminal also supplies the Full Disk Access grant.

`MacSecurity.app` uses the same applet with `run-macsecurity.command`. It runs
`mactriage security` and writes the HTML report to
`~/Library/Logs/MacSecurity/` (folder 0700, report 0600). Under sudo, root
writes into a private temporary folder and the user's shell copies the report
out.

Inside the dashboard, use arrow keys or `j`/`k` to select profiles and findings,
Tab or left/right arrows to change result sections, Page Up/Page Down to scroll
long details, and `?` for the complete key reference.

## Build / refresh the app

Use the repeatable builder from the repo root. It does everything below:

    ./build-app.sh [triage|security] [dest-dir]

It builds the universal binary, compiles the applet, sets a stable
`CFBundleIdentifier` + version, strips the AppleScript boilerplate and the
`com.apple.FinderInfo` detritus that breaks `codesign --strict`, signs
inside-out, and verifies. It then installs the app to `dest-dir`, which
defaults to `dist/build/` (gitignored), and backs up any existing app there.
The verified clean staging bundle is kept under `target/app-stages/`.

## Signing / Gatekeeper

- Ad-hoc by default (no paid Apple Developer account needed).
- To keep the local signing identity stable, create a self-signed **code-signing** certificate
  named `MacTriage Dev` (Keychain Access ▸ Certificate Assistant ▸ Create a
  Certificate ▸ type: Code Signing). `build-app.sh` uses it automatically if present.
- Locally built apps aren't quarantined, so this Mac launches it directly. A copy
  moved to another Mac needs a one-time right-click ▸ Open (or System Settings ▸
  Privacy & Security ▸ Open Anyway). Do not disable Gatekeeper globally.
- In an iCloud-synced folder, macOS adds `com.apple.FinderInfo` to the copied
  app. Then `codesign --verify --strict` fails, but the signature itself stays
  valid.
