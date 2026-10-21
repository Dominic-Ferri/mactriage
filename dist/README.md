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
writes into a private temporary folder. The user's shell then copies the report
from that folder.

Dashboard keys:

- arrow keys or `j`/`k`: select profiles and findings
- Tab or left/right arrows: change result sections
- Page Up/Page Down: scroll long details
- `?`: show the complete key reference

## Build / refresh the app

Use the repeatable builder from the repo root:

    ./build-app.sh [triage|security] [dest-dir]

The builder does these steps:

1. It builds the universal binary.
2. It compiles the applet.
3. It sets a stable `CFBundleIdentifier` and version.
4. It removes the AppleScript boilerplate and the stray `com.apple.FinderInfo`
   attribute that breaks `codesign --strict`.
5. It signs the bundle from the inside out.
6. It verifies the signature.
7. It installs the app to `dest-dir`. The default is `dist/build/` (gitignored).
   It keeps a backup of any existing app there.

The builder keeps the verified clean staging bundle under `target/app-stages/`.

## Signing / Gatekeeper

- The build signs ad hoc by default. You do not need a paid Apple Developer
  account.
- For a stable local signing identity, create a self-signed **code-signing**
  certificate named `MacTriage Dev`. Use Keychain Access ▸ Certificate
  Assistant ▸ Create a Certificate ▸ type: Code Signing. `build-app.sh` uses
  this certificate when it exists.
- macOS does not quarantine a locally built app, so the build Mac opens it
  directly. On another Mac, a copy needs a one-time right-click ▸ Open. System
  Settings ▸ Privacy & Security ▸ Open Anyway also works. Do not disable
  Gatekeeper globally.
- In an iCloud-synced folder, macOS adds `com.apple.FinderInfo` to the copied
  app. Then `codesign --verify --strict` fails, but the signature itself stays
  valid.
