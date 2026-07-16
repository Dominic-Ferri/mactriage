#!/bin/bash
# Build a double-clickable MacTriage.app or MacSecurity.app.
#   ./build-app.sh [triage|security] [dest-dir]
#   ./build-app.sh            → dist/build/MacTriage.app  (Ratatui triage dashboard)
#   ./build-app.sh security   → dist/build/MacSecurity.app (runs `mactriage security`,
#                               writes + opens an HTML report)
# dest-dir defaults to dist/build inside the repo (gitignored).
#
# The app is an AppleScript applet that opens Terminal and runs the bundled
# universal `mactriage` Ratatui interface. sudo -v authorizes only its private
# scan worker; Ctrl-C / 3 wrong passwords select reduced coverage. Terminal is
# deliberate: it hosts the native TUI and supplies the Full Disk Access grant.
#
# Repeatable: run it after any code change. It rebuilds, re-signs, and reinstalls,
# backing up any existing app rather than deleting it.
#
# No paid Apple Developer account needed. Locally built bundles aren't quarantined,
# so this Mac launches it directly. For a build copied to ANOTHER Mac, the first
# launch needs: right-click ▸ Open (or System Settings ▸ Privacy & Security ▸
# Open Anyway). A self-signed code-signing identity named "MacTriage Dev" keeps
# local rebuild identity stable; otherwise the builder safely falls back to
# ad-hoc signing.
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$(pwd)"

VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n1)"
[ -n "$VERSION" ] || { echo "could not read version from Cargo.toml" >&2; exit 1; }
APP_NAME="MacTriage"
LAUNCHER="run-mactriage.command"
BUNDLE_ID="com.dferri.mactriage"
case "${1:-triage}" in
  triage) ;;
  security)
    APP_NAME="MacSecurity"
    LAUNCHER="run-macsecurity.command"
    BUNDLE_ID="com.dferri.macsecurity"
    ;;
  *) echo "usage: $0 [triage|security] [dest-dir]" >&2; exit 2 ;;
esac
DEST_DIR="${2:-$ROOT/dist/build}"

# Stage in a plain temp dir, NOT inside the repo: iCloud/File-Provider-managed
# folders get com.apple.FinderInfo re-stamped on the bundle root, which breaks
# `codesign --strict`. Signing on a clean filesystem sidesteps it; we copy the
# finished app out after.
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/mactriage-app.XXXXXX")"
APP="$STAGE/$APP_NAME.app"
STAGE_ARCHIVE="$ROOT/target/app-stages/$APP_NAME-app-stage.$(date +%Y%m%d-%H%M%S)"
archive_stage() {
  if [ -d "$STAGE" ]; then
    mkdir -p "$(dirname "$STAGE_ARCHIVE")"
    mv "$STAGE" "$STAGE_ARCHIVE"
    echo "staging archived: $STAGE_ARCHIVE"
  fi
}
trap archive_stage EXIT

echo "==> building universal binary"
bash ./build-universal.sh
if [ "$APP_NAME" = "MacTriage" ]; then
  # SSD wear (snap.ssd_wear) needs smartctl on Macs without Homebrew.
  bash ./dist/build-smartctl.sh
fi

echo "==> compiling applet"
sed "s/run-mactriage\.command/$LAUNCHER/" dist/applet-source.applescript > "$STAGE/applet.applescript"
osacompile -o "$APP" "$STAGE/applet.applescript"

echo "==> bundling binary + launcher script"
install -m 0755 target/universal/mactriage "$APP/Contents/Resources/mactriage"
install -m 0755 "dist/$LAUNCHER" "$APP/Contents/Resources/$LAUNCHER"
if [ "$APP_NAME" = "MacTriage" ]; then
  SMARTCTL_DIR="target/vendor/smartctl-7.5"
  install -m 0755 "$SMARTCTL_DIR/smartctl" "$APP/Contents/Resources/smartctl"
  # smartctl is GPL-2.0, shipped as a separate unmodified executable.
  install -m 0644 "$SMARTCTL_DIR/COPYING" "$APP/Contents/Resources/smartmontools-COPYING.txt"
  printf '%s\n' \
    "smartctl 7.5 from smartmontools (https://www.smartmontools.org), GPL-2.0." \
    "Unmodified; built universal by dist/build-smartctl.sh from" \
    "https://github.com/smartmontools/smartmontools/releases/tag/RELEASE_7_5" \
    "(SHA-256 690b83ca331378da9ea0d9d61008c4b22dde391387b9bbad7f29387f2595f76e)." \
    > "$APP/Contents/Resources/smartmontools-SOURCE.txt"
fi

PLIST="$APP/Contents/Info.plist"
set_str() { # key value  (Add or Set a string entry)
  /usr/libexec/PlistBuddy -c "Set :$1 $2" "$PLIST" 2>/dev/null \
    || /usr/libexec/PlistBuddy -c "Add :$1 string $2" "$PLIST"
}
set_str CFBundleIdentifier "$BUNDLE_ID"
set_str CFBundleName "$APP_NAME"
set_str CFBundleShortVersionString "$VERSION"
set_str CFBundleVersion "$VERSION"
set_str LSMinimumSystemVersion "12.0"
# Drop the AppleScript-applet boilerplate: junk privacy prompts + Carbon flag.
for k in NSHomeKitUsageDescription NSAppleMusicUsageDescription NSCalendarsUsageDescription \
         NSSiriUsageDescription NSCameraUsageDescription NSMicrophoneUsageDescription \
         NSRemindersUsageDescription NSContactsUsageDescription NSPhotoLibraryUsageDescription \
         NSSystemAdministrationUsageDescription NSAppleEventsUsageDescription LSRequiresCarbon \
         LSMinimumSystemVersionByArchitecture; do
  /usr/libexec/PlistBuddy -c "Delete :$k" "$PLIST" 2>/dev/null || true
done

# Clear FinderInfo/resource-fork xattrs — they make `codesign --verify --strict`
# fail. The recursive clear misses the bundle root's FinderInfo, so clear it too.
xattr -cr "$APP"
xattr -c "$APP" 2>/dev/null || true

# Prefer a stable self-signed identity if present; else ad-hoc.
if security find-identity -v -p codesigning 2>/dev/null | grep -q "MacTriage Dev"; then
  SIGN_ID="MacTriage Dev"
else
  SIGN_ID="-"
fi
echo "==> signing inside-out (identity: $SIGN_ID)"
# Nested executables first, then the enclosing app.
if [ -f "$APP/Contents/Resources/smartctl" ]; then
  codesign --force --sign "$SIGN_ID" "$APP/Contents/Resources/smartctl"
fi
codesign --force --sign "$SIGN_ID" "$APP/Contents/Resources/mactriage"
codesign --force --sign "$SIGN_ID" "$APP"

echo "==> verifying (strict, on clean staging filesystem)"
plutil -lint "$PLIST" >/dev/null
codesign --verify --deep --strict --verbose=2 "$APP"

# Install to the destination, archiving any existing app rather than deleting it.
mkdir -p "$DEST_DIR"
DEST="$DEST_DIR/$APP_NAME.app"
if [ -e "$DEST" ]; then
  BAK="$DEST_DIR/$APP_NAME.app.bak.$(date +%Y%m%d-%H%M%S)"
  echo "==> backing up existing app → $BAK"
  mv "$DEST" "$BAK"
fi
cp -R "$APP" "$DEST"
xattr -cr "$DEST" 2>/dev/null || true
# In an iCloud-synced folder, FinderInfo comes back on the copy's root. That is
# cosmetic: it trips `--strict` but not the seal. Confirm the signature that
# launch actually checks:
echo "==> verifying installed copy (signature validity)"
codesign -v "$DEST" && echo "    signature valid ✓"

echo
echo "installed: $DEST  (v$VERSION, universal)"
echo "double-click it, or:  open \"$DEST\""
