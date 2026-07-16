#!/bin/bash
# Runs the bundled `mactriage security` audit in Terminal and opens the HTML
# report. Opened by MacSecurity.app (via `open -a Terminal`), so no
# Automation/AppleEvents permission is involved. Read-only: the audit changes
# no settings. sudo adds computer-level profiles, Bootstrap Token and the Jamf
# server check; Ctrl-C at the password prompt runs it unprivileged instead.
#
# Reports go to ~/Library/Logs/MacSecurity (folder 0700, files 0600). Root
# never writes there: under sudo the audit writes into a root-owned private
# temp folder, and this (unprivileged) shell copies the report out.
umask 077
set -C
clear
DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="$DIR/mactriage"
APP="$(cd "$DIR/../.." && pwd)"
LOGS="$HOME/Library/Logs/MacSecurity"
/bin/mkdir -p "$LOGS" && /bin/chmod 700 "$LOGS"
OUT="$LOGS/MacSecurity-$(date +%Y%m%d-%H%M%S).html"
TMP=""

finish() {
    if [ -n "$TMP" ]; then
        /usr/bin/sudo -n /bin/rm -f "$TMP/report.html"
        /usr/bin/sudo -n /bin/rmdir "$TMP"
    fi
    /usr/bin/sudo -k
}
trap finish EXIT

unprivileged() {
    echo
    echo "✗ $1 — reduced-coverage security audit"
    echo
    "$BIN" security --html "$OUT"
}

if ! /usr/bin/codesign --verify --deep "$APP" 2>/dev/null; then
    echo 'MacSecurity: the app signature did not verify, so it will not ask for your password.'
    unprivileged 'signature not verified'
else
    echo 'MacSecurity — enter your password for full coverage, or press Ctrl-C for reduced coverage'
    # Ctrl-C ends only the password prompt, not this script.
    trap ':' INT
    /usr/bin/sudo -v
    AUTH=$?
    trap - INT
    if [ "$AUTH" -eq 0 ] && TMP="$(/usr/bin/sudo /usr/bin/mktemp -d /private/tmp/macsecurity.XXXXXX)"; then
        echo
        echo '✓ password accepted — full-coverage security audit'
        echo
        /usr/bin/sudo /usr/bin/env PATH=/usr/bin:/bin:/usr/sbin:/sbin \
            "$BIN" security --html "$TMP/report.html"
        # Deliberate: this unprivileged shell, not root, creates the report file.
        # shellcheck disable=SC2024
        /usr/bin/sudo /bin/cat "$TMP/report.html" > "$OUT"
    else
        TMP=""
        unprivileged 'no sudo'
    fi
fi

[ -s "$OUT" ] && /usr/bin/open "$OUT"
echo
echo "Report: $OUT"
echo 'Press Return to close this window.'
read -r _
