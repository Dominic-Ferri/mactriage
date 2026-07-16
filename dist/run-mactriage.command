#!/bin/bash
# Runs the bundled Ratatui interface in Terminal. This file is opened by
# MacTriage.app (via `open -a Terminal`), so no Automation/AppleEvents
# permission is involved. sudo -v authorizes only the private scan worker; the
# interface and its exported reports remain owned by the logged-in user.
# Ctrl-C at the password prompt opens the dashboard with reduced coverage.
umask 077
clear
DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="$DIR/mactriage"
APP="$(cd "$DIR/../.." && pwd)"
# The privileged worker inherits this PATH through sudo.
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
trap '/usr/bin/sudo -k' EXIT

AUTH=1
if ! /usr/bin/codesign --verify --deep "$APP" 2>/dev/null; then
    echo 'MacTriage: the app signature did not verify, so it will not ask for your password.'
else
    echo 'MacTriage — enter your password for full coverage, or press Ctrl-C for reduced coverage'
    # Ctrl-C ends only the password prompt, not this script.
    trap ':' INT
    /usr/bin/sudo -v
    AUTH=$?
    trap - INT
fi

if [ "$AUTH" -eq 0 ]; then
    echo
    echo '✓ password accepted — opening the full-coverage dashboard'
    echo
    "$BIN" ui --privileged --autorun
else
    echo
    echo '✗ no sudo — opening with reduced coverage'
    echo
    "$BIN" ui --autorun
fi

echo
echo 'MacTriage closed. Press Return to close this window.'
read -r _
