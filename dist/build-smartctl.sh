#!/bin/bash
# Build a universal (arm64 + x86_64), macOS 12+ `smartctl` for MacTriage.app.
#
# Why from source: Homebrew's smartctl is arm64-only and built for the host's
# macOS (minos 26.0 on this Mac), so it won't run on the Intel or older Macs
# the flash-drive app gets plugged into. The source tarball is pinned by
# SHA-256 (the same value Homebrew's smartmontools formula pins); the upstream
# PGP signature is checked too when gpg and the signing key are available.
#
# Output (cached; rerun only when missing or after changing the pin):
#   target/vendor/smartctl-$VER/smartctl
#   target/vendor/smartctl-$VER/COPYING        (GPL-2.0 license text)
set -euo pipefail
cd "$(dirname "$0")/.."

VER="7.5"
SHA256="690b83ca331378da9ea0d9d61008c4b22dde391387b9bbad7f29387f2595f76e"
URL="https://github.com/smartmontools/smartmontools/releases/download/RELEASE_${VER//./_}/smartmontools-$VER.tar.gz"
OUT="target/vendor/smartctl-$VER"
FLAGS="-O2 -arch arm64 -arch x86_64 -mmacosx-version-min=12.0"

if [ -x "$OUT/smartctl" ] && [ -f "$OUT/COPYING" ]; then
  echo "smartctl $VER already built: $OUT/smartctl"
  exit 0
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/smartctl-build.XXXXXX")"
echo "==> downloading smartmontools $VER"
curl -fsSL -o "$WORK/src.tar.gz" "$URL"
curl -fsSL -o "$WORK/src.tar.gz.asc" "$URL.asc" || true

echo "==> verifying SHA-256"
echo "$SHA256  $WORK/src.tar.gz" | shasum -a 256 -c -

if command -v gpg >/dev/null 2>&1 && [ -s "$WORK/src.tar.gz.asc" ]; then
  if gpg --batch --verify "$WORK/src.tar.gz.asc" "$WORK/src.tar.gz" 2>/dev/null; then
    echo "    PGP signature verified"
  else
    echo "    PGP signature not verified (signing key not in keyring) — relying on the pinned SHA-256"
  fi
fi

echo "==> building universal smartctl (minimum macOS 12.0)"
tar -xzf "$WORK/src.tar.gz" -C "$WORK"
(
  cd "$WORK/smartmontools-$VER"
  ./configure --disable-dependency-tracking \
    CFLAGS="$FLAGS" CXXFLAGS="$FLAGS" LDFLAGS="-arch arm64 -arch x86_64 -mmacosx-version-min=12.0" \
    >"$WORK/configure.log" 2>&1
  make -j"$(sysctl -n hw.ncpu)" smartctl >"$WORK/make.log" 2>&1
)

BIN="$WORK/smartmontools-$VER/smartctl"
ARCHS="$(lipo -archs "$BIN")"
case "$ARCHS" in
  *arm64*x86_64*|*x86_64*arm64*) ;;
  *) echo "smartctl is not universal (archs: $ARCHS)" >&2; exit 1 ;;
esac
if otool -l "$BIN" | grep -A3 LC_BUILD_VERSION | grep minos | grep -qv '12\.0'; then
  echo "smartctl minimum macOS is not 12.0" >&2; exit 1
fi

mkdir -p "$OUT"
install -m 0755 "$BIN" "$OUT/smartctl"
install -m 0644 "$WORK/smartmontools-$VER/COPYING" "$OUT/COPYING"
echo "built: $OUT/smartctl ($ARCHS)"
