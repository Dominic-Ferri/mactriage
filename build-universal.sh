#!/bin/bash
# Build a universal (arm64 + x86_64) release binary at target/universal/mactriage.
set -euo pipefail
cd "$(dirname "$0")"

# Keep both slices aligned with the app bundle's declared minimum OS.
export MACOSX_DEPLOYMENT_TARGET=12.0

# Panic locations carry the builder's home path; ship neutral prefixes instead.
export RUSTFLAGS="--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=${RUSTUP_HOME:-$HOME/.rustup}=/rustup"

rustup target add aarch64-apple-darwin x86_64-apple-darwin 2>/dev/null || true

cargo build --release --target aarch64-apple-darwin
cargo build --release --target x86_64-apple-darwin

mkdir -p target/universal
lipo -create \
    target/aarch64-apple-darwin/release/mactriage \
    target/x86_64-apple-darwin/release/mactriage \
    -output target/universal/mactriage

# A shipped binary must not carry the build Mac's home path.
if LC_ALL=C grep -a -q -F -- "$HOME/" target/universal/mactriage; then
  echo "build-universal.sh: target/universal/mactriage contains $HOME; fix the remap above" >&2
  exit 1
fi

echo "universal binary: target/universal/mactriage"
lipo -info target/universal/mactriage
