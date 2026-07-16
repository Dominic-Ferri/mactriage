#!/bin/bash
# Build a universal (arm64 + x86_64) release binary at target/universal/mactriage.
set -euo pipefail
cd "$(dirname "$0")"

# Keep both slices aligned with the app bundle's declared minimum OS.
export MACOSX_DEPLOYMENT_TARGET=12.0

rustup target add aarch64-apple-darwin x86_64-apple-darwin 2>/dev/null || true

cargo build --release --target aarch64-apple-darwin
cargo build --release --target x86_64-apple-darwin

mkdir -p target/universal
lipo -create \
    target/aarch64-apple-darwin/release/mactriage \
    target/x86_64-apple-darwin/release/mactriage \
    -output target/universal/mactriage

echo "universal binary: target/universal/mactriage"
lipo -info target/universal/mactriage
