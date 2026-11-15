#!/usr/bin/env bash
# Build and run Mini AV on Linux/macOS (needs only Rust). Opens a local web UI at http://127.0.0.1:8787
set -e
cd "$(dirname "$0")"
rustc --edition 2021 -O src/devhost.rs -o mini-av-linux
echo "Open http://127.0.0.1:${1:-8787} in your browser (Ctrl+C to stop)"
exec ./mini-av-linux "${1:-8787}"
