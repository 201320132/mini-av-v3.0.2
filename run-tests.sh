#!/usr/bin/env bash
# 1) unit tests of the engine, 2) end-to-end test of the real program with real files (needs node + playwright).
set -e
cd "$(dirname "$0")/.."
W=$(mktemp -d)
rustc --edition 2021 --test src/engine.rs -o "$W/unit" && "$W/unit" | tail -3
rustc --edition 2021 -O src/devhost.rs -o "$W/mini-av-linux"
NODE_PATH=$(npm root -g) node tests/e2e.js "$W" "$W/mini-av-linux"
