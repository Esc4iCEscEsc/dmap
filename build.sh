#! /usr/bin/env bash

set -ex

export RUSTFLAGS='-C target-feature=+crt-static'
cargo build --release --target x86_64-unknown-linux-gnu

mkdir dist/ || true
mv target/x86_64-unknown-linux-gnu/release/main dist/dmap.fat

strip -o dist/dmap dist/dmap.fat
