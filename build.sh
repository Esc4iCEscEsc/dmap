#! /usr/bin/env bash

set -ex

export RUSTFLAGS='-C target-feature=+crt-static'
# cargo build --release --target x86_64-unknown-linux-gnu
# cargo build --release
cargo build --release --target x86_64-unknown-linux-musl

rm -rf dist/
mkdir dist/
# mv target/x86_64-unknown-linux-gnu/release/main dist/dmap.fat
# mv target/release/main dist/dmap.fat
mv target/x86_64-unknown-linux-musl/release/main dist/dmap.fat

strip -o dist/dmap.stripped dist/dmap.fat
upx --best -o dist/dmap dist/dmap.stripped
