#!/usr/bin/env bash
# Rebuilds the test fixtures in tests/fixtures/bin from src/fixture.rs.
#
# Needs only rustup (works on Linux, macOS and Windows/Git Bash):
#   rustup target add x86_64-unknown-linux-musl i686-unknown-linux-musl aarch64-unknown-linux-musl
#   rustup component add llvm-tools
set -euo pipefail
cd "$(dirname "$0")"

host=$(rustc -vV | sed -n 's/^host: //p')
tools="$(rustc --print sysroot)/lib/rustlib/$host/bin"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p bin

build() { # <name> <rust target> [extra linker args...]
    local name=$1 target=$2
    shift 2
    rustc --edition 2021 --crate-type staticlib --crate-name fixture --target "$target" \
        -C panic=abort -C opt-level=1 -C force-unwind-tables=yes -C codegen-units=1 \
        -C debuginfo=0 -o "$work/$name.a" src/fixture.rs
    "$tools/rust-lld" -flavor gnu -static --gc-sections --eh-frame-hdr --build-id=none \
        -u _start -e _start "$@" -o "bin/$name" "$work/$name.a"
    "$tools/llvm-strip" --strip-all -o "bin/$name.stripped" "bin/$name"
}

build x86_64-exec x86_64-unknown-linux-musl
build x86_64-pie x86_64-unknown-linux-musl -pie --no-dynamic-linker
build i686-exec i686-unknown-linux-musl
build aarch64-exec aarch64-unknown-linux-musl

ls -l bin
