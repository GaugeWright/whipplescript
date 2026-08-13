#!/usr/bin/env bash
# Compiles the workspace the way a release compiles it, for the one target where
# a platform difference shows up: x86_64-pc-windows-msvc.
#
# `dist build` runs `cargo build --workspace`, so a release compiles every
# member of the workspace for every target in dist-workspace.toml — including
# crates that are never distributed. Nothing else in the green bar compiles for
# Windows, so a member that used std::os::unix outside a cfg passed every gate
# and then failed the release, which is what happened between 2026-08-06 and
# 2026-08-13.
#
# scripts/check.sh runs this script, and the `windows-compiles` CI job runs this
# same script instead of a cargo command of its own, so the Windows gate and the
# documented green bar cannot come to mean different things. Change the command
# here and both callers change with it.
#
# `build` under the `dist` profile, not `check` under the default one, because a
# gate is only worth what it reproduces. `cargo check` stops before codegen and
# linking, so it would pass on a Windows-only linker error, a codegen failure, or
# anything gated on the profile's `lto = "thin"` — and then the release, which
# does all three, would fail anyway. A gate that can be green while the thing it
# protects is red is not protecting it. This costs a full optimised build on a
# Windows runner per pull request, and that is the price of the claim.
#
# Deliberately the release's set — libs and bins, not --all-targets. The release
# does not compile tests, so holding them to Windows here would gate on more
# than this is claiming to protect; a Unix-only test is cfg'd where it lives.
set -euo pipefail
cd "$(dirname "$0")/.."

target=x86_64-pc-windows-msvc
host="$(rustc -vV | sed -n 's/^host: //p')"

if [ "$host" = "$target" ]; then
    cargo build --workspace --profile dist --locked
    exit 0
fi

# Cross-checking this target from another host is not available, and the reason
# is a real dependency rather than a missing rustup component: whipplescript-store
# takes rusqlite with `bundled`, whose build script compiles SQLite's C sources
# with the TARGET's C compiler, and an MSVC target wants cl.exe. Build scripts
# run before any compilation, so it fails there first. Installing the target's std would
# not change that, which is why this is a skip and not the hard failure the
# hosted-runtime tooling gets — the gate has to stay runnable on the Linux hosts
# every developer and the green bar use. The `windows-compiles` job, on a Windows
# runner, is where this command is answerable.
echo "skipped: host is $host, and $target needs an MSVC C toolchain (rusqlite bundled);"
echo "         the windows-compiles CI job runs this same script on a Windows runner"
