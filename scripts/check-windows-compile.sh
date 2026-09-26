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
# scripts/check.sh runs this script, and the fleet's Windows job
# (`gaugewright/bar/windows`) runs this same script instead of a cargo command of
# its own, so the Windows gate and the documented green bar cannot come to mean
# different things. Change the command here and both callers change with it.
#
# That job answers every head of main and no pull request (GaugeWright
# DR-0146). Every pull request's Linux bar compiles and tests the whole
# workspace, so what waits for the merge is only what Windows alone can break,
# and that was rare enough — 86 runs, 86 passes — that holding every pull
# request thirteen minutes for it was the wrong trade. A red on main names the
# commit that caused it, and scripts/release-fleet.sh compiles Windows again
# before anything is published.
#
# `build` under the `dist` profile, not `check` under the default one, because a
# gate is only worth what it reproduces. `cargo check` stops before codegen and
# linking, so it would pass on a Windows-only linker error, a codegen failure, or
# anything gated on the profile's `lto = "thin"` — and then the release, which
# does all three, would fail anyway. A gate that can be green while the thing it
# protects is red is not protecting it. This costs a full optimised build on the
# Windows host for every head of main, and that is the price of the claim.
#
# Deliberately the release's set — libs and bins, not --all-targets. The release
# does not compile tests, so holding them to Windows here would gate on more
# than this is claiming to protect; a Unix-only test is cfg'd where it lives.
set -euo pipefail
cd "$(dirname "$0")/.."

target=x86_64-pc-windows-msvc
host="$(rustc -vV | sed -n 's/^host: //p')"

# What the build reads: the same set BUCK declares for the `windows-compile`
# target, whose Linux siblings the read sandbox holds to it (GaugeWright
# FLEET.md stage 0). Keep the two together.
inputs=(Cargo.toml Cargo.lock rust-toolchain.toml dist-workspace.toml
        crates std examples models spec skills scripts/check-windows-compile.sh)

if [ "$host" = "$target" ]; then
    # A tree whose inputs this host has already compiled is answered from that
    # compile rather than compiled again. Most pull requests are answered on a
    # test merge that differs from the last one only outside these paths — a
    # decision record, a page, a workflow — and each still cost a full optimised
    # build, about thirteen minutes, on the one Windows host there is. The key
    # is every input's content as git holds it plus the toolchain's own version,
    # so a changed pin or an updated rustc compiles again, and it is recorded
    # only after a build passed. A tree with uncommitted changes to an input is
    # never looked up, because git's record of it is not what cargo would read.
    record="target/windows-compile-passed"
    key=""
    if git rev-parse --verify -q HEAD >/dev/null && [ -z "$(git status --porcelain -- "${inputs[@]}")" ]; then
        key="$( { rustc -vV; git ls-tree -r HEAD -- "${inputs[@]}"; } | git hash-object --stdin)"
        if [ -f "$record" ] && grep -q "^$key " "$record"; then
            echo "served: these exact inputs compiled under the dist profile on this host at $(grep "^$key " "$record" | tail -1 | cut -d' ' -f2-)"
            exit 0
        fi
    fi
    cargo build --workspace --profile dist --locked
    if [ -n "$key" ]; then
        mkdir -p target
        echo "$key $(git rev-parse --short=12 HEAD) $(date -u +%Y-%m-%dT%H:%MZ)" >> "$record"
    fi
    exit 0
fi

# Cross-checking this target from another host is not available, and the reason
# is a real dependency rather than a missing rustup component: whipplescript-store
# takes rusqlite with `bundled`, whose build script compiles SQLite's C sources
# with the TARGET's C compiler, and an MSVC target wants cl.exe. Build scripts
# run before any compilation, so it fails there first. Installing the target's std would
# not change that, which is why this is a skip and not the hard failure the
# hosted-runtime tooling gets — the gate has to stay runnable on the Linux hosts
# every developer and the green bar use. The fleet's Windows job, on the Windows
# host, is where this command is answerable.
echo "skipped: host is $host, and $target needs an MSVC C toolchain (rusqlite bundled);"
echo "         the fleet's Windows job (gaugewright/bar/windows) runs this same script on every head of main"
