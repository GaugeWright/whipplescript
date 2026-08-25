#!/usr/bin/env bash
# DR-0066: sans-IO is not an implementation detail, it is the testability
# substrate. Deterministic simulation — rung 2 of the verification ladder, and
# the only rung that would catch a failover mid-publish — is possible only while
# the modules a simulator drives are free of ambient time, ambient randomness,
# and IO. A change that reaches for any of them forfeits that permanently and
# silently, so it is refused here rather than discovered later.
#
# SCOPE, stated honestly. This does NOT claim the whole kernel is sans-IO; it is
# not. `harness.rs`, `gov.rs`, and `ifc.rs` all touch the filesystem or the
# clock outside the seam today, and the wasm build excludes them rather than
# they having been cleaned. What the durable-object path relies on is already
# enforced by a stronger check than grep — it has to compile to
# wasm32-unknown-unknown, where `std::fs` and `Instant::now` are simply not
# available, and `npm run build:wasm` runs on every green bar.
#
# What is protected here is the set of modules that are pure BY CONSTRUCTION and
# whose purity nothing else would notice losing: the digest and verification
# cores that both hosts share. If these drift, the two hosts stop agreeing and
# the simulator loses the only components it could have driven deterministically.
set -euo pipefail
cd "$(dirname "$0")/.."

# Modules that must stay pure. Add to this list; do not add exceptions to it.
PURE_MODULES=(
    crates/whipplescript-store/src/event_chain.rs
    crates/whipplescript-store/src/preflight.rs
    crates/whipplescript-kernel/src/sansio.rs
)

# Ambient constructs. Each of these makes a run irreproducible from a seed,
# which is exactly what deterministic simulation cannot tolerate.
FORBIDDEN='SystemTime::now|Instant::now|std::fs::|std::net::|std::process::|rand::|thread::sleep|tokio::'

# Scanning stops at the module's `#[cfg(test)]` boundary.
#
# This narrowing was made AFTER the check caught a test in `preflight.rs` that
# opens a real store in a temp directory — so it deserves saying plainly why it
# is principled rather than convenient. Deterministic simulation drives the
# LIBRARY API: `entry_digest`, `fold_prefix`, `preflight_manifest`. A test
# harness that mints a temp path is not something a simulator ever runs, and the
# alternative — forbidding such tests — would have pushed the real-store test
# (the one that proves erasure is still recorded durably) out of the module it
# tests, making the codebase worse to keep a grep tidy.
#
# What this does NOT protect, stated so nobody reads more into a green line than
# it carries: test code in these modules may do anything, and nothing here says
# the rest of the crate is pure.
scan_library_half() {
    awk '/#\[cfg\(test\)\]/ { exit } { printf "%d:%s\n", NR, $0 }' "$1"
}

status=0
for module in "${PURE_MODULES[@]}"; do
    if [ ! -f "$module" ]; then
        echo "sans-IO purity: $module is listed but missing — update the list or restore the file" >&2
        status=1
        continue
    fi
    if matches="$(scan_library_half "$module" | grep -E "$FORBIDDEN")"; then
        echo "sans-IO purity FAILED: $module reached for an ambient construct:" >&2
        echo "$matches" >&2
        echo "" >&2
        echo "These modules are the shared digest/verification cores. Ambient time," >&2
        echo "randomness, or IO in them forfeits deterministic simulation and makes the" >&2
        echo "two hosts able to disagree. Move the effect behind the sans-IO seam and" >&2
        echo "pass the value in." >&2
        status=1
    fi
done

if [ "$status" -ne 0 ]; then
    exit 1
fi
echo "sans-IO purity: ${#PURE_MODULES[@]} shared cores' library halves are free of ambient time, randomness, and IO"
