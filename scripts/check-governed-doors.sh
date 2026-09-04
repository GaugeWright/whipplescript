#!/usr/bin/env bash
# The governed-doors gate (DR-0091 W3): only the governed doors move refs.
#
# The versioned workspace's write surface — the selective/promotion engine
# methods and the reservation verbs — may be called only from the places
# this table pins: the engine's own file (implementation + its tests), the
# kernel's governed-door choreographies, and the named CLI operator
# commands. The engine lives in `whipplescript-store` and the doors in
# `whipplescript-kernel`, so Rust visibility cannot say "kernel only"
# across the crate boundary; this gate is the enforceable form of the
# tier rule. A NEW call site anywhere fails here and belongs behind a
# kernel door instead. A count that DROPS fails too — a stale pin reads
# as coverage the tree no longer has, so shrink the table with the diff
# that removes the caller.
#
# The pin is `file method expected-count` over `git grep -c "\.<method>("`
# on tracked *.rs files under crates/. Method definitions (`fn <method>`)
# do not match the pattern, so trait declarations and impls stay free.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

METHODS=(
    apply_undo_selection
    transport_selection
    promote_line_exact
    boundary_ref_evidence
    reserve_boundary
    record_ref_advanced
    close_promoted
    release_boundary
    acknowledge_boundary_release
    reserve_branch_head
    release_branch_head_reservation
)

# file|method|count — every call site of the governed write surface.
PINNED="\
crates/whipplescript-store/src/vcs.rs|apply_undo_selection|3
crates/whipplescript-kernel/src/effect_handlers.rs|apply_undo_selection|1
crates/whipplescript-cli/src/main.rs|apply_undo_selection|2
crates/whipplescript-store/src/vcs.rs|transport_selection|4
crates/whipplescript-kernel/src/effect_handlers.rs|transport_selection|1
crates/whipplescript-cli/src/main.rs|transport_selection|1
crates/whipplescript-store/src/vcs.rs|promote_line_exact|7
crates/whipplescript-kernel/src/effect_handlers.rs|promote_line_exact|2
crates/whipplescript-store/src/vcs.rs|boundary_ref_evidence|6
crates/whipplescript-kernel/src/effect_handlers.rs|boundary_ref_evidence|3
crates/whipplescript-store/src/workstreams.rs|reserve_boundary|7
crates/whipplescript-kernel/src/effect_handlers.rs|reserve_boundary|6
crates/whipplescript-store/src/workstreams.rs|record_ref_advanced|1
crates/whipplescript-kernel/src/effect_handlers.rs|record_ref_advanced|3
crates/whipplescript-store/src/workstreams.rs|close_promoted|2
crates/whipplescript-kernel/src/effect_handlers.rs|close_promoted|3
crates/whipplescript-store/src/workstreams.rs|release_boundary|6
crates/whipplescript-kernel/src/effect_handlers.rs|release_boundary|3
crates/whipplescript-store/src/workstreams.rs|acknowledge_boundary_release|7
crates/whipplescript-kernel/src/effect_handlers.rs|acknowledge_boundary_release|3
crates/whipplescript-host-do/src/do_workstreams.rs|acknowledge_boundary_release|4
crates/whipplescript-store/src/vcs.rs|reserve_branch_head|6
crates/whipplescript-kernel/src/effect_handlers.rs|reserve_branch_head|5
crates/whipplescript-kernel/src/effect_handlers.rs|release_branch_head_reservation|2
crates/whipplescript-cli/src/main_tests/tests/cli_surface.rs|reserve_boundary|2
crates/whipplescript-cli/src/main_tests/tests/cli_surface.rs|reserve_branch_head|1
crates/whipplescript-cli/src/main_tests/tests/cli_surface.rs|release_branch_head_reservation|1
crates/whipplescript-host-do/src/do_workstreams.rs|reserve_boundary|4
crates/whipplescript-host-do/src/do_workstreams.rs|release_boundary|4
crates/whipplescript-host-do/src/do_workstreams.rs|reserve_branch_head|4
crates/whipplescript-host-do/src/do_workstreams.rs|release_branch_head_reservation|3
crates/whipplescript-store/examples/workstream_receipt_reports.rs|close_promoted|1
crates/whipplescript-store/examples/workstream_receipt_reports.rs|promote_line_exact|1
crates/whipplescript-store/examples/workstream_receipt_reports.rs|record_ref_advanced|1
crates/whipplescript-store/examples/workstream_receipt_reports.rs|reserve_boundary|1
crates/whipplescript-store/examples/workstream_receipt_reports.rs|reserve_branch_head|1
crates/whipplescript-store/tests/mtarget_receipt_upgrade.rs|boundary_ref_evidence|1"

# workstream_receipt_reports is a schema-test emitter over in-memory/fixture
# stores only: no user-store argument, credentials, or additional host door.

# The DISPATCH half (DR-0091 W4): each host door must reach the kernel's one
# choreography and one renderer. These are free functions, so the pattern has
# no leading dot; the definitions do not match (their generic parameters sit
# between name and paren). A door that stops dispatching — rebuilding its own
# receipt shape — changes a count here, which is the lockstep-drift class the
# parity tests then catch in shape.
DISPATCH=(
    run_reserved_boundary_promotion_generic
    release_reserved_boundary_generic
    run_selective_verb_generic
    promote_effect_outcome
    selective_effect_outcome
)

DISPATCH_PINNED="\
crates/whipplescript-cli/src/main.rs|run_reserved_boundary_promotion_generic|1
crates/whipplescript-host-do/src/do_workstreams.rs|run_reserved_boundary_promotion_generic|1
crates/whipplescript-kernel/src/effect_handlers.rs|run_reserved_boundary_promotion_generic|11
crates/whipplescript-kernel/tests/mtarget_receipt_upgrade.rs|run_reserved_boundary_promotion_generic|1
crates/whipplescript-kernel/src/effect_handlers.rs|release_reserved_boundary_generic|9
crates/whipplescript-host-do/src/do_workstreams.rs|release_reserved_boundary_generic|6
crates/whipplescript-cli/src/main.rs|run_selective_verb_generic|1
crates/whipplescript-host-do/src/do_workstreams.rs|run_selective_verb_generic|1
crates/whipplescript-kernel/src/effect_handlers.rs|run_selective_verb_generic|7
crates/whipplescript-cli/src/main.rs|promote_effect_outcome|1
crates/whipplescript-host-do/src/do_workstreams.rs|promote_effect_outcome|1
crates/whipplescript-kernel/src/effect_handlers.rs|promote_effect_outcome|5
crates/whipplescript-cli/src/main.rs|selective_effect_outcome|1
crates/whipplescript-host-do/src/do_workstreams.rs|selective_effect_outcome|1
crates/whipplescript-kernel/src/effect_handlers.rs|selective_effect_outcome|1"

status=0
observed=""
for method in "${METHODS[@]}"; do
    while IFS=: read -r file count; do
        [ -n "$file" ] || continue
        observed+="${file}|${method}|${count}"$'\n'
    done < <(git grep -c "\.${method}(" -- 'crates/*.rs' 2>/dev/null || true)
done

dispatch_observed=""
for name in "${DISPATCH[@]}"; do
    while IFS=: read -r file count; do
        [ -n "$file" ] || continue
        dispatch_observed+="${file}|${name}|${count}"$'\n'
    done < <(git grep -c "${name}(" -- 'crates/*.rs' 2>/dev/null || true)
done

dispatch_expected_sorted="$(printf '%s\n' "$DISPATCH_PINNED" | sort)"
dispatch_observed_sorted="$(printf '%s' "$dispatch_observed" | sort)"
if [ "$dispatch_expected_sorted" != "$dispatch_observed_sorted" ]; then
    status=1
    echo "governed-doors gate: the door DISPATCH table changed." >&2
    echo >&2
    echo "  Every governed door dispatches to the kernel's one choreography and" >&2
    echo "  renderer (DR-0091 W4). '>' lines are dispatch sites the pin does not" >&2
    echo "  know; '<' lines are pinned dispatches the tree no longer has — a door" >&2
    echo "  that stopped dispatching is rebuilding its own receipt shape. Update" >&2
    echo "  the table only for deliberate door work." >&2
    echo >&2
    diff <(printf '%s\n' "$dispatch_expected_sorted") <(printf '%s\n' "$dispatch_observed_sorted") \
        | grep -E '^[<>]' | sed 's/^/  /' >&2 || true
fi

expected_sorted="$(printf '%s\n' "$PINNED" | sort)"
observed_sorted="$(printf '%s' "$observed" | sort)"

if [ "$expected_sorted" != "$observed_sorted" ]; then
    status=1
    echo "governed-doors gate: the write-surface caller table changed." >&2
    echo >&2
    echo "  Only the governed doors move refs (DR-0091). Lines below marked" >&2
    echo "  '>' are call sites the pin does not allow — route them through a" >&2
    echo "  kernel door in crates/whipplescript-kernel/src/effect_handlers.rs." >&2
    echo "  Lines marked '<' are pinned callers the tree no longer has —" >&2
    echo "  shrink the table in scripts/check-governed-doors.sh in the same" >&2
    echo "  change that removed them." >&2
    echo >&2
    diff <(printf '%s\n' "$expected_sorted") <(printf '%s\n' "$observed_sorted") \
        | grep -E '^[<>]' | sed 's/^/  /' >&2 || true
fi

exit "$status"
