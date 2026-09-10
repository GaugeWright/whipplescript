#!/usr/bin/env bash
# Deep schema/codec correspondence, over the same vectors as the normal Rust test.
set -Eeuo pipefail
cd "$(dirname "$0")/.."
python3 scripts/check-host-action-contract.py
cargo run --quiet -p whipplescript-kernel --example host_action_contract \
  | python3 scripts/check-host-action-contract.py --reports
python3 scripts/check-host-action-contract-v2.py
cargo run --quiet -p whipplescript-kernel --example host_action_contract_v2 \
  | python3 scripts/check-host-action-contract-v2.py --reports

source scripts/lib-cargo-test.sh
action_report_dir="$(mktemp -d)"
scoped_action_report_dir="$(mktemp -d)"
trap 'rm -rf "$action_report_dir" "$scoped_action_report_dir"' EXIT
export WHIPPLESCRIPT_ACTION_REPORT_DIR="$action_report_dir"
export WHIPPLESCRIPT_SCOPED_ACTION_REPORT_DIR="$scoped_action_report_dir"
cargo_test_named whipplescript versioned_save --test admitted_file_execution
cargo_test_named whipplescript host_action_human_and_agent_journey_matches_on_native_and_deployed_do_schema --test host_action_parity
python3 scripts/check-host-action-contract.py --journey-dir "$action_report_dir"
python3 scripts/check-host-action-contract-v2.py --journey-dir "$scoped_action_report_dir"
