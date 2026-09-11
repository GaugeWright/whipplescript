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
python3 scripts/check-host-action-contract-v3.py
cargo run --quiet -p whipplescript-kernel --example host_action_contract_v3 \
  | python3 scripts/check-host-action-contract-v3.py --reports

python3 scripts/check-host-action-contract-v4.py
cargo run --quiet -p whipplescript-kernel --example host_action_contract_v4 \
  | python3 scripts/check-host-action-contract-v4.py --reports

source scripts/lib-cargo-test.sh
action_report_dir="$(mktemp -d)"
scoped_action_report_dir="$(mktemp -d)"
recording_action_report_dir="$(mktemp -d)"
tracker_action_report_dir="$(mktemp -d)"
trap 'rm -rf "$action_report_dir" "$scoped_action_report_dir" "$recording_action_report_dir" "$tracker_action_report_dir"' EXIT
export WHIPPLESCRIPT_ACTION_REPORT_DIR="$action_report_dir"
export WHIPPLESCRIPT_SCOPED_ACTION_REPORT_DIR="$scoped_action_report_dir"
export WHIPPLESCRIPT_RECORDING_ACTION_REPORT_DIR="$recording_action_report_dir"
export WHIPPLESCRIPT_TRACKER_ACTION_REPORT_DIR="$tracker_action_report_dir"
cargo_test_named whipplescript versioned_save --test admitted_file_execution
cargo_test_named whipplescript host_action_human_and_agent_journey_matches_on_native_and_deployed_do_schema --test host_action_parity
cargo_test_named whipplescript governed_resolution_recording_has_the_same_native_and_hosted_journey --test resolution_recording
python3 scripts/check-host-action-contract.py --journey-dir "$action_report_dir"
python3 scripts/check-host-action-contract-v2.py --journey-dir "$scoped_action_report_dir"
python3 scripts/check-host-action-contract-v3.py --journey-dir "$recording_action_report_dir"

cargo_test_named whipplescript governed_tracker_ --test host_action_parity
python3 scripts/check-host-action-contract-v4.py --journey-dir "$tracker_action_report_dir"
