#!/usr/bin/env bash
# `ci.yml` is path-skipped for documentation-only pull requests, and the two
# required status checks live in it, so `ci-docs-gate.yml` reports them instead.
# That only works while the two path filters are exact complements and the job
# names match: drift either way makes a docs-only pull request unmergeable
# again, silently, because a required check that never runs reads as missing
# rather than failing.
#
# This runs inside the green bar. An edit to either workflow is itself outside
# the ignore list, so the check always runs on the change that could break it.
set -euo pipefail
cd "$(dirname "$0")/.."

python3 - <<'PY'
import sys

try:
    import yaml
except ModuleNotFoundError:
    sys.exit("pyyaml is not installed; run: pip install -r requirements-dev.txt")


def load(path):
    with open(path) as handle:
        return yaml.safe_load(handle)


ci = load(".github/workflows/ci.yml")
gate = load(".github/workflows/ci-docs-gate.yml")

# `on` is the YAML 1.1 boolean True once parsed, which is why this is not `["on"]`.
ci_on = ci.get(True, ci.get("on"))
gate_on = gate.get(True, gate.get("on"))

problems = []

ignored = ci_on["pull_request"]["paths-ignore"]
covered = gate_on["pull_request"]["paths"]
if sorted(ignored) != sorted(covered):
    problems.append(
        "ci.yml pull_request paths-ignore and ci-docs-gate.yml pull_request paths "
        "must be the same set, so exactly one workflow starts per pull request.\n"
        f"  only in ci.yml:           {sorted(set(ignored) - set(covered))}\n"
        f"  only in ci-docs-gate.yml: {sorted(set(covered) - set(ignored))}"
    )

# The required contexts are matched by job name, so the gate must name every job
# it stands in for. Keep this list in step with branch protection on `main`.
required = {"green-bar", "hosted-runtime-contracts"}
for path, doc in ((".github/workflows/ci.yml", ci), (".github/workflows/ci-docs-gate.yml", gate)):
    missing = required - set(doc["jobs"])
    if missing:
        problems.append(f"{path} is missing required job(s): {sorted(missing)}")

if problems:
    sys.exit("\n\n".join(problems))

print("ci docs gate: path filters are complements and required jobs are named in both")
PY
