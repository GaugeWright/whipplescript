#!/usr/bin/env python3
"""Check tracker result publication and deliberate weakenings with Apalache."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / "models/tla/TrackerResultDelivery.tla"


def checker():
    if binary := shutil.which("apalache-mc"):
        return [binary]
    if binary := shutil.which("nix"):
        return [binary, "--extra-experimental-features", "nix-command flakes",
                "develop", str(ROOT), "--command", "apalache-mc"]
    raise SystemExit("apalache-mc not found and nix is unavailable")


def check(command, folder, source, invariant, expect_violation):
    folder.mkdir()
    model = folder / MODEL.name
    model.write_text(source)
    result = subprocess.run(
        [*command, "check", "--init=Init", "--next=Next",
         f"--inv={invariant}", "--length=7", str(model)],
        cwd=folder, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        check=False,
    )
    (folder / "check.log").write_text(result.stdout)
    violated = "The outcome is: Error" in result.stdout
    passed = result.returncode == 0 and "The outcome is: NoError" in result.stdout
    if (expect_violation and (result.returncode == 0 or not violated)) or (
        not expect_violation and not passed
    ):
        print(result.stdout, file=sys.stderr)
        raise SystemExit(f"unexpected checker outcome: {folder}")
    print(f"{folder.name}: {'expected invariant violation' if violated else 'holds through 7 transitions'}",
          flush=True)


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise SystemExit(f"mutation anchor must occur exactly once: {old}")
    return source.replace(old, new)


def main():
    command = checker()
    source = MODEL.read_text()
    # Preserve failed-check evidence, independently of any prior invocation.
    reports = ROOT / "target/tracker-result-delivery"
    reports.mkdir(parents=True, exist_ok=True)
    folder = Path(tempfile.mkdtemp(prefix="check-", dir=reports))
    print(f"Tracker result model reports: {folder}", flush=True)
    check(command, folder / "baseline", source, "SafetyInvariants", False)
    for guard in ["current-authority", "exact-receipt", "committed-receipt",
                  "live-workflow", "unhandled-failure", "one-result", "ownership", "head-cas"]:
        lines = [line for line in source.splitlines() if f"GUARD {guard}" in line]
        if len(lines) != 1:
            raise SystemExit(f"expected one guard anchor for {guard}")
        changed = replace_once(source, lines[0] + "\n", "")
        check(command, folder / guard, changed, "SafetyInvariants", True)
    for name, old, new in [
        ("preserve-terminal", 'run\' = IF run = "running" THEN "completed" ELSE run',
         'run\' = "completed"'),
        ("atomic-result", "successFact' = TRUE", "successFact' = FALSE"),
        ("atomic-evidence", "appliedEvidence' = TRUE", "appliedEvidence' = FALSE"),
    ]:
        check(command, folder / name, replace_once(source, old, new), "SafetyInvariants", True)
    check(command, folder / "reachable-recovery", source, "NoRecoveredExpired", True)


if __name__ == "__main__":
    main()
