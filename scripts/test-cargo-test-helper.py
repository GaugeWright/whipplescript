"""Prove named-test selection forwards libtest arguments and rejects zero matches."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="whip-test-helper-") as temporary:
    directory = Path(temporary)
    fake = directory / "fake.py"
    fake.write_text('''import json, os, sys
with open(os.environ["CALLS"], "a") as out: out.write(json.dumps(sys.argv[1:]) + "\\n")
if "--list" in sys.argv:
    print("fixture: test" if os.environ["MODE"] != "empty" else "0 tests")
else:
    sys.exit(7 if os.environ["MODE"] == "fail" else 0)
''')
    shell = 'cargo() { python3 "$FAKE" "$@"; }; source "$HELPER"; cargo_test_named "$@"'
    for mode, extra, expected_status in [
        ("pass", ["--lib"], 0),
        ("pass", ["--test", "norm_commands", "--", "--ignored", "--nocapture"], 0),
        ("empty", ["--test", "norm_commands", "--", "--ignored"], 1),
        ("fail", ["--lib", "--", "--exact"], 7),
    ]:
        calls = directory / "calls.jsonl"
        calls.write_text("")
        result = subprocess.run(["bash", "-c", shell, "fixture", "package", "named test", *extra],
            env={**os.environ, "FAKE": str(fake), "CALLS": str(calls), "MODE": mode,
                 "HELPER": str(ROOT / "scripts/lib-cargo-test.sh")}, capture_output=True, text=True)
        assert result.returncode == expected_status, (mode, result.stdout, result.stderr)
        actual = [json.loads(line) for line in calls.read_text().splitlines()]
        split = extra.index("--") if "--" in extra else len(extra)
        cargo_args, harness_args = extra[:split], extra[split + 1:]
        listing = ["test", "-q", "-p", "package", *cargo_args, "named test", "--", *harness_args, "--list"]
        execution = ["test", "-p", "package", *cargo_args, "named test", "--", *harness_args]
        assert actual == ([listing] if mode == "empty" else [listing, execution]), actual
print("cargo-test helper: ordinary, ignored, zero-match and execution-failure cases passed")
