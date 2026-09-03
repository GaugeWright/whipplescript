"""Advisory identities from one `cargo audit --json` or `npm audit --json` blob.

One line per advisory, `<ecosystem> <id>`, so the caller can compare two tree
states with `comm`. Identity is the ADVISORY, never the package version: a
`fast-uri` bump that clears GHSA-5jgf-p345-68v8 and a different advisory landing
against the same package are not the same event, and a set keyed by package name
would call them equal.

Reads stdin, writes stdout. An empty or malformed blob EXITS 3 rather than
printing nothing: "the audit found no advisories" and "the audit did not run"
produce the same empty set, and a caller comparing two tree states would read
the second as the first. That difference is the whole answer here -- an
unreadable BASE report makes every advisory in the tree look introduced by the
branch, which is a false accusation that blocks it.

Observed, not theorised: the second `cargo audit` of a run intermittently
produced nothing (the advisory database is fetched per invocation), and the
first version of this pair reported both of the tree's inherited RUSTSEC
warnings as introduced by a branch that changed no dependency.
"""

from __future__ import annotations

import json
import sys

# Exit code for "no report to read", distinct from a clean parse of zero
# advisories, which is exit 0 with no lines.
NO_REPORT = 3


def cargo_ids(report: dict) -> set[str]:
    found = set()
    for item in report.get("vulnerabilities", {}).get("list", []) or []:
        ident = (item.get("advisory") or {}).get("id")
        if ident:
            found.add(ident)
    # `warnings` carries unmaintained/yanked/unsound notices, keyed by kind.
    for notices in (report.get("warnings") or {}).values():
        for notice in notices or []:
            ident = (notice.get("advisory") or {}).get("id")
            if ident:
                found.add(ident)
    return found


def npm_ids(report: dict) -> set[str]:
    found = set()
    for entry in (report.get("vulnerabilities") or {}).values():
        for via in entry.get("via") or []:
            # A string `via` names another package that carries the advisory,
            # not an advisory: counting it would report one finding per hop.
            if isinstance(via, dict):
                ident = via.get("url") or via.get("source")
                if ident:
                    found.add(str(ident))
    return found


def main() -> int:
    ecosystem = sys.argv[1] if len(sys.argv) > 1 else "unknown"
    raw = sys.stdin.read().strip()
    if not raw:
        print("advisory_ids: the audit produced no output", file=sys.stderr)
        return NO_REPORT
    try:
        report = json.loads(raw)
    except json.JSONDecodeError:
        print("advisory_ids: the audit output is not JSON", file=sys.stderr)
        return NO_REPORT
    if not isinstance(report, dict):
        print("advisory_ids: the audit output is not a report object", file=sys.stderr)
        return NO_REPORT
    ids = cargo_ids(report) if ecosystem == "cargo" else npm_ids(report)
    for ident in sorted(ids):
        print(f"{ecosystem} {ident}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
