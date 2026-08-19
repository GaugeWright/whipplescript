#!/usr/bin/env bash
# Every third-party action this repository runs is pinned to a full 40-hex
# commit SHA, not a floating tag. A tag can be re-pointed after review to a
# different commit; a job that runs a re-pointed tag runs whatever that tag now
# resolves to. That is worst in publish-crates.yml, whose job holds
# CARGO_REGISTRY_TOKEN and performs the one release step with no undo, which is
# where a floating `actions/checkout@v4` sat unnoticed (SOC 2 3.1 / 6.6).
#
# This lints the whole workflow tree so a future floating tag re-fails here
# rather than at audit time. A local reusable workflow reference (`./...`) is
# this repository's own code and is exempt; everything else must carry an
# `@<40-hex>` pin. The human-readable `# vN` comment after the SHA is
# encouraged but not required by this gate.
set -euo pipefail
cd "$(dirname "$0")/.."

workflows_dir=".github/workflows"
[ -d "$workflows_dir" ] || {
    echo "no $workflows_dir; nothing to lint"
    exit 0
}

status=0
while IFS= read -r file; do
    # Match `uses:` lines, tolerating leading `- ` and arbitrary indentation.
    while IFS= read -r line; do
        ref="${line#*uses:}"
        ref="${ref#"${ref%%[![:space:]]*}"}"   # ltrim
        ref="${ref%%[[:space:]]*}"              # first token only (drop trailing comment)
        ref="${ref%\"}"; ref="${ref#\"}"        # strip optional quotes
        ref="${ref%\'}"; ref="${ref#\'}"
        [ -n "$ref" ] || continue

        # A local reusable workflow — this repository's own code, not a
        # third-party action — needs no SHA pin.
        case "$ref" in
            ./*) continue ;;
        esac

        # Everything else must be `owner/name@<40 lowercase hex>`.
        if [[ ! "$ref" =~ @[0-9a-f]{40}$ ]]; then
            echo "::error::unpinned action in $file: $ref (pin to a 40-hex commit SHA)" >&2
            status=1
        fi
    done < <(grep -E '^[[:space:]]*(-[[:space:]]+)?uses:' "$file" || true)
done < <(find "$workflows_dir" -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \))

if [ "$status" -ne 0 ]; then
    echo "workflow actions are not all SHA-pinned" >&2
    exit 1
fi
echo "all workflow actions are SHA-pinned"
