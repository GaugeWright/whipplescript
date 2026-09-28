#!/usr/bin/env bash
# A placed workspace must run its declared Buck bar. On a cold gate slot the
# daemon can still be walking the cells when the client's 90-second connection
# attempt expires. Wait for that one transient condition instead of running a
# second bar or treating a host that cannot start Buck as a code failure.
set -euo pipefail

expected="whipplescript: $(pwd -P)"
deadline=$((SECONDS + ${WHIPPLESCRIPT_BUCK_READY_SECONDS:-900}))
while :; do
  if audit="$(buck2 audit cell 2>&1)"; then
    if grep -qxF "$expected" <<< "$audit"; then
      exit 0
    fi
    printf 'buck2 did not place this checkout as %s:\n%s\n' "$expected" "$audit" >&2
    exit 126
  fi
  if [[ "$audit" != *"Failed to connect to buck daemon"* ]]; then
    printf 'buck2 could not inspect this cell:\n%s\n' "$audit" >&2
    exit 126
  fi
  if (( SECONDS >= deadline )); then
    printf 'buck2 daemon did not become ready within the gate startup window:\n%s\n' "$audit" >&2
    exit 126
  fi
  printf 'buck2 daemon is starting; waiting for this placed cell\n' >&2
  sleep 2
done
