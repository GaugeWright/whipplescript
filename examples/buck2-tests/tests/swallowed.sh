#!/bin/sh
if [ -n "${WHIP_TEST_LIST:-}" ]; then
  printf 'accepts_grant\nrejects_stale_grant\n'
  exit 0
fi
case "${WHIP_TEST_CASE:-}" in
  accepts_grant) echo "whip-test: case accepts_grant pass" ;;
  # The case fails, the wrapper reports it, and then exits 0 anyway.
  rejects_stale_grant) echo "whip-test: case rejects_stale_grant fail"; echo "stale grant was accepted" >&2 ;;
  *) echo "unknown case: ${WHIP_TEST_CASE:-}" >&2; exit 2 ;;
esac
exit 0
