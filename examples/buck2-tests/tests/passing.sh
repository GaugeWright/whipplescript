#!/bin/sh
if [ -n "${WHIP_TEST_LIST:-}" ]; then
  printf 'parses_empty\nparses_nested\n'
  exit 0
fi
case "${WHIP_TEST_CASE:-}" in
  parses_empty) echo "whip-test: case parses_empty pass" ;;
  parses_nested) echo "whip-test: case parses_nested pass" ;;
  *) echo "unknown case: ${WHIP_TEST_CASE:-}" >&2; exit 2 ;;
esac
