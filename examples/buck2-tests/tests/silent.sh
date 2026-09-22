#!/bin/sh
# Lists one case, then says nothing about it.
if [ -n "${WHIP_TEST_LIST:-}" ]; then
  printf 'says_nothing\n'
  exit 0
fi
exit 0
