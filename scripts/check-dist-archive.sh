#!/usr/bin/env bash
# dispatch: scripts/release-fleet.sh runs it on the packaged Linux and Windows archives before a release is published; it needs built archives, so it is outside the bar.
set -euo pipefail

if [[ "$#" -ne 1 ]]; then
  echo "usage: $0 <archive>" >&2
  exit 2
fi

archive="$1"
if [[ ! -f "$archive" ]]; then
  echo "archive not found: $archive" >&2
  exit 1
fi

tmp="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp"
}
trap cleanup EXIT

case "$archive" in
  *.tar.xz)
    tar -xf "$archive" -C "$tmp"
    ;;
  *.zip)
    if command -v unzip >/dev/null 2>&1; then
      unzip -q "$archive" -d "$tmp"
    elif command -v powershell.exe >/dev/null 2>&1; then
      archive_path="$archive"
      tmp_path="$tmp"
      if command -v cygpath >/dev/null 2>&1; then
        archive_path="$(cygpath -w "$archive")"
        tmp_path="$(cygpath -w "$tmp")"
      fi
      powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \
        "Expand-Archive -LiteralPath '${archive_path}' -DestinationPath '${tmp_path}' -Force"
    else
      echo "cannot extract zip archive; install unzip or PowerShell" >&2
      exit 1
    fi
    ;;
  *)
    echo "unsupported archive format: $archive" >&2
    exit 1
    ;;
esac

exe="$(find "$tmp" -type f \( -name whip -o -name whip.exe \) | head -n 1)"
if [[ -z "$exe" ]]; then
  echo "archive does not contain whip executable: $archive" >&2
  find "$tmp" -maxdepth 3 -type f -print >&2
  exit 1
fi

chmod +x "$exe" 2>/dev/null || true

"$exe" --version
"$exe" doctor --json >/dev/null
"$exe" check examples/minimal-noop.whip >/dev/null
"$exe" --json doctor \
  --provider-config examples/provider-configs/native/native.example.json >/dev/null
