#!/usr/bin/env bash
set -euo pipefail

version=1.74.2
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)
    archive="rclone-v$version-linux-amd64.zip"
    expected="72a806370072015ccbe4d81bcd348cc5eaf3beca6c65ba693fd43fb31fcca5b1"
    ;;
  Darwin-arm64)
    archive="rclone-v$version-osx-arm64.zip"
    expected="e170fc4f225cbe3685695c4761259fe5883115a2b022a2f39b7298f946b8d898"
    ;;
  *)
    echo "unsupported rclone oracle platform: $(uname -s)-$(uname -m)" >&2
    exit 2
    ;;
esac

destination=${1:-"${TMPDIR:-/tmp}/rclone-v$version"}
mkdir -p "$destination"
curl -fsSL --retry 3 "https://downloads.rclone.org/v$version/$archive" \
  -o "$destination/$archive"

if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$destination/$archive" | awk '{print $1}')
else
  actual=$(shasum -a 256 "$destination/$archive" | awk '{print $1}')
fi
if [[ "$actual" != "$expected" ]]; then
  echo "rclone archive checksum mismatch" >&2
  exit 1
fi

unzip -q -o "$destination/$archive" -d "$destination"
binary=$(find "$destination" -type f -name rclone | head -1)
test -n "$binary"
chmod +x "$binary"
"$binary" version | head -1 >&2
printf '%s\n' "$binary"

