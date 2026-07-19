#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
cache="$root/tests/media/cache"
mkdir -p "$cache"

fetch() {
  local url=$1 output=$2 expected=$3
  if [[ ! -f "$output" ]]; then
    curl -fL --retry 3 --connect-timeout 20 "$url" -o "$output.part"
    mv "$output.part" "$output"
  fi
  local actual
  if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$output" | awk '{print $1}')
  else
    actual=$(shasum -a 256 "$output" | awk '{print $1}')
  fi
  if [[ "$actual" != "$expected" ]]; then
    echo "checksum mismatch for $output" >&2
    exit 1
  fi
}

fetch \
  "https://upload.wikimedia.org/wikipedia/commons/0/09/Soni_test_image.png" \
  "$cache/soni-test-image.png" \
  "408499e169ef1bde3c55316c1bd3c39b7f4a625b9b7190f9423ced39d69e1c8b"

fetch \
  "https://download.blender.org/peach/bigbuckbunny_movies/BigBuckBunny_320x180.mp4" \
  "$cache/big-buck-bunny-320x180.mp4" \
  "f78f39603e6774907f2faafabf26a667f4a6fc31769ec304a8a8f7c62d280508"

echo "media assets verified"

