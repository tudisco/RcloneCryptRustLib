#!/usr/bin/env bash
set -euo pipefail
set +x

required=(RCLONE_BIN B2_KEY_ID B2_APPLICATION_KEY B2_BUCKET B2_ENDPOINT B2_REGION)
for name in "${required[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    echo "missing required environment variable: $name" >&2
    exit 2
  fi
done

version=$($RCLONE_BIN version | head -1)
if [[ "$version" != "rclone v1.74.2" ]]; then
  echo "expected rclone v1.74.2, got $version" >&2
  exit 2
fi

root=$(cd "$(dirname "$0")/../.." && pwd)
"$root/tests/media/fetch.sh"

run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
prefix="rclone-crypt-tests/$run_id"
config=$(mktemp "${TMPDIR:-/tmp}/rclone-crypt-b2.XXXXXX.conf")
output="$root/tests/live-b2/output/$run_id"
password="rclone-rust-live-test-password-$run_id"
salt="rclone-rust-live-test-salt-ü-$run_id"
mkdir -p "$output"
chmod 600 "$config"

cleanup() {
  "$RCLONE_BIN" --config "$config" purge "b2:$B2_BUCKET/$prefix" >/dev/null 2>&1 || true
  rm -f "$config"
}
trap cleanup EXIT INT TERM

"$RCLONE_BIN" --config "$config" config create b2 s3 \
  provider Other env_auth false access_key_id "$B2_KEY_ID" \
  secret_access_key "$B2_APPLICATION_KEY" endpoint "$B2_ENDPOINT" \
  region "$B2_REGION" force_path_style true >/dev/null

obscured_password=$($RCLONE_BIN obscure "$password")
obscured_salt=$($RCLONE_BIN obscure "$salt")
"$RCLONE_BIN" --config "$config" config create crypt crypt \
  remote "b2:$B2_BUCKET/$prefix" password "$obscured_password" \
  password2 "$obscured_salt" filename_encryption standard \
  directory_name_encryption true filename_encoding base32 >/dev/null

"$RCLONE_BIN" --config "$config" copy "$root/tests/media/cache" crypt: \
  --include soni-test-image.png --include big-buck-bunny-320x180.mp4 \
  --transfers 2 --checkers 2

verify() {
  local filename=$1
  local encrypted
  encrypted=$($RCLONE_BIN --config "$config" backend encode crypt: "$filename")
  B2_OBJECT_KEY="$prefix/$encrypted" \
  RCLONE_PASSWORD="$password" \
  RCLONE_SALT="$salt" \
  EXPECTED_PLAINTEXT="$root/tests/media/cache/$filename" \
  OUTPUT_PATH="$output/$filename" \
  cargo run --quiet --manifest-path "$root/Cargo.toml" \
    -p rclone-crypt-aws --example b2_smoke
}

verify soni-test-image.png
verify big-buck-bunny-320x180.mp4

verify_rust_upload() {
  local source_filename=$1 plaintext_name=$2
  B2_PREFIX="$prefix" \
  PLAINTEXT_NAME="$plaintext_name" \
  PLAINTEXT_PATH="$root/tests/media/cache/$source_filename" \
  RCLONE_PASSWORD="$password" \
  RCLONE_SALT="$salt" \
  cargo run --quiet --manifest-path "$root/Cargo.toml" \
    -p rclone-crypt-aws --example b2_upload_smoke

  "$RCLONE_BIN" --config "$config" copyto \
    "crypt:$plaintext_name" "$output/rclone-$source_filename"
  if ! cmp -s \
    "$root/tests/media/cache/$source_filename" \
    "$output/rclone-$source_filename"; then
    echo "rclone download differs after Rust upload: $plaintext_name" >&2
    exit 1
  fi
  echo "rclone authenticated Rust upload: $plaintext_name"
}

verify_rust_upload soni-test-image.png "rust-upload-üñícode-image.png"
verify_rust_upload big-buck-bunny-320x180.mp4 "rust-upload-video.mp4"

echo "bidirectional live B2 rclone crypt validation passed under $prefix"
