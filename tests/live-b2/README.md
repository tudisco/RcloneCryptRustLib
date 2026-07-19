# Live Backblaze B2 test

`run.sh` verifies the pinned real image and MP4, uploads them through rclone
crypt v1.74.2, decrypts raw B2 S3 objects with Rust, checks representative
ranges, performs atomic downloads, compares SHA-256, and removes its isolated
remote prefix on exit.

Required environment variables:

- `RCLONE_BIN` (must report v1.74.2)
- `B2_KEY_ID`
- `B2_APPLICATION_KEY`
- `B2_BUCKET`
- `B2_ENDPOINT` including `https://`
- `B2_REGION`

The script disables shell tracing and writes credentials only to a mode-600
temporary rclone config, which is removed by its exit trap. CI secrets must not
be supplied on a command line or printed in logs.

The AWS crate also contains an ignored live doctor test. It creates an
unfinished multipart upload with a 5 MiB part, verifies that dry-run leaves it
alone, aborts and verifies it, checks the reclaimed byte count, and repeats the
scan to prove idempotency:

```sh
B2_PREFIX=rclone-crypt-tests cargo test -p rclone-crypt-aws \
  doctor::tests::live_b2_abandoned_upload_cleanup -- --ignored --exact
```

For operations, `store_doctor` is dry-run unless `--apply` is present. A
non-empty `B2_PREFIX` and a grace period of at least one hour are mandatory:

```sh
DOCTOR_STALE_HOURS=24 cargo run -p rclone-crypt-aws --example store_doctor
DOCTOR_STALE_HOURS=24 cargo run -p rclone-crypt-aws --example store_doctor -- --apply
```

Set `DOCTOR_ACTIVE_UPLOAD_IDS` to a comma-separated list of upload IDs owned by
running application instances. Provider lifecycle cleanup should remain
enabled as the final safety net.
