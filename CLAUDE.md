# CLAUDE.md

Orientation for an AI agent picking up this repo. Read this first, then
`README.md` (user-facing API) and `plan.md` (the original design + confirmed
rclone-compatibility assumptions — that file is the format authority for this
project).

## What this is

A Rust workspace that reads, seeks, streams, downloads, and uploads files in the
**rclone crypt** format, storage-independently. Primary use case: serve
images/seekable video from rclone-encrypted objects in S3/B2 over HTTP byte
ranges without downloading or decrypting the whole object first.

This project does **not** invent a format. rclone is the compatibility
authority, pinned to **rclone v1.74.2** (commit
`b22fe9811c672e4d226ae2c054d7c965d8783805`). Do not change on-disk behavior to
"improve" it — match rclone exactly, and prove it against the oracle.

## Workspace layout

| Path | Purpose |
|---|---|
| `crates/rclone-crypt` | Core: keys/KDF, content crypto, format math, filenames (AES-EME), ranges, `CryptReader`, downloads, `encrypt_to`. No AWS/HTTP deps. |
| `crates/rclone-crypt-aws` | `S3RangeSource`, `S3Uploader` (put + multipart), `StoreDoctor` for abandoned multipart cleanup. |
| `crates/rclone-crypt-http` | Framework-neutral HTTP `GET`/`HEAD`/single-range → streaming `http::Response`. |
| `examples/axum-proxy` | Runnable authenticated S3 → decrypt → HTTP image/video proxy. |

The core exposes storage backends through the `RangeSource` trait
(`size()` + `read_range(start..end)`, end-exclusive). Implement it to use any
backend; `MemorySource` exists for tests.

## Build / test / lint

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

- CI is `.github/workflows/ci.yml`: fmt, oracle-backed tests, clippy (`-D
  warnings`), and `cargo doc` with `RUSTDOCFLAGS=-D warnings`. All four must pass.
- **rclone oracle test** (`crates/rclone-crypt/tests/rclone_oracle.rs`) is
  gated on `RCLONE_TEST_BINARY` pointing at the pinned v1.74.2 binary; it skips
  (does not fail) when unset. `tests/oracle/install_rclone.sh` downloads and
  sha256-verifies it. This test drives compatibility **both directions**
  (rclone-encrypt → Rust-decrypt, and Rust-encrypt → rclone-decrypt).
- **Live B2 tests** are `#[ignore]` and need temporary `B2_*` env vars; see
  `tests/live-b2/README.md` and `tests/live-b2/run.sh`.
- MSRV split is intentional: core + http crates target **1.85**;
  `rclone-crypt-aws` and the example target **1.91.1** (AWS SDK needs it).

## Invariants that must not regress

- Format constants (`format.rs`): magic `RCLONE\0\0`, 32-byte header (8 magic +
  24 nonce), 65,536 plaintext chunk, 16-byte SecretBox overhead, 65,552 full
  chunk. Exact-multiple files have **no** empty terminal chunk; empty file is
  header-only.
- Nonce is a little-endian 192-bit integer, byte 0 first, carry toward byte 23
  (`add_nonce`).
- Every content chunk is authenticated (XSalsa20-Poly1305) **before** plaintext
  is returned. Wrong key and corruption both surface as `Error::Authentication`
  — never auto-delete an object on that basis.
- Empty primary password → all-zero keys (rclone special-case). Kept for compat,
  documented as insecure.
- Secrets (`Credential`, `Keys`, `NameCipher`) redact `Debug` and zeroize on drop.
- `#![forbid(unsafe_code)]` in every crate. Keep it.
- All size/range math is checked; return `Error::RangeOverflow`, never wrap.

## Recent work (2026-07-08 code review + fixes)

A full review was done; the crypto core was found solid (checked math, no unsafe,
zeroized secrets, bidirectional oracle tests). Fixes applied this session:

- **`CryptReader` retry misalignment**: a failed fetch used to leave
  `next_fetch_start` advanced, so a retry-after-error skipped a window and
  misaligned plaintext. Now rewinds to `position` on error. Regression test:
  `reader::tests::retry_after_transient_error_does_not_skip_a_window`.
- **`with_fetch_size` footgun**: windows above ~63.8 MiB mapped past the 64 MiB
  one-shot ciphertext cap and failed every read. Now clamped to `MAX_FETCH_SIZE`
  (63 MiB). Test: `fetch_size_is_clamped_to_a_safe_ceiling`.
- **`Error::AllocationFailed`**: `read_range` now reports `try_reserve` failure
  honestly instead of a mislabeled `RangeTooLarge`.
- **Example bearer auth**: constant-time compare (`subtle::ConstantTimeEq`).
- Minor: HTTP 405 now sends `Allow: GET, HEAD`; `download_to` fsyncs the parent
  dir after rename when `sync_data`; `encrypt_to` uses `FILE_HEADER_SIZE` not a
  literal `32`; `tempfile` deduped into workspace deps; crate description fixed;
  CI `push` scoped to `main`.

### Known follow-ups (deliberately not done — need their own tested pass)

1. **Per-chunk double allocation** in `object.rs::read_range`: `cipher.decrypt`
   allocates a Vec per 64 KiB chunk that's then copied into the output. Switching
   to `decrypt_in_place_detached` (with correct tag handling) would halve copies
   on the video-streaming hot path.
2. **`upload_reader` always multipart**: even a 1 KB stream does
   Create/Upload/Complete. Could buffer the first part and fall back to
   `PutObject` on early EOF.

## Security / handling notes

- `TESTING_CREDENTIALS.md` holds **live temporary B2 keys**, is gitignored, and
  must be revoked after testing. Do not commit it or echo its contents. The repo
  lives under a synced folder (`Sync/Hot/...`), so treat secrets accordingly.
- The library provides no authorization, tenant isolation, or path-traversal
  protection — those belong to the application (see the axum example for the
  pattern: reject empty/`.`/`..` segments before mapping names).
