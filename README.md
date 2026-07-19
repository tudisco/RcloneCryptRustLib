# rclone-crypt for Rust

Production-oriented, asynchronous Rust support for reading, seeking, streaming,
downloading, and uploading files in the **rclone crypt** format.

The main use case is an application that stores rclone-encrypted files in S3 or
an S3-compatible service and needs to serve images, seekable video, or arbitrary
HTTP byte ranges without downloading or decrypting the complete object first.
The cryptographic core is storage-independent. AWS S3 support and HTTP response
helpers live in separate crates.

This project does not define a new encryption format. **rclone is the format and
compatibility authority.** The implementation was derived from rclone's
documentation, source code, and executable behavior, and interoperability tests
are pinned to rclone v1.74.2.

- [rclone crypt documentation](https://rclone.org/crypt/)
- [rclone v1.74.2 source: crypt cipher](https://github.com/rclone/rclone/blob/v1.74.2/backend/crypt/cipher.go)
- [rclone v1.74.2 release](https://github.com/rclone/rclone/releases/tag/v1.74.2)
- [rclone password obscuring source](https://github.com/rclone/rclone/blob/v1.74.2/fs/config/obscure/obscure.go)
- [AES-EME filename algorithm used by rclone](https://github.com/rfjakob/eme)

## Features

- Exact rclone password and password2/salt derivation using scrypt.
- Clear and rclone-obscured credentials.
- Authenticated XSalsa20-Poly1305/NaCl SecretBox content decryption.
- Authentication failure and structural-corruption detection.
- Constant-time plaintext-size calculation from encrypted object size.
- Plaintext-to-ciphertext range mapping.
- Bounded-memory asynchronous sequential reads.
- Tokio `AsyncRead` and `AsyncSeek` support.
- Optional one-window prefetch/double buffering for sequential streams.
- Atomic authenticated downloads to local files.
- Streaming rclone-compatible encryption and uploads.
- Standard AES-256-EME filename encryption/decryption.
- Lowercase, unpadded base32hex filename encoding and Unicode paths.
- Optional AWS S3/Backblaze B2 range source and multipart uploader.
- Replay-safe multipart part retries and verified multipart aborts.
- Dry-run S3 store doctor for abandoned multipart uploads.
- Framework-neutral HTTP `GET`, `HEAD`, and single-range responses.
- Runnable Axum video/image proxy example.
- Differential tests against pinned rclone and live Backblaze B2 tests.
- No `unsafe` code.

## Workspace crates

| Crate | Purpose |
|---|---|
| `rclone-crypt` | Storage-independent keys, format, content crypto, names, ranges, readers, downloads, and encryption. |
| `rclone-crypt-aws` | AWS SDK `RangeSource`, S3 uploads, multipart recovery, and store doctor. |
| `rclone-crypt-http` | HTTP range parsing and streaming response construction. |
| `examples/axum-proxy` | Complete S3 → rclone decrypt → HTTP image/video proxy. |

The AWS SDK is not a dependency of `rclone-crypt`. Applications can use the core
with any object store, database, local file abstraction, or custom transport by
implementing `RangeSource`.

### Public API index

| Crate | Public API |
|---|---|
| `rclone-crypt` | `Credential`, `Keys`, `Error`, `Result`, `RangeSource`, `MemorySource`, `RcloneCryptObject`, `CryptReader`, `DownloadOptions`, `NameCipher`, `Header`, `EncryptionStats`, `encrypt_to`, `encrypted_size`, `plaintext_size`, and format constants. |
| `rclone-crypt-aws` | `S3RangeSource`, `S3Uploader`, `UploadOptions`, `UploadResult`, `StoreDoctor`, `DoctorOptions`, `DoctorReport`, `DoctorFinding`, `DoctorFailure`, and `FindingDisposition`. |
| `rclone-crypt-http` | `ByteRange`, `RangeError`, `ProxyBody`, `parse_range`, and `serve`. |

## Status and compatibility

The current compatibility oracle is **rclone v1.74.2**, release commit
`b22fe9811c672e4d226ae2c054d7c965d8783805`. The implemented content format is:

| Property | Value |
|---|---|
| Magic | `RCLONE\0\0` |
| Initial nonce | 24 bytes |
| Header | 32 bytes total |
| Plaintext chunk | 65,536 bytes |
| Authentication overhead | 16 bytes per chunk |
| Full encrypted chunk | 65,552 bytes |
| Nonce progression | Little-endian 192-bit increment, byte 0 first |
| Content cipher | XSalsa20-Poly1305 SecretBox |
| KDF | scrypt `N=16384, r=8, p=1`, 80-byte output |
| Filename mode | rclone `standard`, AES-256-EME |
| Filename encoding | lowercase unpadded base32hex |

The exact-multiple case has no empty terminal block. An empty plaintext object is
only the 32-byte header. A final partial block contains its plaintext plus the
16-byte SecretBox authenticator.

Current filename support is rclone's standard filename encryption and default
base32hex encoding. The `off`, `obfuscate`, base64, and base32768 filename modes
are not implemented.

## Installation

Until the crates are published, use workspace path dependencies:

```toml
[dependencies]
rclone-crypt = { path = "crates/rclone-crypt" }
rclone-crypt-aws = { path = "crates/rclone-crypt-aws" }
rclone-crypt-http = { path = "crates/rclone-crypt-http" }

async-trait = "0.1"
aws-config = "1"
aws-sdk-s3 = "1"
bytes = "1"
http = "1"
tokio = { version = "1", features = ["fs", "io-util", "macros", "rt-multi-thread"] }
```

Use only the crates needed by the application. A custom storage integration
normally needs only `rclone-crypt`, `async-trait`, and `bytes`.

## Quick start: decrypt an S3 object

```rust,no_run
use std::sync::Arc;

use aws_config::BehaviorVersion;
use aws_sdk_s3::Client;
use rclone_crypt::{Credential, Keys, RcloneCryptObject};
use rclone_crypt_aws::S3RangeSource;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Credentials belong to the host application: environment variables,
    // a secret manager, an injected credentials provider, etc.
    let password = Credential::Clear(std::env::var("RCLONE_CRYPT_PASSWORD")?);
    let salt = Credential::Clear(std::env::var("RCLONE_CRYPT_SALT")?);
    let keys = Keys::derive(&password, Some(&salt))?;

    let config = aws_config::defaults(BehaviorVersion::latest()).load().await;
    let client = Client::new(&config);
    let source = Arc::new(S3RangeSource::new(
        client,
        "media-bucket",
        "encrypted-prefix/encrypted-object-name",
    ));
    let object = Arc::new(RcloneCryptObject::open(source, keys).await?);

    let mut reader = object.reader();
    reader.seek(std::io::SeekFrom::Start(1_000_000)).await?;
    let mut bytes = vec![0; 64 * 1024];
    reader.read_exact(&mut bytes).await?;
    Ok(())
}
```

Construct an optional salt when the host application permits it to be absent:

```rust
# use rclone_crypt::Credential;
let salt = std::env::var("RCLONE_CRYPT_SALT")
    .ok()
    .map(Credential::Clear);
```

If `password2` is absent or empty, pass `None`; rclone's fixed default salt is
then used.

## Credentials and key derivation

`Credential` deliberately distinguishes clear and rclone-obscured values:

```rust
use rclone_crypt::{Credential, Keys};

let clear = Credential::Clear("correct horse battery staple".to_owned());
let salt = Credential::Clear("separate password2".to_owned());
let keys = Keys::derive(&clear, Some(&salt))?;

let from_rclone_config = Credential::Obscured(
    "an-output-value-from-rclone-obscure".to_owned(),
);
# Ok::<(), rclone_crypt::Error>(())
```

The library never guesses whether a value is obscured. `Credential` and `Keys`
redact `Debug` output and zeroize owned secret material on drop. Rclone
obscuring is reversible configuration obfuscation, not password encryption; do
not treat an obscured value as safe to publish.

`Keys::derive` implements the rclone split exactly:

- bytes `0..32`: content key;
- bytes `32..64`: filename AES key;
- bytes `64..80`: filename EME tweak.

An empty primary password follows rclone behavior and produces all-zero key
material. It is supported for compatibility and should not be used for secure
storage.

## Storage abstraction: `RangeSource`

Implement this trait to connect the core to another backend:

```rust
use std::ops::Range;
use async_trait::async_trait;
use bytes::Bytes;
use rclone_crypt::{RangeSource, Result};

struct MyStorage;

#[async_trait]
impl RangeSource for MyStorage {
    async fn size(&self) -> Result<u64> {
        todo!("return the immutable encrypted object size")
    }

    async fn read_range(&self, range: Range<u64>) -> Result<Bytes> {
        todo!("return exactly range.end - range.start bytes")
    }
}
```

The contract is:

- ranges are end-exclusive: `start..end`;
- `start <= end <= size`;
- an empty range returns empty bytes;
- a successful non-empty call returns exactly the requested byte count;
- the source must represent one stable object for the reader's lifetime;
- implementations should convert confirmed absence to `Error::SourceNotFound`
  and other backend failures to `Error::Source`.

`MemorySource::new(bytes)` is provided for tests and small in-memory objects.

## Opening an encrypted object

```rust
use std::sync::Arc;
use rclone_crypt::{Credential, Keys, MemorySource, RcloneCryptObject};

# async fn example(ciphertext: Vec<u8>) -> rclone_crypt::Result<()> {
let keys = Keys::derive(&Credential::Clear("password".into()), None)?;
let source = Arc::new(MemorySource::new(ciphertext));
let object = Arc::new(RcloneCryptObject::open(source, keys).await?);
println!("plaintext bytes: {}", object.plaintext_len());
# Ok(()) }
```

`RcloneCryptObject::open` reads the source size and 32-byte header. It validates
the structural size and magic immediately. Content authentication occurs when
each requested block is decrypted.

### One-shot plaintext ranges

```rust
# use std::sync::Arc;
# use rclone_crypt::{MemorySource, RcloneCryptObject};
# async fn example(object: Arc<RcloneCryptObject<MemorySource>>) -> rclone_crypt::Result<()> {
let bytes = object.read_range(1_000_000..1_100_000).await?;
# Ok(()) }
```

The returned bytes are authenticated. A one-shot request maps to complete
encrypted chunks and is capped at 64 MiB of mapped ciphertext to prevent an
unbounded allocation. Use `CryptReader`, `copy_to`, or repeated ranges for large
streams.

### Sequential reading and seeking

`RcloneCryptObject::reader` returns `CryptReader`, which implements Tokio
`AsyncRead` and `AsyncSeek`:

```rust
use std::{io::SeekFrom, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
# use rclone_crypt::{MemorySource, RcloneCryptObject};

# async fn example(object: Arc<RcloneCryptObject<MemorySource>>) -> std::io::Result<()> {
let mut reader = object
    .reader()
    .with_fetch_size(2 * 1024 * 1024)
    .with_prefetch(true);

reader.seek(SeekFrom::End(-128 * 1024)).await?;
let mut tail = Vec::new();
reader.read_to_end(&mut tail).await?;
assert_eq!(reader.position(), object.plaintext_len());
# Ok(()) }
```

- Default fetch size: 1 MiB.
- `with_fetch_size` is clamped to `1..=63 MiB` so a window can never exceed the
  64 MiB one-shot ciphertext cap and fail at fetch time.
- Prefetch is enabled by default.
- At most the current and next bounded window are retained.
- Seeking discards buffered and speculative data.
- A seek may target any position from zero through EOF.
- Reader errors are surfaced as `std::io::Error` whose source contains the core
  error.

Disable prefetch for small isolated probes. HTTP range handling does this
automatically.

## Streaming and downloading

Stream the complete authenticated plaintext into any Tokio writer:

```rust
# use rclone_crypt::{MemorySource, RcloneCryptObject};
# async fn example(object: &RcloneCryptObject<MemorySource>) -> rclone_crypt::Result<()> {
let mut output = tokio::fs::File::create("output.bin").await.unwrap();
let written = object.copy_to(&mut output).await?;
# Ok(()) }
```

`copy_to` uses bounded double buffering: it writes the current authenticated
batch while fetching and authenticating the next batch. The caller owns rollback
if the writer or a later encrypted chunk fails.

For filesystem publication, prefer `download_to`:

```rust
use rclone_crypt::DownloadOptions;
# use rclone_crypt::{MemorySource, RcloneCryptObject};
# async fn example(object: &RcloneCryptObject<MemorySource>) -> rclone_crypt::Result<()> {
let count = object.download_to(
    "downloads/movie.mp4",
    DownloadOptions {
        overwrite: true,
        create_parent: true,
        sync_data: true,
    },
).await?;
# Ok(()) }
```

`DownloadOptions` fields:

| Field | Default | Meaning |
|---|---:|---|
| `overwrite` | `false` | Permit atomic replacement of an existing destination. |
| `create_parent` | `true` | Create missing parent directories. |
| `sync_data` | `false` | `sync_all` the file, and fsync the parent directory after the rename, before returning. |

The download is written to a sibling temporary file and published only after
all chunks authenticate and the write completes. Cancellation or error removes
the temporary file. If replacement fails, the existing destination is retained.

## Filename encryption and Unicode paths

`NameCipher` implements rclone's standard AES-256-EME filename mode:

```rust
use rclone_crypt::{Credential, Keys, NameCipher};

let keys = Keys::derive(&Credential::Clear("password".into()), None)?;
let names = NameCipher::new(&keys);

let encrypted = names.encrypt_path("películas/東京/mañana 🎬.mp4")?;
let plaintext = names.decrypt_path(&encrypted)?;
assert_eq!(plaintext, "películas/東京/mañana 🎬.mp4");
# Ok::<(), rclone_crypt::Error>(())
```

Available methods:

- `encrypt_path` and `decrypt_path`: transform each `/`-separated segment;
- `encrypt_segment` and `decrypt_segment`: transform one segment;
- empty segments remain empty;
- encrypted input accepts upper- or lowercase base32hex but rejects `=` padding;
- a padded EME segment may not exceed rclone's 2,048-byte limit;
- decrypted filename bytes must be valid UTF-8.

The core performs lexical transformation only. Applications mapping names to a
filesystem or URL must independently reject traversal (`.`, `..`), empty
segments where inappropriate, control characters, and platform-specific unsafe
names.

## Streaming encryption

Use `encrypt_to` when the destination is not S3:

```rust
use rclone_crypt::{Credential, Keys, encrypt_to};

# async fn example() -> rclone_crypt::Result<()> {
let keys = Keys::derive(&Credential::Clear("password".into()), None)?;
let mut input = tokio::fs::File::open("movie.mp4").await.unwrap();
let mut output = tokio::fs::File::create("movie.mp4.bin").await.unwrap();
let stats = encrypt_to(&mut input, &mut output, &keys).await?;
println!("{} plaintext bytes, {} encrypted bytes, {} chunks",
    stats.plaintext_bytes, stats.encrypted_bytes, stats.chunks);
# Ok(()) }
```

`encrypt_to` generates a fresh cryptographically secure 24-byte nonce and emits
the exact rclone content format. It does not encrypt an object name; use
`NameCipher` separately.

## Size and header APIs

The core exports:

- `FILE_MAGIC`: `RCLONE\0\0`;
- `FILE_HEADER_SIZE`: 32;
- `BLOCK_DATA_SIZE`: 65,536;
- `BLOCK_SIZE`: 65,552;
- `encrypted_size(plaintext_len)`;
- `plaintext_size(encrypted_len)`;
- `Header::parse(bytes)`;
- `Header::nonce_for_chunk(index)`.

All size calculations are checked and return `Error::RangeOverflow` rather than
wrapping.

## AWS S3 and compatible storage

`S3RangeSource` converts the end-exclusive core contract to S3's inclusive HTTP
Range syntax. It performs `HeadObject`, pins the observed ETag/version when
possible, validates `Content-Range`, and rejects short responses.

```rust
use rclone_crypt_aws::S3RangeSource;
# use aws_sdk_s3::Client;
# fn example(client: Client) {
let source = S3RangeSource::new(client, "bucket", "encrypted/key")
    .with_expected_etag("\"known-etag\"");

// For a versioned bucket, pin an immutable version instead:
// let source = source.with_version_id("version-id");
# }
```

Methods `bucket()` and `key()` expose the configured identifiers. Credentials
are supplied to `aws_sdk_s3::Client` by the application; this library does not
store global credentials or prescribe a credential source.

For Backblaze B2 and other custom endpoints, configure the AWS client explicitly:

```rust,no_run
use aws_config::{BehaviorVersion, Region};
use aws_sdk_s3::Client;

# async fn example() {
let shared = aws_config::defaults(BehaviorVersion::latest())
    .region(Region::new("us-east-005"))
    .endpoint_url("https://s3.us-east-005.backblazeb2.com")
    .load()
    .await;
let config = aws_sdk_s3::config::Builder::from(&shared)
    .force_path_style(true)
    .build();
let client = Client::from_conf(config);
# }
```

## S3 uploads

Encrypt and upload a local file:

```rust,no_run
use rclone_crypt::{Credential, Keys, NameCipher};
use rclone_crypt_aws::{S3Uploader, UploadOptions};
# use aws_sdk_s3::Client;

# async fn example(client: Client) -> rclone_crypt::Result<()> {
let keys = Keys::derive(&Credential::Clear("password".into()), None)?;
let encrypted_name = NameCipher::new(&keys).encrypt_path("video/movie.mp4")?;
let uploader = S3Uploader::new(client, "bucket");
let result = uploader.upload_file_with_options(
    "movie.mp4",
    encrypted_name,
    &keys,
    UploadOptions::default(),
).await?;
println!("ETag: {:?}, version: {:?}", result.etag, result.version_id);
# Ok(()) }
```

`upload_file` uses default options. It encrypts with bounded memory into a secure
temporary spool, then chooses `PutObject` or multipart upload based on encrypted
size. The spool makes every multipart part replayable.

Stream an unknown-length Tokio reader directly into multipart S3:

```rust,no_run
# use aws_sdk_s3::Client;
# use rclone_crypt::{Credential, Keys};
# use rclone_crypt_aws::{S3Uploader, UploadOptions};
# async fn example(client: Client) -> rclone_crypt::Result<()> {
let keys = Keys::derive(&Credential::Clear("password".into()), None)?;
let mut input = tokio::fs::File::open("movie.mp4").await.unwrap();
let result = S3Uploader::new(client, "bucket")
    .upload_reader(
        &mut input,
        "already-encrypted-object-name",
        &keys,
        UploadOptions::default(),
    )
    .await?;
# Ok(()) }
```

`upload_reader` encrypts through a bounded in-memory pipe. Each complete part is
held only while being uploaded and retried. Backpressure reaches the plaintext
reader.

`UploadOptions` defaults:

| Field | Default | Meaning |
|---|---:|---|
| `multipart_threshold` | 16 MiB | Spool upload switches from `PutObject` to multipart. |
| `part_size` | 8 MiB | Multipart buffer size; minimum 5 MiB. |
| `max_part_attempts` | 3 | Outer attempts for each replayable `UploadPart`. |
| `max_abort_attempts` | 3 | Abort plus `ListParts` verification attempts. |
| `retry_base_delay` | 200 ms | Initial capped exponential-backoff delay. |

The AWS SDK's own retry policy still applies inside each outer attempt.
`UploadResult` contains `encrypted_key`, `EncryptionStats`, optional `etag`, and
optional `version_id`.

On multipart failure, the uploader repeatedly calls `AbortMultipartUpload` and
checks `ListParts`. If cleanup cannot be verified, the returned error includes
both the primary upload failure and cleanup failure. A cancellation guard also
starts best-effort verified cleanup when an upload future is dropped. Provider
lifecycle rules for unfinished multipart uploads should still be enabled.

## Store doctor

`StoreDoctor` finds abandoned multipart uploads and optionally cleans them.
Safety defaults are intentional:

- dry-run unless `apply` is true;
- non-empty prefix is mandatory;
- minimum grace period is one hour;
- default grace period is 24 hours;
- known active upload IDs are excluded;
- at most 100 actions by default;
- aborts are verified using `ListParts`;
- completed objects are never deleted.

```rust,no_run
use std::time::Duration;
use rclone_crypt_aws::{DoctorOptions, StoreDoctor};
# use aws_sdk_s3::Client;

# async fn example(client: Client) -> rclone_crypt::Result<()> {
let doctor = StoreDoctor::new(client, "bucket");
let mut options = DoctorOptions::new("my-application/uploads/");
options.stale_after = Duration::from_secs(24 * 60 * 60);
options.active_upload_ids.insert("upload-owned-by-this-process".into());

let dry_run = doctor.run(&options).await?;
for finding in &dry_run.findings {
    println!("{:?}: {}", finding.disposition, finding.key);
}

options.apply = true;
let repaired = doctor.run(&options).await?;
println!("aborted={}, reclaimed_part_bytes={}",
    repaired.aborted, repaired.verified_reclaimed_bytes);
# Ok(()) }
```

`DoctorReport` includes aggregate counts plus `DoctorFinding` and
`DoctorFailure` records. `FindingDisposition` is one of `Active`, `Recent`,
`MissingMetadata`, `WouldAbort`, `AbortedAndVerified`, `ActionLimitReached`, or
`Failed`.

`DoctorOptions` exposes `prefix`, `stale_after`, `apply`, `active_upload_ids`,
`max_actions`, and `max_abort_attempts`. `DoctorReport` exposes `scanned`,
`stale`, `active`, `recent`, `proposed`, `aborted`,
`verified_reclaimed_bytes`, `action_limit_reached`, `findings`, and `failures`.
Each finding records its key, upload ID, initiation time, calculated age, known
uploaded-part bytes, and disposition. Each failure records the key, upload ID,
and provider/verification error message.

An operator CLI is included:

```sh
DOCTOR_STALE_HOURS=24 \
cargo run -p rclone-crypt-aws --example store_doctor

# Destructive only for stale multipart uploads under B2_PREFIX:
DOCTOR_STALE_HOURS=24 \
cargo run -p rclone-crypt-aws --example store_doctor -- --apply
```

It reads the same `B2_KEY_ID`, `B2_APPLICATION_KEY`, `B2_ENDPOINT`, `B2_REGION`,
`B2_BUCKET`, and `B2_PREFIX` environment variables as the live tests. Optional
`DOCTOR_ACTIVE_UPLOAD_IDS` is a comma-separated exclusion list.

The doctor does not currently delete completed objects, old versions, delete
markers, or arbitrary local files. Those require separate explicit retention or
quarantine policies.

## HTTP image and video streaming

`rclone-crypt-http` builds a streaming `http::Response` around an opened
`RcloneCryptObject`:

```rust,no_run
use std::sync::Arc;
use http::{HeaderMap, HeaderValue, Method};
use rclone_crypt_http::serve;
# use rclone_crypt::{MemorySource, RcloneCryptObject};

# async fn example(object: Arc<RcloneCryptObject<MemorySource>>) {
let headers = HeaderMap::new();
let response = serve(
    object,
    &Method::GET,
    &headers,
    Some(HeaderValue::from_static("video/mp4")),
).await;
# }
```

Behavior:

| Request | Response |
|---|---|
| `GET` without Range | `200`, full streaming body |
| `GET bytes=10-99` | `206`, bytes 10 through 99 |
| `GET bytes=10-` | `206`, offset 10 through EOF |
| `GET bytes=-500` | `206`, final 500 bytes |
| Unsatisfiable range | `416`, `Content-Range: bytes */size` |
| Malformed or multiple ranges | `400` |
| `HEAD` | `200`, full plaintext length, empty body |
| Other method | `405` with `Allow: GET, HEAD` |

Responses include `Accept-Ranges: bytes`, exact `Content-Length`, and
`Content-Range` for partial responses. Only one range is supported; multipart
HTTP range responses are deliberately rejected. `ByteRange` uses an
end-exclusive `start..end` representation and provides `len` and `is_empty`.
`parse_range` returns `RangeError::{Malformed, MultipleUnsupported,
Unsatisfiable}`.

The response body is backpressured and does not materialize a video or requested
range in memory. Small range requests disable speculative prefetch. Dropping the
body drops the reader and pending range operation.

Authentication, authorization, object-name mapping, cache headers, ETags,
content disposition, and trusted MIME selection belong to the application. See
[`examples/axum-proxy`](examples/axum-proxy/README.md) for a complete proxy with
bearer authentication and typed backend-error mapping.

## Error model

Core APIs return `rclone_crypt::Result<T>`, whose error variants distinguish:

- credential/KDF failure;
- random-number generation failure;
- short header, bad magic, or truncated final block;
- SecretBox authentication failure;
- filename encoding, length, padding, or UTF-8 failure;
- invalid range/seek, overflow, oversized one-shot range, or a failed output
  allocation;
- backend source failure versus confirmed `SourceNotFound`;
- exact-length short reads;
- filesystem I/O and an existing destination.

Applications should preserve these distinctions. For an HTTP proxy, map only
`SourceNotFound` to 404. Authentication, invalid magic, and corruption generally
indicate server configuration or stored-data failure, not absence. Provider
authorization, throttling, and outages should normally become 502/503 rather
than 404.

## Security model and limitations

- Every content chunk is independently authenticated before plaintext is
  returned.
- The 32-byte header, encrypted object length, and initial nonce are not covered
  by a separate whole-file authenticator; this follows rclone's format.
- A caller streaming through `copy_to` may have consumed earlier authenticated
  chunks before a later chunk fails. `download_to` avoids publishing such a
  partial file.
- Standard encrypted filenames are deterministic and leak equality.
- Rclone obscure is reversible and is not a secret-storage mechanism.
- The library does not provide authorization, tenant isolation, path traversal
  protection, key rotation, or secret management.
- Wrong keys and corrupted ciphertext both normally surface as authentication
  failure; do not automatically delete a completed object based on that alone.
- S3 objects should be pinned by version ID or ETag so a stream cannot combine
  ranges from different object revisions.

## Performance and resource behavior

- Decryption operates on 64 KiB authenticated chunks.
- `CryptReader` defaults to 1 MiB windows and one-window prefetch.
- `copy_to` uses 8 MiB double-buffered batches.
- One-shot `read_range` rejects mappings above 64 MiB.
- Streaming upload pipe capacity is at most 256 KiB, plus one configured part.
- Multipart parts are retried from immutable in-memory bytes.
- HTTP range requests fetch only containing encrypted chunks and requested
  bounded windows.

Tune fetch and part sizes against the backend's latency, request pricing, and
expected concurrency. Memory consumption scales with concurrent readers and
uploads, so avoid unnecessarily large per-stream windows.

## Testing and the rclone oracle

Run the local suite:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The test suite covers boundary sizes, authentication failures, wrong keys,
corruption, arbitrary ranges, seeking, HTTP responses, atomic replacement,
filename interoperability, upload formatting, retry configuration, and store
doctor safety.

Live tests use temporary credentials supplied through environment variables;
credentials are not part of the library API. The Backblaze suite tests both
directions:

1. rclone encrypt/upload → Rust seek/decrypt/download;
2. Rust encrypt/upload → pinned rclone download/authenticate.

It uses checksummed real image and Big Buck Bunny MP4 fixtures. See
[`tests/live-b2/README.md`](tests/live-b2/README.md) for setup and cleanup.

## Examples

- [`examples/axum-proxy`](examples/axum-proxy/README.md): authenticated Axum
  image/video proxy with S3 ranges.
- `crates/rclone-crypt-aws/examples/b2_smoke.rs`: decrypt, seek, and download a
  real B2 object.
- `crates/rclone-crypt-aws/examples/b2_upload_smoke.rs`: Rust upload followed by
  rclone interoperability validation.
- `crates/rclone-crypt-aws/examples/store_doctor.rs`: dry-run/apply multipart
  cleanup CLI.

## Non-goals

- Implementing an S3 client inside the cryptographic core.
- Inventing or extending the rclone on-disk format.
- Transparent deletion of suspicious completed objects.
- Treating encrypted filenames as trusted filesystem paths or HTTP metadata.
- Supporting unauthenticated plaintext output.

## License

Licensed under either MIT or Apache-2.0, at your option.
