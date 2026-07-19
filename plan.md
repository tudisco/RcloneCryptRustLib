# rclone crypt read/stream library plan

## Goal and boundaries

Build a production-oriented Rust library that reads and writes rclone crypt objects over byte-oriented storage abstractions. Its delivery modes are: stream decrypted bytes to an async consumer, download a complete decrypted object to a file, serve images/video through an HTTP proxy with byte-range seeking, and stream plaintext uploads into rclone-compatible encrypted objects. The cryptographic core will not know about S3 or any HTTP framework. Optional AWS and HTTP adapters provide S3 download/upload and proxy integration. Read interoperability remains the first release gate; uploads are the next milestone after that baseline is stable.

The compatibility oracle for development and CI is **rclone v1.74.2**, release commit `b22fe9811c672e4d226ae2c054d7c965d8783805`. CI will download the official pinned binary and verify its checksum rather than using an unpinned package-manager version.

Primary references:

- [rclone crypt documentation and file format](https://rclone.org/crypt/)
- [rclone v1.74.2 release](https://github.com/rclone/rclone/releases/tag/v1.74.2)
- [v1.74.2 crypt cipher implementation](https://github.com/rclone/rclone/blob/v1.74.2/backend/crypt/cipher.go)
- [v1.74.2 password obscuring implementation](https://github.com/rclone/rclone/blob/v1.74.2/fs/config/obscure/obscure.go)
- [v1.74.2 PKCS#7 implementation](https://github.com/rclone/rclone/tree/v1.74.2/backend/crypt/pkcs7)
- [rclone's EME dependency](https://github.com/rfjakob/eme)

## Confirmed compatibility assumptions

These values were checked against both the v1.74.2 Go source and the v1.74.2 executable on macOS arm64; tests will preserve the executable-generated artifacts as fixtures.

| Item | Required behavior |
|---|---|
| Header | 8 bytes `RCLONE\0\0`, followed by a 24-byte initial nonce; 32 bytes total |
| Content primitive | NaCl SecretBox: XSalsa20-Poly1305 with a 32-byte data key |
| Plaintext chunk | 65,536 bytes |
| Authentication overhead | 16 bytes prepended by SecretBox |
| Full ciphertext chunk | 65,552 bytes |
| Nonce sequence | Treat the 24-byte nonce as a little-endian 192-bit integer; byte 0 increments first, with carry toward byte 23 |
| Final chunk | Contains 1–65,536 plaintext bytes plus 16 authentication bytes; an exact multiple has no extra empty terminal chunk |
| Empty file | Header only (32 encrypted bytes) |
| KDF | scrypt `N=16384, r=8, p=1`, output 80 bytes |
| KDF output split | bytes `0..32` data key, `32..64` name AES key, `64..80` EME tweak |
| Salt | Non-empty `password2` is used as its raw UTF-8 bytes; absent/empty salt uses `a8 0d f4 3a 8f bd 03 08 a7 ca b8 3e 58 1f 86 b1` |
| Empty primary password | rclone special-cases it to 80 zero bytes instead of running scrypt; retain compatibility but document it as unsafe |
| Obscured credentials | Raw URL-safe Base64 without padding; decoded bytes are 16-byte IV + AES-256-CTR ciphertext under rclone's fixed static key |
| Standard filename encryption | Split paths on `/`; PKCS#7-pad each non-empty UTF-8 segment to 16 bytes; AES-256-EME with the derived 16-byte tweak; deterministic per segment |
| Default filename encoding | RFC 4648 **base32hex**, lowercase, with `=` padding stripped; decoding is case-insensitive and rejects supplied padding |
| Decrypted names | Must be valid UTF-8 and must satisfy rclone's control-character validation; preserve Unicode text without normalization |
| Size validity | Encrypted size below 32 is invalid; after the header, a remainder of 1–16 bytes is a truncated/authenticator-only chunk and invalid |

Observed v1.74.2 size vectors: plaintext `0 -> 32`, `1 -> 49`, `65,536 -> 65,584`, and `65,537 -> 65,601` encrypted bytes. The current prose documentation's 1 MiB example says 65,568 bytes per chunk, but the source constants and executable prove the correct value is 65,552; source plus executable wins.

Initial scope supports standard filename encryption with base32hex, because that is the requested/default mode. The public configuration model should leave room for rclone's `off`, `obfuscate`, `base64`, `base32768`, custom suffix, and directory-name-encryption options, but they are not part of the first interoperability milestone unless explicitly added.

## Proposed crate structure

Start as a small workspace so the crypto/storage boundary is enforced by dependencies:

```text
crates/
  rclone-crypt/          # storage-independent format, keys, names, reader
  rclone-crypt-aws/      # optional AWS SDK RangeSource adapter
  rclone-crypt-http/     # framework-neutral HTTP range/response helpers
examples/
  axum-proxy/            # runnable S3 -> decrypt -> HTTP image/video proxy
tests/
  fixtures/rclone-v1.74.2/
  oracle/                # scripts/config templates that regenerate fixtures
  media/                 # checksummed asset manifest and acquisition script
  live-b2/               # opt-in Backblaze B2 S3 interoperability suite
```

The core's public storage contract will be close to:

```rust
#[async_trait]
pub trait RangeSource: Send + Sync {
    async fn size(&self) -> Result<u64, SourceError>;
    async fn read_range(&self, range: Range<u64>) -> Result<Bytes, SourceError>;
}
```

Contract details must be explicit: ranges are end-exclusive, empty ranges return empty bytes without I/O, reads must either return exactly the requested bytes or a typed short-read error, arithmetic is checked, and a range beyond the object is rejected consistently. The source is shared (`Arc<dyn RangeSource>`) so readers can be cheap and concurrent.

Core modules:

- `credentials`: accept clear or explicitly marked rclone-obscured password/password2 values; reveal obscured values without silently guessing their representation.
- `keys`: scrypt derivation and zeroization-aware key ownership; expose no key bytes in `Debug` or errors.
- `format`: constants, strict header parser, encrypted/plaintext size conversion, chunk index/nonce/range calculations.
- `names`: modified base32hex, AES-256-EME, PKCS#7 unpadding, path-segment decryption, UTF-8/control-character validation.
- `source`: `RangeSource`, an in-memory source for tests, and optionally a local-file source useful for examples and oracle tests.
- `reader`: async sequential reads, plaintext seeking, bounded-memory range streams, and download/copy helpers over a `RangeSource`.
- `error`: typed, non-secret-bearing errors separating invalid credentials/authentication, corrupt/truncated format, invalid ranges, unsupported options, and backend failures.

Dependencies will be selected for maintained, audited implementations rather than handwritten cryptography: RustCrypto `scrypt`, `aes`/`ctr`, a compatible SecretBox implementation, `bytes`, `tokio`, `async-trait`, `zeroize`, and an EME implementation that is verified against rclone vectors. Dependency versions and minimum supported Rust version will be pinned in the lockfile/CI after a license and maintenance review.

## Range and reader design

For encrypted object size `C`, plaintext size is:

```text
payload = C - 32
full = payload / 65_552
remainder = payload % 65_552
P = full * 65_536 + (remainder == 0 ? 0 : remainder - 16)
```

Reject `C < 32` and nonzero `remainder <= 16`. All calculations use checked `u64` arithmetic.

For plaintext byte offset `p`:

```text
chunk_index       = p / 65_536
offset_in_chunk   = p % 65_536
cipher_chunk_start = 32 + chunk_index * 65_552
nonce             = initial_nonce + chunk_index (little-endian carry)
```

A requested plaintext range is expanded to whole authenticated encrypted chunks. Each fetched chunk is authenticated before any of its plaintext is returned; then leading/trailing plaintext is sliced. Requests ending at EOF use the actual final encrypted chunk length rather than assuming a full chunk. Adjacent chunks should be coalesced into bounded ranged reads to reduce S3 calls while retaining per-chunk authentication and bounded memory.

`CryptReader<S>` will implement Tokio `AsyncRead` and `AsyncSeek` with a small state machine because trait polling cannot await directly. Seeking updates logical plaintext position and invalidates buffered plaintext; the actual ranged fetch is lazy on the next read. Also provide `stream()` and `stream_range(Range<u64>)` APIs yielding bounded `Bytes` frames with backpressure, plus a size-limited `read_range_bytes` convenience API for callers that genuinely need one in-memory buffer. A large HTTP range must never be materialized into one `Bytes` allocation. EOF, zero-length requests, seeks exactly to EOF, backward seeks, cross-chunk reads, and repeated small video-player probes are first-class cases.

For downloads, provide `copy_to<W: AsyncWrite + Unpin>` returning the verified plaintext byte count, and `download_to(path, options)` as a filesystem convenience. The path helper will stream with bounded memory to a sibling temporary file, flush/sync according to options, preserve the destination on failure, and atomically rename only after successful authenticated completion. It will define overwrite, parent-directory creation, cancellation cleanup, and partial-file behavior explicitly. Authentication remains chunk-local as in rclone: an error late in an object prevents publication by `download_to`, while a caller using raw `copy_to` controls its own rollback policy.

Cache policy for the first version: cache the parsed header and current decrypted chunk only. Make read-ahead/coalescing configurable with conservative defaults; do not create an unbounded cache inside the cryptographic core. Cancellation must drop in-flight backend futures cleanly, and no unauthenticated bytes may escape after cancellation or error.

## Implementation phases

### 1. Scaffold and freeze the oracle

- Create the workspace, feature flags, CI matrix, formatting/linting, deny unsafe code in the core, and documentation skeleton.
- Add an oracle script that downloads rclone v1.74.2, verifies the published SHA-256 for each CI platform, prints `rclone version`, and generates fixtures in a temporary directory.
- Generate deterministic expected plaintext/name results and retain rclone-produced ciphertext files. Content nonces are random, so fixture ciphertext is checked in after generation; fixture provenance records the exact command, config, binary version, and checksum.
- Include empty, 1-byte, boundary (`65,535`, `65,536`, `65,537`), multi-chunk, Unicode path, and binary/random payload fixtures.

### 2. Credentials and key derivation

- Implement strict obscured-value reveal compatible with `rclone obscure`/`rclone reveal`.
- Implement scrypt and exact 80-byte split, including default salt, raw UTF-8 custom salt, and rclone's empty-password special case.
- Cross-check clear and obscured credentials against rclone-generated filename and content fixtures.
- Zeroize temporary derived material and credential buffers where ownership permits; redact `Debug` output.

### 3. Strict format and size layer

- Parse and validate the 32-byte header and magic.
- Implement nonce addition with little-endian carry across all 24 bytes, including overflow/carry vectors copied from rclone behavior.
- Implement checked encrypted/plaintext size conversion and plaintext-to-ciphertext mapping.
- Property-test boundary arithmetic and reject truncated headers, 1–16-byte trailing fragments, overflow, and invalid ranges before backend reads.

### 4. Authenticated chunk decryption

- Decrypt full and final partial chunks with SecretBox.
- Return a stable authentication/corruption error without leaking plaintext or ambiguously treating a bad password as valid data.
- Test bit flips in magic, nonce, tag, ciphertext, middle chunks, and final chunks; test truncation at every structural boundary.
- Differentially verify every valid fixture with `rclone cat` and `rclone check`/local crypt reads.

### 5. Storage-independent async streaming and seeking

- Implement the in-memory and local range sources, strict source contract tests, sequential `AsyncRead`, lazy `AsyncSeek`, full-object streams, and bounded-memory plaintext-range streams.
- Coalesce encrypted reads covering adjacent chunks and slice only after authentication.
- Implement `copy_to` and atomic `download_to`; verify bounded memory, exact byte counts, destination preservation on authentication/backend failure, cancellation cleanup, and no publication of partial downloads.
- Test arbitrary ranges against the original plaintext with randomized/property-based cases, including zero length, EOF, cross-chunk, and thousands of seek/read sequences.
- Add a fault-injecting source for short reads, changing object sizes, backend errors, latency, cancellation, and call-count assertions.
- Benchmark sequential throughput, random 1-byte/HTTP-style ranges, memory bounds, and backend request counts on representative video-sized data.

### 6. Filename and Unicode interoperability

- Implement strict lowercase/unpadded base32hex decoding (while accepting uppercase as rclone does), AES-256-EME, and PKCS#7 validation.
- Decrypt each `/`-separated segment independently; define behavior for empty segments, leading/trailing slash, `.`/`..`, malformed ciphertext, invalid UTF-8, and control characters based on rclone source tests.
- Verify ASCII, composed/decomposed Unicode, emoji, CJK, combining marks, and maximum accepted encrypted segment lengths using `rclone backend encode/decode` in both directions.
- Keep path decryption lexical: never interpret decrypted segments as filesystem traversal inside the core.

### 7. Optional AWS S3 adapter

- Add `rclone-crypt-aws`, feature-gated and absent from core dependencies.
- Represent bucket/key/version (or ETag precondition) explicitly. Use `HeadObject` for size and `GetObject Range: bytes=start-end` for the end-exclusive trait range.
- Validate `Content-Range`, returned byte count, object identity, and mutation/precondition failures. Handle S3's inclusive Range end carefully and map SDK/service errors into source errors.
- Test against a mock HTTP server for exact headers and failure behavior, then run opt-in integration tests against MinIO/LocalStack and a real S3 bucket in a non-default CI job.

### 8. HTTP image/video proxy integration

- Add a lightweight `rclone-crypt-http` crate that parses and normalizes HTTP byte ranges independently of Axum, Actix, or Hyper and turns a decrypted stream into a framework-consumable response body.
- Support `GET` and `HEAD`. A request without `Range` returns `200`, `Content-Length: <plaintext-size>`, and a backpressured full-object stream. A valid single range returns `206`, exact `Content-Range: bytes start-end/size`, range `Content-Length`, `Accept-Ranges: bytes`, and only the requested plaintext bytes. An unsatisfiable range returns `416` with `Content-Range: bytes */size`.
- Correctly parse closed (`bytes=10-99`), open-ended (`bytes=10-`), and suffix (`bytes=-500`) ranges using checked arithmetic. Reject malformed ranges and explicitly reject or defer multipart ranges rather than serving incorrect bytes.
- Allow the application to supply `Content-Type`, `ETag`, `Last-Modified`, cache policy, `Content-Disposition`, and authorization decisions. The cryptographic core must not infer access control or trust decrypted filenames as response headers.
- Preserve backpressure end-to-end from the client through decryption to S3. Client disconnects cancel pending reads; configurable read-ahead remains bounded. Do not buffer an entire video, image, or requested range.
- Provide a runnable Axum example showing S3 object selection, credential/key setup, image/video MIME metadata, `GET`/`HEAD`, range responses, safe error mapping, and shutdown/cancellation.
- Test with raw HTTP assertions and real media-client patterns: initial `bytes=0-`, MP4 metadata probes near EOF, backward/random seeks, repeated thumbnail/image requests, browser disconnects, and concurrent viewers. Verify body hashes and exact `200`/`206`/`416` headers against plaintext fixtures.

### 9. Production hardening and release gate

- Run `cargo fmt`, Clippy with warnings denied, unit/property/integration tests, dependency audit, license checks, docs, and MSRV tests.
- Fuzz header parsing, size/range mapping, modified base32, PKCS#7/EME input, and chunk decryption. Seed fuzz corpora with oracle fixtures and malformed variants.
- Document threat model: per-chunk authenticity, unauthenticated file length/header nonce, deterministic filename leakage, password-obscuring weakness, and lack of whole-object rollback/substitution protection.
- Document download-to-file and HTTP proxy examples, concurrency/caching guidance, S3 request economics, credential handling, media MIME handling, and limitations.
- Release read-only `0.1` only after all oracle fixtures decrypt identically, arbitrary range tests pass, corruption never yields unauthenticated bytes, and benchmark targets are recorded.

### 10. Rclone-compatible streaming uploads

- Add a storage-independent write contract separate from `RangeSource`, with explicit single-stream and multipart capabilities. The core accepts an async plaintext reader and emits encrypted bytes without importing the AWS SDK.
- Implement content encryption exactly as rclone v1.74.2: cryptographically secure random 24-byte initial nonce, `RCLONE\0\0` header, 65,536-byte plaintext chunks, SecretBox authentication, little-endian nonce increment, and no empty terminal chunk for exact multiples.
- Provide an upload API accepting a known plaintext length when available so encrypted size and S3 metadata can be computed before transmission. Define a streaming/unknown-length path with bounded spooling or multipart upload rather than buffering the complete file.
- Add standard filename **encryption** using the existing AES-256-EME key/tweak, PKCS#7 padding, lowercase unpadded base32hex, per-segment path handling, and Unicode preservation.
- Add an optional AWS S3 sink supporting single `PutObject` for small/known bodies and multipart upload for large or unknown-length streams. Bound part memory, upload parts concurrently within a configurable limit, complete only after every part succeeds, and abort multipart uploads on authentication, source, cancellation, or transport failure.
- Expose upload progress in plaintext and encrypted byte counts without exposing keys, nonces, or credentials. Support cancellation and idempotency guidance; never silently overwrite unless the caller's policy permits it.
- Test Rust-encrypted objects by reading them through pinned rclone (`rclone cat`, `rclone copy`, `rclone check`) and by decrypting them again with Rust. Test empty, 1-byte, exact-boundary, partial-final, multi-part, Unicode filename, cancellation, retry, and corrupted/incomplete multipart cases.
- Extend live B2 testing in both directions: rclone upload → Rust download, and Rust upload → rclone download. Compare plaintext size and SHA-256 for the real image/video assets, verify encrypted filenames with `rclone backend decode`, and clean all completed/aborted multipart artifacts and object versions.
- Benchmark upload encryption separately from S3 transport, then measure B2 throughput, time-to-first-byte/first-part, peak memory, part concurrency, request count, and abort cleanup. Retain rclone v1.74.2 as the format oracle.
- Gate upload support as a subsequent release milestone (for example `0.2`) so it does not weaken the established read/stream compatibility guarantees.

### 11. Double-buffer and prefetch optimization

- Add an optional two-buffer pipeline for sequential reads: authenticate/decrypt the current encrypted batch while the next bounded range request is in flight. Preserve strict plaintext ordering and never expose a chunk before its SecretBox authentication succeeds.
- Add an equivalent bounded upload pipeline where plaintext is read/encrypted into one buffer while the prior encrypted part is being sent. Multipart concurrency remains configurable and must not become an unbounded queue.
- Keep random HTTP ranges latency-oriented: do not prefetch beyond a small requested range, and cancel speculative reads immediately when a client disconnects or seeks elsewhere.
- Benchmark single-buffer versus double-buffer behavior locally and against B2. Record throughput, time-to-first-byte, request count, CPU utilization, peak memory per stream, and performance with 1, 10, and many concurrent viewers/uploads.
- Add a fault-injecting source/sink to verify cancellation, short reads/writes, delayed buffers completing out of order, authentication failure in the prefetched batch, upload-part failure, retry behavior, and cleanup without leaked tasks or multipart sessions.
- Enable double buffering by default only when benchmarks show a material remote throughput improvement without unacceptable memory growth or worse small-range latency; retain a configuration switch and conservative buffer-size limits.

### 12. Store doctor and crash-recovery maintenance

Implemented first production slice: the AWS adapter now has a prefix-scoped,
paginated multipart doctor with a mandatory grace period, dry-run default,
active-upload exclusions, an action cap, part-byte accounting, repeated
abort/ListParts verification, per-upload structured findings/failures, an
operator CLI, and an ignored live B2 test covering dry-run, repair, reclaimed
bytes, and idempotency. Upload leases, completed-object health/quarantine,
version retention, and local-spool scanning remain later opt-in slices.

Multipart uploads now also retain each bounded part for replay, make a
configurable bounded number of attempts with capped exponential backoff, and
use the same repeated abort-plus-`ListParts` verification routine as the store
doctor. Cleanup verification failure is returned alongside the primary upload
failure rather than being silently discarded.

- Add an optional `rclone-crypt-aws` doctor API and CLI that is prefix-scoped, paginated, bounded-concurrency, idempotent, and dry-run by default. It must produce a structured report of findings, proposed actions, completed actions, failures, reclaimed part bytes when available, and continuation state.
- Make stale multipart cleanup the primary safe repair: use `ListMultipartUploads`, require an explicit minimum age/grace period, exclude known active upload IDs, call `AbortMultipartUpload`, then use `ListParts`/repeat abort as necessary to verify uploaded parts are gone. Never abort solely because an upload was present during one scan.
- Recommend a provider lifecycle rule as the first line of defense (`AbortIncompleteMultipartUpload` / Backblaze `daysFromStartingToCancelingUnfinishedLargeFiles`) and keep the doctor as faster detection, reporting, verification, and recovery when application crashes bypass local cleanup.
- Add optional upload leases/journaling under a dedicated control prefix or application database so a doctor can distinguish active uploads from abandoned uploads across processes. Lease expiry must be longer than expected uploads and resilient to clock skew; lack of a lease is not sufficient for immediate deletion.
- Separate object health scanning from destructive repair. Levels: metadata/size validation, header/magic validation, sampled authenticated chunks, and full authenticated read. Report corrupt, truncated, foreign, and undecodable-name objects; never automatically delete completed objects based only on failed decryption because a wrong key/config is indistinguishable from corruption.
- Support explicit quarantine of suspect completed objects to a dedicated prefix/version where the provider supports safe copy, with source deletion disabled by default. Require an action token or confirmation derived from the dry-run report before destructive operations.
- Treat old object versions and delete markers as a separate opt-in retention policy. Backblaze buckets are versioned and deleting only the current name can leave older billable versions. Never infer version deletion from rclone format health; require minimum retention age, maximum versions, explicit prefix, and version-aware deletion permissions.
- Scan and clean only library-owned local temporary/spool files whose naming/ownership marker matches this library and whose age exceeds a grace period. Normal cancellation-safe tempfile guards remain the foreground defense.
- Add fault-injected and live B2 tests: abandoned upload with parts, active slow upload, concurrent completion during scan, repeated abort requirement, pagination, permission denial, throttling, stale lease, wrong crypt key, corrupt completed object, old versions, dry-run invariance, and idempotent repeated repair.

## Continuous media and live-object test plan

The test system has three layers so ordinary development is fast while real media and S3 behavior are exercised continuously.

### Media acquisition and provenance

Maintain `tests/media/assets.toml` as a reviewed manifest containing the immutable download URL, expected SHA-256, byte length, MIME type, license, attribution text/source page, and intended test tier for every external asset. `tests/media/fetch.sh` (or a small Rust test-support binary) downloads into a gitignored cache, follows redirects, imposes size/time limits, verifies length and SHA-256 before use, and fails closed if upstream content changes. CI caches assets by manifest hash; external media is not silently updated or committed without its license record.

Initial candidates, to be frozen by checksum when the suite is implemented:

- Image smoke fixture: Wikimedia Commons' 1,280×720 `Soni test image.png` (17,811 bytes at research time), published under CC0. Use its [license/source page](https://commons.wikimedia.org/wiki/File:Soni_test_image.png) and resolved original-file URL.
- Video integration fixture: Blender's `BigBuckBunny_320x180.mp4` (64,657,027 bytes at research time) from the official Blender download host. Record the Big Buck Bunny attribution/license alongside the exact URL and checksum before enabling CI.
- Deterministic boundary fixture: generate a short MP4 locally with pinned FFmpeg/container settings, test pattern, tone, Unicode metadata, keyframes, and a `moov` atom suitable for seeking. This provides reproducible small PR coverage but does not replace the externally sourced real video.
- Deterministic large binary fixture: generate seeded bytes spanning many rclone chunks for cryptographic/range property tests without network downloads.

The acquisition script will first probe availability, but a transient media-host outage should not make every PR fail when a previously checksummed CI cache is present. A scheduled asset-validation job checks source availability and license pages separately and reports drift. It never accepts a new checksum automatically.

### Local continuous loop (every PR)

1. Acquire/verify the small image and generate the short MP4 and boundary fixtures.
2. Create an isolated temporary local backend and an rclone crypt remote using pinned rclone v1.74.2 and test-only clear inputs converted with `rclone obscure`.
3. Upload the plaintext fixtures **through rclone crypt**. This ensures rclone—not Rust code—is the encrypting oracle while the Rust library remains read-only.
4. Read the resulting encrypted objects through both the local `RangeSource` and an HTTP range-source mock.
5. Verify full stream and atomic file download by byte length plus SHA-256 against the original plaintext.
6. Exercise deterministic and randomized plaintext ranges, chunk boundaries, suffix/open-ended HTTP ranges, image body decoding, and MP4 start/end metadata probes.
7. Start the reference proxy on an ephemeral port and assert `HEAD`, full `GET`, `206`, and `416` headers/bodies. Run `ffprobe` against the proxy URL and, where practical, decode selected first/middle/last frames to prove seeking works rather than merely hashing bytes.
8. Run wrong-password, truncated-object, changed-object, and flipped-ciphertext tests and ensure no failed atomic download is published.

Fast PR tests use the small/generated media. The 64 MB real video runs in scheduled/nightly CI and before releases to control bandwidth and external-host dependency.

### Live Backblaze B2 S3 loop (opt-in, scheduled, and pre-release)

Once temporary bucket access is supplied, configure it only through environment variables or the CI secret store—never `rclone.conf` in the repository, command-line logs, fixtures, snapshots, or test output. Expected inputs will include the B2 S3 endpoint, region, bucket, application key ID/access key, application key/secret, and a restricted test prefix. The application key should be bucket-scoped, short-lived, and limited to list/read/write/delete capabilities required by the suite.

Each run uses a collision-proof prefix such as `rclone-crypt-tests/<run-id>/` and records only non-secret object names/version IDs needed for cleanup:

1. Download or restore the checksummed image/video assets and compute local reference hashes.
2. Generate a fresh test-only crypt password and salt in memory, create a temporary pinned-rclone configuration with restrictive file permissions, and point its underlying remote at the run prefix.
3. Upload plaintext image, video, Unicode-named files, empty file, boundary files, and seeded data **via `rclone copy` to the crypt remote**. Confirm the underlying B2 objects have encrypted names/content and expected encrypted sizes.
4. Use the Rust AWS `RangeSource` directly against those encrypted B2 object keys. Verify header/size parsing, full decrypted stream, atomic download-to-file, and SHA-256 equality.
5. Run a fixed range matrix plus randomized ranges over the real video: beginning, end, across every relevant 65,536-byte boundary, open-ended/suffix HTTP requests, MP4 tail probes, backward seeks, and concurrent viewers.
6. Start the HTTP proxy backed by B2, run `curl` header/body assertions and `ffprobe`/frame extraction through the proxy, and verify returned ranges against the original file.
7. Test object-identity protection by replacing or versioning an object between `size()` and `read_range()` and expecting a typed mutation/precondition failure rather than mixed plaintext.
8. Upload deliberately corrupted copies of encrypted objects under the isolated prefix (never alter the good oracle object) and verify authentication/truncation failures.
9. Capture sanitized metrics: S3 request count, bytes fetched versus plaintext served, time-to-first-byte, sequential throughput, random-seek latency, peak buffered memory, retry count, and cancellation behavior. Set regression thresholds only after a baseline run.
10. Delete all objects and versions under the run prefix in a finally/cleanup stage, even after test failure. A separate janitor job removes stale prefixes older than the agreed TTL and operates only below `rclone-crypt-tests/`.

Live tests must not assume AWS-specific hostname or region behavior. They will exercise the configured Backblaze endpoint, inclusive S3 `Range` syntax, returned `Content-Range`, ETag/version preconditions, retries for transient `429`/`5xx` responses, and bounded concurrency. Retry policy uses jittered backoff and never retries authentication/corruption errors as if they were transport failures.

### Continuous schedule and gates

- Per commit/PR: unit, property, checked-in oracle fixtures, generated media, local rclone upload/decrypt, proxy range tests, and atomic download tests.
- Nightly: fetch/checksum real image/video, run the complete local media suite, fuzz smoke tests, and—when secrets are configured—the live B2 suite.
- Weekly: longer randomized seek/concurrency tests, full fuzz budget, media-source/license availability validation, and stale B2-prefix janitor.
- Release candidate: regenerate all oracle fixtures with pinned rclone, run every local and B2 case, compare performance/request metrics with the baseline, and retain a sanitized test report.
- Latest-rclone observation: non-gating scheduled differential run; compatibility drift opens a report but does not silently move the v1.74.2 pin.

A live B2 run is considered successful only when rclone-encrypted uploads can be fully streamed, atomically downloaded, arbitrarily ranged, and served to a media probe through the Rust HTTP proxy with byte-for-byte plaintext equality, while all temporary remote objects are accounted for and cleaned up.

## Test/oracle policy

Rclone remains authoritative rather than merely a one-time fixture generator:

- Fast PR tests use checked-in fixtures generated by exactly v1.74.2.
- A pinned-oracle CI job regenerates data and compares Rust output with `rclone cat`, `rclone backend encode`, `rclone backend decode`, `rclone reveal`, and ranged `rclone cat --offset/--count` results.
- Read-oracle tests use pinned rclone to produce encrypted objects. Upload-oracle tests reverse direction: Rust produces encrypted objects and pinned rclone must successfully list, decode, authenticate, and download them.
- Every compatibility bug adds both a minimal fixture and a live rclone differential test.
- A scheduled, non-gating job may test the latest rclone release and report drift. Changing the pinned oracle requires an explicit compatibility review, fixture regeneration, and changelog entry.
- Never generate expected cryptographic values using the Rust implementation under test.

## Deferred work

- Filename modes `off` and `obfuscate`, and encodings `base64`/`base32768`.
- Directory listing/traversal abstractions, S3 client configuration policy, HTTP frameworks beyond the reference adapter/example, multipart HTTP byte ranges, and persistent caching.
- Whole-file authenticity beyond rclone's per-chunk format; adding an incompatible envelope is out of scope.

## Definition of done for read interoperability

- All specified format constants and edge cases are source-linked and covered by v1.74.2 oracle tests.
- Clear and obscured credentials, default/custom UTF-8 salts, content, names, and Unicode paths match rclone.
- Sequential and arbitrary plaintext range reads return exactly the original bytes across every chunk boundary.
- Full-object streaming and atomic download-to-file complete with bounded memory and never publish a partial destination after an error.
- The HTTP adapter serves exact `HEAD`, `200`, `206`, and `416` semantics and supports browser/media-player seek patterns without buffering complete objects or ranges.
- Wrong keys, corruption, truncation, short backend reads, mutation, and invalid ranges fail with typed errors and never release unauthenticated plaintext.
- Core has no AWS dependency; optional AWS integration passes exact Range/identity tests.
- Performance and request-count benchmarks demonstrate bounded-memory video streaming and document the chosen read-ahead defaults.

## Definition of done for upload interoperability

- Rust streaming encryption matches rclone for header, chunk framing, nonce progression, final chunks, filenames, and encrypted-size reporting.
- Pinned rclone v1.74.2 can decrypt every Rust-produced boundary and media fixture with byte-for-byte SHA-256 equality.
- Core uploads remain storage-independent; AWS single and multipart adapters are optional.
- Uploads use bounded memory, apply backpressure, support cancellation, abort failed multipart sessions, and never publish a successful result before storage completion.
- Live B2 bidirectional tests pass for images, video, Unicode paths, small objects, and multipart objects, with temporary objects and versions cleaned afterward.
