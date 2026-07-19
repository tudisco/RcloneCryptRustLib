#![forbid(unsafe_code)]

mod doctor;

pub use doctor::{
    DoctorFailure, DoctorFinding, DoctorOptions, DoctorReport, FindingDisposition, StoreDoctor,
};

use std::{ops::Range, path::Path, sync::Arc, time::Duration};

use async_trait::async_trait;
use aws_sdk_s3::Client;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use bytes::Bytes;
use rclone_crypt::{EncryptionStats, Error, Keys, RangeSource, Result, encrypt_to};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::OnceCell;

const MIN_MULTIPART_PART_SIZE: u64 = 5 * 1024 * 1024;

/// An immutable S3 object exposed through the core range-source contract.
#[derive(Clone, Debug)]
pub struct S3RangeSource {
    client: Client,
    bucket: String,
    key: String,
    version_id: Option<String>,
    expected_etag: Option<String>,
    snapshot: Arc<OnceCell<ObjectSnapshot>>,
}

#[derive(Clone, Debug)]
struct ObjectSnapshot {
    size: u64,
    etag: Option<String>,
    version_id: Option<String>,
}

impl S3RangeSource {
    pub fn new(client: Client, bucket: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            client,
            bucket: bucket.into(),
            key: key.into(),
            version_id: None,
            expected_etag: None,
            snapshot: Arc::new(OnceCell::new()),
        }
    }

    pub fn with_version_id(mut self, version_id: impl Into<String>) -> Self {
        self.version_id = Some(version_id.into());
        self
    }

    pub fn with_expected_etag(mut self, etag: impl Into<String>) -> Self {
        self.expected_etag = Some(etag.into());
        self
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    async fn object_snapshot(&self) -> Result<&ObjectSnapshot> {
        self.snapshot
            .get_or_try_init(|| async {
                let mut request = self
                    .client
                    .head_object()
                    .bucket(&self.bucket)
                    .key(&self.key);
                if let Some(version_id) = &self.version_id {
                    request = request.version_id(version_id);
                }
                if let Some(etag) = &self.expected_etag {
                    request = request.if_match(etag);
                }
                let response = request.send().await.map_err(|error| {
                    if error
                        .raw_response()
                        .is_some_and(|response| response.status().as_u16() == 404)
                    {
                        Error::SourceNotFound(format!("{}/{}", self.bucket, self.key))
                    } else {
                        Error::Source(format!("S3 HeadObject failed: {error}"))
                    }
                })?;
                let length = response
                    .content_length()
                    .ok_or_else(|| Error::Source("S3 HeadObject omitted Content-Length".into()))?;
                let size = u64::try_from(length)
                    .map_err(|_| Error::Source("S3 returned a negative Content-Length".into()))?;
                Ok(ObjectSnapshot {
                    size,
                    etag: response.e_tag().map(ToOwned::to_owned),
                    version_id: response.version_id().map(ToOwned::to_owned),
                })
            })
            .await
    }
}

#[async_trait]
impl RangeSource for S3RangeSource {
    async fn size(&self) -> Result<u64> {
        Ok(self.object_snapshot().await?.size)
    }

    async fn read_range(&self, range: Range<u64>) -> Result<Bytes> {
        if range.start > range.end {
            return Err(Error::Source("invalid S3 range".into()));
        }
        if range.is_empty() {
            return Ok(Bytes::new());
        }
        let inclusive_end = range.end - 1;
        let snapshot = self.object_snapshot().await?;
        let mut request = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&self.key)
            .range(format!("bytes={}-{}", range.start, inclusive_end));
        if let Some(version_id) = self.version_id.as_ref().or(snapshot.version_id.as_ref()) {
            request = request.version_id(version_id);
        }
        if let Some(etag) = self.expected_etag.as_ref().or(snapshot.etag.as_ref()) {
            request = request.if_match(etag);
        }
        let response = request
            .send()
            .await
            .map_err(|error| Error::Source(format!("S3 ranged GetObject failed: {error}")))?;
        let expected_content_range =
            format!("bytes {}-{inclusive_end}/{}", range.start, snapshot.size);
        let actual_content_range = response.content_range().unwrap_or_default();
        if actual_content_range != expected_content_range {
            return Err(Error::Source(format!(
                "S3 returned unexpected Content-Range {actual_content_range:?}"
            )));
        }
        let collected = response
            .body
            .collect()
            .await
            .map_err(|error| Error::Source(format!("S3 response body failed: {error}")))?;
        let bytes = collected.into_bytes();
        let expected =
            usize::try_from(range.end - range.start).map_err(|_| Error::RangeOverflow)?;
        if bytes.len() != expected {
            return Err(Error::ShortRead {
                expected,
                actual: bytes.len(),
            });
        }
        Ok(bytes)
    }
}

/// Uploads rclone-encrypted objects to S3-compatible storage.
#[derive(Clone, Debug)]
pub struct S3Uploader {
    client: Client,
    bucket: String,
}

impl S3Uploader {
    pub fn new(client: Client, bucket: impl Into<String>) -> Self {
        Self {
            client,
            bucket: bucket.into(),
        }
    }

    /// Encrypts a local file with bounded memory, spools ciphertext to a secure
    /// temporary file, then uploads it with PutObject.
    pub async fn upload_file(
        &self,
        plaintext_path: impl AsRef<Path>,
        encrypted_key: impl Into<String>,
        keys: &Keys,
    ) -> Result<UploadResult> {
        self.upload_file_with_options(
            plaintext_path,
            encrypted_key,
            keys,
            UploadOptions::default(),
        )
        .await
    }

    pub async fn upload_file_with_options(
        &self,
        plaintext_path: impl AsRef<Path>,
        encrypted_key: impl Into<String>,
        keys: &Keys,
        options: UploadOptions,
    ) -> Result<UploadResult> {
        options.validate()?;
        let encrypted_key = encrypted_key.into();
        let temporary = tempfile::NamedTempFile::new()
            .map_err(|source| Error::Io {
                path: Path::new("<encrypted upload spool>").into(),
                source,
            })?
            .into_temp_path();
        let mut plaintext = tokio::fs::File::open(plaintext_path.as_ref())
            .await
            .map_err(|source| Error::Io {
                path: plaintext_path.as_ref().into(),
                source,
            })?;
        let mut ciphertext = tokio::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&temporary)
            .await
            .map_err(|source| Error::Io {
                path: temporary.to_path_buf(),
                source,
            })?;
        let stats = encrypt_to(&mut plaintext, &mut ciphertext, keys).await?;
        tokio::io::AsyncWriteExt::shutdown(&mut ciphertext)
            .await
            .map_err(|source| Error::Io {
                path: temporary.to_path_buf(),
                source,
            })?;
        drop(ciphertext);

        if stats.encrypted_bytes >= options.multipart_threshold {
            self.multipart_upload(&temporary, encrypted_key, stats, options)
                .await
        } else {
            self.put_object(&temporary, encrypted_key, stats).await
        }
    }

    /// Streams an unknown-length plaintext reader directly into S3 multipart
    /// upload through a bounded in-memory pipe. Ciphertext is never fully
    /// materialized on disk or in memory.
    pub async fn upload_reader<R>(
        &self,
        reader: &mut R,
        encrypted_key: impl Into<String>,
        keys: &Keys,
        options: UploadOptions,
    ) -> Result<UploadResult>
    where
        R: AsyncRead + Unpin,
    {
        options.validate()?;
        let encrypted_key = encrypted_key.into();
        let response = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(&encrypted_key)
            .send()
            .await
            .map_err(|error| Error::Source(format!("S3 CreateMultipartUpload failed: {error}")))?;
        let upload_id = response
            .upload_id()
            .ok_or_else(|| Error::Source("S3 omitted multipart upload ID".into()))?
            .to_owned();
        let mut abort_guard = MultipartAbortGuard::new(
            self.client.clone(),
            self.bucket.clone(),
            encrypted_key.clone(),
            upload_id.clone(),
        );

        // The pipe is deliberately much smaller than a part. It provides
        // backpressure while encryption and network upload run concurrently.
        let pipe_capacity = usize::try_from(options.part_size.min(256 * 1024))
            .map_err(|_| Error::Source("streaming pipe size is unsupported".into()))?;
        let (encrypted_reader, mut encrypted_writer) = tokio::io::duplex(pipe_capacity);
        let producer = async {
            let result = encrypt_to(reader, &mut encrypted_writer, keys).await;
            let shutdown = encrypted_writer.shutdown().await;
            let stats = result?;
            shutdown.map_err(|source| Error::Io {
                path: Path::new("<encrypted multipart pipe>").into(),
                source,
            })?;
            Ok(stats)
        };
        let consumer =
            self.upload_stream_parts(encrypted_reader, &encrypted_key, &upload_id, options);
        let (producer_result, consumer_result) = tokio::join!(producer, consumer);

        let outcome = async {
            let stats = producer_result?;
            let (parts, uploaded_bytes) = consumer_result?;
            if uploaded_bytes != stats.encrypted_bytes {
                return Err(Error::ShortRead {
                    expected: usize::try_from(stats.encrypted_bytes).unwrap_or(usize::MAX),
                    actual: usize::try_from(uploaded_bytes).unwrap_or(usize::MAX),
                });
            }
            self.complete_multipart(&encrypted_key, &upload_id, parts, stats)
                .await
        }
        .await;

        if let Err(primary) = outcome {
            match abort_multipart_verified(
                &self.client,
                &self.bucket,
                &encrypted_key,
                &upload_id,
                options.max_abort_attempts,
                options.retry_base_delay,
            )
            .await
            {
                Ok(()) => abort_guard.disarm(),
                Err(cleanup) => {
                    return Err(Error::Source(format!(
                        "upload failed: {primary}; multipart cleanup could not be verified: {cleanup}"
                    )));
                }
            }
            return Err(primary);
        }
        abort_guard.disarm();
        outcome
    }

    async fn put_object(
        &self,
        path: &Path,
        encrypted_key: String,
        stats: EncryptionStats,
    ) -> Result<UploadResult> {
        let content_length = i64::try_from(stats.encrypted_bytes).map_err(|_| {
            Error::Source("encrypted object exceeds S3 content-length limit".into())
        })?;
        let body = ByteStream::from_path(path).await.map_err(|error| {
            Error::Source(format!("failed to open encrypted upload body: {error}"))
        })?;
        let response = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(&encrypted_key)
            .content_length(content_length)
            .body(body)
            .send()
            .await
            .map_err(|error| Error::Source(format!("S3 PutObject failed: {error}")))?;

        Ok(UploadResult::new(
            encrypted_key,
            stats,
            response.e_tag(),
            response.version_id(),
        ))
    }

    async fn multipart_upload(
        &self,
        path: &Path,
        encrypted_key: String,
        stats: EncryptionStats,
        options: UploadOptions,
    ) -> Result<UploadResult> {
        let response = self
            .client
            .create_multipart_upload()
            .bucket(&self.bucket)
            .key(&encrypted_key)
            .send()
            .await
            .map_err(|error| Error::Source(format!("S3 CreateMultipartUpload failed: {error}")))?;
        let upload_id = response
            .upload_id()
            .ok_or_else(|| Error::Source("S3 omitted multipart upload ID".into()))?
            .to_owned();
        let mut abort_guard = MultipartAbortGuard::new(
            self.client.clone(),
            self.bucket.clone(),
            encrypted_key.clone(),
            upload_id.clone(),
        );
        let outcome = self
            .upload_parts(path, &encrypted_key, &upload_id, stats, options)
            .await;
        if let Err(primary) = outcome {
            match abort_multipart_verified(
                &self.client,
                &self.bucket,
                &encrypted_key,
                &upload_id,
                options.max_abort_attempts,
                options.retry_base_delay,
            )
            .await
            {
                Ok(()) => abort_guard.disarm(),
                Err(cleanup) => {
                    return Err(Error::Source(format!(
                        "upload failed: {primary}; multipart cleanup could not be verified: {cleanup}"
                    )));
                }
            }
            return Err(primary);
        }
        abort_guard.disarm();
        outcome
    }

    async fn upload_parts(
        &self,
        path: &Path,
        encrypted_key: &str,
        upload_id: &str,
        stats: EncryptionStats,
        options: UploadOptions,
    ) -> Result<UploadResult> {
        let part_size = options.part_size;
        let part_count = stats.encrypted_bytes.div_ceil(part_size);
        if part_count > 10_000 {
            return Err(Error::Source(format!(
                "multipart upload requires {part_count} parts; S3 maximum is 10000"
            )));
        }
        let mut file = tokio::fs::File::open(path)
            .await
            .map_err(|source| Error::Io {
                path: path.into(),
                source,
            })?;
        let mut remaining = stats.encrypted_bytes;
        let mut parts = Vec::with_capacity(part_count as usize);
        for index in 0..part_count {
            let length = remaining.min(part_size);
            let allocation = usize::try_from(length)
                .map_err(|_| Error::Source("multipart part does not fit in memory".into()))?;
            let content_length = i64::try_from(length)
                .map_err(|_| Error::Source("multipart part exceeds S3 limit".into()))?;
            let mut bytes = vec![0_u8; allocation];
            file.read_exact(&mut bytes)
                .await
                .map_err(|source| Error::Io {
                    path: path.into(),
                    source,
                })?;
            let number = i32::try_from(index + 1).map_err(|_| Error::RangeOverflow)?;
            let etag = self
                .upload_part_with_retry(
                    encrypted_key,
                    upload_id,
                    number,
                    Bytes::from(bytes),
                    content_length,
                    options,
                )
                .await?;
            parts.push(
                CompletedPart::builder()
                    .part_number(number)
                    .e_tag(etag)
                    .build(),
            );
            remaining -= length;
        }

        self.complete_multipart(encrypted_key, upload_id, parts, stats)
            .await
    }

    async fn upload_stream_parts<R>(
        &self,
        mut reader: R,
        encrypted_key: &str,
        upload_id: &str,
        options: UploadOptions,
    ) -> Result<(Vec<CompletedPart>, u64)>
    where
        R: AsyncRead + Unpin,
    {
        let allocation = usize::try_from(options.part_size)
            .map_err(|_| Error::Source("multipart part does not fit in memory".into()))?;
        let mut parts = Vec::new();
        let mut uploaded_bytes = 0_u64;
        loop {
            let mut bytes = vec![0_u8; allocation];
            let mut filled = 0_usize;
            while filled < bytes.len() {
                let count =
                    reader
                        .read(&mut bytes[filled..])
                        .await
                        .map_err(|source| Error::Io {
                            path: Path::new("<encrypted multipart stream>").into(),
                            source,
                        })?;
                if count == 0 {
                    break;
                }
                filled += count;
            }
            if filled == 0 {
                break;
            }
            bytes.truncate(filled);
            let number = i32::try_from(parts.len() + 1).map_err(|_| Error::RangeOverflow)?;
            if number > 10_000 {
                return Err(Error::Source(
                    "streaming multipart upload exceeds S3 maximum of 10000 parts".into(),
                ));
            }
            let content_length = i64::try_from(filled)
                .map_err(|_| Error::Source("multipart part exceeds S3 limit".into()))?;
            let etag = self
                .upload_part_with_retry(
                    encrypted_key,
                    upload_id,
                    number,
                    Bytes::from(bytes),
                    content_length,
                    options,
                )
                .await?;
            parts.push(
                CompletedPart::builder()
                    .part_number(number)
                    .e_tag(etag)
                    .build(),
            );
            uploaded_bytes = uploaded_bytes
                .checked_add(filled as u64)
                .ok_or(Error::RangeOverflow)?;
            if filled < allocation {
                break;
            }
        }
        Ok((parts, uploaded_bytes))
    }

    async fn upload_part_with_retry(
        &self,
        encrypted_key: &str,
        upload_id: &str,
        part_number: i32,
        bytes: Bytes,
        content_length: i64,
        options: UploadOptions,
    ) -> Result<String> {
        let mut last_error = None;
        for attempt in 0..options.max_part_attempts {
            let result = self
                .client
                .upload_part()
                .bucket(&self.bucket)
                .key(encrypted_key)
                .upload_id(upload_id)
                .part_number(part_number)
                .content_length(content_length)
                .body(ByteStream::from(bytes.clone()))
                .send()
                .await;
            match result {
                Ok(response) => {
                    return response
                        .e_tag()
                        .map(ToOwned::to_owned)
                        .ok_or_else(|| Error::Source("S3 UploadPart omitted ETag".into()));
                }
                Err(error) => last_error = Some(error.to_string()),
            }
            if attempt + 1 < options.max_part_attempts {
                tokio::time::sleep(retry_delay(options.retry_base_delay, attempt)).await;
            }
        }
        Err(Error::Source(format!(
            "S3 UploadPart failed after {} attempts: {}",
            options.max_part_attempts,
            last_error.unwrap_or_else(|| "unknown error".into())
        )))
    }

    async fn complete_multipart(
        &self,
        encrypted_key: &str,
        upload_id: &str,
        parts: Vec<CompletedPart>,
        stats: EncryptionStats,
    ) -> Result<UploadResult> {
        let completed = CompletedMultipartUpload::builder()
            .set_parts(Some(parts))
            .build();
        let response = self
            .client
            .complete_multipart_upload()
            .bucket(&self.bucket)
            .key(encrypted_key)
            .upload_id(upload_id)
            .multipart_upload(completed)
            .send()
            .await
            .map_err(|error| {
                Error::Source(format!("S3 CompleteMultipartUpload failed: {error}"))
            })?;
        Ok(UploadResult::new(
            encrypted_key.to_owned(),
            stats,
            response.e_tag(),
            response.version_id(),
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UploadOptions {
    /// Use multipart upload at or above this encrypted size.
    pub multipart_threshold: u64,
    /// In-memory multipart part size. S3 requires at least 5 MiB.
    pub part_size: u64,
    /// Maximum outer attempts for each replayable `UploadPart` request.
    pub max_part_attempts: u8,
    /// Maximum abort followed by `ListParts` verification attempts.
    pub max_abort_attempts: u8,
    /// Initial delay for capped exponential backoff between outer attempts.
    pub retry_base_delay: Duration,
}

impl UploadOptions {
    fn validate(self) -> Result<()> {
        if self.part_size < MIN_MULTIPART_PART_SIZE {
            return Err(Error::Source(format!(
                "multipart part size must be at least {MIN_MULTIPART_PART_SIZE} bytes"
            )));
        }
        if usize::try_from(self.part_size).is_err() || i64::try_from(self.part_size).is_err() {
            return Err(Error::Source(
                "multipart part size is unsupported on this platform".into(),
            ));
        }
        if self.max_part_attempts == 0 || self.max_abort_attempts == 0 {
            return Err(Error::Source(
                "upload retry attempt counts must be non-zero".into(),
            ));
        }
        Ok(())
    }
}

impl Default for UploadOptions {
    fn default() -> Self {
        Self {
            multipart_threshold: 16 * 1024 * 1024,
            part_size: 8 * 1024 * 1024,
            max_part_attempts: 3,
            max_abort_attempts: 3,
            retry_base_delay: Duration::from_millis(200),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadResult {
    pub encrypted_key: String,
    pub stats: EncryptionStats,
    pub etag: Option<String>,
    pub version_id: Option<String>,
}

impl UploadResult {
    fn new(
        encrypted_key: String,
        stats: EncryptionStats,
        etag: Option<&str>,
        version_id: Option<&str>,
    ) -> Self {
        Self {
            encrypted_key,
            stats,
            etag: etag.map(ToOwned::to_owned),
            version_id: version_id.map(ToOwned::to_owned),
        }
    }
}

struct MultipartAbortGuard {
    client: Client,
    bucket: String,
    key: String,
    upload_id: String,
    armed: bool,
}

impl MultipartAbortGuard {
    fn new(client: Client, bucket: String, key: String, upload_id: String) -> Self {
        Self {
            client,
            bucket,
            key,
            upload_id,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for MultipartAbortGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let client = self.client.clone();
        let bucket = self.bucket.clone();
        let key = self.key.clone();
        let upload_id = self.upload_id.clone();
        runtime.spawn(async move {
            let _ = abort_multipart_verified(
                &client,
                &bucket,
                &key,
                &upload_id,
                3,
                Duration::from_millis(200),
            )
            .await;
        });
    }
}

fn retry_delay(base: Duration, attempt: u8) -> Duration {
    base.saturating_mul(1_u32 << attempt.min(8))
}

async fn abort_multipart_verified(
    client: &Client,
    bucket: &str,
    key: &str,
    upload_id: &str,
    max_attempts: u8,
    base_delay: Duration,
) -> std::result::Result<(), String> {
    let mut last_error = None;
    for attempt in 0..max_attempts {
        match client
            .abort_multipart_upload()
            .bucket(bucket)
            .key(key)
            .upload_id(upload_id)
            .send()
            .await
        {
            Ok(_) => {}
            Err(error)
                if error
                    .raw_response()
                    .is_some_and(|response| response.status().as_u16() == 404) =>
            {
                return Ok(());
            }
            Err(error) => {
                last_error = Some(format!("S3 AbortMultipartUpload failed: {error}"));
                if attempt + 1 < max_attempts {
                    tokio::time::sleep(retry_delay(base_delay, attempt)).await;
                }
                continue;
            }
        }

        match client
            .list_parts()
            .bucket(bucket)
            .key(key)
            .upload_id(upload_id)
            .max_parts(1)
            .send()
            .await
        {
            Ok(output) if output.parts().is_empty() => return Ok(()),
            Ok(_) => last_error = Some("multipart upload still has parts after abort".into()),
            Err(error)
                if error
                    .raw_response()
                    .is_some_and(|response| response.status().as_u16() == 404) =>
            {
                return Ok(());
            }
            Err(error) => {
                last_error = Some(format!("S3 ListParts verification failed: {error}"));
            }
        }
        if attempt + 1 < max_attempts {
            tokio::time::sleep(retry_delay(base_delay, attempt)).await;
        }
    }
    Err(last_error.unwrap_or_else(|| "multipart cleanup could not be verified".into()))
}

#[cfg(test)]
mod upload_option_tests {
    use super::*;

    #[test]
    fn upload_retry_defaults_are_bounded() {
        let options = UploadOptions::default();
        assert_eq!(options.max_part_attempts, 3);
        assert_eq!(options.max_abort_attempts, 3);
        assert_eq!(options.retry_base_delay, Duration::from_millis(200));
        options.validate().unwrap();
    }

    #[test]
    fn zero_retry_attempts_are_rejected() {
        let options = UploadOptions {
            max_part_attempts: 0,
            ..UploadOptions::default()
        };
        assert!(options.validate().is_err());
        let options = UploadOptions {
            max_abort_attempts: 0,
            ..UploadOptions::default()
        };
        assert!(options.validate().is_err());
    }

    #[test]
    fn retry_backoff_is_bounded() {
        let base = Duration::from_millis(200);
        assert_eq!(retry_delay(base, 0), Duration::from_millis(200));
        assert_eq!(retry_delay(base, 2), Duration::from_millis(800));
        assert_eq!(retry_delay(base, u8::MAX), Duration::from_millis(51_200));
    }
}
