use std::{ops::Range, path::Path, sync::Arc};

use bytes::Bytes;
use crypto_secretbox::{KeyInit, XSalsa20Poly1305, aead::Aead};
use tokio::io::{AsyncWrite, AsyncWriteExt};

use crate::{
    CryptReader, Error, FILE_HEADER_SIZE, Header, Keys, RangeSource, Result,
    format::{BLOCK_DATA_SIZE, BLOCK_OVERHEAD, BLOCK_SIZE, ciphertext_span, plaintext_size},
};

const DOWNLOAD_BATCH_SIZE: u64 = 8 * 1024 * 1024;
const MAX_ENCRYPTED_RANGE_SIZE: u64 = 64 * 1024 * 1024;

pub struct RcloneCryptObject<S> {
    source: Arc<S>,
    keys: Keys,
    header: Header,
    encrypted_len: u64,
    plaintext_len: u64,
}

impl<S: RangeSource> RcloneCryptObject<S> {
    pub async fn open(source: Arc<S>, keys: Keys) -> Result<Self> {
        let encrypted_len = source.size().await?;
        let plaintext_len = plaintext_size(encrypted_len)?;
        let bytes = source.read_range(0..FILE_HEADER_SIZE).await?;
        exact_len(&bytes, FILE_HEADER_SIZE as usize)?;
        let header = Header::parse(&bytes)?;
        Ok(Self {
            source,
            keys,
            header,
            encrypted_len,
            plaintext_len,
        })
    }

    pub fn plaintext_len(&self) -> u64 {
        self.plaintext_len
    }

    /// Creates a seekable asynchronous reader. Reads are fetched lazily.
    pub fn reader(self: &Arc<Self>) -> CryptReader<S>
    where
        S: 'static,
    {
        CryptReader::new(Arc::clone(self))
    }

    pub async fn read_range(&self, range: Range<u64>) -> Result<Bytes> {
        let span = ciphertext_span(range.clone(), self.plaintext_len, self.encrypted_len)?;
        if span.take == 0 {
            return Ok(Bytes::new());
        }
        let encrypted_range_size = span
            .end
            .checked_sub(span.start)
            .ok_or(Error::RangeOverflow)?;
        if encrypted_range_size > MAX_ENCRYPTED_RANGE_SIZE {
            return Err(Error::RangeTooLarge {
                requested: encrypted_range_size,
                maximum: MAX_ENCRYPTED_RANGE_SIZE,
            });
        }
        let expected_encrypted =
            usize::try_from(encrypted_range_size).map_err(|_| Error::RangeOverflow)?;
        let encrypted = self.source.read_range(span.start..span.end).await?;
        exact_len(&encrypted, expected_encrypted)?;

        let cipher = XSalsa20Poly1305::new((&self.keys.data).into());
        let plaintext_capacity = span
            .chunk_count
            .checked_mul(BLOCK_DATA_SIZE)
            .ok_or(Error::RangeOverflow)?;
        let plaintext_capacity =
            usize::try_from(plaintext_capacity).map_err(|_| Error::RangeOverflow)?;
        let mut plaintext = Vec::new();
        plaintext
            .try_reserve(plaintext_capacity)
            .map_err(|_| Error::AllocationFailed {
                bytes: plaintext_capacity as u64,
            })?;
        let mut cursor = 0_usize;
        for relative in 0..span.chunk_count {
            let remaining = encrypted.len() - cursor;
            let chunk_len = remaining.min(BLOCK_SIZE as usize);
            if chunk_len <= BLOCK_OVERHEAD as usize {
                return Err(Error::TruncatedBlockHeader);
            }
            let nonce = self.header.nonce_for_chunk(span.first_chunk + relative);
            let decrypted = cipher
                .decrypt((&nonce).into(), &encrypted[cursor..cursor + chunk_len])
                .map_err(|_| Error::Authentication)?;
            plaintext.extend_from_slice(&decrypted);
            cursor += chunk_len;
        }
        if cursor != encrypted.len() {
            return Err(Error::ShortRead {
                expected: cursor,
                actual: encrypted.len(),
            });
        }
        let start = usize::try_from(span.discard).map_err(|_| Error::RangeOverflow)?;
        let take = usize::try_from(span.take).map_err(|_| Error::RangeOverflow)?;
        let end = start.checked_add(take).ok_or(Error::RangeOverflow)?;
        Ok(Bytes::from(plaintext).slice(start..end))
    }

    pub async fn copy_to<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<u64> {
        if self.plaintext_len == 0 {
            return Ok(0);
        }
        let first_end = DOWNLOAD_BATCH_SIZE.min(self.plaintext_len);
        let mut current = self.read_range(0..first_end).await?;
        let mut offset = first_end;
        loop {
            if offset == self.plaintext_len {
                writer.write_all(&current).await.map_err(writer_io_error)?;
                break;
            }
            let end = offset
                .checked_add(DOWNLOAD_BATCH_SIZE)
                .ok_or(Error::RangeOverflow)?
                .min(self.plaintext_len);
            let next = self.read_range(offset..end);
            let (write_result, next_result) = tokio::join!(writer.write_all(&current), next);
            write_result.map_err(writer_io_error)?;
            current = next_result?;
            offset = end;
        }
        Ok(offset)
    }

    pub async fn download_to(
        &self,
        destination: impl AsRef<Path>,
        options: DownloadOptions,
    ) -> Result<u64> {
        let destination = destination.as_ref();
        if !options.overwrite
            && tokio::fs::try_exists(destination)
                .await
                .map_err(|source| Error::Io {
                    path: destination.into(),
                    source,
                })?
        {
            return Err(Error::DestinationExists(destination.into()));
        }
        if options.create_parent {
            if let Some(parent) = destination.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .map_err(|source| Error::Io {
                        path: parent.into(),
                        source,
                    })?;
            }
        }
        let filename = destination
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("download");
        let parent = destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let temporary = tempfile::Builder::new()
            .prefix(&format!(".{filename}."))
            .suffix(".part")
            .tempfile_in(parent)
            .map_err(|source| Error::Io {
                path: parent.into(),
                source,
            })?;
        let temporary_path = temporary.path().to_path_buf();
        let std_file = temporary
            .as_file()
            .try_clone()
            .map_err(|source| Error::Io {
                path: temporary_path.clone(),
                source,
            })?;
        let mut file = tokio::fs::File::from_std(std_file);
        let count = self.copy_to(&mut file).await?;
        file.flush().await.map_err(|source| Error::Io {
            path: temporary_path.clone(),
            source,
        })?;
        if options.sync_data {
            file.sync_all().await.map_err(|source| Error::Io {
                path: temporary_path,
                source,
            })?;
        }
        drop(file);
        let persisted = if options.overwrite {
            temporary.persist(destination)
        } else {
            temporary.persist_noclobber(destination)
        };
        persisted.map_err(|error| {
            if error.error.kind() == std::io::ErrorKind::AlreadyExists {
                Error::DestinationExists(destination.into())
            } else {
                Error::Io {
                    path: destination.into(),
                    source: error.error,
                }
            }
        })?;
        if options.sync_data {
            // Persist the rename itself, not just the file contents, so a crash
            // immediately after publication cannot lose the directory entry.
            // Best-effort: the data is already durable and the file published.
            if let Ok(directory) = std::fs::File::open(parent) {
                let _ = directory.sync_all();
            }
        }
        Ok(count)
    }
}

fn writer_io_error(source: std::io::Error) -> Error {
    Error::Io {
        path: Path::new("<async writer>").into(),
        source,
    }
}

fn exact_len(bytes: &[u8], expected: usize) -> Result<()> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(Error::ShortRead {
            expected,
            actual: bytes.len(),
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DownloadOptions {
    /// Permit atomic replacement of an existing destination.
    pub overwrite: bool,
    /// Create missing parent directories before publishing.
    pub create_parent: bool,
    /// `sync_all` the temporary file (and its parent directory after the
    /// rename) before returning, so a crash cannot lose a completed download.
    pub sync_data: bool,
}

impl Default for DownloadOptions {
    fn default() -> Self {
        Self {
            overwrite: false,
            create_parent: true,
            sync_data: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Credential, FILE_MAGIC, MemorySource, encrypt::encrypt_to_with_nonce, encrypted_size,
    };
    use async_trait::async_trait;

    async fn encrypted_fixture(plaintext: &[u8], keys: &Keys) -> Vec<u8> {
        let mut reader = std::io::Cursor::new(plaintext.to_vec());
        let mut encrypted = Vec::new();
        encrypt_to_with_nonce(&mut reader, &mut encrypted, keys, [9; 24])
            .await
            .unwrap();
        encrypted
    }

    #[tokio::test]
    async fn corruption_and_wrong_key_never_return_plaintext() {
        let keys = Keys::derive(
            &Credential::Clear("right password".into()),
            Some(&Credential::Clear("right salt".into())),
        )
        .unwrap();
        let plaintext = vec![0x5a; 100_000];
        let encrypted = encrypted_fixture(&plaintext, &keys).await;

        for index in [32_usize, 40, 65_583, encrypted.len() - 1] {
            let mut corrupt = encrypted.clone();
            corrupt[index] ^= 0x80;
            let object =
                RcloneCryptObject::open(Arc::new(MemorySource::new(corrupt)), keys.clone())
                    .await
                    .unwrap();
            assert!(matches!(
                object.read_range(0..plaintext.len() as u64).await,
                Err(Error::Authentication)
            ));
        }

        let wrong = Keys::derive(
            &Credential::Clear("wrong password".into()),
            Some(&Credential::Clear("right salt".into())),
        )
        .unwrap();
        let object = RcloneCryptObject::open(Arc::new(MemorySource::new(encrypted)), wrong)
            .await
            .unwrap();
        assert!(matches!(
            object.read_range(0..plaintext.len() as u64).await,
            Err(Error::Authentication)
        ));
    }

    #[tokio::test]
    async fn truncated_structures_are_rejected() {
        let keys = Keys::derive(&Credential::Clear(String::new()), None).unwrap();
        for length in 0..32 {
            assert!(matches!(
                RcloneCryptObject::open(
                    Arc::new(MemorySource::new(vec![0_u8; length])),
                    keys.clone()
                )
                .await,
                Err(Error::EncryptedFileTooShort)
            ));
        }

        let mut encrypted = encrypted_fixture(&[7; 32], &keys).await;
        encrypted.truncate(32 + 16);
        assert!(matches!(
            RcloneCryptObject::open(Arc::new(MemorySource::new(encrypted)), keys).await,
            Err(Error::TruncatedBlockHeader)
        ));
    }

    #[tokio::test]
    async fn failed_atomic_download_preserves_existing_destination() {
        let keys = Keys::derive(&Credential::Clear(String::new()), None).unwrap();
        let mut encrypted = encrypted_fixture(&vec![3; 100_000], &keys).await;
        encrypted[40] ^= 1;
        let object = RcloneCryptObject::open(Arc::new(MemorySource::new(encrypted)), keys)
            .await
            .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("existing.bin");
        tokio::fs::write(&destination, b"keep me").await.unwrap();
        let result = object
            .download_to(
                &destination,
                DownloadOptions {
                    overwrite: true,
                    ..DownloadOptions::default()
                },
            )
            .await;
        assert!(matches!(result, Err(Error::Authentication)));
        assert_eq!(tokio::fs::read(&destination).await.unwrap(), b"keep me");
        let entries = std::fs::read_dir(directory.path()).unwrap().count();
        assert_eq!(entries, 1, "temporary partial file was not cleaned");
    }

    #[tokio::test]
    async fn oversized_coalesced_range_is_rejected_before_source_read() {
        struct HugeSource;

        #[async_trait]
        impl RangeSource for HugeSource {
            async fn size(&self) -> Result<u64> {
                encrypted_size(128 * 1024 * 1024)
            }

            async fn read_range(&self, range: Range<u64>) -> Result<Bytes> {
                assert_eq!(
                    range,
                    0..FILE_HEADER_SIZE,
                    "oversized data range was fetched"
                );
                let mut header = FILE_MAGIC.to_vec();
                header.extend_from_slice(&[0_u8; 24]);
                Ok(Bytes::from(header))
            }
        }

        let keys = Keys::derive(&Credential::Clear(String::new()), None).unwrap();
        let object = RcloneCryptObject::open(Arc::new(HugeSource), keys)
            .await
            .unwrap();
        assert!(matches!(
            object.read_range(0..128 * 1024 * 1024).await,
            Err(Error::RangeTooLarge { .. })
        ));
    }
}
