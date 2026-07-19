use std::{
    future::Future,
    io::SeekFrom,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncSeek, ReadBuf};

use crate::{Error, RangeSource, RcloneCryptObject, Result};

const DEFAULT_FETCH_SIZE: u64 = 1024 * 1024;
// A plaintext window maps to whole 64 KiB chunks plus at most one boundary
// chunk. This ceiling keeps the mapped ciphertext under `RcloneCryptObject`'s
// 64 MiB one-shot read cap, so a large configured window can never fail at
// fetch time.
const MAX_FETCH_SIZE: u64 = 63 * 1024 * 1024;
type ReadFuture = Pin<Box<dyn Future<Output = Result<Bytes>> + Send + 'static>>;

/// A bounded-memory Tokio reader with optional one-window prefetch.
pub struct CryptReader<S> {
    object: Arc<RcloneCryptObject<S>>,
    position: u64,
    fetch_size: u64,
    prefetch_enabled: bool,
    buffer: Bytes,
    buffer_offset: usize,
    next_fetch_start: u64,
    in_flight: Option<ReadFuture>,
    prefetched: Option<Result<Bytes>>,
}

impl<S: RangeSource + 'static> CryptReader<S> {
    pub(crate) fn new(object: Arc<RcloneCryptObject<S>>) -> Self {
        Self {
            object,
            position: 0,
            fetch_size: DEFAULT_FETCH_SIZE,
            prefetch_enabled: true,
            buffer: Bytes::new(),
            buffer_offset: 0,
            next_fetch_start: 0,
            in_flight: None,
            prefetched: None,
        }
    }

    pub fn with_fetch_size(mut self, fetch_size: u64) -> Self {
        self.fetch_size = fetch_size.clamp(1, MAX_FETCH_SIZE);
        self
    }

    pub fn with_prefetch(mut self, enabled: bool) -> Self {
        self.prefetch_enabled = enabled;
        self
    }

    pub fn position(&self) -> u64 {
        self.position
    }

    fn seek_target(&self, position: SeekFrom) -> Result<u64> {
        let size = self.object.plaintext_len();
        let target = match position {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::End(delta) => i128::from(size) + i128::from(delta),
            SeekFrom::Current(delta) => i128::from(self.position) + i128::from(delta),
        };
        if target < 0 || target > i128::from(size) {
            return Err(Error::InvalidSeek { target, size });
        }
        Ok(target as u64)
    }

    fn schedule(&mut self) {
        if self.in_flight.is_some()
            || self.prefetched.is_some()
            || self.next_fetch_start >= self.object.plaintext_len()
        {
            return;
        }
        let start = self.next_fetch_start;
        let end = start
            .saturating_add(self.fetch_size)
            .min(self.object.plaintext_len());
        self.next_fetch_start = end;
        let object = Arc::clone(&self.object);
        self.in_flight = Some(Box::pin(async move { object.read_range(start..end).await }));
    }

    fn poll_in_flight(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let Some(future) = &mut self.in_flight else {
            return Poll::Ready(());
        };
        match future.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.in_flight = None;
                self.prefetched = Some(result);
                Poll::Ready(())
            }
        }
    }

    fn reset_to(&mut self, position: u64) {
        self.position = position;
        self.buffer = Bytes::new();
        self.buffer_offset = 0;
        self.next_fetch_start = position;
        self.in_flight = None;
        self.prefetched = None;
    }
}

impl<S: RangeSource + 'static> AsyncRead for CryptReader<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        destination: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if self.buffer_offset < self.buffer.len() {
                if self.prefetch_enabled {
                    self.schedule();
                    let _ = self.poll_in_flight(cx);
                }
                let count = (self.buffer.len() - self.buffer_offset).min(destination.remaining());
                let start = self.buffer_offset;
                destination.put_slice(&self.buffer[start..start + count]);
                self.buffer_offset += count;
                self.position += count as u64;
                return Poll::Ready(Ok(()));
            }

            if destination.remaining() == 0 || self.position == self.object.plaintext_len() {
                return Poll::Ready(Ok(()));
            }

            if let Some(result) = self.prefetched.take() {
                match result {
                    Ok(bytes) => {
                        self.buffer = bytes;
                        self.buffer_offset = 0;
                        if self.prefetch_enabled {
                            self.schedule();
                            let _ = self.poll_in_flight(cx);
                        }
                        continue;
                    }
                    Err(error) => {
                        // The failed window already advanced `next_fetch_start`.
                        // Rewind to the current position so a caller that retries
                        // after this error re-fetches the same window instead of
                        // silently skipping it and misaligning the plaintext.
                        let position = self.position;
                        self.reset_to(position);
                        return Poll::Ready(Err(std::io::Error::other(error)));
                    }
                }
            }

            self.schedule();
            if self.poll_in_flight(cx).is_pending() {
                return Poll::Pending;
            }
        }
    }
}

impl<S: RangeSource + 'static> AsyncSeek for CryptReader<S> {
    fn start_seek(mut self: Pin<&mut Self>, position: SeekFrom) -> std::io::Result<()> {
        let target = self.seek_target(position).map_err(std::io::Error::other)?;
        self.reset_to(target);
        Ok(())
    }

    fn poll_complete(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<u64>> {
        Poll::Ready(Ok(self.position))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        ops::Range,
        sync::atomic::{AtomicU32, Ordering},
    };

    use async_trait::async_trait;
    use tokio::io::AsyncReadExt;

    use super::*;
    use crate::{
        Credential, Error, Keys, MemorySource, RangeSource, RcloneCryptObject,
        encrypt::encrypt_to_with_nonce,
    };

    async fn encrypt(plaintext: &[u8], keys: &Keys) -> Vec<u8> {
        let mut reader = std::io::Cursor::new(plaintext.to_vec());
        let mut ciphertext = Vec::new();
        encrypt_to_with_nonce(&mut reader, &mut ciphertext, keys, [5; 24])
            .await
            .unwrap();
        ciphertext
    }

    /// A source that fails its first data read (after the header) once, then
    /// serves the real ciphertext. Header reads always succeed.
    struct FlakyOnceSource {
        ciphertext: Bytes,
        data_reads: AtomicU32,
    }

    #[async_trait]
    impl RangeSource for FlakyOnceSource {
        async fn size(&self) -> Result<u64> {
            Ok(self.ciphertext.len() as u64)
        }

        async fn read_range(&self, range: Range<u64>) -> Result<Bytes> {
            if range.start >= crate::FILE_HEADER_SIZE
                && self.data_reads.fetch_add(1, Ordering::SeqCst) == 0
            {
                return Err(Error::Source("transient".into()));
            }
            Ok(self
                .ciphertext
                .slice(range.start as usize..range.end as usize))
        }
    }

    #[tokio::test]
    async fn retry_after_transient_error_does_not_skip_a_window() {
        let keys = Keys::derive(&Credential::Clear("pw".into()), None).unwrap();
        let plaintext: Vec<u8> = (0..300_000).map(|index| (index % 251) as u8).collect();
        let ciphertext = encrypt(&plaintext, &keys).await;

        let source = Arc::new(FlakyOnceSource {
            ciphertext: Bytes::from(ciphertext),
            data_reads: AtomicU32::new(0),
        });
        let object = Arc::new(RcloneCryptObject::open(source, keys).await.unwrap());
        let mut reader = object
            .reader()
            .with_fetch_size(64 * 1024)
            .with_prefetch(false);

        // The first data fetch fails; retrying must resume at byte 0, not skip
        // the failed window and misalign every subsequent byte.
        let mut collected = Vec::new();
        let mut buffer = vec![0_u8; 4096];
        loop {
            match reader.read(&mut buffer).await {
                Ok(0) => break,
                Ok(count) => collected.extend_from_slice(&buffer[..count]),
                Err(_) => continue,
            }
        }
        assert_eq!(collected, plaintext);
    }

    #[tokio::test]
    async fn fetch_size_is_clamped_to_a_safe_ceiling() {
        let keys = Keys::derive(&Credential::Clear("pw".into()), None).unwrap();
        let ciphertext = encrypt(&[0_u8; 128], &keys).await;
        let object = Arc::new(
            RcloneCryptObject::open(Arc::new(MemorySource::new(ciphertext)), keys)
                .await
                .unwrap(),
        );
        // A wildly oversized request is clamped so it can never exceed the
        // one-shot ciphertext cap enforced by `read_range`.
        let reader = object.reader().with_fetch_size(1024 * 1024 * 1024);
        assert_eq!(reader.fetch_size, MAX_FETCH_SIZE);
        let reader = object.reader().with_fetch_size(0);
        assert_eq!(reader.fetch_size, 1);
    }
}
