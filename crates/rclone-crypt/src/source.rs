use std::{ops::Range, sync::Arc};

use async_trait::async_trait;
use bytes::Bytes;

use crate::{Error, Result};

#[async_trait]
pub trait RangeSource: Send + Sync {
    async fn size(&self) -> Result<u64>;
    async fn read_range(&self, range: Range<u64>) -> Result<Bytes>;
}

#[derive(Clone, Debug)]
pub struct MemorySource {
    bytes: Arc<Bytes>,
}

impl MemorySource {
    pub fn new(bytes: impl Into<Bytes>) -> Self {
        Self {
            bytes: Arc::new(bytes.into()),
        }
    }
}

#[async_trait]
impl RangeSource for MemorySource {
    async fn size(&self) -> Result<u64> {
        Ok(self.bytes.len() as u64)
    }

    async fn read_range(&self, range: Range<u64>) -> Result<Bytes> {
        let size = self.bytes.len() as u64;
        if range.start > range.end || range.end > size {
            return Err(Error::InvalidRange {
                start: range.start,
                end: range.end,
                size,
            });
        }
        Ok(self.bytes.slice(range.start as usize..range.end as usize))
    }
}
