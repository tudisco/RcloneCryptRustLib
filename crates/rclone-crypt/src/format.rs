use crate::{Error, Result};

pub const FILE_MAGIC: &[u8; 8] = b"RCLONE\0\0";
pub const FILE_HEADER_SIZE: u64 = 32;
pub const BLOCK_DATA_SIZE: u64 = 65_536;
pub const BLOCK_OVERHEAD: u64 = 16;
pub const BLOCK_SIZE: u64 = BLOCK_DATA_SIZE + BLOCK_OVERHEAD;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub nonce: [u8; 24],
}

impl Header {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < FILE_HEADER_SIZE as usize {
            return Err(Error::EncryptedFileTooShort);
        }
        if &bytes[..8] != FILE_MAGIC {
            return Err(Error::BadMagic);
        }
        let mut nonce = [0_u8; 24];
        nonce.copy_from_slice(&bytes[8..32]);
        Ok(Self { nonce })
    }

    pub fn nonce_for_chunk(&self, chunk: u64) -> [u8; 24] {
        add_nonce(self.nonce, chunk)
    }
}

pub fn add_nonce(mut nonce: [u8; 24], mut value: u64) -> [u8; 24] {
    let mut carry = 0_u16;
    for digit in nonce.iter_mut().take(8) {
        carry += u16::from(*digit) + u16::from(value as u8);
        *digit = carry as u8;
        carry >>= 8;
        value >>= 8;
    }
    let mut index = 8;
    while carry != 0 && index < nonce.len() {
        let sum = u16::from(nonce[index]) + carry;
        nonce[index] = sum as u8;
        carry = sum >> 8;
        index += 1;
    }
    nonce
}

pub fn encrypted_size(plaintext: u64) -> Result<u64> {
    let full = plaintext / BLOCK_DATA_SIZE;
    let remainder = plaintext % BLOCK_DATA_SIZE;
    let full_bytes = full.checked_mul(BLOCK_SIZE).ok_or(Error::RangeOverflow)?;
    let tail = if remainder == 0 {
        0
    } else {
        remainder
            .checked_add(BLOCK_OVERHEAD)
            .ok_or(Error::RangeOverflow)?
    };
    FILE_HEADER_SIZE
        .checked_add(full_bytes)
        .and_then(|value| value.checked_add(tail))
        .ok_or(Error::RangeOverflow)
}

pub fn plaintext_size(encrypted: u64) -> Result<u64> {
    let payload = encrypted
        .checked_sub(FILE_HEADER_SIZE)
        .ok_or(Error::EncryptedFileTooShort)?;
    let full = payload / BLOCK_SIZE;
    let remainder = payload % BLOCK_SIZE;
    if remainder != 0 && remainder <= BLOCK_OVERHEAD {
        return Err(Error::TruncatedBlockHeader);
    }
    full.checked_mul(BLOCK_DATA_SIZE)
        .and_then(|value| {
            value.checked_add(if remainder == 0 {
                0
            } else {
                remainder - BLOCK_OVERHEAD
            })
        })
        .ok_or(Error::RangeOverflow)
}

pub(crate) fn ciphertext_span(
    range: std::ops::Range<u64>,
    plaintext_len: u64,
    encrypted_len: u64,
) -> Result<CiphertextSpan> {
    if range.start > range.end || range.end > plaintext_len {
        return Err(Error::InvalidRange {
            start: range.start,
            end: range.end,
            size: plaintext_len,
        });
    }
    if range.is_empty() {
        return Ok(CiphertextSpan {
            first_chunk: 0,
            chunk_count: 0,
            start: FILE_HEADER_SIZE,
            end: FILE_HEADER_SIZE,
            discard: 0,
            take: 0,
        });
    }
    let first_chunk = range.start / BLOCK_DATA_SIZE;
    let last_chunk = (range.end - 1) / BLOCK_DATA_SIZE;
    let start = FILE_HEADER_SIZE
        .checked_add(
            first_chunk
                .checked_mul(BLOCK_SIZE)
                .ok_or(Error::RangeOverflow)?,
        )
        .ok_or(Error::RangeOverflow)?;
    let nominal_end = FILE_HEADER_SIZE
        .checked_add(
            (last_chunk + 1)
                .checked_mul(BLOCK_SIZE)
                .ok_or(Error::RangeOverflow)?,
        )
        .ok_or(Error::RangeOverflow)?;
    Ok(CiphertextSpan {
        first_chunk,
        chunk_count: last_chunk - first_chunk + 1,
        start,
        end: nominal_end.min(encrypted_len),
        discard: range.start % BLOCK_DATA_SIZE,
        take: range.end - range.start,
    })
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct CiphertextSpan {
    pub first_chunk: u64,
    pub chunk_count: u64,
    pub start: u64,
    pub end: u64,
    pub discard: u64,
    pub take: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rclone_size_vectors() {
        for (plain, encrypted) in [(0, 32), (1, 49), (65_536, 65_584), (65_537, 65_601)] {
            assert_eq!(encrypted_size(plain).unwrap(), encrypted);
            assert_eq!(plaintext_size(encrypted).unwrap(), plain);
        }
    }

    #[test]
    fn truncated_authenticator_is_rejected() {
        for trailing in 1..=16 {
            assert!(matches!(
                plaintext_size(FILE_HEADER_SIZE + trailing),
                Err(Error::TruncatedBlockHeader)
            ));
        }
    }

    #[test]
    fn nonce_is_little_endian_with_carry() {
        let mut nonce = [0_u8; 24];
        nonce[0] = 0xff;
        let result = add_nonce(nonce, 1);
        assert_eq!(result[0], 0);
        assert_eq!(result[1], 1);
    }
}
