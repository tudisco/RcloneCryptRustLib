use std::path::Path;

use crypto_secretbox::{KeyInit, XSalsa20Poly1305, aead::Aead};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    BLOCK_DATA_SIZE, Error, FILE_HEADER_SIZE, FILE_MAGIC, Keys, Result, format::add_nonce,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EncryptionStats {
    pub plaintext_bytes: u64,
    pub encrypted_bytes: u64,
    pub chunks: u64,
}

/// Streams plaintext into the exact rclone crypt content format.
pub async fn encrypt_to<R, W>(
    reader: &mut R,
    writer: &mut W,
    keys: &Keys,
) -> Result<EncryptionStats>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut nonce = [0_u8; 24];
    getrandom::fill(&mut nonce).map_err(|error| Error::Random(error.to_string()))?;
    encrypt_to_with_nonce(reader, writer, keys, nonce).await
}

pub(crate) async fn encrypt_to_with_nonce<R, W>(
    reader: &mut R,
    writer: &mut W,
    keys: &Keys,
    initial_nonce: [u8; 24],
) -> Result<EncryptionStats>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    writer.write_all(FILE_MAGIC).await.map_err(writer_error)?;
    writer
        .write_all(&initial_nonce)
        .await
        .map_err(writer_error)?;

    let cipher = XSalsa20Poly1305::new((&keys.data).into());
    let mut plaintext = vec![0_u8; BLOCK_DATA_SIZE as usize];
    let mut stats = EncryptionStats {
        plaintext_bytes: 0,
        encrypted_bytes: FILE_HEADER_SIZE,
        chunks: 0,
    };

    loop {
        let mut filled = 0;
        while filled < plaintext.len() {
            let count = reader
                .read(&mut plaintext[filled..])
                .await
                .map_err(reader_error)?;
            if count == 0 {
                break;
            }
            filled += count;
        }
        if filled == 0 {
            break;
        }
        let nonce = add_nonce(initial_nonce, stats.chunks);
        let encrypted = cipher
            .encrypt((&nonce).into(), &plaintext[..filled])
            .map_err(|_| Error::Authentication)?;
        writer.write_all(&encrypted).await.map_err(writer_error)?;
        stats.plaintext_bytes += filled as u64;
        stats.encrypted_bytes += encrypted.len() as u64;
        stats.chunks += 1;
        if filled < plaintext.len() {
            break;
        }
    }
    writer.flush().await.map_err(writer_error)?;
    Ok(stats)
}

fn reader_error(source: std::io::Error) -> Error {
    Error::Io {
        path: Path::new("<async plaintext reader>").into(),
        source,
    }
}

fn writer_error(source: std::io::Error) -> Error {
    Error::Io {
        path: Path::new("<async encrypted writer>").into(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Credential, encrypted_size};

    #[tokio::test]
    async fn exact_boundaries_have_no_empty_terminal_chunk() {
        for size in [0_usize, 1, 65_535, 65_536, 65_537] {
            let keys = Keys::derive(&Credential::Clear(String::new()), None).unwrap();
            let mut reader = std::io::Cursor::new(vec![7_u8; size]);
            let mut encrypted = Vec::new();
            let stats = encrypt_to_with_nonce(&mut reader, &mut encrypted, &keys, [3; 24])
                .await
                .unwrap();
            assert_eq!(stats.plaintext_bytes, size as u64);
            assert_eq!(stats.encrypted_bytes, encrypted_size(size as u64).unwrap());
            assert_eq!(encrypted.len() as u64, stats.encrypted_bytes);
        }
    }
}
