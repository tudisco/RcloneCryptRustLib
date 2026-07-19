use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid rclone-obscured credential: {0}")]
    InvalidObscuredCredential(String),
    #[error("key derivation failed")]
    KeyDerivation,
    #[error("operating-system random number generation failed: {0}")]
    Random(String),
    #[error("encrypted object is shorter than the 32-byte header")]
    EncryptedFileTooShort,
    #[error("encrypted object has invalid magic")]
    BadMagic,
    #[error("encrypted object has a truncated final block header")]
    TruncatedBlockHeader,
    #[error("encrypted block authentication failed")]
    Authentication,
    #[error("invalid encrypted filename encoding")]
    InvalidFilenameEncoding,
    #[error("encrypted filename segment must decode to 16..=2048 bytes in 16-byte blocks")]
    InvalidFilenameLength,
    #[error("invalid PKCS#7 filename padding")]
    InvalidFilenamePadding,
    #[error("decrypted filename is not valid UTF-8")]
    InvalidFilenameUtf8,
    #[error("invalid plaintext range {start}..{end} for size {size}")]
    InvalidRange { start: u64, end: u64, size: u64 },
    #[error("invalid plaintext seek to {target} for size {size}")]
    InvalidSeek { target: i128, size: u64 },
    #[error("integer overflow while mapping a range")]
    RangeOverflow,
    #[error("mapped encrypted range is too large: {requested} bytes (maximum {maximum})")]
    RangeTooLarge { requested: u64, maximum: u64 },
    #[error("could not allocate {bytes} bytes for decrypted output")]
    AllocationFailed { bytes: u64 },
    #[error("range source returned {actual} bytes, expected {expected}")]
    ShortRead { expected: usize, actual: usize },
    #[error("range source error: {0}")]
    Source(String),
    #[error("source object was not found: {0}")]
    SourceNotFound(String),
    #[error("I/O error for {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("destination already exists: {0}")]
    DestinationExists(PathBuf),
}

pub type Result<T> = std::result::Result<T, Error>;
