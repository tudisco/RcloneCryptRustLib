#![forbid(unsafe_code)]

//! Storage-independent support for reading and writing rclone crypt objects.

mod credentials;
mod encrypt;
mod error;
mod format;
mod names;
mod object;
mod reader;
mod source;

pub use credentials::{Credential, Keys};
pub use encrypt::{EncryptionStats, encrypt_to};
pub use error::{Error, Result};
pub use format::{
    BLOCK_DATA_SIZE, BLOCK_SIZE, FILE_HEADER_SIZE, FILE_MAGIC, Header, encrypted_size,
    plaintext_size,
};
pub use names::NameCipher;
pub use object::{DownloadOptions, RcloneCryptObject};
pub use reader::CryptReader;
pub use source::{MemorySource, RangeSource};
