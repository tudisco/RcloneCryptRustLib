use aes::{
    Aes256,
    cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray},
};
use data_encoding::BASE32HEX_NOPAD;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, Keys, Result};

const BLOCK: usize = 16;
const MAX_EME_BYTES: usize = 2048;

/// Decrypts rclone standard-encrypted filename and directory segments.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct NameCipher {
    key: [u8; 32],
    tweak: [u8; 16],
}

impl std::fmt::Debug for NameCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NameCipher([REDACTED])")
    }
}

impl NameCipher {
    pub fn new(keys: &Keys) -> Self {
        Self {
            key: keys.name,
            tweak: keys.name_tweak,
        }
    }

    /// Decrypts each slash-separated path segment independently.
    pub fn decrypt_path(&self, encrypted_path: &str) -> Result<String> {
        encrypted_path
            .split('/')
            .map(|segment| self.decrypt_segment(segment))
            .collect::<Result<Vec<_>>>()
            .map(|segments| segments.join("/"))
    }

    /// Encrypts each slash-separated path segment using rclone standard mode.
    pub fn encrypt_path(&self, plaintext_path: &str) -> Result<String> {
        plaintext_path
            .split('/')
            .map(|segment| self.encrypt_segment(segment))
            .collect::<Result<Vec<_>>>()
            .map(|segments| segments.join("/"))
    }

    pub fn encrypt_segment(&self, plaintext: &str) -> Result<String> {
        if plaintext.is_empty() {
            return Ok(String::new());
        }
        let mut padded = plaintext.as_bytes().to_vec();
        let padding = BLOCK - (padded.len() % BLOCK);
        padded.extend(std::iter::repeat_n(padding as u8, padding));
        if padded.len() > MAX_EME_BYTES {
            return Err(Error::InvalidFilenameLength);
        }
        let aes = Aes256::new((&self.key).into());
        Ok(BASE32HEX_NOPAD
            .encode(&eme_transform(&aes, self.tweak, &padded, false))
            .to_ascii_lowercase())
    }

    pub fn decrypt_segment(&self, encrypted: &str) -> Result<String> {
        if encrypted.is_empty() {
            return Ok(String::new());
        }
        if encrypted.contains('=') {
            return Err(Error::InvalidFilenameEncoding);
        }
        let uppercase = encrypted.to_ascii_uppercase();
        let ciphertext = BASE32HEX_NOPAD
            .decode(uppercase.as_bytes())
            .map_err(|_| Error::InvalidFilenameEncoding)?;
        if ciphertext.is_empty()
            || ciphertext.len() > MAX_EME_BYTES
            || ciphertext.len() % BLOCK != 0
        {
            return Err(Error::InvalidFilenameLength);
        }
        let aes = Aes256::new((&self.key).into());
        let mut plaintext = eme_transform(&aes, self.tweak, &ciphertext, true);
        let padding = usize::from(*plaintext.last().ok_or(Error::InvalidFilenamePadding)?);
        if padding == 0
            || padding > BLOCK
            || plaintext.len() < padding
            || !plaintext[plaintext.len() - padding..]
                .iter()
                .all(|byte| usize::from(*byte) == padding)
        {
            return Err(Error::InvalidFilenamePadding);
        }
        plaintext.truncate(plaintext.len() - padding);
        String::from_utf8(plaintext).map_err(|_| Error::InvalidFilenameUtf8)
    }
}

fn eme_transform(aes: &Aes256, tweak: [u8; BLOCK], input: &[u8], decrypt: bool) -> Vec<u8> {
    let blocks = input.len() / BLOCK;
    let l_table = tabulate_l(aes, blocks);
    let mut output = vec![0_u8; input.len()];

    for index in 0..blocks {
        let mut value = array_from(&input[index * BLOCK..(index + 1) * BLOCK]);
        xor_in_place(&mut value, &l_table[index]);
        transform_block(aes, &mut value, decrypt);
        output[index * BLOCK..(index + 1) * BLOCK].copy_from_slice(&value);
    }

    let mut mp = array_from(&output[..BLOCK]);
    xor_in_place(&mut mp, &tweak);
    for index in 1..blocks {
        xor_in_place(
            &mut mp,
            &array_from(&output[index * BLOCK..(index + 1) * BLOCK]),
        );
    }
    let mut mc = mp;
    transform_block(aes, &mut mc, decrypt);
    let mut m = mp;
    xor_in_place(&mut m, &mc);

    for index in 1..blocks {
        m = multiply_by_two(m);
        let mut value = array_from(&output[index * BLOCK..(index + 1) * BLOCK]);
        xor_in_place(&mut value, &m);
        output[index * BLOCK..(index + 1) * BLOCK].copy_from_slice(&value);
    }

    let mut first = mc;
    xor_in_place(&mut first, &tweak);
    for index in 1..blocks {
        xor_in_place(
            &mut first,
            &array_from(&output[index * BLOCK..(index + 1) * BLOCK]),
        );
    }
    output[..BLOCK].copy_from_slice(&first);

    for index in 0..blocks {
        let mut value = array_from(&output[index * BLOCK..(index + 1) * BLOCK]);
        transform_block(aes, &mut value, decrypt);
        xor_in_place(&mut value, &l_table[index]);
        output[index * BLOCK..(index + 1) * BLOCK].copy_from_slice(&value);
    }
    output
}

fn tabulate_l(aes: &Aes256, blocks: usize) -> Vec<[u8; BLOCK]> {
    let mut value = [0_u8; BLOCK];
    encrypt_block(aes, &mut value);
    let mut table = Vec::with_capacity(blocks);
    for _ in 0..blocks {
        value = multiply_by_two(value);
        table.push(value);
    }
    table
}

fn multiply_by_two(input: [u8; BLOCK]) -> [u8; BLOCK] {
    let mut output = [0_u8; BLOCK];
    output[0] = input[0].wrapping_mul(2) ^ (0x87 & (0_u8.wrapping_sub(input[15] >> 7)));
    for index in 1..BLOCK {
        output[index] = input[index]
            .wrapping_mul(2)
            .wrapping_add(input[index - 1] >> 7);
    }
    output
}

fn encrypt_block(aes: &Aes256, value: &mut [u8; BLOCK]) {
    aes.encrypt_block(GenericArray::from_mut_slice(value));
}

fn decrypt_block(aes: &Aes256, value: &mut [u8; BLOCK]) {
    aes.decrypt_block(GenericArray::from_mut_slice(value));
}

fn transform_block(aes: &Aes256, value: &mut [u8; BLOCK], decrypt: bool) {
    if decrypt {
        decrypt_block(aes, value);
    } else {
        encrypt_block(aes, value);
    }
}

fn xor_in_place(left: &mut [u8; BLOCK], right: &[u8; BLOCK]) {
    for (left, right) in left.iter_mut().zip(right) {
        *left ^= *right;
    }
}

fn array_from(value: &[u8]) -> [u8; BLOCK] {
    let mut output = [0_u8; BLOCK];
    output.copy_from_slice(value);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Credential;

    #[test]
    fn decrypts_rclone_zero_key_vector() {
        let keys = Keys::derive(&Credential::Clear(String::new()), None).unwrap();
        let cipher = NameCipher::new(&keys);
        assert_eq!(
            cipher
                .decrypt_segment("p0e52nreeaj0a5ea7s64m4j72s")
                .unwrap(),
            "1"
        );
        assert_eq!(
            cipher.encrypt_segment("1").unwrap(),
            "p0e52nreeaj0a5ea7s64m4j72s"
        );
        assert!(matches!(
            cipher.encrypt_segment(&"x".repeat(MAX_EME_BYTES)),
            Err(Error::InvalidFilenameLength)
        ));
    }
}
