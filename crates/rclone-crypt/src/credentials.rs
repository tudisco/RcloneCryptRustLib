use aes::Aes256;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ctr::cipher::{KeyIvInit, StreamCipher};
use scrypt::{Params, scrypt};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, Result};

const DEFAULT_SALT: [u8; 16] = [
    0xA8, 0x0D, 0xF4, 0x3A, 0x8F, 0xBD, 0x03, 0x08, 0xA7, 0xCA, 0xB8, 0x3E, 0x58, 0x1F, 0x86, 0xB1,
];

const OBSCURE_KEY: [u8; 32] = [
    0x9c, 0x93, 0x5b, 0x48, 0x73, 0x0a, 0x55, 0x4d, 0x6b, 0xfd, 0x7c, 0x63, 0xc8, 0x86, 0xa9, 0x2b,
    0xd3, 0x90, 0x19, 0x8e, 0xb8, 0x12, 0x8a, 0xfb, 0xf4, 0xde, 0x16, 0x2b, 0x8b, 0x95, 0xf6, 0x38,
];

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

#[derive(Clone)]
pub enum Credential {
    Clear(String),
    Obscured(String),
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Clear(_) => f.write_str("Credential::Clear([REDACTED])"),
            Self::Obscured(_) => f.write_str("Credential::Obscured([REDACTED])"),
        }
    }
}

impl Zeroize for Credential {
    fn zeroize(&mut self) {
        match self {
            Self::Clear(value) | Self::Obscured(value) => value.zeroize(),
        }
    }
}

impl Drop for Credential {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Credential {
    fn reveal(&self) -> Result<Vec<u8>> {
        match self {
            Self::Clear(value) => Ok(value.as_bytes().to_vec()),
            Self::Obscured(value) => reveal_obscured(value),
        }
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Keys {
    pub(crate) data: [u8; 32],
    pub(crate) name: [u8; 32],
    pub(crate) name_tweak: [u8; 16],
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Keys([REDACTED])")
    }
}

impl Keys {
    pub fn derive(password: &Credential, salt: Option<&Credential>) -> Result<Self> {
        let mut password = password.reveal()?;
        let mut custom_salt = match salt {
            Some(value) => value.reveal()?,
            None => Vec::new(),
        };
        let salt_bytes = if custom_salt.is_empty() {
            DEFAULT_SALT.as_slice()
        } else {
            custom_salt.as_slice()
        };

        let mut material = [0_u8; 80];
        if !password.is_empty() {
            let params = Params::new(14, 8, 1).map_err(|_| Error::KeyDerivation)?;
            scrypt(&password, salt_bytes, &params, &mut material)
                .map_err(|_| Error::KeyDerivation)?;
        }

        let mut data = [0_u8; 32];
        let mut name = [0_u8; 32];
        let mut name_tweak = [0_u8; 16];
        data.copy_from_slice(&material[..32]);
        name.copy_from_slice(&material[32..64]);
        name_tweak.copy_from_slice(&material[64..]);
        material.zeroize();
        password.zeroize();
        custom_salt.zeroize();

        Ok(Self {
            data,
            name,
            name_tweak,
        })
    }

    /// Serializes the derived key material as the 80 bytes
    /// `data(32) || name(32) || name_tweak(16)` — the exact scrypt output layout.
    ///
    /// This lets a caller persist the *derived keys* (e.g. in an OS keyring) for
    /// silent re-unlock without ever storing the password, and reconstruct them
    /// later with [`Keys::from_bytes`]. Treat the output as secret: it is
    /// equivalent to the password for decryption purposes.
    pub fn to_bytes(&self) -> [u8; 80] {
        let mut out = [0_u8; 80];
        out[..32].copy_from_slice(&self.data);
        out[32..64].copy_from_slice(&self.name);
        out[64..].copy_from_slice(&self.name_tweak);
        out
    }

    /// Reconstructs `Keys` from the 80-byte layout produced by [`Keys::to_bytes`].
    /// The inverse of `to_bytes`; no validation beyond length is possible since
    /// the material is opaque key bytes.
    pub fn from_bytes(bytes: &[u8; 80]) -> Self {
        let mut data = [0_u8; 32];
        let mut name = [0_u8; 32];
        let mut name_tweak = [0_u8; 16];
        data.copy_from_slice(&bytes[..32]);
        name.copy_from_slice(&bytes[32..64]);
        name_tweak.copy_from_slice(&bytes[64..]);
        Self {
            data,
            name,
            name_tweak,
        }
    }
}

fn reveal_obscured(value: &str) -> Result<Vec<u8>> {
    let mut decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|error| Error::InvalidObscuredCredential(error.to_string()))?;
    if decoded.len() < 16 {
        decoded.zeroize();
        return Err(Error::InvalidObscuredCredential(
            "decoded value is shorter than the AES IV".into(),
        ));
    }
    let (iv, ciphertext) = decoded.split_at_mut(16);
    let mut cipher = Aes256Ctr::new_from_slices(&OBSCURE_KEY, iv)
        .map_err(|_| Error::InvalidObscuredCredential("invalid AES parameters".into()))?;
    cipher.apply_keystream(ciphertext);
    let plaintext = ciphertext.to_vec();
    decoded.zeroize();
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reveal_matches_rclone_vector() {
        // Produced by `rclone v1.74.2 obscure 'correct horse battery staple'`.
        let obscured = "szreQczr78U6hkRLKHCGHTkEJO9XdxQSKvh_kX7ckMvzZNmzGm_KJDiu2dY";
        assert_eq!(
            reveal_obscured(obscured).unwrap(),
            b"correct horse battery staple"
        );
    }

    #[test]
    fn empty_password_is_all_zero_keys() {
        let keys = Keys::derive(&Credential::Clear(String::new()), None).unwrap();
        assert_eq!(keys.data, [0; 32]);
        assert_eq!(keys.name, [0; 32]);
        assert_eq!(keys.name_tweak, [0; 16]);
    }

    #[test]
    fn keys_bytes_roundtrip() {
        let keys = Keys::derive(
            &Credential::Clear("correct horse battery staple".into()),
            Some(&Credential::Clear("salty".into())),
        )
        .unwrap();
        let bytes = keys.to_bytes();
        let restored = Keys::from_bytes(&bytes);
        assert_eq!(restored.data, keys.data);
        assert_eq!(restored.name, keys.name);
        assert_eq!(restored.name_tweak, keys.name_tweak);
        // The layout is exactly data || name || name_tweak.
        assert_eq!(&bytes[..32], &keys.data);
        assert_eq!(&bytes[32..64], &keys.name);
        assert_eq!(&bytes[64..], &keys.name_tweak);
    }

    #[test]
    fn credential_debug_is_redacted() {
        let clear = Credential::Clear("top-secret".into());
        let obscured = Credential::Obscured("also-secret".into());
        assert!(!format!("{clear:?}").contains("top-secret"));
        assert!(!format!("{obscured:?}").contains("also-secret"));
    }
}
