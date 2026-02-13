use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use sha2::{Digest, Sha256};
use std::fmt;

const NONCE_SIZE: usize = 12;

#[derive(Debug)]
pub enum CryptoError {
    EncryptionFailed,
    DecryptionFailed,
    InvalidFormat,
    KeyDerivationFailed,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::EncryptionFailed => write!(f, "Encryption failed"),
            CryptoError::DecryptionFailed => write!(f, "Decryption failed"),
            CryptoError::InvalidFormat => write!(f, "Invalid encrypted data format"),
            CryptoError::KeyDerivationFailed => write!(f, "Key derivation failed"),
        }
    }
}

impl std::error::Error for CryptoError {}

pub fn derive_encryption_key() -> Result<[u8; 32], CryptoError> {
    let machine_id = machine_uid::get().map_err(|_| CryptoError::KeyDerivationFailed)?;

    let mut hasher = Sha256::new();
    hasher.update(b"kiro-tools-v1:");
    hasher.update(machine_id.as_bytes());

    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);

    Ok(key)
}

pub fn encrypt_string(plaintext: &str) -> Result<String, CryptoError> {
    let key_bytes = derive_encryption_key()?;
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    use aes_gcm::aead::rand_core::RngCore;
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let mut combined = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    Ok(BASE64.encode(&combined))
}

pub fn decrypt_string(encrypted: &str) -> Result<String, CryptoError> {
    let combined = BASE64
        .decode(encrypted)
        .map_err(|_| CryptoError::InvalidFormat)?;

    if combined.len() < NONCE_SIZE {
        return Err(CryptoError::InvalidFormat);
    }

    let (nonce_bytes, ciphertext) = combined.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    let key_bytes = derive_encryption_key()?;
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    String::from_utf8(plaintext).map_err(|_| CryptoError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_encryption_key() {
        let key1 = derive_encryption_key().unwrap();
        let key2 = derive_encryption_key().unwrap();
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = "test_access_token_12345";
        let encrypted = encrypt_string(plaintext).unwrap();
        let decrypted = decrypt_string(&encrypted).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_encrypt_produces_different_ciphertext() {
        let plaintext = "same_plaintext";
        let encrypted1 = encrypt_string(plaintext).unwrap();
        let encrypted2 = encrypt_string(plaintext).unwrap();
        assert_ne!(encrypted1, encrypted2);
    }

    #[test]
    fn test_decrypt_invalid_format() {
        let result = decrypt_string("invalid_base64!");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_too_short() {
        let short_data = BASE64.encode(b"short");
        let result = decrypt_string(&short_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_empty_string() {
        let encrypted = encrypt_string("").unwrap();
        let decrypted = decrypt_string(&encrypted).unwrap();
        assert_eq!("", decrypted);
    }

    #[test]
    fn test_encrypt_unicode() {
        let plaintext = "测试中文Token🔐";
        let encrypted = encrypt_string(plaintext).unwrap();
        let decrypted = decrypt_string(&encrypted).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_encrypt_long_string() {
        let plaintext = "a".repeat(10000);
        let encrypted = encrypt_string(&plaintext).unwrap();
        let decrypted = decrypt_string(&encrypted).unwrap();
        assert_eq!(plaintext, decrypted);
    }
}
