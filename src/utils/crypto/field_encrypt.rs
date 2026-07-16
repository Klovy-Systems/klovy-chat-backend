use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use sha2::{Digest, Sha256};
use std::env;

use super::keyed_hash::derive_subkey;

const NONCE_LEN: usize = 12;
const FIELD_ENCRYPT_CONTEXT: &str = "field-encrypt-v2";

fn legacy_key_from_jwt() -> Result<[u8; 32], String> {
    let jwt_key = env::var("JWT_KEY").map_err(|_| "JWT_KEY is not defined".to_string())?;
    let digest = Sha256::digest(jwt_key.as_bytes());
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    Ok(key)
}

fn encryption_key() -> Result<[u8; 32], String> {
    if let Ok(raw) = env::var("FIELD_ENCRYPTION_KEY") {
        let raw = raw.trim();
        if !raw.is_empty() {
            if raw.len() < 32 {
                return Err("FIELD_ENCRYPTION_KEY must be at least 32 characters".to_string());
            }
            return Ok(derive_subkey(raw, FIELD_ENCRYPT_CONTEXT));
        }
    }
    legacy_key_from_jwt()
}

fn decrypt_with_key(key: &[u8; 32], encoded: &str) -> Result<String, String> {
    let data = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, encoded)
        .ok_or_else(|| "Invalid encrypted field".to_string())?;
    if data.len() <= NONCE_LEN {
        return Err("Invalid encrypted field".to_string());
    }
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let plain = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Failed to decrypt field".to_string())?;
    String::from_utf8(plain).map_err(|_| "Invalid decrypted field".to_string())
}

pub fn encrypt_field(plain: &str) -> Result<String, String> {
    let key = encryption_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    aes_gcm::aead::rand_core::RngCore::fill_bytes(&mut OsRng, &mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plain.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &out))
}

pub fn decrypt_field(encoded: &str) -> Result<String, String> {
    let key = encryption_key()?;
    match decrypt_with_key(&key, encoded) {
        Ok(value) => Ok(value),
        Err(primary_err) => {
            if env::var("FIELD_ENCRYPTION_KEY")
                .map(|v| !v.trim().is_empty())
                .unwrap_or(false)
            {
                if let Ok(raw) = env::var("FIELD_ENCRYPTION_KEY") {
                    let raw = raw.trim();
                    if raw.len() >= 32 {
                        let legacy_derived = {
                            let digest = Sha256::digest(raw.as_bytes());
                            let mut k = [0u8; 32];
                            k.copy_from_slice(&digest);
                            k
                        };
                        if let Ok(value) = decrypt_with_key(&legacy_derived, encoded) {
                            return Ok(value);
                        }
                    }
                }
                if let Ok(legacy) = legacy_key_from_jwt() {
                    if let Ok(value) = decrypt_with_key(&legacy, encoded) {
                        return Ok(value);
                    }
                }
            }
            Err(primary_err)
        }
    }
}
