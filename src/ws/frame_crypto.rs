use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};

pub const FRAME_VERSION: u8 = 1;
pub const NONCE_LEN: usize = 12;

/// Per-connection AES-GCM cipher — avoids `Aes256Gcm::new_from_slice` on every frame.
pub struct FrameCipher {
    cipher: Aes256Gcm,
}

impl FrameCipher {
    pub fn new(key: &[u8; 32]) -> Result<Self, String> {
        Ok(Self {
            cipher: Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?,
        })
    }

    pub fn encrypt(&self, plaintext: &str) -> Result<Vec<u8>, String> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        aes_gcm::aead::rand_core::RngCore::fill_bytes(&mut OsRng, &mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| e.to_string())?;

        let mut out = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
        out.push(FRAME_VERSION);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<String, String> {
        if data.first().copied() != Some(FRAME_VERSION) {
            return Err("Unsupported WS frame version".to_string());
        }
        if data.len() <= 1 + NONCE_LEN {
            return Err("Invalid encrypted WS frame".to_string());
        }

        let nonce = Nonce::from_slice(&data[1..1 + NONCE_LEN]);
        let ciphertext = &data[1 + NONCE_LEN..];
        let plain = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| "Failed to decrypt WS frame".to_string())?;
        String::from_utf8(plain).map_err(|_| "Invalid decrypted WS frame".to_string())
    }
}

pub fn encrypt_frame(key: &[u8; 32], plaintext: &str) -> Result<Vec<u8>, String> {
    FrameCipher::new(key)?.encrypt(plaintext)
}

pub fn decrypt_frame(key: &[u8; 32], data: &[u8]) -> Result<String, String> {
    FrameCipher::new(key)?.decrypt(data)
}
