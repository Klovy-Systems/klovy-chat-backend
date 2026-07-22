pub mod message_content;
pub mod verify;

use base64::Engine;

/// Max length of base64 ciphertext stored in `content` for E2E messages.
pub const MAX_E2E_CIPHERTEXT_LEN: usize = 16_384;

pub const E2E_VERSION_DM: u8 = 1;
pub const E2E_VERSION_CHANNEL: u8 = 2;

pub fn is_valid_e2e_ciphertext(content: &str) -> bool {
    let trimmed = content.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_E2E_CIPHERTEXT_LEN {
        return false;
    }
    base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .is_ok()
}

pub fn compute_identity_fingerprint(identity_key_b64: &str) -> Option<String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(identity_key_b64.trim())
        .ok()?;
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(&bytes);
    Some(hex::encode(hash))
}
