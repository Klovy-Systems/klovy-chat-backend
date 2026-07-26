pub mod message_content;
pub mod verify;

use base64::Engine;

use crate::model::messages_model::MessageType;

/// When true, legacy path rejected plaintext at the WS boundary. Superseded by at-rest sealing.
pub const PLAINTEXT_STORAGE_FORBIDDEN: bool = false;

/** @deprecated use PLAINTEXT_STORAGE_FORBIDDEN */
pub const E2E_REQUIRED: bool = PLAINTEXT_STORAGE_FORBIDDEN;

/// Max length of base64 ciphertext stored in `content` for E2E messages.
pub const MAX_E2E_CIPHERTEXT_LEN: usize = 16_384;

pub const E2E_VERSION_DM: u8 = 1;
pub const E2E_VERSION_CHANNEL: u8 = 2;

fn decode_ciphertext_bytes(content: &str) -> Option<Vec<u8>> {
    let trimmed = content.trim();
    base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .ok()
        .or_else(|| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(trimmed)
                .ok()
        })
        .or_else(|| base64::engine::general_purpose::URL_SAFE.decode(trimmed).ok())
}

pub fn is_valid_e2e_ciphertext(content: &str) -> bool {
    let trimmed = content.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_E2E_CIPHERTEXT_LEN {
        return false;
    }
    decode_ciphertext_bytes(trimmed).is_some()
}

/// Returns true when content must not be stored (human-readable or fake base64 wrapping).
/// Does not depend on the client sending `e2eEncrypted`.
pub fn rejects_plaintext_storage(content: &str) -> bool {
    if !is_valid_e2e_ciphertext(content) {
        return true;
    }
    let Some(bytes) = decode_ciphertext_bytes(content) else {
        return true;
    };
    // Reject trivial base64("hello") masquerading as E2E — real Signal blobs are longer binary.
    if bytes.len() < 28 {
        if let Ok(text) = std::str::from_utf8(&bytes) {
            if !text.is_empty()
                && text
                    .chars()
                    .all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
            {
                return true;
            }
        }
    }
    false
}

pub fn message_type_allows_plaintext(msg_type: &MessageType) -> bool {
    matches!(msg_type, MessageType::Call)
}

pub fn compute_identity_fingerprint(identity_key_b64: &str) -> Option<String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(identity_key_b64.trim())
        .ok()?;
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(&bytes);
    Some(hex::encode(hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_human_readable_content_without_e2e_flag() {
        assert!(rejects_plaintext_storage("hello world"));
        assert!(rejects_plaintext_storage("cześć, jak leci?"));
    }

    #[test]
    fn rejects_base64_wrapped_short_plaintext() {
        assert!(rejects_plaintext_storage("aGVsbG8=")); // "hello"
    }

    #[test]
    fn accepts_opaque_binary_like_ciphertext() {
        let fake_signal_blob = base64::engine::general_purpose::STANDARD.encode([0x08_u8; 64]);
        assert!(!rejects_plaintext_storage(&fake_signal_blob));
    }
}
