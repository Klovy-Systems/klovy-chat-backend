use base64::Engine;

use crate::utils::crypto::field_encrypt::{decrypt_field, encrypt_field};

/// Client-compatible opaque wrap (matches `wrapOpaquePayload` in mobile/web).
pub fn wrap_client_opaque(plain: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(plain.as_bytes())
}

pub fn is_client_opaque(stored: &str) -> bool {
    let trimmed = stored.trim();
    if trimmed.is_empty() || trimmed.starts_with('{') || trimmed.starts_with('[') {
        return false;
    }
    base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .ok()
        .is_some_and(|bytes| std::str::from_utf8(&bytes).is_ok())
}

fn is_server_sealed(stored: &str) -> bool {
    decrypt_field(stored.trim()).is_ok()
}

/// True when `content` is already stored in server-sealed form (safe to skip migration).
pub fn is_content_server_sealed(stored: &str) -> bool {
    is_server_sealed(stored)
}

/// Plaintext for validation, mentions, and other server-side processing (never exposed via API).
pub fn inbound_plaintext_for_processing(incoming: &str, e2e_encrypted: bool) -> String {
    if e2e_encrypted {
        return incoming.to_string();
    }
    if is_client_opaque(incoming) {
        return unwrap_client_opaque(incoming);
    }
    if is_server_sealed(incoming) {
        if let Ok(plain) = decrypt_field(incoming.trim()) {
            if is_client_opaque(&plain) {
                return unwrap_client_opaque(&plain);
            }
            return plain;
        }
    }
    incoming.to_string()
}

pub fn prepare_content_for_storage(incoming: &str, e2e_encrypted: bool) -> Result<String, String> {
    if e2e_encrypted {
        return Ok(incoming.to_string());
    }
    let opaque = if is_client_opaque(incoming) {
        incoming.to_string()
    } else if is_server_sealed(incoming) {
        let plain = decrypt_field(incoming.trim())?;
        wrap_client_opaque(&plain)
    } else {
        wrap_client_opaque(incoming)
    };
    encrypt_field(&opaque)
}

/// API / WS payload: never human-readable plaintext.
pub fn content_for_api(stored: &str, e2e_encrypted: bool) -> String {
    if e2e_encrypted {
        return stored.to_string();
    }
    if is_client_opaque(stored) {
        return stored.to_string();
    }
    if is_server_sealed(stored) {
        if let Ok(plain) = decrypt_field(stored.trim()) {
            if is_client_opaque(&plain) {
                return plain;
            }
            return wrap_client_opaque(&plain);
        }
    }
    wrap_client_opaque(stored)
}

/// Plaintext for mentions/search/internal use (server-side only).
pub fn reveal_content_internal(stored: &str, e2e_encrypted: bool) -> String {
    if e2e_encrypted {
        return stored.to_string();
    }
    if let Ok(plain) = decrypt_field(stored.trim()) {
        if is_client_opaque(&plain) {
            return unwrap_client_opaque(&plain);
        }
        return plain;
    }
    if is_client_opaque(stored) {
        return unwrap_client_opaque(stored);
    }
    stored.to_string()
}

pub fn unwrap_client_opaque(stored: &str) -> String {
    let trimmed = stored.trim();
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(trimmed) {
        if let Ok(text) = std::str::from_utf8(&bytes) {
            return text.to_string();
        }
    }
    trimmed.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_never_returns_plaintext_for_legacy() {
        assert_ne!(content_for_api("hello world", false), "hello world");
    }

    #[test]
    fn storage_roundtrip_internal_reveal() {
        std::env::set_var("JWT_KEY", "test-jwt-key-for-message-storage-seal-roundtrip");
        let plain = "witaj";
        let stored = prepare_content_for_storage(plain, false).expect("store");
        assert_ne!(content_for_api(&stored, false), plain);
        assert_eq!(reveal_content_internal(&stored, false), plain);
    }

    #[test]
    fn e2e_passes_through() {
        let cipher = "QKJVBEVCTFR-signal-ciphertext";
        assert_eq!(content_for_api(cipher, true), cipher);
    }
}
