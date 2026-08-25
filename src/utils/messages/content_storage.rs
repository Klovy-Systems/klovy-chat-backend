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
    let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(trimmed) else {
        return false;
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return false;
    };
    if text.contains('\u{FFFD}') {
        return false;
    }
    client_opaque_normalized_equal(&wrap_client_opaque(text), trimmed)
}

fn client_opaque_normalized_equal(a: &str, b: &str) -> bool {
    fn strip_pad(s: &str) -> &str {
        s.trim_end_matches('=')
    }
    strip_pad(a) == strip_pad(b)
}

fn is_server_sealed(stored: &str) -> bool {
    decrypt_field(stored.trim()).is_ok()
}

/// True when `content` is already stored in server-sealed form (safe to skip migration).
pub fn is_content_server_sealed(stored: &str) -> bool {
    is_server_sealed(stored)
}

/// Plaintext for validation, mentions, and other server-side processing (never exposed via API).
pub fn inbound_plaintext_for_processing(incoming: &str, _legacy: bool) -> String {
    if is_client_opaque(incoming) {
        return normalize_client_opaque_to_plaintext(incoming);
    }
    if is_server_sealed(incoming) {
        if let Ok(plain) = decrypt_field(incoming.trim()) {
            if is_client_opaque(&plain) {
                return normalize_client_opaque_to_plaintext(&plain);
            }
            return plain;
        }
    }
    incoming.to_string()
}

pub fn prepare_content_for_storage(incoming: &str) -> Result<String, String> {
    let plain = if is_client_opaque(incoming) || is_server_sealed(incoming) {
        inbound_plaintext_for_processing(incoming, false)
    } else {
        incoming.to_string()
    };
    encrypt_field(&wrap_client_opaque(&plain))
}

pub async fn prepare_content_for_storage_async(incoming: String) -> Result<String, String> {
    tokio::task::spawn_blocking(move || prepare_content_for_storage(&incoming))
        .await
        .map_err(|_| "Content seal task failed".to_string())?
}

/// API / WS payload: human-readable plaintext for clients.
/// At-rest storage stays sealed via [`prepare_content_for_storage`].
pub fn content_for_api(stored: &str) -> String {
    reveal_content_internal(stored)
}

pub async fn content_for_api_async(stored: String) -> String {
    let fallback = stored.clone();
    tokio::task::spawn_blocking(move || content_for_api(&stored))
        .await
        .unwrap_or(fallback)
}

/// Decrypt a batch of sealed contents on the blocking pool (serialization hot path).
pub async fn contents_for_api_batch_async(contents: Vec<String>) -> Vec<String> {
    let fallback = contents.clone();
    tokio::task::spawn_blocking(move || contents.iter().map(|s| content_for_api(s)).collect())
        .await
        .unwrap_or(fallback)
}

/// Plaintext for mentions/search/internal use (server-side only).
pub fn reveal_content_internal(stored: &str) -> String {
    let trimmed = stored.trim();
    if let Ok(plain) = decrypt_field(trimmed) {
        if is_client_opaque(&plain) {
            return unwrap_client_opaque(&plain);
        }
        return plain;
    }
    if is_client_opaque(trimmed) {
        return unwrap_client_opaque(trimmed);
    }
    trimmed.to_string()
}

pub async fn reveal_content_internal_async(stored: String) -> String {
    let fallback = stored.clone();
    tokio::task::spawn_blocking(move || reveal_content_internal(&stored))
        .await
        .unwrap_or(fallback)
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

/// Peel nested client opaque layers down to plaintext (guards legacy double-wrap).
pub fn normalize_client_opaque_to_plaintext(incoming: &str) -> String {
    let mut current = incoming.trim().to_string();
    for _ in 0..4 {
        if !is_client_opaque(&current) {
            return current;
        }
        let inner = unwrap_client_opaque(&current);
        if inner == current {
            return current;
        }
        if !is_client_opaque(&inner) {
            return inner;
        }
        current = inner;
    }
    current
}
