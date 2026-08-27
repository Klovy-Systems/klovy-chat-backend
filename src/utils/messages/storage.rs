// storage.rs
// Klucze R2 załącznika i powiązanie pending→message.
// Zakres:
//  - delete
//  - klucz R2 i pending→message; osierocone = reconcile
// Osierocone: reconcile.rs.
// Przy zmianach: r2.rs, uploads.rs.

use base64::Engine;

use crate::utils::crypto::encrypt::{decrypt_field, encrypt_field};

const OPAQUE_PREFIX: &str = "k1.";

fn encode_legacy_opaque(plain: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(plain.as_bytes())
}

pub fn wrap_client_opaque(plain: &str) -> String {
    format!("{OPAQUE_PREFIX}{}", encode_legacy_opaque(plain))
}

fn looks_like_legacy_envelope(stored: &str) -> bool {
    !stored.bytes().any(|b| b.is_ascii_whitespace())
        && stored
            .bytes()
            .any(|b| b.is_ascii_uppercase() || matches!(b, b'+' | b'/' | b'='))
}

fn decode_opaque_body(body: &str) -> Option<String> {
    if body.len() < 4 || body.len() % 4 != 0 {
        return None;
    }
    let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(body) else {
        return None;
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return None;
    };
    if text.is_empty() || text.contains('\u{FFFD}') {
        return None;
    }
    if encode_legacy_opaque(text) != body {
        return None;
    }
    Some(text.to_string())
}

pub fn is_client_opaque(stored: &str) -> bool {
    opaque_plain(stored).is_some()
}

fn opaque_plain(stored: &str) -> Option<String> {
    let trimmed = stored.trim();
    if trimmed.is_empty() || trimmed.starts_with('{') || trimmed.starts_with('[') {
        return None;
    }
    if let Some(body) = trimmed.strip_prefix(OPAQUE_PREFIX) {
        return decode_opaque_body(body);
    }
    if !looks_like_legacy_envelope(trimmed) {
        return None;
    }
    decode_opaque_body(trimmed)
}

fn is_server_sealed(stored: &str) -> bool {
    decrypt_field(stored.trim()).is_ok()
}

pub fn is_content_server_sealed(stored: &str) -> bool {
    is_server_sealed(stored)
}

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

pub fn content_for_api(stored: &str) -> String {
    reveal_content_internal(stored)
}

pub async fn content_for_api_async(stored: String) -> String {
    let fallback = stored.clone();
    tokio::task::spawn_blocking(move || content_for_api(&stored))
        .await
        .unwrap_or(fallback)
}

pub async fn contents_for_api_batch_async(contents: Vec<String>) -> Vec<String> {
    let fallback = contents.clone();
    tokio::task::spawn_blocking(move || contents.iter().map(|s| content_for_api(s)).collect())
        .await
        .unwrap_or(fallback)
}

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
    opaque_plain(stored).unwrap_or_else(|| stored.trim().to_string())
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sentences_and_words_stay_plaintext() {
        for text in [
            "elo",
            "file",
            "hej co tam",
            "Elo elo elo",
            "to jest całe zdanie.",
        ] {
            assert!(!is_client_opaque(text), "{text}");
            assert_eq!(unwrap_client_opaque(text), text);
        }
    }

    #[test]
    fn prefixed_wrap_roundtrips_plaintext() {
        let wrapped = wrap_client_opaque("elo");
        assert!(wrapped.starts_with("k1."));
        assert!(is_client_opaque(&wrapped));
        assert_eq!(unwrap_client_opaque(&wrapped), "elo");
        assert_eq!(inbound_plaintext_for_processing(&wrapped, false), "elo");
    }

    #[test]
    fn legacy_unprefixed_wrap_still_unwraps() {
        let legacy = encode_legacy_opaque("elo");
        assert_eq!(legacy, "ZWxv");
        assert!(is_client_opaque(&legacy));
        assert_eq!(unwrap_client_opaque(&legacy), "elo");
    }
}
