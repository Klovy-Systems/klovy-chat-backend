use base64::Engine;

use crate::model::e2e_keys_model::{E2eKeyBundle, OneTimePreKeyRecord, SignedPreKeyRecord};

pub const MAX_ONE_TIME_PREKEYS: usize = 100;

pub struct PutKeyBundleInput<'a> {
    pub identity_key: &'a str,
    pub signed_pre_key: &'a SignedPreKeyRecord,
    pub one_time_pre_keys: &'a [OneTimePreKeyRecord],
}

/// Signal wire public key: 32 raw bytes or 33 bytes with 0x05 type prefix.
pub fn decode_signal_public_key(b64: &str) -> Option<Vec<u8>> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    match bytes.len() {
        32 => Some(bytes),
        33 if bytes.first() == Some(&5) => Some(bytes[1..].to_vec()),
        _ => None,
    }
}

pub fn decode_signed_prekey_public(b64: &str) -> Option<Vec<u8>> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    if bytes.len() == 33 && bytes.first() == Some(&5) {
        Some(bytes)
    } else if bytes.len() == 32 {
        let mut out = vec![5u8];
        out.extend_from_slice(&bytes);
        Some(out)
    } else {
        None
    }
}

pub fn decode_signature(b64: &str) -> Option<Vec<u8>> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    (bytes.len() == 64).then_some(bytes)
}

pub fn validate_one_time_prekeys(keys: &[OneTimePreKeyRecord]) -> bool {
    if keys.len() > MAX_ONE_TIME_PREKEYS {
        return false;
    }
    keys.iter().all(|k| {
        decode_signal_public_key(&k.public_key)
            .map(|b| b.len() == 32)
            .unwrap_or(false)
    })
}

pub fn validate_signed_prekey_record(record: &SignedPreKeyRecord) -> bool {
    decode_signed_prekey_public(&record.public_key).is_some()
        && decode_signature(&record.signature).is_some()
}

/// Structural validation for uploaded bundles. Cryptographic signature verification
/// is performed client-side in SessionBuilder (same as Signal desktop/web clients).
pub fn validate_put_key_bundle(body: &PutKeyBundleInput<'_>, existing: Option<&E2eKeyBundle>) -> bool {
    if decode_signal_public_key(body.identity_key).is_none() {
        return false;
    }
    if !validate_signed_prekey_record(body.signed_pre_key) {
        return false;
    }
    if !validate_one_time_prekeys(body.one_time_pre_keys) {
        return false;
    }

    let Some(fingerprint) = super::compute_identity_fingerprint(body.identity_key) else {
        return false;
    };

    if let Some(existing) = existing {
        if existing.identity_fingerprint != fingerprint {
            return false;
        }
    }

    let _ = fingerprint;
    true
}
