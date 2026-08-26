// hmac.rs
// HMAC n-gramów wyszukiwania (+ legacy SHA lookup).
// Zakres:
//  - searchTokens
//  - n-gramy searchTokens; nie zwracaj w API
// Nie zwracaj tokenów w API serializerze.
// Przy zmianach: messages/search.rs.

use ::hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub fn derive_subkey(secret: &str, context: &str) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts arbitrary key length");
    mac.update(context.as_bytes());
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub fn hmac_sha256_hex(key: &[u8], message: &str) -> String {
    hex::encode(hmac_sha256(key, message))
}

fn hmac_sha256(key: &[u8], message: &str) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts arbitrary key length");
    mac.update(message.as_bytes());
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub fn verify_hmac_sha256_hex(key: &[u8], message: &str, expected_hex: &str) -> bool {
    let expected = match hex::decode(expected_hex) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        _ => return false,
    };
    let actual = hmac_sha256(key, message);
    crate::utils::security::timing::constant_time_eq(&actual, &expected)
}

pub fn sha256_hex(message: &str) -> String {
    use sha2::Digest;
    hex::encode(Sha256::digest(message.as_bytes()))
}
