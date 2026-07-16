use rand::Rng;
use totp_rs::{Algorithm, Secret, TOTP};

use crate::utils::crypto::{
    credential_hash::{hash_reset_token, verify_reset_token},
    field_encrypt::{decrypt_field, encrypt_field},
};

pub const BACKUP_CODE_COUNT: usize = 8;
const ISSUER: &str = "KlovyChat";

/// New 2FA setups use SHA-256. SHA-1 is kept only for verifying existing enrollments.
const PRIMARY_TOTP_ALGORITHM: Algorithm = Algorithm::SHA256;
const LEGACY_TOTP_ALGORITHM: Algorithm = Algorithm::SHA1;

pub fn generate_totp_secret() -> String {
    secret_base32(&Secret::generate_secret())
}

fn secret_base32(secret: &Secret) -> String {
    match secret.to_encoded() {
        Secret::Encoded(value) => value,
        Secret::Raw(bytes) => base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &bytes),
    }
}

fn normalize_secret(secret: &str) -> String {
    secret
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_uppercase()
}

fn totp_for_account(
    username: &str,
    secret: &str,
    algorithm: Algorithm,
) -> Result<TOTP, String> {
    let normalized = normalize_secret(secret);
    TOTP::new(
        algorithm,
        6,
        1,
        30,
        Secret::Encoded(normalized)
            .to_bytes()
            .map_err(|e| e.to_string())?,
        Some(ISSUER.to_string()),
        username.to_string(),
    )
    .map_err(|e| e.to_string())
}

pub fn build_otpauth_url(username: &str, secret: &str) -> String {
    totp_for_account(username, secret, PRIMARY_TOTP_ALGORITHM)
        .map(|totp| totp.get_url())
        .unwrap_or_default()
}

pub fn verify_totp_code(username: &str, secret: &str, code: &str) -> bool {
    let normalized = code.trim();
    if normalized.len() != 6 || !normalized.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }

    for algorithm in [PRIMARY_TOTP_ALGORITHM, LEGACY_TOTP_ALGORITHM] {
        let Ok(totp) = totp_for_account(username, secret, algorithm) else {
            continue;
        };
        if totp.check_current(normalized).unwrap_or(false) {
            return true;
        }
    }
    false
}

pub fn encrypt_totp_secret(secret: &str) -> Result<String, String> {
    encrypt_field(&normalize_secret(secret))
}

pub fn decrypt_totp_secret(encrypted: &str) -> Result<String, String> {
    decrypt_field(encrypted)
}

pub fn generate_backup_codes() -> Vec<String> {
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::thread_rng();
    (0..BACKUP_CODE_COUNT)
        .map(|_| {
            let part1: String = (0..4)
                .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
                .collect();
            let part2: String = (0..4)
                .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
                .collect();
            format!("{part1}-{part2}")
        })
        .collect()
}

pub fn normalize_backup_code(code: &str) -> String {
    code.trim()
        .to_uppercase()
        .replace('-', "")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect()
}

pub async fn hash_backup_codes(codes: &[String]) -> Result<Vec<String>, String> {
    let mut hashed = Vec::with_capacity(codes.len());
    for code in codes {
        let normalized = normalize_backup_code(code);
        let hash = hash_reset_token(&normalized)
            .await
            .map_err(|e| e.to_string())?;
        hashed.push(hash);
    }
    Ok(hashed)
}

pub async fn verify_and_consume_backup_code(
    code: &str,
    stored_hashes: &[String],
) -> Option<usize> {
    let normalized = normalize_backup_code(code);
    if normalized.len() != 8 {
        return None;
    }
    for (index, hash) in stored_hashes.iter().enumerate() {
        if verify_reset_token(&normalized, hash).await {
            return Some(index);
        }
    }
    None
}

pub fn is_totp_code(code: &str) -> bool {
    let trimmed = code.trim();
    trimmed.len() == 6 && trimmed.chars().all(|c| c.is_ascii_digit())
}
