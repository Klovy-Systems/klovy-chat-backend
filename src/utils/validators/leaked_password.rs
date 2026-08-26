// leaked_password.rs
// HIBP k-anonimowość na serwerze.
// Zakres:
//  - prefix SHA-1
//  - HIBP k-anonimowość; nie loguj reszty hasha
// Nie loguj reszty hasha. FE ma analogiczny check UX.
// Przy zmianach: leakedPassword.ts, auth.rs.

use once_cell::sync::Lazy;
use sha1::{Digest, Sha1};
use std::time::Duration;

use crate::utils::env::is_development;

static HIBP_CLIENT: Lazy<reqwest::Client> = Lazy::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("failed to build HIBP HTTP client")
});

#[derive(Debug)]
pub enum PwnedPasswordError {
    RequestFailed,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PasswordBreachCheck {
    Safe,
    Breached,
    Unavailable,
}

fn is_check_enabled() -> bool {
    std::env::var("PWNED_PASSWORD_CHECK_ENABLED")
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            normalized != "false" && normalized != "0" && normalized != "off"
        })
        .unwrap_or(true)
}

fn sha1_hex_upper(password: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    format!("{:X}", hasher.finalize())
}

pub async fn is_password_pwned(password: &str) -> Result<bool, PwnedPasswordError> {
    let hash = sha1_hex_upper(password);
    let (prefix, suffix) = hash.split_at(5);

    let url = format!("https://api.pwnedpasswords.com/range/{prefix}");
    let response = HIBP_CLIENT
        .get(&url)
        .header("User-Agent", "Klovy-Chat-PasswordCheck")
        .header("Add-Padding", "true")
        .send()
        .await
        .map_err(|_| PwnedPasswordError::RequestFailed)?;

    if !response.status().is_success() {
        return Err(PwnedPasswordError::RequestFailed);
    }

    let body_bytes = crate::utils::http::read_response_limited(
        response,
        crate::utils::http::MAX_HIBP_RANGE_BYTES,
    )
    .await
    .map_err(|_| PwnedPasswordError::RequestFailed)?;
    let body = String::from_utf8_lossy(&body_bytes);

    let pwned = body.lines().any(|line| {
        line.split_once(':')
            .map(|(hash_suffix, _)| hash_suffix.eq_ignore_ascii_case(suffix))
            .unwrap_or(false)
    });

    Ok(pwned)
}

pub async fn check_password_breach(password: &str) -> PasswordBreachCheck {
    if !is_check_enabled() {
        return PasswordBreachCheck::Safe;
    }

    match is_password_pwned(password).await {
        Ok(true) => PasswordBreachCheck::Breached,
        Ok(false) => PasswordBreachCheck::Safe,
        Err(_) if is_development() => {
            log::warn!("Pwned password check skipped due to API error (development mode)");
            PasswordBreachCheck::Safe
        }
        Err(_) => PasswordBreachCheck::Unavailable,
    }
}
