// fingerprint.rs
// Odcisk sesji UA+IP+client.
// Zakres:
//  - anomalia cookie
//  - UA+IP+client; CGNAT = sygnał, nie twardy ban
// Fałszywe positive na CGNAT — nie twardy ban, tylko sygnał.
// Przy zmianach: ip.rs, session.rs.

use actix_web::HttpRequest;

use crate::utils::auth::user_agent::user_agent_from_request;
use crate::utils::ip::client_ip_from_http_request;
use crate::utils::crypto::hmac::hmac_sha256_hex;
use crate::utils::crypto::token_hash::refresh_token_hmac_key;

const FINGERPRINT_PREFIX: &str = "refresh-fingerprint-v1|";

pub fn session_fingerprint_from_request(req: &HttpRequest) -> Option<String> {
    let ip = client_ip_from_http_request(req);
    let ua = user_agent_from_request(req);

    if ip == "unknown" && ua.is_empty() {
        return None;
    }

    let key = refresh_token_hmac_key().ok()?;
    Some(hmac_sha256_hex(
        &key,
        &format!("{FINGERPRINT_PREFIX}{ip}|{ua}"),
    ))
}

pub fn fingerprints_match(stored: &str, current: &str) -> bool {
    stored.len() == current.len()
        && crate::utils::security::timing::constant_time_eq(
            stored.as_bytes(),
            current.as_bytes(),
        )
}
