use http::HeaderMap;

use crate::utils::app_env::is_production;

/// True when the client connection reached us over HTTPS (via reverse proxy).
pub fn is_secure_client_connection(headers: &HeaderMap) -> bool {
    if !is_production() {
        return true;
    }

    headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("https"))
        .unwrap_or(false)
}
