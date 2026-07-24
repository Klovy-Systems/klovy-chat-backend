use std::env;

use actix_web::http::Method;
use http::HeaderMap;

fn push_origin(origins: &mut Vec<String>, origin: &str) {
    let origin = origin.trim();
    if origin.is_empty() || origins.iter().any(|value| value == origin) {
        return;
    }
    origins.push(origin.to_string());
}

pub fn allowed_origins() -> Vec<String> {
    let configured = env::var("ORIGIN").unwrap_or_else(|_| "http://127.0.0.1:5173".to_string());
    let mut origins: Vec<String> = configured
        .split(',')
        .map(str::trim)
        .filter(|origin| !origin.is_empty())
        .map(str::to_string)
        .collect();

    if let Ok(frontend_url) = env::var("FRONTEND_URL") {
        for origin in frontend_url.split(',') {
            push_origin(&mut origins, origin);
        }
    }

    if crate::utils::app_env::is_development() {
        for origin in ["http://127.0.0.1:5173", "http://localhost:5173"] {
            push_origin(&mut origins, origin);
        }
    }

    if let Ok(mobile_origins) = env::var("MOBILE_ORIGIN") {
        for origin in mobile_origins.split(',') {
            push_origin(&mut origins, origin);
        }
    }

    // Official React Native app (EXPO_PUBLIC_ORIGIN=klovychat://).
    push_origin(&mut origins, "klovychat://");

    origins
}

/// Nagłówki CORS z wewnętrznego Actix — nie przekazujemy ich do przeglądarki,
/// bo publiczna warstwa Axum ustawia własne (podwójne ACAO psuje CORS w browserze).
pub fn is_cors_response_header(name: &str) -> bool {
    matches!(
        name,
        "access-control-allow-origin"
            | "access-control-allow-credentials"
            | "access-control-allow-methods"
            | "access-control-allow-headers"
            | "access-control-expose-headers"
            | "access-control-max-age"
    )
}

pub fn origin_allowed(value: &str, allowed: &[String]) -> bool {
    allowed
        .iter()
        .any(|origin| value == origin || value.starts_with(&format!("{origin}/")))
}

/// Ścieżki zwolnione z kontroli Origin (OAuth redirect).
pub fn is_origin_guard_exempt(path: &str) -> bool {
    path == "/api"
        || path == "/api/"
        || path.starts_with("/api/security")
        || path.starts_with("/api/integrations/spotify/callback")
}

pub fn requires_origin_guard(method: &Method, path: &str) -> bool {
    if *method == Method::OPTIONS || is_origin_guard_exempt(path) {
        return false;
    }
    path.starts_with("/api") || path.starts_with("/whitelist")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginGuardMode {
    /// Mutacje w produkcji: wymagany poprawny Origin lub Referer.
    Strict,
    /// GET/HEAD: odrzucaj tylko gdy Origin/Referer są obecne i niedozwolone.
    RejectKnownBad,
}

pub fn validate_browser_origin(
    headers: &HeaderMap,
    allowed: &[String],
    mode: OriginGuardMode,
) -> bool {
    let origin = headers
        .get("origin")
        .and_then(|v| v.to_str().ok());
    let referer = headers
        .get("referer")
        .and_then(|v| v.to_str().ok());
    validate_browser_origin_values(origin, referer, allowed, mode)
}

pub fn validate_browser_origin_values(
    origin: Option<&str>,
    referer: Option<&str>,
    allowed: &[String],
    mode: OriginGuardMode,
) -> bool {
    let origin_ok = origin.map(|value| origin_allowed(value, allowed));
    let referer_ok = referer.map(|value| origin_allowed(value, allowed));

    match mode {
        OriginGuardMode::Strict => {
            if crate::utils::app_env::is_production() {
                origin_ok == Some(true) || referer_ok == Some(true)
            } else {
                !matches!(
                    (origin_ok, referer_ok),
                    (Some(false), _) | (None, Some(false))
                )
            }
        }
        OriginGuardMode::RejectKnownBad => {
            if origin_ok == Some(false) || referer_ok == Some(false) {
                return false;
            }
            if crate::utils::app_env::is_production() {
                return true;
            }
            !matches!(
                (origin_ok, referer_ok),
                (Some(false), _) | (None, Some(false))
            )
        }
    }
}

pub fn is_origin_header_allowed(headers: &HeaderMap) -> bool {
    let allowed = allowed_origins();
    validate_browser_origin(headers, &allowed, OriginGuardMode::Strict)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mobile_app_origin_is_allowed() {
        let allowed = allowed_origins();
        assert!(origin_allowed("klovychat://", &allowed));
    }

    #[test]
    fn strict_requires_allowed_origin_in_production() {
        let allowed = vec!["https://app.klovy.chat".to_string()];
        assert!(validate_browser_origin_values(
            Some("https://app.klovy.chat"),
            None,
            &allowed,
            OriginGuardMode::Strict,
        ));
        assert!(!validate_browser_origin_values(
            Some("https://evil.com"),
            None,
            &allowed,
            OriginGuardMode::Strict,
        ));
    }

    #[test]
    fn reject_known_bad_blocks_invalid_get_origin() {
        let allowed = vec!["https://app.klovy.chat".to_string()];
        assert!(!validate_browser_origin_values(
            Some("https://evil.com"),
            None,
            &allowed,
            OriginGuardMode::RejectKnownBad,
        ));
        assert!(validate_browser_origin_values(
            None,
            None,
            &allowed,
            OriginGuardMode::RejectKnownBad,
        ));
    }

    #[test]
    fn origin_allowed_rejects_prefix_bypass() {
        let allowed = vec!["https://app.klovy.chat".to_string()];
        assert!(!origin_allowed("https://app.klovy.chat.evil.com", &allowed));
        assert!(origin_allowed("https://app.klovy.chat/settings", &allowed));
    }
}
