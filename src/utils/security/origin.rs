use std::env;

use actix_web::http::Method;
use http::HeaderMap;

fn normalize_origin(origin: &str) -> String {
    // Browser `Origin` never includes a trailing slash; strip so env typos don't
    // silently break CORS / WS origin checks in production.
    origin.trim().trim_end_matches('/').to_string()
}

fn push_origin(origins: &mut Vec<String>, origin: &str) {
    let origin = normalize_origin(origin);
    if origin.is_empty() || origins.iter().any(|value| value == &origin) {
        return;
    }
    origins.push(origin);
}

pub fn allowed_origins() -> Vec<String> {
    let configured = env::var("ORIGIN").unwrap_or_else(|_| "http://127.0.0.1:5173".to_string());
    let mut origins: Vec<String> = Vec::new();
    for origin in configured.split(',') {
        push_origin(&mut origins, origin);
    }

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

use crate::utils::security::client_id::{
    canonicalize_request_path, is_security_webhook_path,
};

/// Ścieżki zwolnione z kontroli Origin.
pub fn is_origin_guard_exempt(path: &str) -> bool {
    let path = canonicalize_request_path(path);
    path == "/api" || is_security_webhook_path(&path)
}

pub fn requires_origin_guard(method: &Method, path: &str) -> bool {
    if *method == Method::OPTIONS {
        return false;
    }
    if (*method == Method::GET || *method == Method::HEAD) && is_origin_guard_exempt(path) {
        return false;
    }
    let path = canonicalize_request_path(path);
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
