use std::env;

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

pub fn is_origin_header_allowed(headers: &HeaderMap) -> bool {
    let allowed = allowed_origins();
    let origin = headers
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let referer = headers
        .get("referer")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let origin_ok = origin
        .as_deref()
        .map(|value| origin_allowed(value, &allowed));
    // Referer to pełny URL — używamy tej samej logiki co dla Origin (dopasowanie
    // dokładne lub z separatorem `/`), aby zapobiec obejściu prefiksowemu typu
    // `https://klovy.chat.evil.com`.
    let referer_ok = referer
        .as_deref()
        .map(|value| origin_allowed(value, &allowed));

    if crate::utils::app_env::is_production() {
        origin_ok == Some(true) || referer_ok == Some(true)
    } else {
        match (origin_ok, referer_ok) {
            (Some(false), _) | (None, Some(false)) => false,
            _ => true,
        }
    }
}
