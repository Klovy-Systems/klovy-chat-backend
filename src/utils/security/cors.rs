//! Dozwolone nagłówki żądań cross-origin (preflight CORS).
//!
//! Trzymaj listę zsynchronizowaną z frontendem (`src/utils/env/clientId.ts`
//! oraz nagłówki wysyłane z `src/api/client.ts`).
//!
//! Metadane środowiska klienta (browser/os) są kodowane w `x-klovy-user-agent`,
//! żeby nie wymagać dodatkowych nagłówków CORS przy deployu frontu przed backendem.

use http::header::HeaderName;

use super::client_id::CLIENT_HEADER_NAME;
use super::client_user_agent::CLIENT_USER_AGENT_HEADER;
use super::csrf::CSRF_HEADER_NAME;

/// Nagłówki dozwolone w preflight CORS (Axum `CorsLayer::allow_headers`).
pub const CORS_ALLOWED_REQUEST_HEADERS: [HeaderName; 10] = [
    HeaderName::from_static("content-type"),
    HeaderName::from_static("authorization"),
    HeaderName::from_static("accept"),
    HeaderName::from_static("accept-language"),
    HeaderName::from_static("accept-encoding"),
    HeaderName::from_static("x-requested-with"),
    HeaderName::from_static(CSRF_HEADER_NAME),
    HeaderName::from_static("x-client-version"),
    HeaderName::from_static(CLIENT_HEADER_NAME),
    HeaderName::from_static(CLIENT_USER_AGENT_HEADER),
];

pub fn cors_allowed_request_header_names() -> &'static [&'static str] {
    &[
        "content-type",
        "authorization",
        "accept",
        "accept-language",
        "accept-encoding",
        "x-requested-with",
        CSRF_HEADER_NAME,
        "x-client-version",
        CLIENT_HEADER_NAME,
        CLIENT_USER_AGENT_HEADER,
    ]
}
