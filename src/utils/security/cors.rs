//! Dozwolone nagłówki żądań cross-origin (preflight CORS).
//!
//! Trzymaj listę zsynchronizowaną z frontendem (`src/utils/env/clientId.ts`
//! oraz nagłówki wysyłane z `src/api/client.ts`).

use super::client_environment::{
    CLIENT_BROWSER_HEADER, CLIENT_ENVIRONMENT_LABEL_HEADER, CLIENT_OS_HEADER,
};
use super::client_id::CLIENT_HEADER_NAME;
use super::client_user_agent::CLIENT_USER_AGENT_HEADER;
use super::csrf::CSRF_HEADER_NAME;

/// Nagłówki dozwolone w preflight CORS (Axum `CorsLayer::allow_headers`).
pub const CORS_ALLOWED_REQUEST_HEADERS: &[&str] = &[
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
    CLIENT_BROWSER_HEADER,
    CLIENT_OS_HEADER,
    CLIENT_ENVIRONMENT_LABEL_HEADER,
];
