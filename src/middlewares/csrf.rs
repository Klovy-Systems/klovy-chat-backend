// csrf.rs
// Porównanie cookie CSRF z nagłówkiem.
// Zakres:
//  - mutacje
//  - cookie vs nagłówek na mutacjach; GET bez CSRF
// GET bez CSRF; zmiana nazwy cookie = FE csrf.ts.
// Przy zmianach: utils/security/csrf.rs, api/client.ts.

use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    http::Method,
    HttpResponse,
};
use actix_web_lab::middleware::Next;

use crate::utils::security::csrf::{constant_time_eq, CSRF_COOKIE_NAME, CSRF_HEADER_NAME};

use crate::utils::security::id::canonicalize_request_path;

fn is_exempt(path: &str) -> bool {
    const EXACT: &[&str] = &[
        "/api/auth/login",
        "/api/auth/sign-in",
        "/api/auth/signin",
        "/api/auth/signup",
        "/api/auth/register",
        "/api/auth/login/2fa",
        "/api/auth/refresh",
    ];

    let path = canonicalize_request_path(path);
    EXACT.iter().any(|p| path == *p)
}

pub async fn csrf_middleware(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    let method = req.method().clone();
    if matches!(method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return Ok(next.call(req).await?.map_into_boxed_body());
    }

    let path = req.path().to_string();
    if is_exempt(&path) {
        return Ok(next.call(req).await?.map_into_boxed_body());
    }

    let cookie_token = req
        .cookie(CSRF_COOKIE_NAME)
        .map(|c| c.value().to_string())
        .filter(|v| !v.is_empty());

    let header_token = req
        .headers()
        .get(CSRF_HEADER_NAME)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string);

    let valid = match (cookie_token, header_token) {
        (Some(cookie), Some(header)) => constant_time_eq(&cookie, &header),
        _ => false,
    };

    if !valid {
        let (req, _) = req.into_parts();
        let res = HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Invalid or missing CSRF token",
        }));
        return Ok(ServiceResponse::new(req, res).map_into_boxed_body());
    }

    Ok(next.call(req).await?.map_into_boxed_body())
}
