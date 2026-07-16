//! Opcjonalny sekret dla wewnętrznego serwera Actix (defense-in-depth).
//!
//! Publiczny ruch trafia do warstwy Axum, która proxuje żądania do Actix na
//! `127.0.0.1:INTERNAL_HTTP_PORT`. W środowiskach współdzielących loopback
//! (np. wiele kontenerów w jednym podzie) inny proces mógłby uderzać w port
//! wewnętrzny bezpośrednio. Gdy ustawiony jest `INTERNAL_PROXY_SECRET`, ten
//! middleware wymaga nagłówka `x-internal-proxy` o tej wartości — proxy Axum
//! (oraz health-check) wstrzykują go automatycznie.
//!
//! Domyślnie (brak zmiennej) middleware jest przezroczysty — nic nie zmienia.

use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    HttpResponse,
};
use actix_web_lab::middleware::Next;

use crate::utils::security::constant_time::constant_time_eq_str;

pub const INTERNAL_PROXY_HEADER: &str = "x-internal-proxy";

/// Zwraca skonfigurowany sekret proxy, o ile ustawiony i niepusty.
pub fn internal_proxy_secret() -> Option<String> {
    std::env::var("INTERNAL_PROXY_SECRET")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub async fn internal_proxy_guard(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    if let Some(secret) = internal_proxy_secret() {
        let provided = req
            .headers()
            .get(INTERNAL_PROXY_HEADER)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !constant_time_eq_str(provided, &secret) {
            let (req, _) = req.into_parts();
            let res = HttpResponse::Forbidden().json(serde_json::json!({ "error": "Forbidden" }));
            return Ok(ServiceResponse::new(req, res).map_into_boxed_body());
        }
    }

    Ok(next.call(req).await?.map_into_boxed_body())
}
