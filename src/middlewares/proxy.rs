// proxy.rs
// Wymaga x-internal-proxy gdy INTERNAL_PROXY_SECRET ustawiony.
// Zakres:
//  - ochrona Actix na loopback
//  - x-internal-proxy gdy INTERNAL_PROXY_SECRET ustawiony
// Axum musi wstrzykiwać ten sam sekret. Brak env = transparent.
// Przy zmianach: loaders/server.rs.

use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    HttpResponse,
};
use actix_web_lab::middleware::Next;

use crate::utils::security::timing::constant_time_eq_str;

pub const INTERNAL_PROXY_HEADER: &str = "x-internal-proxy";

pub fn internal_proxy_secret() -> Option<String> {
    std::env::var("INTERNAL_PROXY_SECRET")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub async fn proxy(
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
