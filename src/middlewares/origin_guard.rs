use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    http::Method,
    HttpResponse,
};
use actix_web_lab::middleware::Next;

use crate::utils::security::origin::{allowed_origins, origin_allowed};

pub async fn origin_guard_middleware(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    let method = req.method().clone();
    if matches!(method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return Ok(next.call(req).await?.map_into_boxed_body());
    }

    // Runtime botów uwierzytelnia się tokenem Bearer i jest wywoływane spoza
    // przeglądarki (brak nagłówków Origin/Referer) — pomijamy kontrolę origin.
    if req.path().starts_with("/api/bot/") {
        return Ok(next.call(req).await?.map_into_boxed_body());
    }

    let allowed = allowed_origins();
    let origin = req
        .headers()
        .get("Origin")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let referer = req
        .headers()
        .get("Referer")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let origin_ok = origin
        .as_deref()
        .map(|value| origin_allowed(value, &allowed));
    // Dopasowanie referera tą samą logiką co Origin — zapobiega obejściu
    // prefiksowemu typu `https://klovy.chat.evil.com`.
    let referer_ok = referer
        .as_deref()
        .map(|value| origin_allowed(value, &allowed));

    if crate::utils::app_env::is_production() {
        if origin_ok != Some(true) && referer_ok != Some(true) {
            let (req, _) = req.into_parts();
            let res =
                HttpResponse::Forbidden().json(serde_json::json!({ "error": "Invalid origin" }));
            return Ok(ServiceResponse::new(req, res).map_into_boxed_body());
        }
        return Ok(next.call(req).await?.map_into_boxed_body());
    }

    match (origin_ok, referer_ok) {
        (Some(false), _) | (None, Some(false)) => {
            let (req, _) = req.into_parts();
            let res =
                HttpResponse::Forbidden().json(serde_json::json!({ "error": "Invalid origin" }));
            Ok(ServiceResponse::new(req, res).map_into_boxed_body())
        }
        _ => Ok(next.call(req).await?.map_into_boxed_body()),
    }
}
