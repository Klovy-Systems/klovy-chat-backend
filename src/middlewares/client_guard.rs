//! Middleware filtrujący ruch niepochodzący od oficjalnego klienta.
//!
//! Każde żądanie do powierzchni API musi przedstawić nagłówek
//! `X-Klovy-Client: KlovyChatApp/<wersja>`. Żądania bez poprawnego identyfikatora
//! są tanio odrzucane (zanim dotrą do CSRF/auth/DB) i zgłaszane do mechanizmu
//! blokowania IP, dzięki czemu wolumetryczne floody DoS/DDoS eskalują do
//! czasowej blokady adresu IP.

use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    http::Method,
    HttpResponse,
};
use actix_web_lab::middleware::Next;

use crate::middlewares::ip_blocker::IPBlockerArc;
use crate::utils::client_ip::client_ip_from_service_request;
use crate::utils::security::client_id::{
    is_valid_client_identifier, query_client_valid, CLIENT_HEADER_NAME,
};

/// Ścieżki zwolnione z wymogu identyfikatora klienta:
/// - publiczny endpoint informacyjny / health-check (`/api`, `/api/`),
/// - webhook bezpieczeństwa server-to-server (`/api/security/*`, chroniony Bearer),
/// - OAuth callback (`/api/integrations/spotify/callback`).
fn is_exempt(path: &str) -> bool {
    path == "/api"
        || path == "/api/"
        || path.starts_with("/api/security")
        || path.starts_with("/api/integrations/spotify/callback")
}

pub async fn client_guard_middleware(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    // Preflight CORS nie może nieść nagłówków niestandardowych — przepuszczamy.
    if req.method() == Method::OPTIONS {
        return Ok(next.call(req).await?.map_into_boxed_body());
    }

    let path = req.path();
    let guarded = path.starts_with("/api") || path.starts_with("/whitelist");
    if !guarded || is_exempt(path) {
        return Ok(next.call(req).await?.map_into_boxed_body());
    }

    let valid = req
        .headers()
        .get(CLIENT_HEADER_NAME)
        .and_then(|v| v.to_str().ok())
        .map(is_valid_client_identifier)
        .unwrap_or(false);

    if valid {
        return Ok(next.call(req).await?.map_into_boxed_body());
    }

    // Nawigacja przeglądarki (np. OAuth connect) nie może nieść nagłówków — akceptuj ?client=
    if req.method() == Method::GET && query_client_valid(Some(req.query_string())) {
        return Ok(next.call(req).await?.map_into_boxed_body());
    }

    // Brak/niepoprawny identyfikator klienta — potraktuj jako ruch botów/DoS.
    if let Some(blocker) = req
        .app_data::<actix_web::web::Data<IPBlockerArc>>()
        .cloned()
    {
        let ip = client_ip_from_service_request(&req);
        blocker.add_suspicious_activity(&ip);
    }

    let (req, _) = req.into_parts();
    let res = HttpResponse::BadRequest().json(serde_json::json!({
        "error": "Unsupported client",
    }));
    Ok(ServiceResponse::new(req, res).map_into_boxed_body())
}
