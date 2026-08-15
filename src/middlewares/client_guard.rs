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
    HttpResponse,
};
use actix_web_lab::middleware::Next;

use crate::middlewares::ip_blocker::IPBlockerArc;
use crate::utils::client_ip::client_ip_from_service_request;
use crate::utils::security::client_id::{
    official_client_presented, CLIENT_HEADER_NAME,
};

/// Ścieżki zwolnione z wymogu identyfikatora klienta:
/// - publiczny endpoint informacyjny / health-check (`/api`, `/api/`),
/// - webhook bezpieczeństwa server-to-server (`/api/security/*`, chroniony Bearer).
pub async fn client_guard_middleware(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    // Preflight CORS nie może nieść nagłówków niestandardowych — przepuszczamy.
    let path = req.path().to_string();
    let method = req.method().as_str().to_string();
    let query = req.query_string();
    let query = (!query.is_empty()).then_some(query);
    let header_value = req
        .headers()
        .get(CLIENT_HEADER_NAME)
        .and_then(|v| v.to_str().ok());

    if official_client_presented(&method, &path, query, header_value) {
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
