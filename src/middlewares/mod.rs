pub mod admin_auth_middleware;
pub mod auth_fallback_guard;
pub mod auth_middleware;
pub mod client_guard;
pub mod csrf;
pub mod internal_proxy_guard;
pub mod ip_blocker;
pub mod origin_guard;
pub mod turnstile_middleware;
pub mod validation_middleware;
pub mod whitelist;

use actix_web::dev::Payload;
use actix_web::web::{Bytes, BytesMut};

use crate::utils::upload_limits::MAX_HTTP_BODY_BYTES;

pub(crate) async fn read_body_bytes(mut payload: Payload) -> Result<Bytes, actix_web::Error> {
    use futures_util::StreamExt;
    let mut buf = BytesMut::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk.map_err(actix_web::error::ErrorBadRequest)?;
        // Twardy limit rozmiaru — chroni middleware buforujące ciało żądania
        // przed wyczerpaniem pamięci (istotne na wewnętrznym porcie Actix,
        // który nie przechodzi przez limit proxy Axum).
        if buf.len() + chunk.len() > MAX_HTTP_BODY_BYTES {
            return Err(actix_web::error::ErrorPayloadTooLarge("Payload too large"));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf.freeze())
}
