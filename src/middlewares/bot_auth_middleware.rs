//! Uwierzytelnianie runtime botów (`/api/bot/*`).
//!
//! Zamiast ciasteczka JWT boty przedstawiają nagłówek
//! `Authorization: Bearer {botIdHex}.{sekret}`. Middleware weryfikuje token,
//! ładuje konto bota (musi być aktywne i mieć flagę `is_bot`), zapisuje id bota
//! w rozszerzeniach żądania oraz odświeża `lastUsedAt`.

use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    http::header::AUTHORIZATION,
    HttpMessage, HttpRequest, HttpResponse,
};
use actix_web_lab::middleware::Next;

use crate::model::bot_token_model::BotToken;
use crate::model::user_model::User;
use crate::utils::auth::admin_session::is_admin_user_id;
use crate::utils::db::get_db;
use crate::utils::whitelist::is_whitelist_enabled;

#[derive(Debug, Clone)]
pub struct RequestBotId(pub String);

pub fn request_bot_id(req: &HttpRequest) -> Option<String> {
    req.extensions().get::<RequestBotId>().map(|b| b.0.clone())
}

fn unauthorized(req: ServiceRequest, message: &str) -> ServiceResponse<BoxBody> {
    let (req, _) = req.into_parts();
    let res = HttpResponse::Unauthorized().json(serde_json::json!({ "message": message }));
    ServiceResponse::new(req, res)
}

pub async fn verify_bot_token(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    let token = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|v| v.trim().to_string());

    let token = match token {
        Some(t) if !t.is_empty() && t.len() <= 256 => t,
        _ => return Ok(unauthorized(req, "Brak lub nieprawidłowy token bota.")),
    };

    let db = get_db();
    let bot_id = match BotToken::verify(&db, &token).await {
        Some(id) => id,
        None => return Ok(unauthorized(req, "Nieprawidłowy token bota.")),
    };

    let bot = match User::find_bot(&db, bot_id).await {
        Ok(Some(u)) => u,
        _ => return Ok(unauthorized(req, "Bot nie istnieje.")),
    };

    if bot.is_blocked || bot.is_banned || !bot.is_active {
        let (req, _) = req.into_parts();
        let res = HttpResponse::Forbidden()
            .json(serde_json::json!({ "message": "Konto bota jest nieaktywne." }));
        return Ok(ServiceResponse::new(req, res));
    }

    // Bot runtime must follow the owner's whitelist status.
    if is_whitelist_enabled() {
        let owner_ok = match bot.owner_id {
            Some(owner_oid) => match User::find_by_id(&db, owner_oid).await {
                Ok(Some(owner)) => {
                    owner.is_whitelisted || is_admin_user_id(&owner_oid.to_hex())
                }
                _ => false,
            },
            None => false,
        };
        if !owner_ok {
            let (req, _) = req.into_parts();
            let res = HttpResponse::Forbidden().json(serde_json::json!({
                "message": "Właściciel bota nie jest zatwierdzony (whitelist)."
            }));
            return Ok(ServiceResponse::new(req, res));
        }
    }

    BotToken::touch_last_used(&db, bot_id).await;
    req.extensions_mut()
        .insert(RequestBotId(bot_id.to_hex()));

    Ok(next.call(req).await?.map_into_boxed_body())
}
