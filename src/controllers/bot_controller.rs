//! Kontroler botów.
//!
//! Dwie powierzchnie:
//! - **Zarządzanie** (`/api/bots/*`) — uwierzytelniane ciasteczkiem właściciela;
//!   tworzenie/edycja/usuwanie botów oraz wydawanie tokenów.
//! - **Runtime** (`/api/bot/*`) — uwierzytelniane nagłówkiem `Bearer`; bot wysyła
//!   wiadomości do kanałów, w których jest członkiem.

use actix_web::{web, HttpRequest, HttpResponse};
use mongodb::bson::{doc, oid::ObjectId, DateTime};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::middlewares::auth_middleware::request_user_id;
use crate::middlewares::bot_auth_middleware::request_bot_id;
use crate::model::bot_token_model::BotToken;
use crate::model::channel_model::Channel;
use crate::model::messages_model::MessageType;
use crate::model::user_model::User;
use crate::utils::access::membership_gate::require_channel_message_access;
use crate::utils::db::get_db;
use crate::utils::ratelimit::bot_send_allowed;
use crate::utils::ratelimit::slowmode::check_channel_slowmode;
use crate::utils::user::serialize_user::{resolve_display_name, DISPLAY_NAME_MAX_LENGTH};
use crate::utils::validators::normalize_username::{is_valid_username, normalize_username};
use crate::ws::handlers::{create_and_broadcast_channel_message, ChannelBroadcastInput};
use crate::ws::registry::{channel_recipient_ids, emit_to_user};

const MAX_BOTS_PER_USER: u64 = 10;
const MAX_BOT_MESSAGE_LEN: usize = 4000;

fn param<'a>(req: &'a HttpRequest, name: &str) -> &'a str {
    req.match_info().get(name).unwrap_or("")
}

fn iso(dt: &DateTime) -> Option<String> {
    dt.try_to_rfc3339_string().ok()
}

async fn serialize_bot(db: &mongodb::Database, bot: &User) -> Value {
    let token = BotToken::collection(db)
        .find_one(doc! { "botId": bot.id })
        .await
        .ok()
        .flatten();

    json!({
        "id": bot.id.map(|o| o.to_hex()),
        "username": bot.username,
        "displayName": resolve_display_name(bot),
        "color": bot.color,
        "image": bot.image,
        "isBot": true,
        "ownerId": bot.owner_id.map(|o| o.to_hex()),
        "createdAt": iso(&bot.created_at),
        "tokenPrefix": token.as_ref().map(|t| t.token_prefix.clone()),
        "tokenLastUsedAt": token.as_ref().and_then(|t| t.last_used_at.as_ref().and_then(iso)),
    })
}

// ---------------------------------------------------------------------------
// Zarządzanie (auth ciasteczkiem)
// ---------------------------------------------------------------------------

pub async fn list_my_bots(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "message": "Unauthorized" }));
    };
    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::Unauthorized().json(json!({ "message": "Unauthorized" }));
    };

    let db = get_db();
    let bots = match User::find_bots_by_owner(&db, uid).await {
        Ok(b) => b,
        Err(_) => return HttpResponse::InternalServerError().json(json!({ "message": "Internal Server Error" })),
    };

    let mut out = Vec::with_capacity(bots.len());
    for bot in &bots {
        out.push(serialize_bot(&db, bot).await);
    }
    HttpResponse::Ok().json(json!({ "bots": out }))
}

#[derive(Deserialize)]
pub struct CreateBotBody {
    pub username: Option<String>,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
}

pub async fn create_bot(req: HttpRequest, body: web::Json<CreateBotBody>) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "message": "Unauthorized" }));
    };
    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::Unauthorized().json(json!({ "message": "Unauthorized" }));
    };

    let normalized = normalize_username(body.username.as_deref().unwrap_or(""));
    if !is_valid_username(&normalized) {
        return HttpResponse::BadRequest().json(json!({
            "message": "Nazwa bota: 3–32 znaków, tylko małe litery, cyfry i _."
        }));
    }

    let display_name = body
        .display_name
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_string();
    if display_name.chars().count() > DISPLAY_NAME_MAX_LENGTH {
        return HttpResponse::BadRequest().json(json!({
            "message": format!("Nazwa wyświetlana może mieć maksymalnie {DISPLAY_NAME_MAX_LENGTH} znaków.")
        }));
    }

    let db = get_db();

    let count = User::collection(&db)
        .count_documents(doc! { "isBot": true, "ownerId": uid })
        .await
        .unwrap_or(0);
    if count >= MAX_BOTS_PER_USER {
        return HttpResponse::BadRequest().json(json!({
            "message": format!("Osiągnięto limit {MAX_BOTS_PER_USER} botów na konto.")
        }));
    }

    match User::username_exists(&db, &normalized).await {
        Ok(true) => {
            return HttpResponse::Conflict().json(json!({
                "message": "Ta nazwa użytkownika jest już zajęta. Wybierz inną."
            }));
        }
        Ok(false) => {}
        Err(_) => return HttpResponse::InternalServerError().json(json!({ "message": "Internal Server Error" })),
    }

    let bot = match User::create_bot(&db, &normalized, &display_name, uid).await {
        Ok(b) => b,
        Err(_) => {
            if User::username_exists(&db, &normalized).await.unwrap_or(false) {
                return HttpResponse::Conflict().json(json!({
                    "message": "Ta nazwa użytkownika jest już zajęta. Wybierz inną."
                }));
            }
            return HttpResponse::InternalServerError().json(json!({ "message": "Internal Server Error" }));
        }
    };

    let Some(bot_id) = bot.id else {
        return HttpResponse::InternalServerError().json(json!({ "message": "Internal Server Error" }));
    };

    let token = match BotToken::issue(&db, bot_id).await {
        Ok(t) => t,
        Err(_) => return HttpResponse::InternalServerError().json(json!({ "message": "Internal Server Error" })),
    };

    let mut serialized = serialize_bot(&db, &bot).await;
    if let Some(obj) = serialized.as_object_mut() {
        obj.insert("token".into(), json!(token));
    }
    HttpResponse::Created().json(json!({ "bot": serialized }))
}

async fn owned_bot(
    db: &mongodb::Database,
    owner: ObjectId,
    bot_id_str: &str,
) -> Result<User, HttpResponse> {
    let Ok(bot_id) = ObjectId::parse_str(bot_id_str) else {
        return Err(HttpResponse::NotFound().json(json!({ "message": "Bot nie znaleziony." })));
    };
    match User::find_bot(db, bot_id).await {
        Ok(Some(bot)) if bot.owner_id == Some(owner) => Ok(bot),
        Ok(_) => Err(HttpResponse::NotFound().json(json!({ "message": "Bot nie znaleziony." }))),
        Err(_) => Err(HttpResponse::InternalServerError().json(json!({ "message": "Internal Server Error" }))),
    }
}

async fn emit_bot_profile_updated(db: &mongodb::Database, bot: &User) {
    let Some(bot_id) = bot.id else {
        return;
    };
    let bot_id_str = bot_id.to_hex();
    let payload = json!({
        "userId": bot_id_str,
        "username": bot.username,
        "displayName": resolve_display_name(bot),
        "color": bot.color,
        "isBot": true,
    });

    let Ok(channels) = Channel::find_by_member(db, bot_id).await else {
        return;
    };

    let mut notified = std::collections::HashSet::new();
    for channel in channels {
        for member_id in channel_recipient_ids(&channel) {
            if member_id != bot_id_str && notified.insert(member_id.clone()) {
                emit_to_user(&member_id, "profile-updated", payload.clone());
            }
        }
    }
}

#[derive(Deserialize)]
pub struct UpdateBotBody {
    pub username: Option<String>,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    pub color: Option<i32>,
}

pub async fn update_bot(req: HttpRequest, body: web::Json<UpdateBotBody>) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "message": "Unauthorized" }));
    };
    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::Unauthorized().json(json!({ "message": "Unauthorized" }));
    };

    let db = get_db();
    let bot = match owned_bot(&db, uid, param(&req, "botId")).await {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    let Some(bot_id) = bot.id else {
        return HttpResponse::InternalServerError().json(json!({ "message": "Internal Server Error" }));
    };

    let mut set = doc! { "updatedAt": DateTime::now() };
    let mut profile_changed = false;

    if let Some(raw_username) = body.username.as_ref() {
        let normalized = normalize_username(raw_username);
        if !is_valid_username(&normalized) {
            return HttpResponse::BadRequest().json(json!({
                "message": "Nazwa użytkownika: 3–32 znaków, tylko małe litery, cyfry i _."
            }));
        }
        if normalized != bot.username {
            match User::username_taken_by_other(&db, &normalized, bot_id).await {
                Ok(true) => {
                    return HttpResponse::Conflict().json(json!({
                        "message": "Ta nazwa użytkownika jest już zajęta. Wybierz inną."
                    }));
                }
                Ok(false) => {}
                Err(_) => {
                    return HttpResponse::InternalServerError()
                        .json(json!({ "message": "Internal Server Error" }));
                }
            }
            set.insert("username", normalized);
            profile_changed = true;
        }
    }

    if let Some(dn) = body.display_name.as_ref() {
        let trimmed = dn.trim();
        if trimmed.chars().count() > DISPLAY_NAME_MAX_LENGTH {
            return HttpResponse::BadRequest().json(json!({
                "message": format!("Nazwa wyświetlana może mieć maksymalnie {DISPLAY_NAME_MAX_LENGTH} znaków.")
            }));
        }
        let new_display = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        };
        let current_display = bot
            .display_name
            .as_deref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());
        if new_display != current_display {
            profile_changed = true;
        }
        if trimmed.is_empty() {
            set.insert("displayName", mongodb::bson::Bson::Null);
        } else {
            set.insert("displayName", trimmed.to_string());
        }
    }

    if let Some(color) = body.color {
        if bot.color != Some(color) {
            profile_changed = true;
        }
        set.insert("color", color);
    }

    if set.len() <= 1 {
        let updated = match User::find_bot(&db, bot_id).await {
            Ok(Some(b)) => b,
            _ => return HttpResponse::InternalServerError().json(json!({ "message": "Internal Server Error" })),
        };
        return HttpResponse::Ok().json(json!({ "bot": serialize_bot(&db, &updated).await }));
    }

    match User::set_fields(&db, bot_id, set).await {
        Ok(Some(_)) => {}
        Ok(None) => return HttpResponse::NotFound().json(json!({ "message": "Bot nie znaleziony." })),
        Err(_) => {
            if let Some(raw_username) = body.username.as_ref() {
                let normalized = normalize_username(raw_username);
                if User::username_taken_by_other(&db, &normalized, bot_id)
                    .await
                    .unwrap_or(false)
                {
                    return HttpResponse::Conflict().json(json!({
                        "message": "Ta nazwa użytkownika jest już zajęta. Wybierz inną."
                    }));
                }
            }
            return HttpResponse::InternalServerError().json(json!({ "message": "Internal Server Error" }));
        }
    }

    let updated = match User::find_bot(&db, bot_id).await {
        Ok(Some(b)) => b,
        _ => return HttpResponse::InternalServerError().json(json!({ "message": "Internal Server Error" })),
    };

    if profile_changed {
        emit_bot_profile_updated(&db, &updated).await;
    }

    HttpResponse::Ok().json(json!({ "bot": serialize_bot(&db, &updated).await }))
}

pub async fn regenerate_bot_token(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "message": "Unauthorized" }));
    };
    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::Unauthorized().json(json!({ "message": "Unauthorized" }));
    };

    let db = get_db();
    let bot = match owned_bot(&db, uid, param(&req, "botId")).await {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    let Some(bot_id) = bot.id else {
        return HttpResponse::InternalServerError().json(json!({ "message": "Internal Server Error" }));
    };

    match BotToken::issue(&db, bot_id).await {
        Ok(token) => HttpResponse::Ok().json(json!({ "token": token })),
        Err(_) => HttpResponse::InternalServerError().json(json!({ "message": "Internal Server Error" })),
    }
}

pub async fn delete_bot(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "message": "Unauthorized" }));
    };
    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::Unauthorized().json(json!({ "message": "Unauthorized" }));
    };

    let db = get_db();
    let bot = match owned_bot(&db, uid, param(&req, "botId")).await {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    let Some(bot_id) = bot.id else {
        return HttpResponse::InternalServerError().json(json!({ "message": "Internal Server Error" }));
    };

    let _ = BotToken::revoke_for_bot(&db, bot_id).await;
    let _ = Channel::collection(&db)
        .update_many(
            doc! { "members": bot_id },
            doc! { "$pull": { "members": bot_id }, "$set": { "updatedAt": DateTime::now() } },
        )
        .await;
    let _ = User::collection(&db).delete_one(doc! { "_id": bot_id }).await;

    HttpResponse::Ok().json(json!({ "message": "Bot usunięty." }))
}

// ---------------------------------------------------------------------------
// Runtime (auth Bearer)
// ---------------------------------------------------------------------------

pub async fn bot_me(req: HttpRequest) -> HttpResponse {
    let Some(bot_id) = request_bot_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "message": "Unauthorized" }));
    };
    let Ok(oid) = ObjectId::parse_str(&bot_id) else {
        return HttpResponse::Unauthorized().json(json!({ "message": "Unauthorized" }));
    };

    let db = get_db();
    match User::find_bot(&db, oid).await {
        Ok(Some(bot)) => HttpResponse::Ok().json(json!({
            "id": bot.id.map(|o| o.to_hex()),
            "username": bot.username,
            "displayName": resolve_display_name(&bot),
            "isBot": true,
            "ownerId": bot.owner_id.map(|o| o.to_hex()),
        })),
        _ => HttpResponse::Unauthorized().json(json!({ "message": "Unauthorized" })),
    }
}

#[derive(Deserialize)]
pub struct BotSendMessageBody {
    pub content: Option<String>,
}

pub async fn bot_send_channel_message(
    req: HttpRequest,
    body: web::Json<BotSendMessageBody>,
) -> HttpResponse {
    let Some(bot_id) = request_bot_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "message": "Unauthorized" }));
    };

    if !bot_send_allowed(&bot_id) {
        return HttpResponse::TooManyRequests().json(json!({
            "message": "Zbyt wiele wiadomości. Zwolnij tempo.",
            "code": "RATE_LIMIT"
        }));
    }

    let content = body.content.as_deref().unwrap_or("").trim().to_string();
    if content.is_empty() {
        return HttpResponse::BadRequest().json(json!({ "message": "Treść wiadomości jest wymagana." }));
    }
    if content.chars().count() > MAX_BOT_MESSAGE_LEN {
        return HttpResponse::BadRequest().json(json!({
            "message": format!("Wiadomość może mieć maksymalnie {MAX_BOT_MESSAGE_LEN} znaków.")
        }));
    }

    let channel_id = param(&req, "channelId").to_string();
    let db = get_db();

    let channel = match require_channel_message_access(&db, &channel_id, &bot_id).await {
        Ok(channel) => channel,
        Err(reason) => {
            return HttpResponse::Forbidden().json(json!({
                "message": reason.as_str(),
                "code": "FORBIDDEN"
            }));
        }
    };

    if crate::utils::channel::is_channel_chat_locked_for_sender(&channel, &bot_id) {
        return HttpResponse::Forbidden().json(json!({
            "message": "Czat na tym kanale jest zablokowany.",
            "code": "CHAT_LOCKED"
        }));
    }

    if let Err(retry_after) =
        check_channel_slowmode(&bot_id, &channel_id, channel.rate_limit_per_user, false).await
    {
        return HttpResponse::TooManyRequests().json(json!({
            "message": "Slowmode is enabled for this channel.",
            "code": "SLOWMODE",
            "retryAfter": retry_after,
        }));
    }

    let Ok(channel_oid) = ObjectId::parse_str(&channel_id) else {
        return HttpResponse::NotFound().json(json!({ "message": "Kanał nie znaleziony." }));
    };
    let Ok(sender) = ObjectId::parse_str(&bot_id) else {
        return HttpResponse::Unauthorized().json(json!({ "message": "Unauthorized" }));
    };

    let populated = create_and_broadcast_channel_message(
        &db,
        ChannelBroadcastInput {
            channel,
            channel_oid,
            sender,
            content,
            message_type: MessageType::Text,
            file_url: None,
            file_type: None,
            file_size: None,
            file_name: None,
            duration_ms: None,
            quoted_message: None,
        },
    )
    .await;

    match populated {
        Some(message) => HttpResponse::Created().json(json!({ "message": message })),
        None => HttpResponse::InternalServerError().json(json!({ "message": "Internal Server Error" })),
    }
}
