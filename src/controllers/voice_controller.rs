use actix_web::{web, HttpRequest, HttpResponse};
use jsonwebtoken::{encode, EncodingKey};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;
use uuid::Uuid;

use crate::middlewares::auth_middleware::request_user_id;
use crate::utils::db::get_db;
use crate::utils::friends::are_friends;
use crate::utils::ratelimit::Store;
use crate::utils::voice::call_sessions::{active_session_for_user, token_allowed, CallSessionError};

const TOKEN_TTL_SECS: i64 = 3 * 60;

static VOICE_TOKEN_LIMIT: Lazy<Store> = Lazy::new(|| Store::new(20, Duration::from_secs(60)));

pub fn build_dm_room_name(user_a: &str, user_b: &str) -> String {
    let mut ids = [user_a, user_b];
    ids.sort();
    format!("dm_{}_{}", ids[0], ids[1])
}

#[derive(Deserialize)]
pub struct VoiceTokenBody {
    #[serde(rename = "peerId")]
    pub peer_id: Option<String>,
}

#[derive(Serialize)]
struct VideoGrant {
    room: String,
    #[serde(rename = "roomJoin")]
    room_join: bool,
    #[serde(rename = "canPublish")]
    can_publish: bool,
    #[serde(rename = "canSubscribe")]
    can_subscribe: bool,
    #[serde(rename = "canPublishData")]
    can_publish_data: bool,
}

#[derive(Serialize)]
struct LiveKitClaims {
    exp: usize,
    iss: String,
    sub: String,
    nbf: usize,
    jti: String,
    video: VideoGrant,
}

fn token_denied_message(err: CallSessionError) -> &'static str {
    match err {
        CallSessionError::NotFound | CallSessionError::InvalidPhase => {
            "Połączenie nie jest aktywne lub wygasło. Zaakceptuj rozmowę przed dołączeniem."
        }
        CallSessionError::WrongRole | CallSessionError::InProgress => {
            "Brak uprawnień do dołączenia do tej rozmowy."
        }
    }
}

pub async fn get_voice_token(req: HttpRequest, body: web::Json<VoiceTokenBody>) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "message": "Not authenticated." }));
    };

    let rate_key = format!("voice-token:{user_id}");
    if !VOICE_TOKEN_LIMIT.check_and_increment_with_window(&rate_key, 20, Duration::from_secs(60)) {
        return HttpResponse::TooManyRequests().json(json!({
            "message": "Zbyt wiele prób dołączenia do rozmowy. Spróbuj za chwilę."
        }));
    }

    let peer_id = match body.peer_id.as_deref() {
        Some(p) if !p.is_empty() => p.to_string(),
        _ => return HttpResponse::BadRequest().json(json!({ "message": "peerId is required." })),
    };

    if peer_id == user_id {
        return HttpResponse::BadRequest().json(json!({ "message": "Cannot call yourself." }));
    }

    let session = match token_allowed(&user_id, &peer_id) {
        Ok(session) => session,
        Err(err) => {
            return HttpResponse::Forbidden().json(json!({
                "message": token_denied_message(err),
                "code": "CALL_NOT_ACCEPTED"
            }));
        }
    };

    let (Ok(api_key), Ok(api_secret), Ok(url)) = (
        std::env::var("LIVEKIT_API_KEY"),
        std::env::var("LIVEKIT_API_SECRET"),
        std::env::var("LIVEKIT_URL"),
    ) else {
        log::error!("LiveKit env vars are missing (LIVEKIT_API_KEY/SECRET/URL).");
        return HttpResponse::InternalServerError()
            .json(json!({ "message": "Voice service is not configured." }));
    };

    if !crate::utils::security::outbound_url::is_allowed_livekit_url(&url) {
        log::error!("LIVEKIT_URL is not allowed: blocked host or scheme");
        return HttpResponse::InternalServerError()
            .json(json!({ "message": "Voice service is not configured." }));
    }

    let db = get_db();
    if !are_friends(&db, &user_id, &peer_id).await {
        return HttpResponse::Forbidden()
            .json(json!({ "message": "Możesz dzwonić tylko do znajomych." }));
    }

    let room = build_dm_room_name(&user_id, &peer_id);

    let now = chrono::Utc::now().timestamp();
    let jti = format!("{}:{}", session.session_id, Uuid::new_v4());
    let claims = LiveKitClaims {
        exp: (now + TOKEN_TTL_SECS) as usize,
        iss: api_key,
        sub: user_id.clone(),
        nbf: now as usize,
        jti,
        video: VideoGrant {
            room: room.clone(),
            room_join: true,
            can_publish: true,
            can_subscribe: true,
            can_publish_data: true,
        },
    };

    let token = match encode(
        &crate::utils::auth::jwt_validation::hs256_header(),
        &claims,
        &EncodingKey::from_secret(api_secret.as_bytes()),
    ) {
        Ok(t) => t,
        Err(e) => {
            log::error!("Error in getVoiceToken: {}", e);
            return HttpResponse::InternalServerError()
                .json(json!({ "message": "Failed to create voice token." }));
        }
    };

    HttpResponse::Ok().json(json!({ "token": token, "url": url, "room": room }))
}

pub async fn get_active_call(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "message": "Not authenticated." }));
    };

    let Some(session) = active_session_for_user(&user_id) else {
        return HttpResponse::Ok().json(json!({ "active": false }));
    };

    let peer_id = if session.caller_id == user_id {
        session.callee_id.clone()
    } else {
        session.caller_id.clone()
    };

    HttpResponse::Ok().json(json!({
        "active": true,
        "peerId": peer_id,
        "mode": session.mode,
    }))
}
