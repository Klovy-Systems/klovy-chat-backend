use actix_web::{HttpRequest, HttpResponse};
use mongodb::bson::{doc, oid::ObjectId, DateTime};
use serde_json::json;

use crate::middlewares::auth_middleware::request_user_id;
use crate::model::channel_model::Channel;
use crate::model::invite_model::Invite;
use crate::model::user_model::User;
use crate::utils::channel::{is_channel_banned, is_channel_member};
use crate::utils::db::get_db;
use crate::utils::user::serialize_user::resolve_display_name;
use crate::ws::registry::emit_to_user;

fn db_error(context: &str, e: impl std::fmt::Display) -> HttpResponse {
    log::error!("{context}: {e}");
    HttpResponse::InternalServerError().json(json!({ "error": "Internal Server Error" }))
}

pub async fn create_invite(req: HttpRequest) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let channel_id = req.match_info().get("channelId").unwrap_or("");
    let Ok(channel_oid) = ObjectId::parse_str(channel_id) else {
        return HttpResponse::NotFound().json(json!({ "error": "Channel not found" }));
    };

    let db = get_db();
    let channel = match Channel::find_by_id(&db, channel_oid).await {
        Ok(Some(c)) => c,
        Ok(None) => return HttpResponse::NotFound().json(json!({ "error": "Channel not found" })),
        Err(e) => return db_error("create_invite: channel lookup", e),
    };

    if channel.admin.to_hex() != user_id {
        return HttpResponse::Forbidden()
            .json(json!({ "error": "Only the channel owner can create invites" }));
    }

    let Ok(user_oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::InternalServerError().json(json!({ "error": "Invalid user" }));
    };

    let invite = match Invite::create(&db, channel_oid, user_oid, None).await {
        Ok(i) => i,
        Err(e) => return db_error("create_invite: invite creation", e),
    };

    let origin = if crate::utils::app_env::is_production() {
        std::env::var("FRONTEND_URL").unwrap_or_else(|_| "http://127.0.0.1:5173".to_string())
    } else {
        req.headers()
            .get("origin")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                std::env::var("FRONTEND_URL").unwrap_or_else(|_| "http://127.0.0.1:5173".to_string())
            })
    };
    let origin = origin.trim_end_matches('/');

    HttpResponse::Ok().json(json!({
        "inviteId": invite.invite_id,
        "url": format!("{}/invite/{}", origin, invite.invite_id),
    }))
}

pub async fn get_invite(req: HttpRequest) -> HttpResponse {
    let invite_id = req.match_info().get("inviteId").unwrap_or("");

    let db = get_db();
    let invite = match Invite::find_by_invite_id(&db, invite_id).await {
        Ok(Some(i)) => i,
        Ok(None) => return HttpResponse::NotFound().json(json!({ "error": "Invite not found" })),
        Err(e) => return db_error("get_invite: lookup", e),
    };

    let channel = Channel::find_by_id(&db, invite.channel_id).await.ok().flatten();
    let channel_json = channel.map(|c| {
        json!({
            "_id": c.id.map(|o| o.to_hex()),
            "name": c.name,
            "image": c.image,
        })
    });

    let inviter_json = match User::find_by_id(&db, invite.created_by).await {
        Ok(Some(user)) => Some(json!({
            "displayName": resolve_display_name(&user),
            "username": user.username,
            "image": user.image,
            "color": user.color,
        })),
        _ => None,
    };

    HttpResponse::Ok().json(json!({
        "invite": {
            "inviteId": invite.invite_id,
            "channelId": channel_json,
            "inviter": inviter_json,
            "used": invite.used,
            "expiresAt": invite.expires_at.as_ref().and_then(|d| d.try_to_rfc3339_string().ok()),
        }
    }))
}

pub async fn accept_invite(req: HttpRequest) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let invite_id = req.match_info().get("inviteId").unwrap_or("");

    let db = get_db();
    let invite = match Invite::find_by_invite_id(&db, invite_id).await {
        Ok(Some(i)) => i,
        Ok(None) => {
            return HttpResponse::NotFound().json(json!({ "error": "Zaproszenie nie znalezione" }))
        }
        Err(e) => return db_error("accept_invite: invite lookup", e),
    };

    if let Some(exp) = invite.expires_at {
        if exp < DateTime::now() {
            return HttpResponse::BadRequest().json(json!({ "error": "Zaproszenie wygasło" }));
        }
    }

    if invite.used {
        return HttpResponse::BadRequest()
            .json(json!({ "error": "Zaproszenie zostało już wykorzystane" }));
    }

    let channel = match Channel::find_by_id(&db, invite.channel_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return HttpResponse::NotFound().json(json!({ "error": "Kanał nie istnieje" })),
        Err(e) => return db_error("accept_invite: channel lookup", e),
    };

    if is_channel_banned(&channel, Some(&user_id)) {
        return HttpResponse::Forbidden()
            .json(json!({ "error": "Nie masz dostępu do tego kanału" }));
    }

    let channel_id_hex = channel.id.map(|o| o.to_hex());

    if is_channel_member(&channel, Some(&user_id)) {
        return HttpResponse::Ok().json(json!({
            "success": true,
            "channelId": channel_id_hex,
            "alreadyMember": true,
        }));
    }

    let consumed = match Invite::try_consume(&db, invite_id).await {
        Ok(Some(i)) => i,
        Ok(None) => {
            return HttpResponse::BadRequest()
                .json(json!({ "error": "Zaproszenie zostało już wykorzystane lub wygasło" }))
        }
        Err(e) => return db_error("accept_invite: consume invite", e),
    };

    let channel = match Channel::find_by_id(&db, consumed.channel_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return HttpResponse::NotFound().json(json!({ "error": "Kanał nie istnieje" })),
        Err(e) => return db_error("accept_invite: channel reload", e),
    };

    if is_channel_banned(&channel, Some(&user_id)) {
        return HttpResponse::Forbidden()
            .json(json!({ "error": "Nie masz dostępu do tego kanału" }));
    }

    let channel_id_hex = channel.id.map(|o| o.to_hex());

    let Ok(user_oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::BadRequest().json(json!({ "error": "Użytkownik nie istnieje" }));
    };
    match User::find_by_id(&db, user_oid).await {
        Ok(Some(_)) => {}
        _ => return HttpResponse::BadRequest().json(json!({ "error": "Użytkownik nie istnieje" })),
    }

    let Some(channel_oid) = channel.id else {
        return HttpResponse::InternalServerError().json(json!({ "error": "Kanał nie istnieje" }));
    };
    let res = Channel::collection(&db)
        .update_one(
            doc! { "_id": channel_oid },
            doc! { "$push": { "members": user_oid }, "$set": { "updatedAt": DateTime::now() } },
        )
        .await;
    if res.is_err() {
        return HttpResponse::InternalServerError().json(json!({ "error": "Internal Server Error" }));
    }

    emit_to_user(
        &user_id,
        "channel-added",
        json!({ "channelId": channel_oid.to_hex() }),
    );
    HttpResponse::Ok().json(json!({ "success": true, "channelId": channel_id_hex }))
}
