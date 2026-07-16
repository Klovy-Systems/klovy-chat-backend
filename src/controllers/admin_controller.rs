use actix_web::{web, HttpRequest, HttpResponse};
use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, DateTime, Bson};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::model::badge_model::{Badge, CreateBadgeInput};
use crate::model::channel_model::Channel;
use crate::model::channel_report_model::{ChannelReport, ChannelReportStatus};
use crate::model::invite_model::Invite;
use crate::model::messages_model::Message;
use crate::model::refresh_token_model::RefreshToken;
use crate::model::user_model::{User, UserBadge};
use crate::model::warning_model::{
    parse_severity, severity_str, CreateWarningInput, Warning, WARNING_REASON_MAX_LENGTH,
};
use crate::utils::admin::purge_user_completely;
use crate::utils::admin_audit::log_admin_action;
use crate::utils::auth::admin_session::{
    admin_user_ids_configured, clear_admin_cookie, resolve_admin_user,
};
use crate::utils::security::csrf::{csrf_token_for_response};
use crate::utils::channel::channel_member_count;
use crate::ws::registry::{channel_recipient_ids, disconnect_user, emit_to_user, emit_to_users};
use crate::utils::db::get_db;
use crate::utils::friends::emit_to_friends;
use crate::utils::user::badges::{
    dedupe_user_badges, ensure_badge_ids, featured_badge_ids_for_response, populate_user_badges,
    user_has_badge_id, BadgeVisibility,
};
use crate::utils::user::serialize_user::resolve_display_name;
use crate::utils::validators::badge::{is_valid_badge_icon, normalize_badge_color};
use crate::utils::validators::pwned_password::{check_password_breach, PasswordBreachCheck};
use crate::utils::whitelist::is_whitelist_enabled;

fn param<'a>(req: &'a HttpRequest, name: &str) -> &'a str {
    req.match_info().get(name).unwrap_or("")
}

async fn terminate_user_sessions(db: &mongodb::Database, uid: ObjectId) {
    if let Err(e) = User::invalidate_tokens(db, uid).await {
        log::error!("Failed to invalidate tokens for {}: {e}", uid.to_hex());
    }
    if let Err(e) = RefreshToken::revoke_all_for_user(db, uid).await {
        log::error!("Failed to revoke refresh tokens for {}: {e}", uid.to_hex());
    }
    disconnect_user(&uid.to_hex());
}

fn iso(dt: &DateTime) -> Option<String> {
    dt.try_to_rfc3339_string().ok()
}

fn query_u64(req: &HttpRequest, key: &str, default: u64) -> u64 {
    req.uri()
        .query()
        .and_then(|q| {
            q.split('&').find_map(|pair| {
                let (k, v) = pair.split_once('=')?;
                if k == key { v.parse().ok() } else { None }
            })
        })
        .unwrap_or(default)
}

fn query_str(req: &HttpRequest, key: &str) -> String {
    req.uri()
        .query()
        .and_then(|q| {
            q.split('&').find_map(|pair| {
                let (k, v) = pair.split_once('=')?;
                if k == key { Some(v.to_string()) } else { None }
            })
        })
        .unwrap_or_default()
}

fn serialize_badge(b: &Badge) -> Value {
    json!({
        "_id": b.id.map(|o| o.to_hex()),
        "name": b.name,
        "icon": b.icon,
        "color": b.color,
        "description": b.description,
        "createdAt": iso(&b.created_at),
        "updatedAt": iso(&b.updated_at),
    })
}

fn report_status_str(status: &ChannelReportStatus) -> &'static str {
    match status {
        ChannelReportStatus::Pending => "pending",
        ChannelReportStatus::Reviewed => "reviewed",
        ChannelReportStatus::Dismissed => "dismissed",
    }
}

fn serialize_warning(w: &Warning) -> Value {
    json!({
        "id": w.id.map(|o| o.to_hex()),
        "reason": w.reason,
        "severity": severity_str(&w.severity),
        "acknowledged": w.acknowledged,
        "acknowledgedAt": w.acknowledged_at.as_ref().and_then(iso),
        "createdAt": iso(&w.created_at),
    })
}

async fn warning_counts_for_users(
    db: &mongodb::Database,
    users: &[User],
) -> std::collections::HashMap<String, u64> {
    let ids: Vec<ObjectId> = users.iter().filter_map(|u| u.id).collect();
    let mut counts = std::collections::HashMap::new();
    if ids.is_empty() {
        return counts;
    }

    let pipeline = vec![
        doc! { "$match": { "userId": { "$in": &ids } } },
        doc! { "$group": { "_id": "$userId", "count": { "$sum": 1 } } },
    ];

    if let Ok(mut cursor) = Warning::collection(db).aggregate(pipeline).await {
        while let Ok(Some(doc)) = cursor.try_next().await {
            if let Ok(oid) = doc.get_object_id("_id") {
                let count = doc.get_i32("count").map(|c| c as u64).unwrap_or_else(|_| {
                    doc.get_i64("count").map(|c| c as u64).unwrap_or(0)
                });
                counts.insert(oid.to_hex(), count);
            }
        }
    }

    counts
}

pub async fn admin_logout() -> HttpResponse {
    HttpResponse::Ok()
        .cookie(clear_admin_cookie())
        .json(json!({ "message": "Zamknięto panel administratora." }))
}

pub async fn admin_session_status(req: HttpRequest) -> HttpResponse {
    if !admin_user_ids_configured() {
        return HttpResponse::Ok().json(json!({
            "authenticated": false,
        }));
    }

    let Some(user) = resolve_admin_user(&req).await else {
        return HttpResponse::Ok().json(json!({
            "authenticated": false,
        }));
    };

    let (csrf, csrf_cookie) = csrf_token_for_response(&req);
    let mut builder = HttpResponse::Ok();
    if let Some(cookie) = csrf_cookie {
        builder.cookie(cookie);
    }
    builder.json(json!({
        "authenticated": true,
        "userId": user.id.map(|id| id.to_hex()),
        "username": user.username,
        "csrfToken": csrf,
        "whitelistEnabled": is_whitelist_enabled(),
        "pendingWhitelistCount": pending_whitelist_count().await,
    }))
}

async fn pending_whitelist_count() -> u64 {
    if !is_whitelist_enabled() {
        return 0;
    }
    User::collection(&get_db())
        .count_documents(doc! { "isWhitelisted": false })
        .await
        .unwrap_or(0)
}

pub async fn list_users(req: HttpRequest) -> HttpResponse {
    let page = query_u64(&req, "page", 1).max(1);
    let limit = query_u64(&req, "limit", 50).clamp(1, 100);
    let search = query_str(&req, "search")
        .trim()
        .trim_start_matches('@')
        .to_lowercase();
    let whitelist_filter = query_str(&req, "whitelist").trim().to_lowercase();

    let mut filter = doc! {};
    if !search.is_empty() {
        let escaped = regex::escape(&search);
        filter.insert(
            "$or",
            vec![
                doc! { "username": { "$regex": &escaped, "$options": "i" } },
                doc! { "displayName": { "$regex": &escaped, "$options": "i" } },
            ],
        );
    }
    if whitelist_filter == "pending" {
        filter.insert("isWhitelisted", false);
    } else if whitelist_filter == "approved" {
        filter.insert("isWhitelisted", true);
    }

    let db = get_db();
    let pending_count = pending_whitelist_count().await;
    let total = User::collection(&db).count_documents(filter.clone()).await.unwrap_or(0);
    let skip = (page - 1) * limit;

    let users: Vec<User> = match User::collection(&db)
        .find(filter)
        .sort(doc! { "createdAt": -1 })
        .skip(skip)
        .limit(limit as i64)
        .await
    {
        Ok(c) => c.try_collect().await.unwrap_or_default(),
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(json!({ "error": "Nie udało się pobrać listy użytkowników." }));
        }
    };

    let warning_counts = warning_counts_for_users(&db, &users).await;

    let items: Vec<Value> = users
        .iter()
        .map(|u| {
            let warning_count = u
                .id
                .and_then(|oid| warning_counts.get(&oid.to_hex()).copied())
                .unwrap_or(0);
            json!({
                "id": u.id.map(|o| o.to_hex()),
                "username": u.username,
                "displayName": resolve_display_name(u),
                "image": u.image,
                "color": u.color.unwrap_or(0),
                "isActive": u.is_active,
                "isBlocked": u.is_blocked,
                "isBanned": u.is_banned,
                "isDisabled": u.is_disabled,
                "disabledAt": u.disabled_at.as_ref().and_then(iso),
                "deletionRequestedAt": u.deletion_requested_at.as_ref().and_then(iso),
                "deletionScheduledAt": u.deletion_scheduled_at.as_ref().and_then(iso),
                "blockReason": u.block_reason,
                "blockedAt": u.blocked_at.as_ref().and_then(iso),
                "isWhitelisted": u.is_whitelisted,
                "warningCount": warning_count,
                "createdAt": iso(&u.created_at),
            })
        })
        .collect();

    HttpResponse::Ok()
        .insert_header(("X-Total-Count", total.to_string()))
        .json(json!({
            "users": items,
            "total": total,
            "page": page,
            "limit": limit,
            "pendingCount": pending_count,
            "whitelistEnabled": is_whitelist_enabled(),
        }))
}

#[derive(Deserialize)]
pub struct SetWhitelistBody {
    pub approved: Option<bool>,
}

pub async fn set_user_whitelist(req: HttpRequest, body: web::Json<SetWhitelistBody>) -> HttpResponse {
    if !is_whitelist_enabled() {
        return HttpResponse::BadRequest().json(json!({
            "error": "Whitelista nie jest włączona na tym serwerze."
        }));
    }

    let approved = body.approved.unwrap_or(false);
    let Ok(uid) = ObjectId::parse_str(param(&req, "userId")) else {
        return HttpResponse::NotFound().json(json!({ "error": "Użytkownik nie istnieje." }));
    };

    let db = get_db();
    if User::find_by_id(&db, uid).await.ok().flatten().is_none() {
        return HttpResponse::NotFound().json(json!({ "error": "Użytkownik nie istnieje." }));
    }

    match User::set_fields(&db, uid, doc! { "isWhitelisted": approved }).await {
        Ok(Some(updated)) => {
            if approved {
                emit_to_user(
                    &uid.to_hex(),
                    "whitelist:approved",
                    json!({ "userId": uid.to_hex() }),
                );
            } else {
                terminate_user_sessions(&db, uid).await;
            }
            log_admin_action(
                &req,
                if approved {
                    "whitelist.approve"
                } else {
                    "whitelist.revoke"
                },
                Some("user"),
                Some(&uid.to_hex()),
                json!({ "approved": approved }),
            )
            .await;
            HttpResponse::Ok().json(json!({
                "message": if approved {
                    "Użytkownik został zatwierdzony na whitelistę."
                } else {
                    "Użytkownik został usunięty z whitelisty."
                },
                "user": {
                    "id": updated.id.map(|o| o.to_hex()),
                    "username": updated.username,
                    "isWhitelisted": updated.is_whitelisted,
                },
            }))
        }
        Ok(None) => HttpResponse::NotFound().json(json!({ "error": "Użytkownik nie istnieje." })),
        Err(_) => HttpResponse::InternalServerError()
            .json(json!({ "error": "Nie udało się zaktualizować whitelisty." })),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetUserPasswordBody {
    pub new_password: Option<String>,
}

/// Admin-forced password reset (e.g. forgotten password). Terminates all sessions.
pub async fn set_user_password(
    req: HttpRequest,
    body: web::Json<SetUserPasswordBody>,
) -> HttpResponse {
    let Ok(uid) = ObjectId::parse_str(param(&req, "userId")) else {
        return HttpResponse::NotFound().json(json!({ "error": "Użytkownik nie istnieje." }));
    };

    let new_password = body.new_password.as_deref().unwrap_or("").trim();
    if new_password.is_empty() {
        return HttpResponse::BadRequest().json(json!({
            "error": "Nowe hasło jest wymagane."
        }));
    }

    let db = get_db();
    let user = match User::find_by_id(&db, uid).await {
        Ok(Some(u)) => u,
        _ => return HttpResponse::NotFound().json(json!({ "error": "Użytkownik nie istnieje." })),
    };

    if user.is_bot {
        return HttpResponse::BadRequest().json(json!({
            "error": "Nie można zmienić hasła konta bota."
        }));
    }

    match check_password_breach(new_password).await {
        PasswordBreachCheck::Breached => {
            return HttpResponse::BadRequest().json(json!({
                "error": "To hasło pojawiło się w wycieku danych. Wybierz inne, bezpieczniejsze hasło.",
                "code": "PASSWORD_BREACHED"
            }));
        }
        PasswordBreachCheck::Unavailable => {
            return HttpResponse::ServiceUnavailable().json(json!({
                "error": "Nie można teraz zweryfikować hasła. Spróbuj ponownie za chwilę."
            }));
        }
        PasswordBreachCheck::Safe => {}
    }

    if let Err(e) = User::update_password(&db, uid, new_password).await {
        log::error!("Admin password reset failed for {}: {e}", uid.to_hex());
        return HttpResponse::InternalServerError()
            .json(json!({ "error": "Nie udało się zmienić hasła." }));
    }

    terminate_user_sessions(&db, uid).await;

    log_admin_action(
        &req,
        "user.password.reset",
        Some("user"),
        Some(&uid.to_hex()),
        json!({ "username": user.username }),
    )
    .await;

    HttpResponse::Ok().json(json!({
        "message": "Hasło zostało zresetowane. Użytkownik musi zalogować się ponownie.",
        "user": {
            "id": uid.to_hex(),
            "username": user.username,
        },
    }))
}

#[derive(Deserialize)]
pub struct BlockUserBody {
    pub reason: Option<String>,
}

pub async fn block_user(req: HttpRequest, body: web::Json<BlockUserBody>) -> HttpResponse {
    let Ok(uid) = ObjectId::parse_str(param(&req, "userId")) else {
        return HttpResponse::NotFound().json(json!({ "error": "Użytkownik nie istnieje." }));
    };

    let db = get_db();
    let user = match User::find_by_id(&db, uid).await {
        Ok(Some(u)) => u,
        _ => return HttpResponse::NotFound().json(json!({ "error": "Użytkownik nie istnieje." })),
    };

    let block_reason = body
        .reason
        .as_ref()
        .map(|r| r.trim().chars().take(500).collect::<String>())
        .filter(|r| !r.is_empty());
    let now = DateTime::now();

    let update = doc! {
        "$set": {
            "isBlocked": true,
            "isBanned": true,
            "blockReason": block_reason.clone(),
            "blockedAt": now,
            "updatedAt": now,
        },
        "$inc": { "tokenVersion": 1 },
    };

    if User::collection(&db)
        .update_one(doc! { "_id": uid }, update)
        .await
        .is_err()
    {
        return HttpResponse::InternalServerError()
            .json(json!({ "error": "Nie udało się zbanować użytkownika." }));
    }

    let _ = RefreshToken::revoke_all_for_user(&db, uid).await;
    disconnect_user(&uid.to_hex());

    log_admin_action(
        &req,
        "user.ban",
        Some("user"),
        Some(&uid.to_hex()),
        json!({ "reason": block_reason }),
    )
    .await;

    HttpResponse::Ok().json(json!({
        "message": "Użytkownik został zbanowany.",
        "user": {
            "id": user.id.map(|o| o.to_hex()),
            "isBlocked": true,
            "isBanned": true,
            "blockReason": block_reason,
            "blockedAt": iso(&now),
        },
    }))
}

pub async fn unblock_user(req: HttpRequest) -> HttpResponse {
    let Ok(uid) = ObjectId::parse_str(param(&req, "userId")) else {
        return HttpResponse::NotFound().json(json!({ "error": "Użytkownik nie istnieje." }));
    };

    let db = get_db();
    if User::find_by_id(&db, uid).await.ok().flatten().is_none() {
        return HttpResponse::NotFound().json(json!({ "error": "Użytkownik nie istnieje." }));
    }

    let now = DateTime::now();
    if User::collection(&db)
        .update_one(
            doc! { "_id": uid },
            doc! {
                "$set": {
                    "isBlocked": false,
                    "isBanned": false,
                    "blockReason": Bson::Null,
                    "blockedAt": Bson::Null,
                    "updatedAt": now,
                },
            },
        )
        .await
        .is_err()
    {
        return HttpResponse::InternalServerError()
            .json(json!({ "error": "Nie udało się odbanować użytkownika." }));
    }

    log_admin_action(
        &req,
        "user.unban",
        Some("user"),
        Some(&uid.to_hex()),
        json!({}),
    )
    .await;

    HttpResponse::Ok().json(json!({
        "message": "Użytkownik został odbanowany.",
        "user": {
            "id": uid.to_hex(),
            "isBlocked": false,
            "isBanned": false,
        },
    }))
}

pub async fn delete_user(req: HttpRequest) -> HttpResponse {
    let Ok(uid) = ObjectId::parse_str(param(&req, "userId")) else {
        return HttpResponse::NotFound().json(json!({ "error": "Użytkownik nie istnieje." }));
    };

    let db = get_db();
    if User::find_by_id(&db, uid).await.ok().flatten().is_none() {
        return HttpResponse::NotFound().json(json!({ "error": "Użytkownik nie istnieje." }));
    }

    terminate_user_sessions(&db, uid).await;

    match purge_user_completely(&db, uid).await {
        Ok(channels_deleted) => {
            log_admin_action(
                &req,
                "user.delete",
                Some("user"),
                Some(&uid.to_hex()),
                json!({ "channelsDeleted": channels_deleted }),
            )
            .await;
            HttpResponse::Ok().json(json!({
            "message": "Konto użytkownika zostało usunięte.",
            "channelsDeleted": channels_deleted,
        }))},
        Err(_) => HttpResponse::InternalServerError()
            .json(json!({ "error": "Nie udało się usunąć użytkownika." })),
    }
}

pub async fn restore_user(req: HttpRequest) -> HttpResponse {
    let Ok(uid) = ObjectId::parse_str(param(&req, "userId")) else {
        return HttpResponse::NotFound().json(json!({ "error": "Użytkownik nie istnieje." }));
    };

    let db = get_db();
    let user = match User::find_by_id(&db, uid).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return HttpResponse::NotFound().json(json!({ "error": "Użytkownik nie istnieje." }));
        }
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(json!({ "error": "Nie udało się pobrać użytkownika." }));
        }
    };

    if !user.is_disabled {
        return HttpResponse::BadRequest().json(json!({
            "error": "To konto nie wymaga przywrócenia."
        }));
    }

    let now = DateTime::now();
    if User::collection(&db)
        .update_one(
            doc! { "_id": uid },
            doc! {
                "$set": {
                    "isDisabled": false,
                    "isActive": true,
                    "updatedAt": now,
                },
                "$unset": {
                    "disabledAt": "",
                },
            },
        )
        .await
        .is_err()
    {
        return HttpResponse::InternalServerError()
            .json(json!({ "error": "Nie udało się przywrócić konta." }));
    }

    log_admin_action(
        &req,
        "user.restore",
        Some("user"),
        Some(&uid.to_hex()),
        json!({
            "wasDisabled": user.is_disabled,
        }),
    )
    .await;

    HttpResponse::Ok().json(json!({
        "message": "Konto użytkownika zostało przywrócone.",
        "user": {
            "id": uid.to_hex(),
            "isDisabled": false,
            "deletionScheduledAt": null,
        },
    }))
}

pub async fn list_channels(req: HttpRequest) -> HttpResponse {
    let page = query_u64(&req, "page", 1).max(1);
    let limit = query_u64(&req, "limit", 50).clamp(1, 100);
    let search = query_str(&req, "search").trim().to_string();

    let mut filter = doc! {};
    if !search.is_empty() {
        let escaped = regex::escape(&search);
        filter.insert("name", doc! { "$regex": &escaped, "$options": "i" });
    }

    let db = get_db();
    let total = Channel::collection(&db).count_documents(filter.clone()).await.unwrap_or(0);
    let skip = (page - 1) * limit;

    let channels: Vec<Channel> = match Channel::collection(&db)
        .find(filter)
        .sort(doc! { "createdAt": -1 })
        .skip(skip)
        .limit(limit as i64)
        .await
    {
        Ok(c) => c.try_collect().await.unwrap_or_default(),
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(json!({ "error": "Nie udało się pobrać listy kanałów." }));
        }
    };

    // Batch-load channel admins in a single query instead of per-channel lookups.
    let admin_ids: Vec<ObjectId> = channels.iter().map(|c| c.admin).collect();
    let mut admin_map: std::collections::HashMap<ObjectId, User> =
        std::collections::HashMap::new();
    if !admin_ids.is_empty() {
        if let Ok(cursor) = User::collection(&db)
            .find(doc! { "_id": { "$in": &admin_ids } })
            .await
        {
            let users: Vec<User> = cursor.try_collect().await.unwrap_or_default();
            for u in users {
                if let Some(id) = u.id {
                    admin_map.insert(id, u);
                }
            }
        }
    }

    let mut items = Vec::with_capacity(channels.len());
    for ch in &channels {
        let admin = match admin_map.get(&ch.admin) {
            Some(u) => json!({
                "id": u.id.map(|o| o.to_hex()),
                "username": u.username,
                "displayName": resolve_display_name(u),
            }),
            None => json!({ "id": Value::Null, "username": Value::Null, "displayName": Value::Null }),
        };

        items.push(json!({
            "id": ch.id.map(|o| o.to_hex()),
            "name": ch.name,
            "description": ch.description.as_deref().unwrap_or(""),
            "isPrivate": ch.is_private,
            "memberCount": channel_member_count(ch),
            "messageCount": ch.messages.len(),
            "admin": admin,
            "createdAt": iso(&ch.created_at),
        }));
    }

    HttpResponse::Ok()
        .insert_header(("X-Total-Count", total.to_string()))
        .json(json!({ "channels": items, "total": total, "page": page, "limit": limit }))
}

pub async fn delete_channel_admin(req: HttpRequest) -> HttpResponse {
    let Ok(cid) = ObjectId::parse_str(param(&req, "channelId")) else {
        return HttpResponse::NotFound().json(json!({ "error": "Kanał nie istnieje." }));
    };

    let db = get_db();
    let channel = match Channel::find_by_id(&db, cid).await {
        Ok(Some(c)) => c,
        _ => return HttpResponse::NotFound().json(json!({ "error": "Kanał nie istnieje." })),
    };
    let channel_id = cid.to_hex();
    let recipients = channel_recipient_ids(&channel);

    if Message::collection(&db)
        .delete_many(doc! { "channel": cid })
        .await
        .is_err()
        || Invite::collection(&db)
            .delete_many(doc! { "channelId": cid })
            .await
            .is_err()
        || Channel::collection(&db)
            .delete_one(doc! { "_id": cid })
            .await
            .is_err()
    {
        return HttpResponse::InternalServerError()
            .json(json!({ "error": "Nie udało się usunąć kanału." }));
    }

    emit_to_users(
        &recipients,
        "channel-deleted",
        json!({ "channelId": channel_id }),
    );
    log_admin_action(
        &req,
        "channel.delete",
        Some("channel"),
        Some(&channel_id),
        json!({ "memberCount": recipients.len() }),
    )
    .await;
    HttpResponse::Ok().json(json!({ "message": "Kanał został usunięty." }))
}

pub async fn list_channel_reports() -> HttpResponse {
    let db = get_db();
    let reports: Vec<ChannelReport> = match ChannelReport::collection(&db)
        .find(doc! {})
        .sort(doc! { "createdAt": -1 })
        .limit(200)
        .await
    {
        Ok(c) => c.try_collect().await.unwrap_or_default(),
        Err(_) => return HttpResponse::InternalServerError().json(json!({ "message": "Internal Server Error" })),
    };

    let mut rows = Vec::with_capacity(reports.len());
    let mut pending_count = 0u64;

    for r in &reports {
        if r.status == ChannelReportStatus::Pending {
            pending_count += 1;
        }

        let reporter = match User::find_by_id(&db, r.reported_by).await {
            Ok(Some(u)) => json!({
                "id": u.id.map(|o| o.to_hex()),
                "username": u.username,
                "displayName": resolve_display_name(&u),
                "image": u.image,
                "color": u.color.unwrap_or(0),
            }),
            _ => json!({
                "id": r.reported_by.to_hex(),
                "username": r.reporter_username,
                "displayName": Value::Null,
            }),
        };

        rows.push(json!({
            "id": r.id.map(|o| o.to_hex()),
            "channelId": r.channel_id.to_hex(),
            "channelName": r.channel_name,
            "reason": r.reason,
            "details": r.details.as_deref().unwrap_or(""),
            "status": report_status_str(&r.status),
            "createdAt": iso(&r.created_at),
            "reporter": reporter,
        }));
    }

    HttpResponse::Ok().json(json!({ "reports": rows, "pendingCount": pending_count }))
}

#[derive(Deserialize)]
pub struct UpdateReportBody {
    pub status: Option<String>,
}

pub async fn update_channel_report_status(
    req: HttpRequest,
    body: web::Json<UpdateReportBody>,
) -> HttpResponse {
    let status = body.status.clone().unwrap_or_default();
    if status != "reviewed" && status != "dismissed" {
        return HttpResponse::BadRequest().json(json!({ "message": "Nieprawidłowy status" }));
    }

    let Ok(rid) = ObjectId::parse_str(param(&req, "reportId")) else {
        return HttpResponse::NotFound().json(json!({ "message": "Zgłoszenie nie znalezione" }));
    };

    let new_status = if status == "reviewed" {
        ChannelReportStatus::Reviewed
    } else {
        ChannelReportStatus::Dismissed
    };

    let db = get_db();
    if ChannelReport::update_status(&db, rid, new_status).await.is_err() {
        return HttpResponse::InternalServerError().json(json!({ "message": "Internal Server Error" }));
    }

    log_admin_action(
        &req,
        "report.update",
        Some("channel_report"),
        Some(&rid.to_hex()),
        json!({ "status": status }),
    )
    .await;

    let report = match ChannelReport::find_by_id(&db, rid).await {
        Ok(Some(r)) => r,
        _ => return HttpResponse::NotFound().json(json!({ "message": "Zgłoszenie nie znalezione" })),
    };

    HttpResponse::Ok().json(json!({
        "message": "Status zaktualizowany",
        "report": {
            "_id": report.id.map(|o| o.to_hex()),
            "channelId": report.channel_id.to_hex(),
            "channelName": report.channel_name,
            "reportedBy": report.reported_by.to_hex(),
            "reporterUsername": report.reporter_username,
            "reason": report.reason,
            "details": report.details,
            "status": report_status_str(&report.status),
            "createdAt": iso(&report.created_at),
            "reviewedAt": report.reviewed_at.as_ref().and_then(iso),
        },
    }))
}

pub async fn list_badges() -> HttpResponse {
    let db = get_db();
    let badges: Vec<Badge> = match Badge::collection(&db)
        .find(doc! {})
        .sort(doc! { "createdAt": -1 })
        .await
    {
        Ok(c) => c.try_collect().await.unwrap_or_default(),
        Err(e) => {
            log::error!("list_badges: {e}");
            return HttpResponse::InternalServerError().json(json!({
                "success": false,
                "message": "Failed to fetch badges",
            }));
        }
    };

    HttpResponse::Ok().json(json!({
        "success": true,
        "data": badges.iter().map(serialize_badge).collect::<Vec<_>>(),
    }))
}

#[derive(Deserialize)]
pub struct CreateBadgeBody {
    pub name: Option<String>,
    pub icon: Option<String>,
    pub color: Option<String>,
    pub description: Option<String>,
}

pub async fn create_badge(body: web::Json<CreateBadgeBody>) -> HttpResponse {
    let name = body.name.clone().unwrap_or_default();
    let icon = body.icon.clone().unwrap_or_default();
    if name.trim().is_empty() || icon.trim().is_empty() {
        return HttpResponse::BadRequest().json(json!({
            "success": false,
            "message": "Name and icon are required",
        }));
    }
    if name.trim().chars().count() > 64 {
        return HttpResponse::BadRequest().json(json!({
            "success": false,
            "message": "Badge name is too long (max 64 characters)",
        }));
    }
    if !is_valid_badge_icon(icon.trim()) {
        return HttpResponse::BadRequest().json(json!({
            "success": false,
            "message": "Invalid icon name",
        }));
    }
    if let Some(raw_color) = body.color.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        if normalize_badge_color(Some(raw_color)).is_none() {
            return HttpResponse::BadRequest().json(json!({
                "success": false,
                "message": "Invalid badge color (use #RRGGBB)",
            }));
        }
    }
    if let Some(desc) = body.description.as_deref() {
        if desc.chars().count() > 500 {
            return HttpResponse::BadRequest().json(json!({
                "success": false,
                "message": "Description is too long (max 500 characters)",
            }));
        }
    }

    let db = get_db();
    if Badge::find_by_name(&db, name.trim()).await.ok().flatten().is_some() {
        return HttpResponse::Conflict().json(json!({
            "success": false,
            "message": "Badge with this name already exists",
        }));
    }

    let input = CreateBadgeInput {
        name,
        icon,
        color: normalize_badge_color(body.color.as_deref()),
        description: body
            .description
            .as_ref()
            .map(|d| d.trim().chars().take(500).collect()),
    };

    match Badge::create(&db, input).await {
        Ok(badge) => HttpResponse::Created().json(json!({ "success": true, "data": serialize_badge(&badge) })),
        Err(e) => {
            log::error!("create_badge: {e}");
            HttpResponse::InternalServerError().json(json!({
            "success": false,
            "message": "Failed to create badge",
        }))
        }
    }
}

#[derive(Deserialize)]
pub struct UpdateBadgeBody {
    pub name: Option<String>,
    pub icon: Option<String>,
    pub color: Option<String>,
    pub description: Option<String>,
}

pub async fn update_badge(req: HttpRequest, body: web::Json<UpdateBadgeBody>) -> HttpResponse {
    let Ok(bid) = ObjectId::parse_str(param(&req, "badgeId")) else {
        return HttpResponse::BadRequest().json(json!({ "success": false, "message": "Invalid badge ID" }));
    };

    let db = get_db();
    let badge = match Badge::find_by_id(&db, bid).await {
        Ok(Some(b)) => b,
        Ok(None) => return HttpResponse::NotFound().json(json!({ "success": false, "message": "Badge not found" })),
        Err(e) => {
            log::error!("update_badge: lookup: {e}");
            return HttpResponse::InternalServerError().json(json!({
                "success": false,
                "message": "Failed to update badge",
            }));
        }
    };

    let mut set = doc! { "updatedAt": DateTime::now() };

    if let Some(name) = &body.name {
        let trimmed = name.trim();
        if trimmed.chars().count() > 64 {
            return HttpResponse::BadRequest().json(json!({
                "success": false,
                "message": "Badge name is too long (max 64 characters)",
            }));
        }
        if !trimmed.is_empty() && trimmed != badge.name {
            if Badge::find_by_name(&db, trimmed).await.ok().flatten().is_some() {
                return HttpResponse::Conflict().json(json!({
                    "success": false,
                    "message": "Badge with this name already exists",
                }));
            }
            set.insert("name", trimmed);
        }
    }
    if let Some(icon) = &body.icon {
        let trimmed = icon.trim();
        if !trimmed.is_empty() {
            if !is_valid_badge_icon(trimmed) {
                return HttpResponse::BadRequest().json(json!({
                    "success": false,
                    "message": "Invalid icon name",
                }));
            }
            set.insert("icon", trimmed);
        }
    }
    if body.color.is_some() {
        let c = body.color.as_deref().unwrap_or("").trim();
        if c.is_empty() {
            set.insert("color", Bson::Null);
        } else if let Some(normalized) = normalize_badge_color(Some(c)) {
            set.insert("color", Bson::String(normalized));
        } else {
            return HttpResponse::BadRequest().json(json!({
                "success": false,
                "message": "Invalid badge color (use #RRGGBB)",
            }));
        }
    }
    if body.description.is_some() {
        let d = body.description.as_deref().unwrap_or("").trim();
        set.insert(
            "description",
            if d.is_empty() {
                Bson::Null
            } else if d.chars().count() > 500 {
                return HttpResponse::BadRequest().json(json!({
                    "success": false,
                    "message": "Description is too long (max 500 characters)",
                }));
            } else {
                Bson::String(d.to_string())
            },
        );
    }

    if Badge::collection(&db)
        .update_one(doc! { "_id": bid }, doc! { "$set": set })
        .await
        .is_err()
    {
        return HttpResponse::InternalServerError().json(json!({
            "success": false,
            "message": "Failed to update badge",
        }));
    }

    let updated = Badge::find_by_id(&db, bid).await.ok().flatten();
    match updated {
        Some(b) => HttpResponse::Ok().json(json!({ "success": true, "data": serialize_badge(&b) })),
        None => HttpResponse::InternalServerError().json(json!({
            "success": false,
            "message": "Failed to update badge",
        })),
    }
}

pub async fn delete_badge(req: HttpRequest) -> HttpResponse {
    let Ok(bid) = ObjectId::parse_str(param(&req, "badgeId")) else {
        return HttpResponse::BadRequest().json(json!({ "success": false, "message": "Invalid badge ID" }));
    };

    let db = get_db();
    if Badge::find_by_id(&db, bid).await.ok().flatten().is_none() {
        return HttpResponse::NotFound().json(json!({ "success": false, "message": "Badge not found" }));
    }

    if Badge::collection(&db).delete_one(doc! { "_id": bid }).await.is_err() {
        return HttpResponse::InternalServerError().json(json!({
            "success": false,
            "message": "Failed to delete badge",
        }));
    }

    let _ = User::collection(&db)
        .update_many(
            doc! { "badges.badgeId": bid },
            doc! { "$pull": { "badges": { "badgeId": bid } } },
        )
        .await;

    HttpResponse::Ok().json(json!({
        "success": true,
        "message": "Badge deleted successfully",
    }))
}

#[derive(Deserialize)]
pub struct AssignBadgeBody {
    #[serde(rename = "badgeId")]
    pub badge_id: Option<String>,
}

pub async fn assign_badge(req: HttpRequest, body: web::Json<AssignBadgeBody>) -> HttpResponse {
    let Ok(uid) = ObjectId::parse_str(param(&req, "userId")) else {
        return HttpResponse::BadRequest().json(json!({ "success": false, "message": "Invalid user ID" }));
    };
    let badge_id_str = body.badge_id.clone().unwrap_or_default();
    let Ok(bid) = ObjectId::parse_str(&badge_id_str) else {
        return HttpResponse::BadRequest().json(json!({ "success": false, "message": "Invalid badge ID" }));
    };

    let db = get_db();
    let user = match User::find_by_id(&db, uid).await {
        Ok(Some(u)) => u,
        Ok(None) => return HttpResponse::NotFound().json(json!({ "success": false, "message": "User not found" })),
        Err(e) => {
            log::error!("assign_badge: user lookup: {e}");
            return HttpResponse::InternalServerError().json(json!({
                "success": false,
                "message": "Failed to assign badge",
            }));
        }
    };

    if Badge::find_by_id(&db, bid).await.ok().flatten().is_none() {
        return HttpResponse::NotFound().json(json!({ "success": false, "message": "Badge not found" }));
    }

    let mut badges = user.badges.clone();
    ensure_badge_ids(&mut badges);
    let deduped = dedupe_user_badges(&mut badges);
    if deduped {
        let badges_bson = mongodb::bson::to_bson(&badges).unwrap_or(Bson::Array(vec![]));
        let _ = User::set_fields(&db, uid, doc! { "badges": badges_bson }).await;
    }

    if user_has_badge_id(&badges, bid) {
        return HttpResponse::BadRequest().json(json!({
            "success": false,
            "message": "Ten użytkownik ma już tę odznakę.",
            "code": "BADGE_ALREADY_ASSIGNED",
        }));
    }

    let new_badge = UserBadge {
        id: Some(ObjectId::new()),
        badge_id: bid,
        assigned_at: DateTime::now(),
    };
    badges.push(new_badge);
    let badges_bson = mongodb::bson::to_bson(&badges).unwrap_or(Bson::Array(vec![]));

    if User::set_fields(&db, uid, doc! { "badges": badges_bson }).await.is_err() {
        return HttpResponse::InternalServerError().json(json!({
            "success": false,
            "message": "Failed to assign badge",
        }));
    }

    let updated = User::find_by_id(&db, uid).await.ok().flatten();
    let populated = if let Some(ref u) = updated {
        let all_badges = populate_user_badges(&db, u, BadgeVisibility::All).await;
        emit_to_user(
            &uid.to_hex(),
            "badge:assigned",
            json!({
                "userId": uid.to_hex(),
                "badges": all_badges.clone(),
            }),
        );
        emit_to_friends(
            &db,
            &uid.to_hex(),
            "badge:assigned",
            json!({
                "userId": uid.to_hex(),
                "badges": all_badges.clone(),
            }),
        )
        .await;
        json!({
            "badges": all_badges,
            "featuredBadgeIds": featured_badge_ids_for_response(u),
            "_id": u.id.map(|o| o.to_hex()),
            "username": u.username,
        })
    } else {
        json!(null)
    };

    HttpResponse::Ok().json(json!({
        "success": true,
        "message": "Badge assigned successfully",
        "data": populated,
    }))
}

pub async fn get_user_badges(req: HttpRequest) -> HttpResponse {
    let Ok(uid) = ObjectId::parse_str(param(&req, "userId")) else {
        return HttpResponse::BadRequest().json(json!({ "success": false, "message": "Invalid user ID" }));
    };

    let db = get_db();
    let user = match User::find_by_id(&db, uid).await {
        Ok(Some(u)) => u,
        Ok(None) => return HttpResponse::NotFound().json(json!({ "success": false, "message": "User not found" })),
        Err(e) => {
            log::error!("get_user_badges: user lookup: {e}");
            return HttpResponse::InternalServerError().json(json!({
                "success": false,
                "message": "Failed to load user badges",
            }));
        }
    };

    let badges = populate_user_badges(&db, &user, BadgeVisibility::All).await;
    HttpResponse::Ok().json(json!({
        "success": true,
        "data": {
            "badges": badges,
            "featuredBadgeIds": featured_badge_ids_for_response(&user),
            "_id": user.id.map(|o| o.to_hex()),
            "username": user.username,
        },
    }))
}

pub async fn remove_badge(req: HttpRequest) -> HttpResponse {
    let Ok(uid) = ObjectId::parse_str(param(&req, "userId")) else {
        return HttpResponse::BadRequest().json(json!({ "success": false, "message": "Invalid user ID" }));
    };
    let Ok(aid) = ObjectId::parse_str(param(&req, "assignmentId")) else {
        return HttpResponse::BadRequest().json(json!({ "success": false, "message": "Invalid badge assignment ID" }));
    };

    let db = get_db();
    let user = match User::find_by_id(&db, uid).await {
        Ok(Some(u)) => u,
        Ok(None) => return HttpResponse::NotFound().json(json!({ "success": false, "message": "User not found" })),
        Err(e) => {
            log::error!("remove_badge: user lookup: {e}");
            return HttpResponse::InternalServerError().json(json!({
                "success": false,
                "message": "Failed to remove badge",
            }));
        }
    };

    let mut badges = user.badges.clone();
    ensure_badge_ids(&mut badges);

    let before_len = badges.len();
    badges.retain(|b| b.id != Some(aid));
    if badges.len() == before_len {
        return HttpResponse::NotFound().json(json!({
            "success": false,
            "message": "Badge assignment not found",
        }));
    }

    let featured_badge_ids: Vec<ObjectId> = user
        .featured_badge_ids
        .iter()
        .filter(|id| **id != aid)
        .copied()
        .collect();

    let badges_bson = mongodb::bson::to_bson(&badges).unwrap_or(Bson::Array(vec![]));
    let featured_bson =
        mongodb::bson::to_bson(&featured_badge_ids).unwrap_or(Bson::Array(vec![]));

    if User::set_fields(
        &db,
        uid,
        doc! { "badges": badges_bson, "featuredBadgeIds": featured_bson },
    )
    .await
    .is_err()
    {
        return HttpResponse::InternalServerError().json(json!({
            "success": false,
            "message": "Failed to remove badge",
        }));
    }

    let updated = User::find_by_id(&db, uid).await.ok().flatten();
    let populated = if let Some(ref u) = updated {
        let all_badges = populate_user_badges(&db, u, BadgeVisibility::All).await;
        emit_to_user(
            &uid.to_hex(),
            "badge:removed",
            json!({
                "userId": uid.to_hex(),
                "badges": all_badges.clone(),
            }),
        );
        emit_to_friends(
            &db,
            &uid.to_hex(),
            "badge:removed",
            json!({
                "userId": uid.to_hex(),
                "badges": all_badges.clone(),
            }),
        )
        .await;
        json!({
            "badges": all_badges,
            "featuredBadgeIds": featured_badge_ids_for_response(u),
            "_id": u.id.map(|o| o.to_hex()),
            "username": u.username,
        })
    } else {
        json!(null)
    };

    HttpResponse::Ok().json(json!({
        "success": true,
        "message": "Badge removed successfully",
        "data": populated,
    }))
}

#[derive(Deserialize)]
pub struct WarnUserBody {
    pub reason: Option<String>,
    pub severity: Option<String>,
}

pub async fn warn_user(req: HttpRequest, body: web::Json<WarnUserBody>) -> HttpResponse {
    let Ok(uid) = ObjectId::parse_str(param(&req, "userId")) else {
        return HttpResponse::NotFound().json(json!({ "error": "Użytkownik nie istnieje." }));
    };

    let reason = body
        .reason
        .as_ref()
        .map(|r| r.trim().to_string())
        .unwrap_or_default();
    if reason.is_empty() {
        return HttpResponse::BadRequest()
            .json(json!({ "error": "Powód ostrzeżenia jest wymagany." }));
    }
    if reason.chars().count() > WARNING_REASON_MAX_LENGTH {
        return HttpResponse::BadRequest().json(json!({
            "error": "Powód ostrzeżenia jest zbyt długi (maks. 1000 znaków)."
        }));
    }

    let severity = parse_severity(body.severity.as_deref());

    let db = get_db();
    if User::find_by_id(&db, uid).await.ok().flatten().is_none() {
        return HttpResponse::NotFound().json(json!({ "error": "Użytkownik nie istnieje." }));
    }

    let warning = match Warning::create(
        &db,
        CreateWarningInput {
            user_id: uid,
            reason: reason.clone(),
            severity: severity.clone(),
        },
    )
    .await
    {
        Ok(w) => w,
        Err(e) => {
            log::error!("warn_user create error: {e}");
            return HttpResponse::InternalServerError()
                .json(json!({ "error": "Nie udało się wystawić ostrzeżenia." }));
        }
    };

    let total = Warning::count_for_user(&db, uid).await.unwrap_or(0);

    emit_to_user(
        &uid.to_hex(),
        "user:warned",
        json!({
            "warning": serialize_warning(&warning),
            "warningCount": total,
        }),
    );

    log_admin_action(
        &req,
        "user.warn",
        Some("user"),
        Some(&uid.to_hex()),
        json!({ "severity": severity_str(&severity), "reason": reason }),
    )
    .await;

    HttpResponse::Ok().json(json!({
        "message": "Ostrzeżenie zostało wystawione.",
        "warning": serialize_warning(&warning),
        "warningCount": total,
    }))
}

pub async fn list_user_warnings(req: HttpRequest) -> HttpResponse {
    let Ok(uid) = ObjectId::parse_str(param(&req, "userId")) else {
        return HttpResponse::NotFound().json(json!({ "error": "Użytkownik nie istnieje." }));
    };

    let db = get_db();
    let warnings = match Warning::list_for_user(&db, uid).await {
        Ok(w) => w,
        Err(_) => {
            return HttpResponse::InternalServerError()
                .json(json!({ "error": "Nie udało się pobrać ostrzeżeń." }));
        }
    };

    let unacknowledged = warnings.iter().filter(|w| !w.acknowledged).count();
    let items: Vec<Value> = warnings.iter().map(serialize_warning).collect();

    HttpResponse::Ok().json(json!({
        "warnings": items,
        "total": items.len(),
        "unacknowledged": unacknowledged,
    }))
}

pub async fn delete_user_warning(req: HttpRequest) -> HttpResponse {
    let Ok(uid) = ObjectId::parse_str(param(&req, "userId")) else {
        return HttpResponse::NotFound().json(json!({ "error": "Użytkownik nie istnieje." }));
    };
    let Ok(wid) = ObjectId::parse_str(param(&req, "warningId")) else {
        return HttpResponse::NotFound().json(json!({ "error": "Ostrzeżenie nie istnieje." }));
    };

    let db = get_db();
    match Warning::delete_one(&db, wid, uid).await {
        Ok(true) => {
            let total = Warning::count_for_user(&db, uid).await.unwrap_or(0);
            emit_to_user(
                &uid.to_hex(),
                "user:warning-revoked",
                json!({ "warningId": wid.to_hex(), "warningCount": total }),
            );
            log_admin_action(
                &req,
                "user.warning.delete",
                Some("user"),
                Some(&uid.to_hex()),
                json!({ "warningId": wid.to_hex() }),
            )
            .await;
            HttpResponse::Ok().json(json!({
                "message": "Ostrzeżenie zostało usunięte.",
                "warningCount": total,
            }))
        }
        Ok(false) => HttpResponse::NotFound().json(json!({ "error": "Ostrzeżenie nie istnieje." })),
        Err(_) => HttpResponse::InternalServerError()
            .json(json!({ "error": "Nie udało się usunąć ostrzeżenia." })),
    }
}
