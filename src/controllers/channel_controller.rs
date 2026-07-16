use actix_multipart::form::{tempfile::TempFile, MultipartForm};
use actix_web::{web, HttpRequest, HttpResponse};
use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, DateTime};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::middlewares::auth_middleware::request_user_id;
use crate::utils::access::membership_gate::require_channel_access;
use crate::utils::image_reencode::{reencode_error_message, reencode_upload_to_webp};
use crate::utils::storage::{avatar_channel_key, avatar_key_owned_by_channel, storage};
use crate::utils::upload_limits::{file_bytes_within_limit, local_file_size, MAX_AVATAR_BYTES};
use crate::utils::validators::file_magic::validate_file_magic;
use crate::model::channel_model::{Channel, CreateChannelInput};
use crate::model::channel_report_model::{ChannelReport, CreateChannelReportInput};
use crate::model::messages_model::Message;
use crate::model::user_model::User;
use crate::utils::channel::{
    can_access_channel, channel_member_count, enrich_channel_unread, fetch_users_by_refs,
    get_channel_ban_mute_lists, is_channel_admin, is_channel_member, is_channel_muted_member,
    populate_channel_user, moderation,
};
use crate::ws::registry::{channel_recipient_ids, emit_to_user, emit_to_users};
use crate::utils::db::get_db;
use crate::utils::friends::are_friends;
use crate::utils::messages::serialize_messages_batch;
use crate::utils::user::serialize_user::resolve_display_name;

const REPORT_REASONS: &[&str] = &[
    "Spam lub reklamy",
    "Treści obraźliwe",
    "Nękanie lub bullying",
    "Nielegalne treści",
    "Podszywanie się",
    "Inne",
];

/// Domyślna i maksymalna liczba wiadomości zwracanych na jedną stronę historii kanału.
const DEFAULT_CHANNEL_MESSAGE_LIMIT: i64 = 30;
const MAX_CHANNEL_MESSAGE_LIMIT: i64 = 50;

fn param<'a>(req: &'a HttpRequest, name: &str) -> &'a str {
    req.match_info().get(name).unwrap_or("")
}

fn iso(dt: &DateTime) -> Option<String> {
    dt.try_to_rfc3339_string().ok()
}

async fn serialize_channel_for_client(db: &mongodb::Database, c: &Channel, viewer_id: ObjectId) -> Value {
    let (unread, last) = enrich_channel_unread(db, viewer_id, c).await;
    let admin = populate_channel_user(db, c.admin).await;
    let members = fetch_users_by_refs(db, &c.members).await;
    let ch_id = c.id.map(|o| o.to_hex()).unwrap_or_default();
    let is_muted = User::find_by_id(db, viewer_id)
        .await
        .ok()
        .flatten()
        .map(|u| u.muted_channels.iter().any(|id| Some(*id) == c.id))
        .unwrap_or(false);

    json!({
        "_id": ch_id,
        "name": c.name,
        "description": c.description,
        "image": c.image,
        "admin": admin,
        "members": members,
        "bannedMembers": moderation::active_moderation_user_ids(&c.banned_members),
        "mutedMembers": moderation::active_moderation_user_ids(&c.muted_members),
        "isMutedHere": is_channel_muted_member(c, Some(&viewer_id.to_hex())),
        "messages": c.messages.iter().map(|m| m.to_hex()).collect::<Vec<_>>(),
        "isPrivate": c.is_private,
        "rateLimitPerUser": c.rate_limit_per_user,
        "chatLocked": c.chat_locked,
        "createdAt": iso(&c.created_at),
        "updatedAt": iso(&c.updated_at),
        "unreadCount": unread,
        "lastMessage": last.as_ref().map(|(_, c)| c.clone()),
        "lastMessageTime": last.as_ref().and_then(|(t, _)| iso(t)),
        "isMuted": is_muted,
    })
}

#[derive(Deserialize)]
pub struct CreateChannelBody {
    pub name: Option<String>,
    pub members: Option<Vec<String>>,
}

pub async fn create_channel(req: HttpRequest, body: web::Json<CreateChannelBody>) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::BadRequest().json(json!({ "message": "Admin user not found." }));
    };

    let db = get_db();
    if User::find_by_id(&db, uid).await.ok().flatten().is_none() {
        return HttpResponse::BadRequest().json(json!({ "message": "Admin user not found." }));
    }

    let mut valid_member_ids: Vec<ObjectId> = Vec::new();
    if let Some(members) = body.members.as_ref().filter(|m| !m.is_empty()) {
        let oids: Vec<ObjectId> = members.iter().filter_map(|m| ObjectId::parse_str(m).ok()).collect();
        let found: Vec<User> = match User::collection(&db)
            .find(doc! { "_id": { "$in": &oids } })
            .await
        {
            Ok(c) => c.try_collect().await.unwrap_or_default(),
            Err(_) => return HttpResponse::InternalServerError().json(json!({ "message": "Internal Server Error" })),
        };
        if found.len() != members.len() {
            return HttpResponse::BadRequest()
                .json(json!({ "message": "Some members are not valid users." }));
        }
        valid_member_ids = found.into_iter().filter_map(|u| u.id).collect();

        // Zgoda: do kanału można dodać tylko znajomych twórcy (bez wymuszania
        // członkostwa obcym osobom).
        for member_oid in &valid_member_ids {
            let member_hex = member_oid.to_hex();
            if member_hex != user_id && !are_friends(&db, &user_id, &member_hex).await {
                return HttpResponse::Forbidden().json(json!({
                    "message": "Możesz dodawać do kanału tylko swoich znajomych."
                }));
            }
        }
    }

    let input = CreateChannelInput {
        name: body.name.clone().unwrap_or_default(),
        description: None,
        admin: uid,
        members: Some(valid_member_ids),
        is_private: None,
        image: None,
    };

    match Channel::create(&db, input).await {
        Ok(channel) => {
            let serialized = serialize_channel_for_client(&db, &channel, uid).await;
            if let Some(ch_id) = channel.id {
                let ch_hex = ch_id.to_hex();
                for member_id in &channel.members {
                    let mid = member_id.to_hex();
                    if mid != user_id {
                        emit_to_user(&mid, "channel-added", json!({ "channelId": ch_hex }));
                    }
                }
            }
            HttpResponse::Created().json(json!({ "channel": serialized }))
        }
        Err(_) => HttpResponse::InternalServerError().json(json!({ "message": "Internal Server Error" })),
    }
}

pub async fn get_user_channels(req: HttpRequest) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::InternalServerError().json(json!({ "message": "Internal Server Error" }));
    };

    let db = get_db();
    let channels: Vec<Channel> = match Channel::collection(&db)
        .find(doc! { "$or": [ { "admin": uid }, { "members": uid } ] })
        .sort(doc! { "updatedAt": -1 })
        .await
    {
        Ok(c) => c.try_collect().await.unwrap_or_default(),
        Err(_) => return HttpResponse::InternalServerError().json(json!({ "message": "Internal Server Error" })),
    };

    let muted: Vec<String> = User::find_by_id(&db, uid)
        .await
        .ok()
        .flatten()
        .map(|u| u.muted_channels.iter().map(|o| o.to_hex()).collect())
        .unwrap_or_default();

    let mut enriched: Vec<(i64, Value)> = Vec::new();
    for ch in &channels {
        let (unread, last) = enrich_channel_unread(&db, uid, ch).await;
        let admin = populate_channel_user(&db, ch.admin).await;
        let members = fetch_users_by_refs(&db, &ch.members).await;
        let ch_id = ch.id.map(|o| o.to_hex()).unwrap_or_default();
        let is_muted = muted.contains(&ch_id);

        let sort_key = last
            .as_ref()
            .map(|(t, _)| t.timestamp_millis())
            .unwrap_or_else(|| ch.updated_at.timestamp_millis());

        enriched.push((
            sort_key,
            json!({
                "_id": ch_id,
                "name": ch.name,
                "description": ch.description,
                "image": ch.image,
                "admin": admin,
                "members": members,
                "bannedMembers": moderation::active_moderation_user_ids(&ch.banned_members),
                "mutedMembers": moderation::active_moderation_user_ids(&ch.muted_members),
                "messages": ch.messages.iter().map(|m| m.to_hex()).collect::<Vec<_>>(),
                "isPrivate": ch.is_private,
                "createdAt": iso(&ch.created_at),
                "updatedAt": iso(&ch.updated_at),
                "unreadCount": unread,
                "lastMessage": last.as_ref().map(|(_, c)| c.clone()),
                "lastMessageTime": last.as_ref().and_then(|(t, _)| iso(t)),
                "isMuted": is_muted,
            }),
        ));
    }

    enriched.sort_by(|a, b| b.0.cmp(&a.0));
    let channels: Vec<Value> = enriched.into_iter().map(|(_, c)| c).collect();

    HttpResponse::Ok().json(json!({ "channels": channels }))
}

pub async fn get_channel_messages(req: HttpRequest) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let channel_id = param(&req, "channelId");

    let db = get_db();
    let channel = match require_channel_access(&db, channel_id, &user_id).await {
        Ok(channel) => channel,
        Err(reason) => {
            return HttpResponse::NotFound().json(json!({
                "message": reason.as_str(),
            }));
        }
    };

    let query = web::Query::<std::collections::HashMap<String, String>>::from_query(req.query_string())
        .map(|q| q.into_inner())
        .unwrap_or_default();
    let limit = query
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(DEFAULT_CHANNEL_MESSAGE_LIMIT)
        .clamp(1, MAX_CHANNEL_MESSAGE_LIMIT);

    let mut and_clauses = vec![
        doc! { "_id": { "$in": &channel.messages } },
        doc! { "deleted": { "$ne": true } },
    ];
    if let Some(before_id) = query.get("before").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        let Ok(before_oid) = ObjectId::parse_str(before_id) else {
            return HttpResponse::BadRequest().json(json!({ "message": "Invalid cursor" }));
        };
        and_clauses.push(doc! { "_id": { "$lt": before_oid } });
    }

    let mut messages: Vec<Message> = match Message::collection(&db)
        .find(doc! { "$and": and_clauses })
        .sort(doc! { "_id": -1 })
        .limit(limit + 1)
        .await
    {
        Ok(c) => c.try_collect().await.unwrap_or_default(),
        Err(e) => {
            log::error!("get_channel_messages: {e}");
            return HttpResponse::InternalServerError().json(json!({ "message": "Internal Server Error" }));
        }
    };

    let has_more = messages.len() as i64 > limit;
    if has_more {
        messages.truncate(limit as usize);
    }
    messages.reverse();

    let out = serialize_messages_batch(&db, &messages).await;
    HttpResponse::Ok().json(json!({ "messages": out, "hasMore": has_more }))
}

pub async fn get_channel_details(req: HttpRequest) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let Ok(cid) = ObjectId::parse_str(param(&req, "channelId")) else {
        return HttpResponse::NotFound().json(json!({ "message": "Kanał nie znaleziony lub brak dostępu" }));
    };

    let db = get_db();
    let channel = match Channel::find_by_id(&db, cid).await {
        Ok(Some(c)) if can_access_channel(&c, Some(&user_id)) => {
            moderation::maybe_prune_channel_moderation(&db, &c).await
        }
        _ => return HttpResponse::NotFound().json(json!({ "message": "Kanał nie znaleziony lub brak dostępu" })),
    };

    let muted: Vec<String> = User::find_by_id(&db, ObjectId::parse_str(&user_id).unwrap_or_default())
        .await
        .ok()
        .flatten()
        .map(|u| u.muted_channels.iter().map(|o| o.to_hex()).collect())
        .unwrap_or_default();
    let is_muted = muted.contains(&cid.to_hex());

    let admin = populate_channel_user(&db, channel.admin).await;
    let members = fetch_users_by_refs(&db, &channel.members).await;
    let (banned_members, muted_members) = get_channel_ban_mute_lists(&db, cid).await;

    HttpResponse::Ok().json(json!({
        "channel": {
            "_id": cid.to_hex(),
            "name": channel.name,
            "description": channel.description,
            "image": if channel.image.is_empty() { Value::Null } else { json!(channel.image) },
            "admin": admin,
            "members": members,
            "bannedMembers": banned_members,
            "mutedMembers": muted_members,
            "memberCount": channel_member_count(&channel),
            "isAdmin": is_channel_admin(&channel, Some(&user_id)),
            "isMuted": is_muted,
            "isMutedHere": is_channel_muted_member(&channel, Some(&user_id)),
            "rateLimitPerUser": channel.rate_limit_per_user,
            "chatLocked": channel.chat_locked,
        }
    }))
}

#[derive(Deserialize)]
pub struct RenameBody {
    pub name: Option<String>,
}

pub async fn rename_channel(req: HttpRequest, body: web::Json<RenameBody>) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let name = body.name.clone().unwrap_or_default();
    let trimmed = name.trim();
    if trimmed.chars().count() < 3 || trimmed.chars().count() > 50 {
        return HttpResponse::BadRequest()
            .json(json!({ "error": "Nazwa kanału musi mieć od 3 do 50 znaków" }));
    }

    let Ok(cid) = ObjectId::parse_str(param(&req, "channelId")) else {
        return HttpResponse::NotFound().json(json!({ "error": "Kanał nie istnieje" }));
    };

    let db = get_db();
    let channel = match Channel::find_by_id(&db, cid).await {
        Ok(Some(c)) => c,
        _ => return HttpResponse::NotFound().json(json!({ "error": "Kanał nie istnieje" })),
    };

    if channel.admin.to_hex() != user_id {
        return HttpResponse::Forbidden()
            .json(json!({ "error": "Tylko administrator może zmienić nazwę kanału" }));
    }

    let new_name = trimmed.to_string();
    let _ = Channel::collection(&db)
        .update_one(
            doc! { "_id": cid },
            doc! { "$set": { "name": &new_name, "updatedAt": DateTime::now() } },
        )
        .await;

    emit_to_users(
        &channel_recipient_ids(&channel),
        "channel-name-updated",
        json!({ "channelId": cid.to_hex(), "name": new_name }),
    );
    HttpResponse::Ok().json(json!({ "name": new_name }))
}

#[derive(Deserialize)]
pub struct SlowmodeBody {
    #[serde(rename = "rateLimitPerUser")]
    pub rate_limit_per_user: Option<u32>,
}

pub async fn update_channel_slowmode(
    req: HttpRequest,
    body: web::Json<SlowmodeBody>,
) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let rate_limit = body.rate_limit_per_user.unwrap_or(0);
    if rate_limit > 21_600 {
        return HttpResponse::BadRequest().json(json!({
            "error": "Slowmode nie może przekraczać 21600 sekund (6 godzin)."
        }));
    }

    let Ok(cid) = ObjectId::parse_str(param(&req, "channelId")) else {
        return HttpResponse::NotFound().json(json!({ "error": "Kanał nie istnieje" }));
    };

    let db = get_db();
    let channel = match Channel::find_by_id(&db, cid).await {
        Ok(Some(c)) => c,
        _ => return HttpResponse::NotFound().json(json!({ "error": "Kanał nie istnieje" })),
    };

    if channel.admin.to_hex() != user_id {
        return HttpResponse::Forbidden().json(json!({
            "error": "Tylko administrator może zmienić slowmode kanału."
        }));
    }

    let _ = Channel::collection(&db)
        .update_one(
            doc! { "_id": cid },
            doc! {
                "$set": {
                    "rateLimitPerUser": rate_limit,
                    "updatedAt": DateTime::now(),
                }
            },
        )
        .await;

    emit_to_users(
        &channel_recipient_ids(&channel),
        "channel-slowmode-updated",
        json!({ "channelId": cid.to_hex(), "rateLimitPerUser": rate_limit }),
    );

    HttpResponse::Ok().json(json!({ "rateLimitPerUser": rate_limit }))
}

#[derive(Deserialize)]
pub struct ChatLockBody {
    #[serde(rename = "chatLocked")]
    pub chat_locked: Option<bool>,
}

pub async fn update_channel_chat_lock(
    req: HttpRequest,
    body: web::Json<ChatLockBody>,
) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let chat_locked = body.chat_locked.unwrap_or(false);

    let Ok(cid) = ObjectId::parse_str(param(&req, "channelId")) else {
        return HttpResponse::NotFound().json(json!({ "error": "Kanał nie istnieje" }));
    };

    let db = get_db();
    let channel = match Channel::find_by_id(&db, cid).await {
        Ok(Some(c)) => c,
        _ => return HttpResponse::NotFound().json(json!({ "error": "Kanał nie istnieje" })),
    };

    if channel.admin.to_hex() != user_id {
        return HttpResponse::Forbidden().json(json!({
            "error": "Tylko administrator może zablokować lub odblokować czat kanału."
        }));
    }

    let _ = Channel::collection(&db)
        .update_one(
            doc! { "_id": cid },
            doc! {
                "$set": {
                    "chatLocked": chat_locked,
                    "updatedAt": DateTime::now(),
                }
            },
        )
        .await;

    emit_to_users(
        &channel_recipient_ids(&channel),
        "channel-chat-locked-updated",
        json!({ "channelId": cid.to_hex(), "chatLocked": chat_locked }),
    );

    HttpResponse::Ok().json(json!({ "chatLocked": chat_locked }))
}

pub async fn delete_channel_avatar(req: HttpRequest) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let Ok(cid) = ObjectId::parse_str(param(&req, "channelId")) else {
        return HttpResponse::NotFound().json(json!({ "message": "Channel not found" }));
    };

    let db = get_db();
    let channel = match Channel::find_by_id(&db, cid).await {
        Ok(Some(c)) => c,
        _ => return HttpResponse::NotFound().json(json!({ "message": "Channel not found" })),
    };

    if channel.admin.to_hex() != user_id {
        return HttpResponse::Forbidden()
            .json(json!({ "message": "Only admin can delete channel avatar" }));
    }

    if !channel.image.is_empty() {
        let channel_id = cid.to_hex();
        if avatar_key_owned_by_channel(&channel.image, &channel_id) {
            let _ = storage().delete_avatar_key(&channel.image).await;
        }
        let _ = Channel::collection(&db)
            .update_one(
                doc! { "_id": cid },
                doc! { "$set": { "image": "", "updatedAt": DateTime::now() } },
            )
            .await;
        emit_to_users(
            &channel_recipient_ids(&channel),
            "channel-avatar-updated",
            json!({ "channelId": channel_id, "image": "" }),
        );
    }

    HttpResponse::Ok().json(json!({ "message": "Channel avatar deleted" }))
}

#[derive(MultipartForm)]
pub struct ChannelAvatarForm {
    #[multipart(rename = "avatar", limit = "5 MiB")]
    pub file: TempFile,
}

pub async fn upload_channel_avatar(
    req: HttpRequest,
    form: MultipartForm<ChannelAvatarForm>,
) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let Ok(cid) = ObjectId::parse_str(param(&req, "channelId")) else {
        return HttpResponse::NotFound().json(json!({ "message": "Channel not found" }));
    };

    let db = get_db();
    let channel = match Channel::find_by_id(&db, cid).await {
        Ok(Some(c)) => c,
        _ => return HttpResponse::NotFound().json(json!({ "message": "Channel not found" })),
    };

    if channel.admin.to_hex() != user_id {
        return HttpResponse::Forbidden()
            .json(json!({ "message": "Only admin can change channel avatar" }));
    }

    let ext = form
        .file
        .file_name
        .as_deref()
        .and_then(|n| n.rsplit('.').next())
        .map(|e| e.to_lowercase())
        .filter(|e| ["jpg", "jpeg", "png", "webp"].contains(&e.as_str()))
        .unwrap_or_else(|| "png".to_string());

    if !validate_file_magic(form.file.file.path(), &ext) {
        return HttpResponse::BadRequest().json(json!({ "message": "Invalid file content" }));
    }
    if local_file_size(form.file.file.path())
        .map(|size| !file_bytes_within_limit(size, MAX_AVATAR_BYTES))
        .unwrap_or(true)
    {
        return HttpResponse::PayloadTooLarge()
            .json(json!({ "message": "File too large. Maximum size is 5 MB." }));
    }

    let previous_image = channel.image.clone();
    let channel_id = cid.to_hex();
    let key = avatar_channel_key(&channel_id);
    let webp = match reencode_upload_to_webp(form.file.file.path()) {
        Ok(bytes) => bytes,
        Err(err) => {
            return HttpResponse::BadRequest().json(json!({
                "message": reencode_error_message(&err),
            }));
        }
    };
    if storage()
        .put_public(&key, webp, "image/webp")
        .await
        .is_err()
    {
        return HttpResponse::InternalServerError().json(json!({ "message": "Internal Server Error" }));
    }

    let _ = Channel::collection(&db)
        .update_one(
            doc! { "_id": cid },
            doc! { "$set": { "image": &key, "updatedAt": DateTime::now() } },
        )
        .await;

    if !previous_image.is_empty()
        && previous_image != key
        && avatar_key_owned_by_channel(&previous_image, &channel_id)
    {
        let _ = storage().delete_avatar_key(&previous_image).await;
    }

    emit_to_users(
        &channel_recipient_ids(&channel),
        "channel-avatar-updated",
        json!({ "channelId": channel_id, "image": key }),
    );
    HttpResponse::Ok().json(json!({ "message": "Avatar updated", "image": key }))
}

pub async fn leave_channel(req: HttpRequest) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let Ok(cid) = ObjectId::parse_str(param(&req, "channelId")) else {
        return HttpResponse::NotFound().json(json!({ "message": "Channel not found" }));
    };

    let db = get_db();
    let channel = match Channel::find_by_id(&db, cid).await {
        Ok(Some(c)) => c,
        _ => return HttpResponse::NotFound().json(json!({ "message": "Channel not found" })),
    };

    if channel.admin.to_hex() == user_id {
        return HttpResponse::Forbidden()
            .json(json!({ "message": "Admin cannot leave channel. Delete instead." }));
    }

    if let Ok(uid) = ObjectId::parse_str(&user_id) {
        let _ = Channel::collection(&db)
            .update_one(
                doc! { "_id": cid },
                doc! { "$pull": { "members": uid }, "$set": { "updatedAt": DateTime::now() } },
            )
            .await;
    }

    emit_to_user(
        &user_id,
        "channel-left",
        json!({ "channelId": cid.to_hex() }),
    );
    HttpResponse::Ok().json(json!({ "message": "Left channel" }))
}

#[derive(Deserialize)]
pub struct AddUserBody {
    #[serde(rename = "userIdToAdd")]
    pub user_id_to_add: Option<String>,
}

pub async fn add_user_to_channel(req: HttpRequest, body: web::Json<AddUserBody>) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let Ok(cid) = ObjectId::parse_str(param(&req, "channelId")) else {
        return HttpResponse::NotFound().json(json!({ "message": "Channel not found" }));
    };
    let target = body.user_id_to_add.clone().unwrap_or_default();

    let db = get_db();
    let channel = match Channel::find_by_id(&db, cid).await {
        Ok(Some(c)) => c,
        _ => return HttpResponse::NotFound().json(json!({ "message": "Channel not found" })),
    };

    if channel.admin.to_hex() != user_id {
        return HttpResponse::Forbidden().json(json!({ "message": "Only admin can add users" }));
    }

    if channel.members.iter().any(|m| m.to_hex() == target) {
        return HttpResponse::BadRequest().json(json!({ "message": "User is already a member" }));
    }

    if crate::utils::channel::is_channel_banned(&channel, Some(&target)) {
        return HttpResponse::Forbidden().json(json!({
            "message": "User is banned from this channel. Unban them before adding again."
        }));
    }

    // Zgoda: administrator może dodać do kanału tylko swoich znajomych.
    if target != user_id && !are_friends(&db, &user_id, &target).await {
        return HttpResponse::Forbidden().json(json!({
            "message": "Możesz dodawać do kanału tylko swoich znajomych."
        }));
    }

    let Ok(target_oid) = ObjectId::parse_str(&target) else {
        return HttpResponse::InternalServerError().json(json!({ "message": "Internal Server Error" }));
    };
    let _ = Channel::collection(&db)
        .update_one(
            doc! { "_id": cid },
            doc! { "$addToSet": { "members": target_oid }, "$set": { "updatedAt": DateTime::now() } },
        )
        .await;

    emit_to_user(
        &target,
        "channel-added",
        json!({ "channelId": cid.to_hex() }),
    );
    HttpResponse::Ok().json(json!({ "message": "User added to channel" }))
}

fn serialize_bot_ref(bot: &User) -> Value {
    json!({
        "_id": bot.id.map(|o| o.to_hex()),
        "username": bot.username,
        "displayName": resolve_display_name(bot),
        "color": bot.color,
        "image": bot.image,
        "isBot": true,
    })
}

/// Boty należące do admina kanału, których nie ma jeszcze w kanale.
pub async fn get_installable_bots(req: HttpRequest) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let Ok(cid) = ObjectId::parse_str(param(&req, "channelId")) else {
        return HttpResponse::NotFound().json(json!({ "message": "Channel not found" }));
    };
    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::Unauthorized().json(json!({ "message": "Unauthorized" }));
    };

    let db = get_db();
    let channel = match Channel::find_by_id(&db, cid).await {
        Ok(Some(c)) => c,
        _ => return HttpResponse::NotFound().json(json!({ "message": "Channel not found" })),
    };

    if channel.admin != uid {
        return HttpResponse::Forbidden().json(json!({ "message": "Tylko administrator kanału może zarządzać botami." }));
    }

    let bots = match User::find_bots_by_owner(&db, uid).await {
        Ok(b) => b,
        Err(_) => return HttpResponse::InternalServerError().json(json!({ "message": "Internal Server Error" })),
    };

    let installable: Vec<Value> = bots
        .iter()
        .filter(|b| b.id.map(|id| !channel.members.contains(&id)).unwrap_or(false))
        .map(serialize_bot_ref)
        .collect();

    HttpResponse::Ok().json(json!({ "bots": installable }))
}

#[derive(Deserialize)]
pub struct AddBotBody {
    #[serde(rename = "botId")]
    pub bot_id: Option<String>,
}

pub async fn add_bot_to_channel(req: HttpRequest, body: web::Json<AddBotBody>) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let Ok(cid) = ObjectId::parse_str(param(&req, "channelId")) else {
        return HttpResponse::NotFound().json(json!({ "message": "Channel not found" }));
    };
    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::Unauthorized().json(json!({ "message": "Unauthorized" }));
    };
    let Ok(bot_oid) = ObjectId::parse_str(&body.bot_id.clone().unwrap_or_default()) else {
        return HttpResponse::BadRequest().json(json!({ "message": "Nieprawidłowy identyfikator bota." }));
    };

    let db = get_db();
    let channel = match Channel::find_by_id(&db, cid).await {
        Ok(Some(c)) => c,
        _ => return HttpResponse::NotFound().json(json!({ "message": "Channel not found" })),
    };

    if channel.admin != uid {
        return HttpResponse::Forbidden().json(json!({ "message": "Tylko administrator kanału może dodawać boty." }));
    }

    let bot = match User::find_bot(&db, bot_oid).await {
        Ok(Some(b)) if b.owner_id == Some(uid) => b,
        Ok(_) => return HttpResponse::Forbidden().json(json!({ "message": "Możesz dodać tylko własnego bota." })),
        Err(_) => return HttpResponse::InternalServerError().json(json!({ "message": "Internal Server Error" })),
    };

    if channel.members.contains(&bot_oid) {
        return HttpResponse::BadRequest().json(json!({ "message": "Bot jest już w tym kanale." }));
    }

    let _ = Channel::collection(&db)
        .update_one(
            doc! { "_id": cid },
            doc! { "$addToSet": { "members": bot_oid }, "$set": { "updatedAt": DateTime::now() } },
        )
        .await;

    HttpResponse::Ok().json(json!({ "message": "Bot dodany do kanału.", "bot": serialize_bot_ref(&bot) }))
}

pub async fn remove_bot_from_channel(req: HttpRequest) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let Ok(cid) = ObjectId::parse_str(param(&req, "channelId")) else {
        return HttpResponse::NotFound().json(json!({ "message": "Channel not found" }));
    };
    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::Unauthorized().json(json!({ "message": "Unauthorized" }));
    };
    let Ok(bot_oid) = ObjectId::parse_str(param(&req, "botId")) else {
        return HttpResponse::BadRequest().json(json!({ "message": "Nieprawidłowy identyfikator bota." }));
    };

    let db = get_db();
    let channel = match Channel::find_by_id(&db, cid).await {
        Ok(Some(c)) => c,
        _ => return HttpResponse::NotFound().json(json!({ "message": "Channel not found" })),
    };

    if channel.admin != uid {
        return HttpResponse::Forbidden().json(json!({ "message": "Tylko administrator kanału może usuwać boty." }));
    }

    let _ = Channel::collection(&db)
        .update_one(
            doc! { "_id": cid },
            doc! { "$pull": { "members": bot_oid }, "$set": { "updatedAt": DateTime::now() } },
        )
        .await;

    HttpResponse::Ok().json(json!({ "message": "Bot usunięty z kanału." }))
}

pub async fn delete_channel(req: HttpRequest) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let Ok(cid) = ObjectId::parse_str(param(&req, "channelId")) else {
        return HttpResponse::NotFound().json(json!({ "message": "Channel not found" }));
    };

    let db = get_db();
    let channel = match Channel::find_by_id(&db, cid).await {
        Ok(Some(c)) => c,
        _ => return HttpResponse::NotFound().json(json!({ "message": "Channel not found" })),
    };

    if channel.admin.to_hex() != user_id {
        return HttpResponse::Forbidden().json(json!({ "message": "Only admin can delete channel" }));
    }

    let channel_id = cid.to_hex();
    let recipients = channel_recipient_ids(&channel);
    let _ = Channel::collection(&db).delete_one(doc! { "_id": cid }).await;

    emit_to_users(
        &recipients,
        "channel-deleted",
        json!({ "channelId": channel_id }),
    );
    HttpResponse::Ok().json(json!({ "message": "Channel deleted" }))
}

pub async fn toggle_channel_mute(req: HttpRequest) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let Ok(cid) = ObjectId::parse_str(param(&req, "channelId")) else {
        return HttpResponse::NotFound().json(json!({ "message": "Kanał nie znaleziony lub brak dostępu" }));
    };

    let db = get_db();
    match Channel::find_by_id(&db, cid).await {
        Ok(Some(c)) if can_access_channel(&c, Some(&user_id)) => {}
        _ => return HttpResponse::NotFound().json(json!({ "message": "Kanał nie znaleziony lub brak dostępu" })),
    };

    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::NotFound().json(json!({ "message": "Użytkownik nie znaleziony" }));
    };
    let user = match User::find_by_id(&db, uid).await {
        Ok(Some(u)) => u,
        _ => return HttpResponse::NotFound().json(json!({ "message": "Użytkownik nie znaleziony" })),
    };

    let mut muted = user.muted_channels.clone();
    let is_muted;
    if let Some(pos) = muted.iter().position(|o| *o == cid) {
        muted.remove(pos);
        is_muted = false;
    } else {
        muted.push(cid);
        is_muted = true;
    }

    let muted_bson = mongodb::bson::to_bson(&muted).unwrap_or(mongodb::bson::Bson::Array(vec![]));
    if User::set_fields(&db, uid, doc! { "mutedChannels": muted_bson }).await.is_err() {
        return HttpResponse::InternalServerError().json(json!({ "message": "Internal Server Error" }));
    }

    HttpResponse::Ok().json(json!({
        "isMuted": is_muted,
        "message": if is_muted { "Kanał wyciszony" } else { "Wyciszenie wyłączone" },
    }))
}

#[derive(Deserialize)]
pub struct TargetUserBody {
    #[serde(rename = "userId")]
    pub user_id: Option<String>,
    /// 0 or omitted = permanent. Otherwise duration in seconds.
    #[serde(rename = "durationSeconds")]
    pub duration_seconds: Option<u64>,
}

pub async fn kick_channel_member(req: HttpRequest, body: web::Json<TargetUserBody>) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let target = body.user_id.clone().unwrap_or_default();
    if target.is_empty() {
        return HttpResponse::BadRequest().json(json!({ "message": "Brak identyfikatora użytkownika" }));
    }
    let Ok(cid) = ObjectId::parse_str(param(&req, "channelId")) else {
        return HttpResponse::NotFound().json(json!({ "message": "Kanał nie znaleziony" }));
    };

    let db = get_db();
    let channel = match Channel::find_by_id(&db, cid).await {
        Ok(Some(c)) => c,
        _ => return HttpResponse::NotFound().json(json!({ "message": "Kanał nie znaleziony" })),
    };

    if !is_channel_admin(&channel, Some(&user_id)) {
        return HttpResponse::Forbidden().json(json!({ "message": "Tylko twórca kanału może wyrzucać członków" }));
    }
    if channel.admin.to_hex() == target {
        return HttpResponse::BadRequest().json(json!({ "message": "Nie można wyrzucić twórcy kanału" }));
    }

    if let Ok(target_oid) = ObjectId::parse_str(&target) {
        let muted_members = moderation::prepare_unmute_lists(&channel, target_oid);
        let banned_members = moderation::active_entries(&channel.banned_members);
        let members: Vec<ObjectId> = channel
            .members
            .iter()
            .copied()
            .filter(|member| *member != target_oid)
            .collect();
        let members_bson =
            mongodb::bson::to_bson(&members).unwrap_or(mongodb::bson::Bson::Array(vec![]));
        let _ = Channel::collection(&db)
            .update_one(
                doc! { "_id": cid },
                doc! {
                    "$set": {
                        "members": members_bson,
                        "updatedAt": DateTime::now(),
                    }
                },
            )
            .await;
        let _ = moderation::persist_moderation_lists(&db, cid, banned_members, muted_members).await;
    }

    emit_to_user(
        &target,
        "channel-left",
        json!({ "channelId": cid.to_hex() }),
    );
    HttpResponse::Ok().json(json!({ "message": "Użytkownik wyrzucony z kanału" }))
}

pub async fn ban_channel_member(req: HttpRequest, body: web::Json<TargetUserBody>) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let target = body.user_id.clone().unwrap_or_default();
    if target.is_empty() {
        return HttpResponse::BadRequest().json(json!({ "message": "Brak identyfikatora użytkownika" }));
    }
    let Ok(target_oid) = ObjectId::parse_str(&target) else {
        return HttpResponse::BadRequest().json(json!({ "message": "Nieprawidłowy identyfikator użytkownika" }));
    };
    let Ok(cid) = ObjectId::parse_str(param(&req, "channelId")) else {
        return HttpResponse::NotFound().json(json!({ "message": "Kanał nie znaleziony" }));
    };

    let db = get_db();
    let channel = match Channel::find_by_id(&db, cid).await {
        Ok(Some(c)) => c,
        _ => return HttpResponse::NotFound().json(json!({ "message": "Kanał nie znaleziony" })),
    };

    if !is_channel_admin(&channel, Some(&user_id)) {
        return HttpResponse::Forbidden().json(json!({ "message": "Tylko twórca kanału może banować" }));
    }
    if channel.admin.to_hex() == target {
        return HttpResponse::BadRequest().json(json!({ "message": "Nie można zbanować twórcy kanału" }));
    }

    let (banned_members, muted_members, members) =
        moderation::prepare_ban_lists(&channel, target_oid, body.duration_seconds);

    let banned_bson = mongodb::bson::to_bson(&banned_members).unwrap_or(mongodb::bson::Bson::Array(vec![]));
    let muted_bson = mongodb::bson::to_bson(&muted_members).unwrap_or(mongodb::bson::Bson::Array(vec![]));
    let members_bson = mongodb::bson::to_bson(&members).unwrap_or(mongodb::bson::Bson::Array(vec![]));

    let _ = Channel::collection(&db)
        .update_one(
            doc! { "_id": cid },
            doc! {
                "$set": {
                    "bannedMembers": banned_bson,
                    "mutedMembers": muted_bson,
                    "members": members_bson,
                    "updatedAt": DateTime::now(),
                }
            },
        )
        .await;

    emit_to_user(
        &target,
        "channel-left",
        json!({ "channelId": cid.to_hex() }),
    );
    let (banned_members, muted_members) = get_channel_ban_mute_lists(&db, cid).await;
    HttpResponse::Ok().json(json!({
        "message": "Użytkownik zbanowany na kanale",
        "bannedMembers": banned_members,
        "mutedMembers": muted_members,
    }))
}

pub async fn unban_channel_member(req: HttpRequest, body: web::Json<TargetUserBody>) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let target = body.user_id.clone().unwrap_or_default();
    if target.is_empty() {
        return HttpResponse::BadRequest().json(json!({ "message": "Brak identyfikatora użytkownika" }));
    }
    let Ok(target_oid) = ObjectId::parse_str(&target) else {
        return HttpResponse::BadRequest().json(json!({ "message": "Nieprawidłowy identyfikator użytkownika" }));
    };
    let Ok(cid) = ObjectId::parse_str(param(&req, "channelId")) else {
        return HttpResponse::NotFound().json(json!({ "message": "Kanał nie znaleziony" }));
    };

    let db = get_db();
    let channel = match Channel::find_by_id(&db, cid).await {
        Ok(Some(c)) => c,
        _ => return HttpResponse::NotFound().json(json!({ "message": "Kanał nie znaleziony" })),
    };

    if !is_channel_admin(&channel, Some(&user_id)) {
        return HttpResponse::Forbidden().json(json!({ "message": "Tylko twórca kanału może odbanować" }));
    }

    let banned_members = moderation::prepare_unban_lists(&channel, target_oid);
    let muted_members = moderation::active_entries(&channel.muted_members);
    let _ = moderation::persist_moderation_lists(&db, cid, banned_members, muted_members).await;

    let (banned_members, muted_members) = get_channel_ban_mute_lists(&db, cid).await;
    HttpResponse::Ok().json(json!({
        "message": "Ban użytkownika cofnięty",
        "bannedMembers": banned_members,
        "mutedMembers": muted_members,
    }))
}

pub async fn mute_channel_member(req: HttpRequest, body: web::Json<TargetUserBody>) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let target = body.user_id.clone().unwrap_or_default();
    if target.is_empty() {
        return HttpResponse::BadRequest().json(json!({ "message": "Brak identyfikatora użytkownika" }));
    }
    let Ok(target_oid) = ObjectId::parse_str(&target) else {
        return HttpResponse::BadRequest().json(json!({ "message": "Nieprawidłowy identyfikator użytkownika" }));
    };
    let Ok(cid) = ObjectId::parse_str(param(&req, "channelId")) else {
        return HttpResponse::NotFound().json(json!({ "message": "Kanał nie znaleziony" }));
    };

    let db = get_db();
    let channel = match Channel::find_by_id(&db, cid).await {
        Ok(Some(c)) => c,
        _ => return HttpResponse::NotFound().json(json!({ "message": "Kanał nie znaleziony" })),
    };

    if !is_channel_admin(&channel, Some(&user_id)) {
        return HttpResponse::Forbidden().json(json!({ "message": "Tylko twórca kanału może wyciszać członków" }));
    }
    if channel.admin.to_hex() == target {
        return HttpResponse::BadRequest().json(json!({ "message": "Nie można wyciszyć twórcy kanału" }));
    }
    if !is_channel_member(&channel, Some(&target)) {
        return HttpResponse::BadRequest().json(json!({ "message": "Użytkownik nie jest na kanale" }));
    }

    let (muted_members, banned_members) =
        moderation::prepare_mute_lists(&channel, target_oid, body.duration_seconds);
    let _ = moderation::persist_moderation_lists(&db, cid, banned_members, muted_members).await;

    emit_to_user(
        &target,
        "channel-moderation-updated",
        json!({
            "channelId": cid.to_hex(),
            "isMutedHere": true,
        }),
    );

    let (banned_members, muted_members) = get_channel_ban_mute_lists(&db, cid).await;
    HttpResponse::Ok().json(json!({
        "message": "Użytkownik wyciszony na kanale",
        "bannedMembers": banned_members,
        "mutedMembers": muted_members,
    }))
}

pub async fn unmute_channel_member(req: HttpRequest, body: web::Json<TargetUserBody>) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let target = body.user_id.clone().unwrap_or_default();
    if target.is_empty() {
        return HttpResponse::BadRequest().json(json!({ "message": "Brak identyfikatora użytkownika" }));
    }
    let Ok(target_oid) = ObjectId::parse_str(&target) else {
        return HttpResponse::BadRequest().json(json!({ "message": "Nieprawidłowy identyfikator użytkownika" }));
    };
    let Ok(cid) = ObjectId::parse_str(param(&req, "channelId")) else {
        return HttpResponse::NotFound().json(json!({ "message": "Kanał nie znaleziony" }));
    };

    let db = get_db();
    let channel = match Channel::find_by_id(&db, cid).await {
        Ok(Some(c)) => c,
        _ => return HttpResponse::NotFound().json(json!({ "message": "Kanał nie znaleziony" })),
    };

    if !is_channel_admin(&channel, Some(&user_id)) {
        return HttpResponse::Forbidden().json(json!({ "message": "Tylko twórca kanału może cofnąć wyciszenie" }));
    }

    let muted_members = moderation::prepare_unmute_lists(&channel, target_oid);
    let banned_members = moderation::active_entries(&channel.banned_members);
    let _ = moderation::persist_moderation_lists(&db, cid, banned_members, muted_members).await;

    emit_to_user(
        &target,
        "channel-moderation-updated",
        json!({
            "channelId": cid.to_hex(),
            "isMutedHere": false,
        }),
    );

    let (banned_members, muted_members) = get_channel_ban_mute_lists(&db, cid).await;
    HttpResponse::Ok().json(json!({
        "message": "Wyciszenie użytkownika cofnięte",
        "bannedMembers": banned_members,
        "mutedMembers": muted_members,
    }))
}

#[derive(Deserialize)]
pub struct ReportBody {
    pub reason: Option<String>,
    pub details: Option<String>,
}

pub async fn report_channel(req: HttpRequest, body: web::Json<ReportBody>) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let reason = body.reason.clone().unwrap_or_default();
    let reason_trimmed = reason.trim();
    if reason_trimmed.is_empty() {
        return HttpResponse::BadRequest().json(json!({ "message": "Podaj powód zgłoszenia" }));
    }
    if !REPORT_REASONS.contains(&reason_trimmed) {
        return HttpResponse::BadRequest().json(json!({
            "message": "Nieprawidłowy powód zgłoszenia",
            "reasons": REPORT_REASONS,
        }));
    }
    let details = body
        .details
        .as_deref()
        .unwrap_or("")
        .trim()
        .chars()
        .take(1000)
        .collect::<String>();
    let Ok(cid) = ObjectId::parse_str(param(&req, "channelId")) else {
        return HttpResponse::NotFound().json(json!({ "message": "Kanał nie znaleziony" }));
    };

    let db = get_db();
    let channel = match Channel::find_by_id(&db, cid).await {
        Ok(Some(c)) => c,
        _ => return HttpResponse::NotFound().json(json!({ "message": "Kanał nie znaleziony" })),
    };

    if !is_channel_member(&channel, Some(&user_id)) {
        return HttpResponse::Forbidden().json(json!({ "message": "Musisz być na kanale, aby go zgłosić" }));
    }

    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::NotFound().json(json!({ "message": "Użytkownik nie znaleziony" }));
    };
    let reporter = match User::find_by_id(&db, uid).await {
        Ok(Some(u)) => u,
        _ => return HttpResponse::NotFound().json(json!({ "message": "Użytkownik nie znaleziony" })),
    };

    let input = CreateChannelReportInput {
        channel_id: cid,
        channel_name: channel.name.clone(),
        reported_by: uid,
        reporter_username: reporter.username.clone(),
        reason: reason_trimmed.to_string(),
        details: if details.is_empty() { None } else { Some(details) },
    };

    match ChannelReport::create(&db, input).await {
        Ok(_) => HttpResponse::Created().json(json!({
            "message": "Zgłoszenie zostało wysłane do panelu administratora",
            "reasons": REPORT_REASONS,
        })),
        Err(_) => HttpResponse::InternalServerError().json(json!({ "message": "Internal Server Error" })),
    }
}
