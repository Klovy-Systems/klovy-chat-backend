use actix_web::{web, HttpRequest, HttpResponse};
use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, Bson, DateTime};
use serde::Deserialize;
use serde_json::json;

use crate::middlewares::auth_middleware::request_user_id;
use crate::model::friend_request_model::FriendRequest;
use crate::model::messages_model::Message;
use crate::model::user_model::User;
use crate::utils::db::get_db;
use crate::utils::friends::are_friends;
use crate::utils::messages::{
    access::cleanup_attachment_if_unreferenced,
    dm_only_or_clause,
};
use crate::utils::messages::escape_regex;
use crate::utils::listening::serialize::{effective_listening, listening_activity_json};
use crate::utils::user::badges::{populate_user_badges, BadgeVisibility};
use crate::utils::user::serialize_user::resolve_display_name;
use crate::utils::whitelist::is_whitelist_enabled;

const MIN_SEARCH_LENGTH: usize = 3;
const SEARCH_RESULT_LIMIT: i64 = 10;

fn normalize_text(s: &str) -> String {
    let mapped: String = s
        .chars()
        .map(|c| match c {
            'ą' | 'Ą' => 'a',
            'ć' | 'Ć' => 'c',
            'ę' | 'Ę' => 'e',
            'ł' | 'Ł' => 'l',
            'ń' | 'Ń' => 'n',
            'ó' | 'Ó' => 'o',
            'ś' | 'Ś' => 's',
            'ź' | 'Ź' | 'ż' | 'Ż' => 'z',
            other => other,
        })
        .collect();
    mapped.to_lowercase().split_whitespace().collect::<Vec<_>>().join(" ")
}

async fn search_users_by_term(
    db: &mongodb::Database,
    exclude: ObjectId,
    term: &str,
) -> Vec<User> {
    let escaped = escape_regex(term);
    let mut filter = doc! {
        "_id": { "$ne": exclude },
        "isActive": { "$ne": false },
        "isBlocked": { "$ne": true },
        "isBanned": { "$ne": true },
        "isDisabled": { "$ne": true },
        "deletionScheduledAt": { "$exists": false },
        "isBot": { "$ne": true },
        "$or": [
            { "username": { "$regex": format!("^{escaped}"), "$options": "i" } },
            { "displayName": { "$regex": format!("^{escaped}"), "$options": "i" } },
        ],
    };
    if is_whitelist_enabled() {
        filter.insert("isWhitelisted", true);
    }

    match User::collection(db)
        .find(filter)
        .limit(SEARCH_RESULT_LIMIT)
        .await
    {
        Ok(cursor) => cursor.try_collect().await.unwrap_or_default(),
        Err(e) => {
            log::error!("search_users_by_term: {e}");
            Vec::new()
        }
    }
}

#[derive(Deserialize)]
pub struct SearchBody {
    #[serde(rename = "searchTerm")]
    pub search_term: Option<String>,
}

pub async fn search_contacts(req: HttpRequest, body: web::Json<SearchBody>) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::InternalServerError().body("Internal Server Error.");
    };

    let Some(search_term) = body.search_term.clone() else {
        return HttpResponse::BadRequest().body("Search Term is required.");
    };

    let normalized = normalize_text(&search_term);
    if normalized.chars().count() < MIN_SEARCH_LENGTH {
        return HttpResponse::BadRequest().body(format!(
            "Search term must be at least {MIN_SEARCH_LENGTH} characters."
        ));
    }

    let db = get_db();
    let matches = search_users_by_term(&db, uid, &normalized).await;

    let mut results = Vec::with_capacity(matches.len());
    for c in &matches {
        let Some(candidate_id) = c.id.map(|o| o.to_hex()) else {
            continue;
        };
        if are_friends(&db, &user_id, &candidate_id).await {
            results.push(json!({
                "_id": candidate_id,
                "username": c.username,
                "displayName": resolve_display_name(c),
                "bio": c.bio,
                "image": c.image,
                "color": c.color,
            }));
        } else {
            results.push(json!({
                "_id": candidate_id,
                "username": c.username,
                "displayName": resolve_display_name(c),
                "color": c.color,
            }));
        }
    }

    HttpResponse::Ok().json(json!({ "contacts": results }))
}

async fn dm_last_message(
    db: &mongodb::Database,
    uid: ObjectId,
    fid: ObjectId,
) -> Option<(DateTime, String)> {
    let filter = doc! {
        "deleted": { "$ne": true },
        "$and": [
            { "$or": dm_only_or_clause() },
            { "$or": [
                { "sender": uid, "recipient": fid },
                { "recipient": uid, "sender": fid },
            ]},
        ],
    };
    let mut cursor = Message::collection(db)
        .find(filter)
        .sort(doc! { "timestamp": -1 })
        .limit(1)
        .await
        .ok()?;
    let msg = cursor.try_next().await.ok().flatten()?;
    Some((msg.timestamp, msg.content))
}

async fn dm_unread_count(db: &mongodb::Database, uid: ObjectId, fid: ObjectId) -> u64 {
    let filter = doc! {
        "recipient": uid,
        "sender": fid,
        "read": false,
        "deleted": { "$ne": true },
        "$or": dm_only_or_clause(),
    };
    Message::collection(db).count_documents(filter).await.unwrap_or(0)
}

pub async fn get_contacts_for_list(req: HttpRequest) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    if user_id.is_empty() {
        return HttpResponse::BadRequest().body("User ID is required.");
    }
    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::BadRequest().body("User ID is required.");
    };

    let db = get_db();

    let friendships: Vec<FriendRequest> = match FriendRequest::collection(&db)
        .find(doc! { "status": "accepted", "$or": [ { "from": uid }, { "to": uid } ] })
        .await
    {
        Ok(c) => c.try_collect().await.unwrap_or_default(),
        Err(_) => return HttpResponse::InternalServerError().body("Internal Server Error"),
    };

    let current_user = User::find_by_id(&db, uid).await.ok().flatten();
    let muted: Vec<String> = current_user
        .as_ref()
        .map(|u| u.muted_contacts.iter().map(|o| o.to_hex()).collect())
        .unwrap_or_default();
    let blocked: Vec<String> = current_user
        .as_ref()
        .map(|u| u.blocked_contacts.iter().map(|o| o.to_hex()).collect())
        .unwrap_or_default();

    let mut contacts = Vec::new();
    for f in &friendships {
        let other_id = if f.from == uid { f.to } else { f.from };
        let Ok(Some(friend)) = User::find_by_id(&db, other_id).await else {
            continue;
        };
        let fid = other_id;
        let fid_hex = fid.to_hex();

        let last = dm_last_message(&db, uid, fid).await;
        let unread = dm_unread_count(&db, uid, fid).await;

        let last_time_ms = last.as_ref().map(|(t, _)| t.timestamp_millis()).unwrap_or(0);
        let listening_activity = effective_listening(&friend).map(listening_activity_json);
        let badges = populate_user_badges(&db, &friend, BadgeVisibility::All).await;

        contacts.push((
            last_time_ms,
            json!({
                "_id": fid_hex,
                "username": friend.username,
                "displayName": resolve_display_name(&friend),
                "bio": friend.bio,
                "image": friend.image,
                "banner": friend.banner,
                "color": friend.color,
                "isOnline": friend.is_online,
                "lastSeen": friend.last_seen.as_ref().and_then(|d| d.try_to_rfc3339_string().ok()),
                "availabilityStatus": crate::utils::user::serialize_user::availability_status_str(&friend.availability_status),
                "listeningActivity": listening_activity,
                "badges": badges,
                "createdAt": friend.created_at.try_to_rfc3339_string().ok(),
                "lastMessageTime": last.as_ref().and_then(|(t, _)| t.try_to_rfc3339_string().ok()),
                "lastMessage": last.as_ref().map(|(_, c)| c.clone()),
                "unreadCount": unread,
                "isMuted": muted.contains(&fid_hex),
                "isBlockedByMe": blocked.contains(&fid_hex),
            }),
        ));
    }

    contacts.sort_by(|a, b| b.0.cmp(&a.0));
    let contacts: Vec<_> = contacts.into_iter().map(|(_, c)| c).collect();

    HttpResponse::Ok().json(json!({ "contacts": contacts }))
}

pub async fn toggle_contact_mute(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "message": "Brak autoryzacji" }));
    };
    let contact_id = req.match_info().get("contactId").unwrap_or("");
    let Ok(contact_oid) = ObjectId::parse_str(contact_id) else {
        return HttpResponse::BadRequest()
            .json(json!({ "message": "Nieprawidłowy identyfikator kontaktu" }));
    };

    let db = get_db();
    if !are_friends(&db, &user_id, contact_id).await {
        return HttpResponse::NotFound()
            .json(json!({ "message": "Kontakt nie znaleziony lub brak relacji znajomości" }));
    }

    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::NotFound().json(json!({ "message": "Użytkownik nie znaleziony" }));
    };
    let user = match User::find_by_id(&db, uid).await {
        Ok(Some(u)) => u,
        _ => return HttpResponse::NotFound().json(json!({ "message": "Użytkownik nie znaleziony" })),
    };

    let mut muted = user.muted_contacts.clone();
    let is_muted;
    if let Some(pos) = muted.iter().position(|o| *o == contact_oid) {
        muted.remove(pos);
        is_muted = false;
    } else {
        muted.push(contact_oid);
        is_muted = true;
    }

    let muted_bson = mongodb::bson::to_bson(&muted).unwrap_or(Bson::Array(vec![]));
    if User::set_fields(&db, uid, doc! { "mutedContacts": muted_bson }).await.is_err() {
        return HttpResponse::InternalServerError().json(json!({ "message": "Internal Server Error" }));
    }

    HttpResponse::Ok().json(json!({
        "isMuted": is_muted,
        "message": if is_muted { "Konwersacja wyciszona" } else { "Wyciszenie wyłączone" },
    }))
}

pub async fn get_blocked_contacts(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "message": "Brak autoryzacji" }));
    };
    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::BadRequest().json(json!({ "message": "Nieprawidłowy użytkownik" }));
    };

    let db = get_db();
    let user = match User::find_by_id(&db, uid).await {
        Ok(Some(u)) => u,
        _ => return HttpResponse::NotFound().json(json!({ "message": "Użytkownik nie znaleziony" })),
    };

    let mut blocked = Vec::new();
    for contact_oid in &user.blocked_contacts {
        let Ok(Some(friend)) = User::find_by_id(&db, *contact_oid).await else {
            continue;
        };
        let badges = populate_user_badges(&db, &friend, BadgeVisibility::All).await;
        blocked.push(json!({
            "_id": contact_oid.to_hex(),
            "username": friend.username,
            "displayName": resolve_display_name(&friend),
            "image": friend.image,
            "color": friend.color,
            "badges": badges,
        }));
    }

    HttpResponse::Ok().json(json!({ "contacts": blocked }))
}

pub async fn toggle_contact_block(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "message": "Brak autoryzacji" }));
    };
    let contact_id = req.match_info().get("contactId").unwrap_or("");
    let Ok(contact_oid) = ObjectId::parse_str(contact_id) else {
        return HttpResponse::BadRequest()
            .json(json!({ "message": "Nieprawidłowy identyfikator kontaktu" }));
    };

    let db = get_db();
    if !are_friends(&db, &user_id, contact_id).await {
        return HttpResponse::NotFound()
            .json(json!({ "message": "Kontakt nie znaleziony lub brak relacji znajomości" }));
    }

    let Ok(uid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::NotFound().json(json!({ "message": "Użytkownik nie znaleziony" }));
    };
    let user = match User::find_by_id(&db, uid).await {
        Ok(Some(u)) => u,
        _ => return HttpResponse::NotFound().json(json!({ "message": "Użytkownik nie znaleziony" })),
    };

    let mut blocked = user.blocked_contacts.clone();
    let is_blocked;
    if let Some(pos) = blocked.iter().position(|o| *o == contact_oid) {
        blocked.remove(pos);
        is_blocked = false;
    } else {
        blocked.push(contact_oid);
        is_blocked = true;
    }

    let blocked_bson = mongodb::bson::to_bson(&blocked).unwrap_or(Bson::Array(vec![]));
    if User::set_fields(&db, uid, doc! { "blockedContacts": blocked_bson }).await.is_err() {
        return HttpResponse::InternalServerError().json(json!({ "message": "Internal Server Error" }));
    }

    HttpResponse::Ok().json(json!({
        "isBlocked": is_blocked,
        "message": if is_blocked { "Użytkownik zablokowany" } else { "Użytkownik odblokowany" },
    }))
}

pub async fn delete_conversation(req: HttpRequest) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    let contact_id = req.match_info().get("contactId").unwrap_or("");

    if user_id.is_empty() || contact_id.is_empty() {
        return HttpResponse::BadRequest().json(json!({ "message": "Missing user or contact id" }));
    }

    let (Ok(uid), Ok(cid)) = (ObjectId::parse_str(&user_id), ObjectId::parse_str(contact_id)) else {
        return HttpResponse::BadRequest().json(json!({ "message": "Missing user or contact id" }));
    };

    let db = get_db();
    if !are_friends(&db, &user_id, contact_id).await {
        return HttpResponse::Forbidden()
            .json(json!({ "message": "You can only delete conversations with friends" }));
    }

    let messages: Vec<Message> = match Message::collection(&db)
        .find(doc! {
            "$or": [
                { "sender": uid, "recipient": cid },
                { "sender": cid, "recipient": uid },
            ],
            "deleted": { "$ne": true },
        })
        .await
    {
        Ok(cursor) => cursor.try_collect().await.unwrap_or_default(),
        Err(_) => vec![],
    };

    for msg in messages {
        if let Some(mid) = msg.id {
            let _ = Message::soft_delete(&db, mid).await;
            cleanup_attachment_if_unreferenced(&db, msg.file_url.as_deref()).await;
        }
    }

    HttpResponse::Ok().json(json!({ "message": "Conversation deleted" }))
}
