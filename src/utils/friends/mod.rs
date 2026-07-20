use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId};
use mongodb::Database;
use serde_json::{json, Value};

use crate::model::friend_request_model::FriendRequest;
use crate::model::user_model::User;
use crate::utils::user::serialize_user::resolve_display_name;

pub async fn are_friends(db: &Database, user_id1: &str, user_id2: &str) -> bool {
    if user_id1.is_empty() || user_id2.is_empty() || user_id1 == user_id2 {
        return false;
    }
    let (Ok(u1), Ok(u2)) = (ObjectId::parse_str(user_id1), ObjectId::parse_str(user_id2)) else {
        return false;
    };

    let filter = doc! {
        "status": "accepted",
        "$or": [
            { "from": u1, "to": u2 },
            { "from": u2, "to": u1 },
        ],
    };

    matches!(
        FriendRequest::collection(db).find_one(filter).await,
        Ok(Some(_))
    )
}

pub async fn is_dm_blocked(db: &Database, user_id1: &str, user_id2: &str) -> bool {
    if user_id1.is_empty() || user_id2.is_empty() || user_id1 == user_id2 {
        return false;
    }
    let (Ok(u1), Ok(u2)) = (ObjectId::parse_str(user_id1), ObjectId::parse_str(user_id2)) else {
        return false;
    };

    let user_blocks_other = |user: &User, other: ObjectId| {
        user.blocked_contacts.iter().any(|id| *id == other)
    };

    let Ok(Some(a)) = User::find_by_id(db, u1).await else {
        return false;
    };
    let Ok(Some(b)) = User::find_by_id(db, u2).await else {
        return false;
    };

    user_blocks_other(&a, u2) || user_blocks_other(&b, u1)
}

/// Zwraca listę identyfikatorów (hex) zaakceptowanych znajomych użytkownika.
/// Używane do rozgłaszania zdarzeń obecności/profilu tylko do znajomych,
/// zamiast do wszystkich zalogowanych klientów.
pub async fn friend_ids(db: &Database, user_id: &str) -> Vec<String> {
    let Ok(uid) = ObjectId::parse_str(user_id) else {
        return Vec::new();
    };

    let filter = doc! {
        "status": "accepted",
        "$or": [ { "from": uid }, { "to": uid } ],
    };

    let cursor = match FriendRequest::collection(db).find(filter).await {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let requests: Vec<FriendRequest> = cursor.try_collect().await.unwrap_or_default();

    requests
        .into_iter()
        .filter_map(|r| {
            let other = if r.from == uid { r.to } else { r.from };
            if other == uid {
                None
            } else {
                Some(other.to_hex())
            }
        })
        .collect()
}

/// Rozgłasza zdarzenie WS tylko do zaakceptowanych znajomych użytkownika.
/// Zastępuje globalny broadcast, który wyciekał obecność/profil do wszystkich
/// zalogowanych klientów (spójne z polityką HTTP `get_user_status`).
pub async fn emit_to_friends(db: &Database, user_id: &str, event: &str, data: Value) {
    let recipients = friend_ids(db, user_id).await;
    if !recipients.is_empty() {
        crate::ws::registry::emit_to_users(&recipients, event, data);
    }
}

/// Wysyła zdarzenie profilu do samego użytkownika i jego znajomych (panel admina, kontakty).
pub async fn emit_profile_event(db: &Database, user_id: &str, event: &str, data: Value) {
    crate::ws::registry::emit_to_user(user_id, event, data.clone());
    emit_to_friends(db, user_id, event, data).await;
}

/// Rozgłasza zmianę obecności/statusu do samego użytkownika (wiele kart) i znajomych.
pub async fn emit_status_event(db: &Database, user_id: &str, data: Value) {
    crate::ws::registry::emit_to_user(user_id, "user-status-changed", data.clone());
    emit_to_friends(db, user_id, "user-status-changed", data).await;
}

pub fn map_friend_user(user: &User) -> Value {
    json!({
        "_id": user.id.map(|o| o.to_hex()).unwrap_or_default(),
        "username": user.username,
        "displayName": resolve_display_name(user),
        "bio": user.bio,
        "image": user.image,
        "banner": user.banner,
        "color": user.color,
        "createdAt": user.created_at.try_to_rfc3339_string().ok(),
    })
}
