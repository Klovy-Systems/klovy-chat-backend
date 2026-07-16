use mongodb::bson::{doc, oid::ObjectId, DateTime};
use mongodb::Database;
use serde_json::{json, Value};

use crate::model::channel_moderation::has_active_entry;
use crate::model::channel_model::Channel;
use crate::model::channel_read_state_model::ChannelReadState;
use crate::model::messages_model::Message;
use crate::model::user_model::User;
use crate::utils::user::badges::{populate_user_badges, BadgeVisibility};
use crate::utils::user::serialize_user::resolve_display_name;

pub mod moderation;

pub fn channel_member_count(channel: &Channel) -> usize {
    channel.members.len() + 1
}

pub fn is_channel_admin(channel: &Channel, user_id: Option<&str>) -> bool {
    match user_id {
        Some(uid) if !uid.is_empty() => channel.admin.to_hex() == uid,
        _ => false,
    }
}

pub fn is_channel_member(channel: &Channel, user_id: Option<&str>) -> bool {
    let Some(uid) = user_id.filter(|u| !u.is_empty()) else {
        return false;
    };
    if is_channel_admin(channel, Some(uid)) {
        return true;
    }
    channel.members.iter().any(|m| m.to_hex() == uid)
}

pub fn is_channel_banned(channel: &Channel, user_id: Option<&str>) -> bool {
    let Some(uid) = user_id.filter(|u| !u.is_empty()) else {
        return false;
    };
    has_active_entry(&channel.banned_members, uid)
}

pub fn is_channel_muted_member(channel: &Channel, user_id: Option<&str>) -> bool {
    let Some(uid) = user_id.filter(|u| !u.is_empty()) else {
        return false;
    };
    has_active_entry(&channel.muted_members, uid)
}

pub fn can_access_channel(channel: &Channel, user_id: Option<&str>) -> bool {
    is_channel_member(channel, user_id) && !is_channel_banned(channel, user_id)
}

pub fn is_channel_chat_locked_for_sender(channel: &Channel, sender_id: &str) -> bool {
    channel.chat_locked && channel.admin.to_hex() != sender_id
}

pub async fn populate_channel_user(db: &Database, id: ObjectId) -> Value {
    match User::find_by_id(db, id).await {
        Ok(Some(u)) => {
            let badges = populate_user_badges(db, &u, BadgeVisibility::All).await;
            json!({
                "_id": u.id.map(|o| o.to_hex()),
                "username": u.username,
                "displayName": resolve_display_name(&u),
                "bio": u.bio,
                "image": u.image,
                "banner": u.banner,
                "color": u.color,
                "isBot": u.is_bot,
                "badges": badges,
            })
        }
        _ => json!({ "_id": id.to_hex() }),
    }
}

pub async fn fetch_users_by_refs(db: &Database, ids: &[ObjectId]) -> Vec<Value> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for id in ids {
        if seen.insert(id.to_hex()) {
            out.push(populate_channel_user(db, *id).await);
        }
    }
    out
}

pub async fn get_channel_ban_mute_lists(db: &Database, channel_id: ObjectId) -> (Vec<Value>, Vec<Value>) {
    moderation::get_channel_ban_mute_lists(db, channel_id).await
}

pub async fn enrich_channel_unread(
    db: &Database,
    user_id: ObjectId,
    channel: &Channel,
) -> (u64, Option<(DateTime, String)>) {
    use futures_util::TryStreamExt;

    let Some(channel_id) = channel.id else {
        return (0, None);
    };

    let last_read = ChannelReadState::find(db, user_id, channel_id)
        .await
        .ok()
        .flatten()
        .map(|s| s.last_read_at)
        .unwrap_or_else(|| DateTime::from_millis(0));

    let unread = Message::collection(db)
        .count_documents(doc! {
            "channel": channel_id,
            "timestamp": { "$gt": last_read },
            "sender": { "$ne": user_id },
            "deleted": { "$ne": true },
        })
        .await
        .unwrap_or(0);

    let last = match Message::collection(db)
        .find(doc! { "channel": channel_id, "deleted": { "$ne": true } })
        .sort(doc! { "timestamp": -1 })
        .limit(1)
        .await
    {
        Ok(mut cursor) => match cursor.try_next().await.ok().flatten() {
            Some(m) => Some((m.timestamp, m.content)),
            None => None,
        },
        Err(_) => None,
    };

    (unread, last)
}
