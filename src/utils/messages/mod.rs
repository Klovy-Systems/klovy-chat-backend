pub mod access;
pub mod content_storage;
pub mod mentions;
pub mod seal_legacy_content;

use futures::stream::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, Bson, DateTime};
use mongodb::Database;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

use crate::model::channel_model::Channel;
use crate::model::messages_model::Message;
use crate::model::user_model::User;
use crate::utils::access::membership_gate::require_channel_access;
use crate::utils::channel::{can_access_channel, is_channel_admin};
use crate::utils::access::membership_gate::require_dm_access;
use crate::utils::user::serialize_user::resolve_display_name;

pub fn dm_only_or_clause() -> Bson {
    Bson::Array(vec![
        doc! { "channel": Bson::Null }.into(),
        doc! { "channel": { "$exists": false } }.into(),
    ])
}

pub fn escape_regex(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '.' | '*' | '+' | '?' | '^' | '$' | '{' | '}' | '(' | ')' | '|' | '[' | ']' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn iso(dt: &DateTime) -> Option<String> {
    dt.try_to_rfc3339_string().ok()
}

pub async fn populate_user(db: &Database, id: ObjectId) -> Value {
    match User::find_by_id(db, id).await {
        Ok(Some(u)) => json!({
            "_id": u.id.map(|o| o.to_hex()),
            "username": u.username,
            "displayName": resolve_display_name(&u),
            "bio": u.bio,
            "image": u.image,
            "color": u.color,
        }),
        _ => Value::Null,
    }
}

fn reactions_to_json(msg: &Message) -> Value {
    let mut map = serde_json::Map::new();
    for (key, reaction) in &msg.reactions {
        let users: Vec<String> = reaction.users.iter().map(|o| o.to_hex()).collect();
        map.insert(key.clone(), json!(users));
    }
    Value::Object(map)
}

fn message_content_for_api(msg: &Message) -> String {
    crate::utils::messages::content_storage::content_for_api(
        &msg.content,
    )
}

async fn serialize_message_inner(db: &Database, msg: &Message, include_quote: bool) -> Value {
    let sender = populate_user(db, msg.sender).await;

    let recipient = match msg.recipient {
        Some(r) => populate_user(db, r).await,
        None => Value::Null,
    };

    let pinned_by = match msg.pinned_by {
        Some(p) => populate_user(db, p).await,
        None => Value::Null,
    };

    let mut mentions = Vec::new();
    for m in &msg.mentions {
        mentions.push(populate_user(db, *m).await);
    }

    let quoted = if include_quote {
        match msg.quoted_message {
            Some(q) => match Message::find_by_id(db, q).await {
                Ok(Some(qm)) => Box::pin(serialize_message_inner(db, &qm, false)).await,
                _ => Value::Null,
            },
            None => Value::Null,
        }
    } else {
        Value::Null
    };

    let read_by: Vec<Value> = msg
        .read_by
        .iter()
        .map(|rb| json!({ "user": rb.user.to_hex(), "readAt": iso(&rb.read_at) }))
        .collect();

    json!({
        "_id": msg.id.map(|o| o.to_hex()),
        "sender": sender,
        "recipient": recipient,
        "channel": msg.channel.map(|o| o.to_hex()),
        "content": message_content_for_api(msg),
        "messageType": serde_json::to_value(&msg.message_type).unwrap_or(Value::Null),
        "fileUrl": msg.file_url,
        "fileType": msg.file_type,
        "fileSize": msg.file_size,
        "fileName": msg.file_name,
        "durationMs": msg.duration_ms,
        "timestamp": iso(&msg.timestamp),
        "read": msg.read,
        "readBy": read_by,
        "reactions": reactions_to_json(msg),
        "quotedMessage": quoted,
        "mentions": mentions,
        "mentionsEveryone": msg.mentions_everyone,
        "edited": msg.edited,
        "editedAt": msg.edited_at.as_ref().and_then(iso),
        "deleted": msg.deleted,
        "deletedAt": msg.deleted_at.as_ref().and_then(iso),
        "pinned": msg.pinned,
        "pinnedAt": msg.pinned_at.as_ref().and_then(iso),
        "pinnedBy": pinned_by,
        "createdAt": iso(&msg.created_at),
        "updatedAt": iso(&msg.updated_at),
    })
}

pub async fn serialize_message(db: &Database, msg: &Message) -> Value {
    serialize_message_inner(db, msg, true).await
}

fn user_to_json(u: &User) -> Value {
    json!({
        "_id": u.id.map(|o| o.to_hex()),
        "username": u.username,
        "displayName": resolve_display_name(u),
        "bio": u.bio,
        "image": u.image,
        "color": u.color,
    })
}

fn collect_message_user_ids(msg: &Message, set: &mut HashSet<ObjectId>) {
    set.insert(msg.sender);
    if let Some(r) = msg.recipient {
        set.insert(r);
    }
    if let Some(p) = msg.pinned_by {
        set.insert(p);
    }
    for m in &msg.mentions {
        set.insert(*m);
    }
}

fn cached_user(users: &HashMap<ObjectId, Value>, id: ObjectId) -> Value {
    users.get(&id).cloned().unwrap_or(Value::Null)
}

fn serialize_message_cached(
    msg: &Message,
    users: &HashMap<ObjectId, Value>,
    quoted: Option<&Message>,
) -> Value {
    let sender = cached_user(users, msg.sender);
    let recipient = msg
        .recipient
        .map(|r| cached_user(users, r))
        .unwrap_or(Value::Null);
    let pinned_by = msg
        .pinned_by
        .map(|p| cached_user(users, p))
        .unwrap_or(Value::Null);
    let mentions: Vec<Value> = msg.mentions.iter().map(|m| cached_user(users, *m)).collect();

    let quoted = match quoted {
        Some(qm) => serialize_message_cached(qm, users, None),
        None => Value::Null,
    };

    let read_by: Vec<Value> = msg
        .read_by
        .iter()
        .map(|rb| json!({ "user": rb.user.to_hex(), "readAt": iso(&rb.read_at) }))
        .collect();

    json!({
        "_id": msg.id.map(|o| o.to_hex()),
        "sender": sender,
        "recipient": recipient,
        "channel": msg.channel.map(|o| o.to_hex()),
        "content": message_content_for_api(msg),
        "messageType": serde_json::to_value(&msg.message_type).unwrap_or(Value::Null),
        "fileUrl": msg.file_url,
        "fileType": msg.file_type,
        "fileSize": msg.file_size,
        "fileName": msg.file_name,
        "durationMs": msg.duration_ms,
        "timestamp": iso(&msg.timestamp),
        "read": msg.read,
        "readBy": read_by,
        "reactions": reactions_to_json(msg),
        "quotedMessage": quoted,
        "mentions": mentions,
        "mentionsEveryone": msg.mentions_everyone,
        "edited": msg.edited,
        "editedAt": msg.edited_at.as_ref().and_then(iso),
        "deleted": msg.deleted,
        "deletedAt": msg.deleted_at.as_ref().and_then(iso),
        "pinned": msg.pinned,
        "pinnedAt": msg.pinned_at.as_ref().and_then(iso),
        "pinnedBy": pinned_by,
        "createdAt": iso(&msg.created_at),
        "updatedAt": iso(&msg.updated_at),
    })
}

/// Serialize a batch of messages with only three DB round-trips (quoted
/// messages, then all referenced users), instead of the previous N+1 pattern
/// that issued several `find_one` calls per message.
pub async fn serialize_messages_batch(db: &Database, msgs: &[Message]) -> Vec<Value> {
    if msgs.is_empty() {
        return Vec::new();
    }

    // 1. Fetch all quoted messages in one query.
    let quoted_ids: Vec<ObjectId> = msgs.iter().filter_map(|m| m.quoted_message).collect();
    let mut quoted_map: HashMap<ObjectId, Message> = HashMap::new();
    if !quoted_ids.is_empty() {
        if let Ok(cursor) = Message::collection(db)
            .find(doc! { "_id": { "$in": &quoted_ids } })
            .await
        {
            let list: Vec<Message> = cursor.try_collect().await.unwrap_or_default();
            for m in list {
                if let Some(id) = m.id {
                    quoted_map.insert(id, m);
                }
            }
        }
    }

    // 2. Gather every referenced user id (from messages and their quotes).
    let mut user_ids: HashSet<ObjectId> = HashSet::new();
    for m in msgs {
        collect_message_user_ids(m, &mut user_ids);
    }
    for m in quoted_map.values() {
        collect_message_user_ids(m, &mut user_ids);
    }

    // 3. Fetch all users in one query and build a lookup cache.
    let mut user_map: HashMap<ObjectId, Value> = HashMap::new();
    if !user_ids.is_empty() {
        let ids: Vec<ObjectId> = user_ids.into_iter().collect();
        if let Ok(cursor) = User::collection(db)
            .find(doc! { "_id": { "$in": &ids } })
            .await
        {
            let users: Vec<User> = cursor.try_collect().await.unwrap_or_default();
            for u in users {
                if let Some(id) = u.id {
                    user_map.insert(id, user_to_json(&u));
                }
            }
        }
    }

    msgs.iter()
        .map(|m| {
            let quoted = m.quoted_message.and_then(|q| quoted_map.get(&q));
            serialize_message_cached(m, &user_map, quoted)
        })
        .collect()
}

pub async fn can_pin_message(db: &Database, user_id: &str, msg: &Message) -> bool {
    if msg.deleted {
        return false;
    }

    if let Some(channel_id) = msg.channel {
        let Ok(Some(channel)) = Channel::find_by_id(db, channel_id).await else {
            return false;
        };
        if !can_access_channel(&channel, Some(user_id)) {
            return false;
        }
        return is_channel_admin(&channel, Some(user_id));
    }

    if let Some(recipient) = msg.recipient {
        let sender_id = msg.sender.to_hex();
        let recipient_id = recipient.to_hex();
        let is_participant = user_id == sender_id || user_id == recipient_id;
        if !is_participant {
            return false;
        }
        let other_id = if user_id == sender_id { recipient_id } else { sender_id };
        if require_dm_access(db, user_id, &other_id).await.is_err() {
            return false;
        }
        return true;
    }

    false
}

pub fn dm_conversation_base_clauses(user: ObjectId, contact: ObjectId) -> Vec<mongodb::bson::Document> {
    vec![
        doc! { "$or": [
            { "sender": user, "recipient": contact },
            { "sender": contact, "recipient": user },
        ]},
        doc! { "deleted": { "$ne": true } },
        doc! { "$or": dm_only_or_clause() },
    ]
}

pub fn message_belongs_to_dm_conversation(msg: &Message, user: ObjectId, contact: ObjectId) -> bool {
    msg.recipient.is_some()
        && msg.channel.is_none()
        && !msg.deleted
        && ((msg.sender == user && msg.recipient == Some(contact))
            || (msg.sender == contact && msg.recipient == Some(user)))
}

/// Kursor paginacji musi wskazywać wiadomość z tej samej rozmowy DM.
pub async fn validate_dm_history_before_cursor(
    db: &Database,
    user: ObjectId,
    contact: ObjectId,
    before_id: &str,
) -> Result<ObjectId, ()> {
    let Ok(before_oid) = ObjectId::parse_str(before_id) else {
        return Err(());
    };
    let Some(msg) = Message::find_by_id(db, before_oid).await.ok().flatten() else {
        return Err(());
    };
    if message_belongs_to_dm_conversation(&msg, user, contact) {
        Ok(before_oid)
    } else {
        Err(())
    }
}

pub async fn can_access_dm_messages(db: &Database, user_id: &str, contact_id: &str) -> bool {
    require_dm_access(db, user_id, contact_id).await.is_ok()
}

pub async fn can_access_channel_messages(
    db: &Database,
    user_id: &str,
    channel_id: &str,
) -> Option<Channel> {
    require_channel_access(db, channel_id, user_id).await.ok()
}
