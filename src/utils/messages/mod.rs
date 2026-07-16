pub mod access;
pub mod mentions;

use mongodb::bson::{doc, oid::ObjectId, Bson, DateTime};
use mongodb::Database;
use serde_json::{json, Value};

use crate::model::channel_model::Channel;
use crate::model::messages_model::Message;
use crate::model::user_model::User;
use crate::utils::access::membership_gate::require_channel_access;
use crate::utils::channel::{can_access_channel, is_channel_admin};
use crate::utils::friends::are_friends;
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
            "isBot": u.is_bot,
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
        "content": msg.content,
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
        return are_friends(db, user_id, &other_id).await;
    }

    false
}

pub async fn can_access_dm_messages(db: &Database, user_id: &str, contact_id: &str) -> bool {
    are_friends(db, user_id, contact_id).await
}

pub async fn can_access_channel_messages(
    db: &Database,
    user_id: &str,
    channel_id: &str,
) -> Option<Channel> {
    require_channel_access(db, channel_id, user_id).await.ok()
}
