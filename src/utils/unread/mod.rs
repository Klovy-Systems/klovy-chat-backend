use mongodb::bson::{doc, oid::ObjectId, DateTime};
use mongodb::Database;
use serde::Serialize;

use crate::model::channel_read_state_model::ChannelReadState;
use crate::model::messages_model::Message;
use crate::ws::registry;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnreadUpdatedEvent {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
    pub unread_count: u64,
}

fn dm_only() -> mongodb::bson::Document {
    doc! { "$or": [ { "channel": mongodb::bson::Bson::Null }, { "channel": { "$exists": false } } ] }
}

pub async fn count_dm_unread(
    db: &Database,
    user_id: ObjectId,
    contact_id: ObjectId,
) -> u64 {
    Message::collection(db)
        .count_documents(doc! {
            "sender": contact_id,
            "recipient": user_id,
            "read": false,
            "deleted": { "$ne": true },
            "$and": [ dm_only() ],
        })
        .await
        .unwrap_or(0)
}

pub async fn count_channel_unread(
    db: &Database,
    user_id: ObjectId,
    channel_id: ObjectId,
) -> u64 {
    let last_read = ChannelReadState::find(db, user_id, channel_id)
        .await
        .ok()
        .flatten()
        .map(|s| s.last_read_at)
        .unwrap_or_else(|| DateTime::from_millis(0));

    Message::collection(db)
        .count_documents(doc! {
            "channel": channel_id,
            "timestamp": { "$gt": last_read },
            "sender": { "$ne": user_id },
            "deleted": { "$ne": true },
        })
        .await
        .unwrap_or(0)
}

pub fn emit_unread_updated(user_id: &str, event: UnreadUpdatedEvent) {
    registry::emit_to_user(user_id, "unread-updated", event);
}

pub async fn emit_dm_unread_updated(db: &Database, user_id: &str, contact_id: &str) {
    let (Ok(uid), Ok(cid)) = (ObjectId::parse_str(user_id), ObjectId::parse_str(contact_id)) else {
        return;
    };
    let unread = count_dm_unread(db, uid, cid).await;
    emit_unread_updated(
        user_id,
        UnreadUpdatedEvent {
            kind: "dm".into(),
            id: contact_id.to_string(),
            unread_count: unread,
        },
    );
}

pub async fn emit_channel_unread_updated(db: &Database, user_id: &str, channel_id: &str) {
    let (Ok(uid), Ok(cid)) = (ObjectId::parse_str(user_id), ObjectId::parse_str(channel_id)) else {
        return;
    };
    let unread = count_channel_unread(db, uid, cid).await;
    emit_unread_updated(
        user_id,
        UnreadUpdatedEvent {
            kind: "channel".into(),
            id: channel_id.to_string(),
            unread_count: unread,
        },
    );
}

pub async fn mark_channel_as_read_for_user(db: &Database, user_id: &str, channel_id: &str) {
    let (Ok(uid), Ok(cid)) = (ObjectId::parse_str(user_id), ObjectId::parse_str(channel_id)) else {
        return;
    };
    let _ = ChannelReadState::upsert(db, uid, cid).await;
}
