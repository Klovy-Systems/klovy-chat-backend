use mongodb::bson::{doc, oid::ObjectId, DateTime, Bson};
use mongodb::Database;
use serde_json::{json, Value};

use crate::model::channel_moderation::{
    active_moderation_entries, remove_entry_for_user, upsert_entry,
    ChannelModerationEntry,
};
use crate::model::channel_model::Channel;

pub async fn persist_moderation_lists(
    db: &Database,
    channel_id: ObjectId,
    banned_members: Vec<ChannelModerationEntry>,
    muted_members: Vec<ChannelModerationEntry>,
) -> mongodb::error::Result<()> {
    let banned_bson = mongodb::bson::to_bson(&banned_members).unwrap_or(Bson::Array(vec![]));
    let muted_bson = mongodb::bson::to_bson(&muted_members).unwrap_or(Bson::Array(vec![]));
    Channel::collection(db)
        .update_one(
            doc! { "_id": channel_id },
            doc! {
                "$set": {
                    "bannedMembers": banned_bson,
                    "mutedMembers": muted_bson,
                    "updatedAt": DateTime::now(),
                }
            },
        )
        .await?;
    Ok(())
}

pub async fn populate_moderation_user_list(
    db: &Database,
    entries: &[ChannelModerationEntry],
) -> Vec<Value> {
    use super::populate_channel_user;

    let mut out = Vec::new();
    for entry in active_moderation_entries(entries) {
        let mut user = populate_channel_user(db, entry.user_id).await;
        if let Some(obj) = user.as_object_mut() {
            obj.insert(
                "moderationExpiresAt".to_string(),
                json!(entry
                    .expires_at
                    .as_ref()
                    .and_then(|dt| dt.try_to_rfc3339_string().ok())),
            );
            obj.insert(
                "moderationCreatedAt".to_string(),
                json!(entry.created_at.try_to_rfc3339_string().ok()),
            );
            obj.insert(
                "moderationPermanent".to_string(),
                json!(entry.expires_at.is_none()),
            );
        }
        out.push(user);
    }
    out
}

pub async fn get_channel_ban_mute_lists(
    db: &Database,
    channel_id: ObjectId,
) -> (Vec<Value>, Vec<Value>) {
    let Ok(Some(channel)) = Channel::find_by_id(db, channel_id).await else {
        return (vec![], vec![]);
    };
    let banned = populate_moderation_user_list(db, &channel.banned_members).await;
    let muted = populate_moderation_user_list(db, &channel.muted_members).await;
    (banned, muted)
}

pub fn build_moderation_entry(
    user_id: ObjectId,
    duration_seconds: Option<u64>,
) -> ChannelModerationEntry {
    match duration_seconds {
        Some(0) | None => ChannelModerationEntry::permanent(user_id),
        Some(seconds) => ChannelModerationEntry::timed(user_id, seconds),
    }
}

pub fn prepare_ban_lists(
    channel: &Channel,
    target_id: ObjectId,
    duration_seconds: Option<u64>,
) -> (Vec<ChannelModerationEntry>, Vec<ChannelModerationEntry>, Vec<ObjectId>) {
    let banned = upsert_entry(
        &channel.banned_members,
        build_moderation_entry(target_id, duration_seconds),
    );
    let muted = remove_entry_for_user(&channel.muted_members, target_id);
    let members = channel
        .members
        .iter()
        .copied()
        .filter(|member| *member != target_id)
        .collect();
    (banned, muted, members)
}

pub fn prepare_mute_lists(
    channel: &Channel,
    target_id: ObjectId,
    duration_seconds: Option<u64>,
) -> (Vec<ChannelModerationEntry>, Vec<ChannelModerationEntry>) {
    let muted = upsert_entry(
        &channel.muted_members,
        build_moderation_entry(target_id, duration_seconds),
    );
    let banned = remove_entry_for_user(&channel.banned_members, target_id);
    (muted, banned)
}

pub fn prepare_unban_lists(
    channel: &Channel,
    target_id: ObjectId,
) -> Vec<ChannelModerationEntry> {
    remove_entry_for_user(&channel.banned_members, target_id)
}

pub fn prepare_unmute_lists(
    channel: &Channel,
    target_id: ObjectId,
) -> Vec<ChannelModerationEntry> {
    remove_entry_for_user(&channel.muted_members, target_id)
}

pub fn active_entries(entries: &[ChannelModerationEntry]) -> Vec<ChannelModerationEntry> {
    active_moderation_entries(entries)
}

pub fn active_moderation_user_ids(entries: &[ChannelModerationEntry]) -> Vec<String> {
    active_moderation_entries(entries)
        .into_iter()
        .map(|entry| entry.user_id.to_hex())
        .collect()
}

pub async fn maybe_prune_channel_moderation(db: &Database, channel: &Channel) -> Channel {
    let banned = active_moderation_entries(&channel.banned_members);
    let muted = active_moderation_entries(&channel.muted_members);
    if banned.len() == channel.banned_members.len() && muted.len() == channel.muted_members.len() {
        return channel.clone();
    }
    if let Some(channel_id) = channel.id {
        let _ = persist_moderation_lists(db, channel_id, banned.clone(), muted.clone()).await;
    }
    Channel {
        banned_members: banned,
        muted_members: muted,
        ..channel.clone()
    }
}
