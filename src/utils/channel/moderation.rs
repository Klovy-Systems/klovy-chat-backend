use mongodb::bson::{doc, oid::ObjectId, DateTime};
use mongodb::Database;
use serde_json::{json, Value};

use crate::model::channel_moderation::{
    active_moderation_entries, remove_entry_for_user, upsert_entry,
    ChannelModerationEntry,
};
use crate::model::channel_model::Channel;

/// Atomic mute-list remove — avoids rewriting full arrays from a stale snapshot.
pub async fn pull_muted_member(
    db: &Database,
    channel_id: ObjectId,
    user_id: ObjectId,
) -> mongodb::error::Result<()> {
    Channel::collection(db)
        .update_one(
            doc! { "_id": channel_id },
            doc! {
                "$pull": { "mutedMembers": { "userId": user_id } },
                "$set": { "updatedAt": DateTime::now() },
            },
        )
        .await?;
    Ok(())
}

/// Atomic ban-list remove.
pub async fn pull_banned_member(
    db: &Database,
    channel_id: ObjectId,
    user_id: ObjectId,
) -> mongodb::error::Result<()> {
    Channel::collection(db)
        .update_one(
            doc! { "_id": channel_id },
            doc! {
                "$pull": { "bannedMembers": { "userId": user_id } },
                "$set": { "updatedAt": DateTime::now() },
            },
        )
        .await?;
    Ok(())
}

/// Upsert one ban entry without clobbering the rest of the list (single pipeline update).
pub async fn upsert_banned_member(
    db: &Database,
    channel_id: ObjectId,
    entry: ChannelModerationEntry,
) -> mongodb::error::Result<()> {
    let entry_bson = mongodb::bson::to_bson(&entry).map_err(|e| {
        mongodb::error::Error::custom(format!("failed to serialize ban entry: {e}"))
    })?;
    let uid = entry.user_id;
    Channel::collection(db)
        .update_one(
            doc! { "_id": channel_id },
            vec![doc! {
                "$set": {
                    "bannedMembers": {
                        "$concatArrays": [
                            {
                                "$filter": {
                                    "input": { "$ifNull": ["$bannedMembers", []] },
                                    "as": "e",
                                    "cond": { "$ne": ["$$e.userId", uid] },
                                }
                            },
                            [entry_bson],
                        ]
                    },
                    "updatedAt": DateTime::now(),
                }
            }],
        )
        .await?;
    Ok(())
}

/// Upsert one mute entry without clobbering the rest of the list (single pipeline update).
pub async fn upsert_muted_member(
    db: &Database,
    channel_id: ObjectId,
    entry: ChannelModerationEntry,
) -> mongodb::error::Result<()> {
    let entry_bson = mongodb::bson::to_bson(&entry).map_err(|e| {
        mongodb::error::Error::custom(format!("failed to serialize mute entry: {e}"))
    })?;
    let uid = entry.user_id;
    Channel::collection(db)
        .update_one(
            doc! { "_id": channel_id },
            vec![doc! {
                "$set": {
                    "mutedMembers": {
                        "$concatArrays": [
                            {
                                "$filter": {
                                    "input": { "$ifNull": ["$mutedMembers", []] },
                                    "as": "e",
                                    "cond": { "$ne": ["$$e.userId", uid] },
                                }
                            },
                            [entry_bson],
                        ]
                    },
                    "updatedAt": DateTime::now(),
                }
            }],
        )
        .await?;
    Ok(())
}

pub async fn populate_moderation_user_list(
    db: &Database,
    entries: &[ChannelModerationEntry],
) -> Vec<Value> {
    use super::fetch_users_map;

    let active = active_moderation_entries(entries);
    if active.is_empty() {
        return Vec::new();
    }
    let ids: Vec<ObjectId> = active.iter().map(|e| e.user_id).collect();
    let map = fetch_users_map(db, &ids).await;
    let mut out = Vec::with_capacity(active.len());
    for entry in active {
        let mut user = map
            .get(&entry.user_id)
            .cloned()
            .unwrap_or_else(|| json!({ "_id": entry.user_id.to_hex() }));
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
) -> Option<(Vec<Value>, Vec<Value>)> {
    let channel = match Channel::find_by_id(db, channel_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return Some((vec![], vec![])),
        Err(_) => return None,
    };
    let banned = populate_moderation_user_list(db, &channel.banned_members).await;
    let muted = populate_moderation_user_list(db, &channel.muted_members).await;
    Some((banned, muted))
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

/// ISO expiry for the viewer's active timed mute (if any).
pub fn viewer_mute_expires_at(channel: &Channel, viewer_id: &str) -> Option<String> {
    channel
        .muted_members
        .iter()
        .find(|entry| entry.is_active() && entry.user_id.to_hex() == viewer_id)
        .and_then(|entry| entry.expires_at.as_ref())
        .and_then(|dt| dt.try_to_rfc3339_string().ok())
}

pub async fn maybe_prune_channel_moderation(db: &Database, channel: &Channel) -> Channel {
    let banned = active_moderation_entries(&channel.banned_members);
    let muted = active_moderation_entries(&channel.muted_members);
    if banned.len() == channel.banned_members.len() && muted.len() == channel.muted_members.len() {
        return channel.clone();
    }

    let active_muted: std::collections::HashSet<ObjectId> =
        muted.iter().map(|e| e.user_id).collect();
    let expired_mute_users: Vec<String> = channel
        .muted_members
        .iter()
        .filter(|entry| !active_muted.contains(&entry.user_id))
        .map(|entry| entry.user_id.to_hex())
        .collect();

    if let Some(channel_id) = channel.id {
        // Pull only expired timed entries — never rewrite full arrays (races upsert).
        let now = DateTime::now();
        let _ = Channel::collection(db)
            .update_one(
                doc! { "_id": channel_id },
                doc! {
                    "$pull": {
                        "bannedMembers": { "expiresAt": { "$lte": now } },
                        "mutedMembers": { "expiresAt": { "$lte": now } },
                    },
                    "$set": { "updatedAt": now },
                },
            )
            .await;
        let channel_id_hex = channel_id.to_hex();
        crate::ws::typing_access_cache::invalidate_channel(&channel_id_hex);
        crate::utils::access::channel_access_cache::invalidate_channel(&channel_id_hex);
        for user_id in expired_mute_users {
            crate::ws::registry::emit_to_user(
                &user_id,
                "channel-moderation-updated",
                json!({
                    "channelId": channel_id_hex,
                    "isMutedHere": false,
                    "mutedHereExpiresAt": Value::Null,
                }),
            );
        }
    }
    Channel {
        banned_members: banned,
        muted_members: muted,
        ..channel.clone()
    }
}
