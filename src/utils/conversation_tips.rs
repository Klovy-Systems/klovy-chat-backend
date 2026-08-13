//! Denormalized last-message tips for sidebar list (avoids $sort+$group on refresh).

use mongodb::bson::{doc, oid::ObjectId, Bson, DateTime};
use mongodb::options::{IndexOptions, UpdateOptions};
use mongodb::{Collection, Database, IndexModel};
use serde::{Deserialize, Serialize};

use crate::model::channel_model::Channel;
use crate::model::messages_model::Message;
use crate::utils::messages::content_storage::content_for_api;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmConversationTip {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    #[serde(rename = "pairKey")]
    pub pair_key: String,

    #[serde(rename = "userA")]
    pub user_a: ObjectId,

    #[serde(rename = "userB")]
    pub user_b: ObjectId,

    #[serde(rename = "lastMessage")]
    pub last_message: String,

    #[serde(rename = "lastMessageAt")]
    pub last_message_at: DateTime,

    #[serde(rename = "lastMessageId")]
    pub last_message_id: ObjectId,

    #[serde(rename = "unreadA", default)]
    pub unread_a: Option<u64>,

    #[serde(rename = "unreadB", default)]
    pub unread_b: Option<u64>,

    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime,
}

impl DmConversationTip {
    pub fn collection(db: &Database) -> Collection<DmConversationTip> {
        db.collection("dm_conversation_tips")
    }

    pub async fn create_indexes(db: &Database) -> mongodb::error::Result<()> {
        Self::collection(db)
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "pairKey": 1 })
                    .options(IndexOptions::builder().unique(true).build())
                    .build(),
            )
            .await?;
        Ok(())
    }
}

pub fn dm_pair_key(a: ObjectId, b: ObjectId) -> (String, ObjectId, ObjectId) {
    let (ha, hb) = (a.to_hex(), b.to_hex());
    if ha <= hb {
        (format!("{ha}:{hb}"), a, b)
    } else {
        (format!("{hb}:{ha}"), b, a)
    }
}

fn tip_preview(msg: &Message) -> String {
    content_for_api(&msg.content)
}

/// Upsert tip for a new/newer message. Never clobber a newer tip with an older edit/send.
/// Skips soft-deleted messages (late tip after delete×send race).
pub async fn upsert_dm_tip(db: &Database, msg: &Message) {
    let (Some(recipient), None) = (msg.recipient, msg.channel) else {
        return;
    };
    let Some(mid) = msg.id else { return };
    // Soft-deleted — do not resurrect tip after delete×late-upsert race.
    // Probe Err ≠ deleted: skip upsert (leave tip) rather than treat as gone.
    let still_active = match Message::collection(db)
        .find_one(doc! { "_id": mid, "deleted": { "$ne": true } })
        .projection(doc! { "_id": 1 })
        .await
    {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(e) => {
            log::warn!("upsert_dm_tip still_active probe failed mid={}: {e}", mid.to_hex());
            return;
        }
    };
    if !still_active {
        return;
    }
    let (pair_key, user_a, user_b) = dm_pair_key(msg.sender, recipient);
    let now = DateTime::now();
    let preview = tip_preview(msg);

    // Atomic stale guard — filter out older tips in the write itself (no TOCTOU).
    // Equal timestamp: prefer higher message id so concurrent same-ms sends converge.
    if let Err(e) = DmConversationTip::collection(db)
        .update_one(
            doc! {
                "pairKey": &pair_key,
                "$or": [
                    { "lastMessageAt": { "$exists": false } },
                    { "lastMessageAt": { "$lt": msg.timestamp } },
                    {
                        "lastMessageAt": msg.timestamp,
                        "lastMessageId": { "$lt": mid },
                    },
                    { "lastMessageId": mid },
                ],
            },
            doc! {
                "$set": {
                    "lastMessage": &preview,
                    "lastMessageAt": msg.timestamp,
                    "lastMessageId": mid,
                    "updatedAt": now,
                    "userA": user_a,
                    "userB": user_b,
                },
                "$setOnInsert": {
                    "createdAt": now,
                    "unreadA": 0i64,
                    "unreadB": 0i64,
                },
            },
        )
        .with_options(UpdateOptions::builder().upsert(true).build())
        .await
    {
        // List recount verifies tip-0; log for ops visibility.
        log::warn!("upsert_dm_tip failed pair={pair_key}: {e}");
    }
}

pub async fn upsert_channel_tip(db: &Database, channel_id: ObjectId, msg: &Message) {
    let Some(mid) = msg.id else { return };
    let still_active = match Message::collection(db)
        .find_one(doc! { "_id": mid, "deleted": { "$ne": true } })
        .projection(doc! { "_id": 1 })
        .await
    {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(e) => {
            log::warn!(
                "upsert_channel_tip still_active probe failed mid={}: {e}",
                mid.to_hex()
            );
            return;
        }
    };
    if !still_active {
        return;
    }
    let preview = tip_preview(msg);
    if let Err(e) = Channel::collection(db)
        .update_one(
            doc! {
                "_id": channel_id,
                "$or": [
                    { "lastMessageAt": { "$exists": false } },
                    { "lastMessageAt": { "$eq": Bson::Null } },
                    { "lastMessageAt": { "$lt": msg.timestamp } },
                    {
                        "lastMessageAt": msg.timestamp,
                        "lastMessageId": { "$lt": mid },
                    },
                    { "lastMessageId": mid },
                ],
            },
            doc! {
                "$set": {
                    "lastMessage": &preview,
                    "lastMessageAt": msg.timestamp,
                    "lastMessageId": mid,
                    "updatedAt": DateTime::now(),
                }
            },
        )
        .await
    {
        log::warn!("upsert_channel_tip failed channel={}: {e}", channel_id.to_hex());
    }
}

/// Returns whether the tip row was matched (false → caller should heal absolute).
pub async fn bump_dm_unread(db: &Database, sender: ObjectId, recipient: ObjectId) -> bool {
    let (pair_key, user_a, _) = dm_pair_key(sender, recipient);
    let field = if recipient == user_a {
        "unreadA"
    } else {
        "unreadB"
    };
    // Tip row is created by upsert_dm_tip on send — no upsert here (avoids fake lastMessageId).
    match DmConversationTip::collection(db)
        .update_one(
            doc! { "pairKey": &pair_key },
            doc! {
                "$inc": { field: 1i64 },
                "$set": { "updatedAt": DateTime::now() },
            },
        )
        .await
    {
        Ok(res) => res.matched_count > 0,
        Err(_) => false,
    }
}

/// Returns `false` when the tip unread write fails (callers must not treat as stable).
pub async fn set_dm_unread(db: &Database, viewer: ObjectId, peer: ObjectId, unread: u64) -> bool {
    let (pair_key, user_a, _) = dm_pair_key(viewer, peer);
    let field = if viewer == user_a {
        "unreadA"
    } else {
        "unreadB"
    };
    // Tip row is created by upsert_dm_tip on send — no invent on miss (parity bump).
    match DmConversationTip::collection(db)
        .update_one(
            doc! { "pairKey": &pair_key },
            doc! { "$set": { field: unread as i64, "updatedAt": DateTime::now() } },
        )
        .await
    {
        Ok(res) => res.matched_count > 0,
        Err(_) => false,
    }
}

/// `Ok(Some(n))` tip field present · `Ok(None)` missing tip/field · `Err(())` DB fail.
async fn tip_unread_field(db: &Database, viewer: ObjectId, peer: ObjectId) -> Result<Option<u64>, ()> {
    let (pair_key, user_a, _) = dm_pair_key(viewer, peer);
    let tip = match DmConversationTip::collection(db)
        .find_one(doc! { "pairKey": &pair_key })
        .await
    {
        Ok(t) => t,
        Err(_) => return Err(()),
    };
    let Some(tip) = tip else {
        return Ok(None);
    };
    Ok(if viewer == user_a {
        tip.unread_a
    } else {
        tip.unread_b
    })
}

/// Recount tip unread until stable. Returns `None` when count fails — callers
/// must not emit absolute 0 from that (would clobber concurrent send).
pub async fn try_sync_dm_tip_unread(
    db: &Database,
    viewer: ObjectId,
    peer: ObjectId,
) -> Option<u64> {
    let Some(mut n) = crate::utils::unread::try_count_dm_unread(db, viewer, peer).await else {
        return None;
    };
    for _ in 0..3 {
        if !set_dm_unread(db, viewer, peer, n).await {
            return None;
        }
        // Tip read Err / missing field must not invent tip_n == n (false stable).
        let tip_n = match tip_unread_field(db, viewer, peer).await {
            Ok(Some(v)) => v,
            Ok(None) | Err(()) => return None,
        };
        // Recount Err — do not invent tip-stable (would emit absolute under pressure).
        let Some(n2) = crate::utils::unread::try_count_dm_unread(db, viewer, peer).await else {
            return None;
        };
        if n2 == n && tip_n == n {
            return Some(n);
        }
        n = n2;
    }
    if !set_dm_unread(db, viewer, peer, n).await {
        return None;
    }
    // Final path: tip + recount must both match — no invent-stable under churn.
    match tip_unread_field(db, viewer, peer).await {
        Ok(Some(v)) if v == n => {}
        _ => return None,
    }
    match crate::utils::unread::try_count_dm_unread(db, viewer, peer).await {
        Some(n2) if n2 == n => Some(n),
        _ => None,
    }
}

/// Recount tip unread and re-check until stable (max 3) so a concurrent send
/// cannot be clobbered by a stale mark-read `set_dm_unread(0)`.
/// Also re-reads the tip field so a late `$inc` after `$set` cannot stick.
/// Prefer `try_sync_dm_tip_unread` before emitting absolute.
/// Prefer `try_sync_dm_tip_unread` — this alias never invents 0 on count failure.
pub async fn sync_dm_tip_unread(
    db: &Database,
    viewer: ObjectId,
    peer: ObjectId,
) -> Option<u64> {
    try_sync_dm_tip_unread(db, viewer, peer).await
}

pub async fn dec_dm_unread(db: &Database, viewer: ObjectId, peer: ObjectId) {
    let (pair_key, user_a, _) = dm_pair_key(viewer, peer);
    let field = if viewer == user_a {
        "unreadA"
    } else {
        "unreadB"
    };
    let _ = DmConversationTip::collection(db)
        .update_one(
            doc! { "pairKey": &pair_key, field: { "$gt": 0 } },
            doc! {
                "$inc": { field: -1i64 },
                "$set": { "updatedAt": DateTime::now() },
            },
        )
        .await;
}

pub async fn refresh_dm_tip_after_delete(
    db: &Database,
    sender: ObjectId,
    recipient: ObjectId,
    deleted_id: ObjectId,
) {
    use futures_util::TryStreamExt;
    let (pair_key, user_a, user_b) = dm_pair_key(sender, recipient);
    let tip = match DmConversationTip::collection(db)
        .find_one(doc! { "pairKey": &pair_key })
        .await
    {
        Ok(t) => t,
        // Transient — do not invent "tip already moved" or force recompute/wipe.
        Err(_) => return,
    };
    if tip
        .as_ref()
        .is_some_and(|t| t.last_message_id != deleted_id)
    {
        return;
    }
    let filter = doc! {
        "deleted": { "$ne": true },
        "$and": [
            { "$or": [
                { "channel": mongodb::bson::Bson::Null },
                { "channel": { "$exists": false } },
            ]},
            { "$or": [
                { "sender": sender, "recipient": recipient },
                { "sender": recipient, "recipient": sender },
            ]},
        ],
    };
    let latest = match Message::collection(db)
        .find(filter)
        .sort(doc! { "timestamp": -1, "_id": -1 })
        .limit(1)
        .await
    {
        Ok(mut c) => match c.try_next().await {
            Ok(m) => m,
            // Fail closed — do not delete tip on stream Err.
            Err(e) => {
                log::warn!("refresh_dm_tip_after_delete try_next failed: {e}");
                return;
            }
        },
        Err(e) => {
            log::warn!("refresh_dm_tip_after_delete find failed: {e}");
            return;
        }
    };
    match latest {
        Some(msg) => upsert_dm_tip(db, &msg).await,
        None => {
            // Only wipe if this delete still owns the tip (concurrent send may have won).
            let _ = DmConversationTip::collection(db)
                .delete_one(doc! { "pairKey": pair_key, "lastMessageId": deleted_id })
                .await;
            let _ = (user_a, user_b);
        }
    }
}

/// Wipe denormalized DM tip after the whole conversation is deleted.
/// Only removes tips whose last message is not newer than `wiped_at`, so a
/// concurrent send that lands after the wipe keeps its tip.
pub async fn clear_dm_tip(db: &Database, user_a: ObjectId, user_b: ObjectId) {
    clear_dm_tip_at_most(db, user_a, user_b, DateTime::now()).await;
}

pub async fn clear_dm_tip_at_most(
    db: &Database,
    user_a: ObjectId,
    user_b: ObjectId,
    wiped_at: DateTime,
) {
    let (pair_key, _, _) = dm_pair_key(user_a, user_b);
    let _ = DmConversationTip::collection(db)
        .delete_one(doc! {
            "pairKey": pair_key,
            "$or": [
                { "lastMessageAt": { "$exists": false } },
                { "lastMessageAt": { "$lte": wiped_at } },
            ],
        })
        .await;
}

pub async fn refresh_channel_tip_after_delete(
    db: &Database,
    channel_id: ObjectId,
    deleted_id: ObjectId,
) {
    let ch = match Channel::find_by_id(db, channel_id).await {
        Ok(c) => c,
        // Transient — do not invent "tip already moved" or force recompute/$unset.
        Err(_) => return,
    };
    if ch
        .as_ref()
        .and_then(|c| c.last_message_id)
        .is_some_and(|id| id != deleted_id)
    {
        return;
    }
    recompute_channel_tip(db, channel_id).await;
}

/// Force-rebuild channel tip from the latest non-deleted message (purge / bulk wipe).
pub async fn recompute_channel_tip(db: &Database, channel_id: ObjectId) {
    use futures_util::TryStreamExt;
    // Snapshot tip id before the latest-message query so a concurrent send's
    // upsert is not wiped by an unguarded `$unset`.
    let prior_tip_id = match Channel::find_by_id(db, channel_id).await {
        Ok(ch) => ch.and_then(|c| c.last_message_id),
        Err(e) => {
            log::warn!(
                "recompute_channel_tip prior tip read failed channel={}: {e}",
                channel_id.to_hex()
            );
            return;
        }
    };
    let latest = match Message::collection(db)
        .find(doc! { "channel": channel_id, "deleted": { "$ne": true } })
        .sort(doc! { "timestamp": -1, "_id": -1 })
        .limit(1)
        .await
    {
        Ok(mut c) => match c.try_next().await {
            Ok(m) => m,
            // Fail closed — do not $unset tip on stream Err.
            Err(e) => {
                log::warn!(
                    "recompute_channel_tip try_next failed channel={}: {e}",
                    channel_id.to_hex()
                );
                return;
            }
        },
        Err(e) => {
            log::warn!(
                "recompute_channel_tip find failed channel={}: {e}",
                channel_id.to_hex()
            );
            return;
        }
    };
    match latest {
        Some(msg) => upsert_channel_tip(db, channel_id, &msg).await,
        None => {
            let filter = match prior_tip_id {
                Some(id) => doc! { "_id": channel_id, "lastMessageId": id },
                None => doc! {
                    "_id": channel_id,
                    "$or": [
                        { "lastMessageId": { "$exists": false } },
                        { "lastMessageId": Bson::Null },
                    ],
                },
            };
            let _ = Channel::collection(db)
                .update_one(
                    filter,
                    doc! {
                        "$unset": {
                            "lastMessage": "",
                            "lastMessageAt": "",
                            "lastMessageId": "",
                        },
                        "$set": { "updatedAt": DateTime::now() },
                    },
                )
                .await;
        }
    }
}

/// peer → (lastAt, preview, lastId, denorm_unread).
/// `None` when tip stream fails — callers must not invent false-zero unreads.
pub async fn load_dm_tips_for_friends(
    db: &Database,
    uid: ObjectId,
    friend_ids: &[ObjectId],
) -> Option<std::collections::HashMap<ObjectId, (DateTime, String, ObjectId, Option<u64>)>> {
    use futures_util::TryStreamExt;
    let mut out = std::collections::HashMap::new();
    if friend_ids.is_empty() {
        return Some(out);
    }
    let keys: Vec<String> = friend_ids
        .iter()
        .map(|fid| dm_pair_key(uid, *fid).0)
        .collect();
    let cursor = match DmConversationTip::collection(db)
        .find(doc! { "pairKey": { "$in": keys } })
        .await
    {
        Ok(c) => c,
        Err(_) => return None,
    };
    let tips: Vec<DmConversationTip> = match cursor.try_collect().await {
        Ok(t) => t,
        Err(_) => return None,
    };
    for tip in tips {
        let peer = if tip.user_a == uid {
            tip.user_b
        } else {
            tip.user_a
        };
        let unread = if tip.user_a == uid {
            tip.unread_a
        } else {
            tip.unread_b
        };
        out.insert(
            peer,
            (
                tip.last_message_at,
                tip.last_message.clone(),
                tip.last_message_id,
                unread,
            ),
        );
    }
    Some(out)
}
