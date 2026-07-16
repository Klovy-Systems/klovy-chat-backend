use std::collections::{HashMap, HashSet};

use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId};
use mongodb::Database;

use crate::model::messages_model::Message;
use crate::model::pending_upload_model::PendingUpload;
use crate::model::user_storage_usage_model::UserStorageUsage;
use crate::utils::storage::{is_attachment_key, storage, StorageError};

#[derive(Debug, Default)]
pub struct ReconcileReport {
    pub orphan_objects_deleted: u64,
    pub missing_objects: u64,
    pub usage_users_updated: u64,
}

pub async fn reconcile_attachments(db: &Database) -> Result<ReconcileReport, StorageError> {
    let mut report = ReconcileReport::default();

    let referenced = collect_referenced_paths(db).await;
    let objects = storage().list_public_attachments().await?;

    let r2_keys: HashSet<String> = objects.iter().map(|(key, _)| key.clone()).collect();

    for (key, _) in &objects {
        if referenced.contains(key) {
            continue;
        }
        if storage().delete_attachment_key(key).await.is_ok() {
            report.orphan_objects_deleted += 1;
        }
    }

    for path in &referenced {
        if !r2_keys.contains(path) {
            report.missing_objects += 1;
            log::warn!("Attachment referenced in MongoDB but missing in R2: {path}");
        }
    }

    match rebuild_user_storage_usage(db).await {
        Ok(updated) => report.usage_users_updated = updated,
        Err(e) => log::warn!("Storage usage rebuild failed: {e}"),
    }

    Ok(report)
}

async fn collect_referenced_paths(db: &Database) -> HashSet<String> {
    let mut paths = HashSet::new();

    if let Ok(cursor) = PendingUpload::collection(db).find(doc! {}).await {
        if let Ok(entries) = cursor.try_collect::<Vec<PendingUpload>>().await {
            for entry in entries {
                paths.insert(entry.file_path);
            }
        }
    }

    if let Ok(cursor) = Message::collection(db)
        .find(doc! {
            "deleted": { "$ne": true },
            "fileUrl": { "$exists": true, "$ne": null },
        })
        .await
    {
        if let Ok(messages) = cursor.try_collect::<Vec<Message>>().await {
            for msg in messages {
                if let Some(url) = msg.file_url {
                    let normalized = url.trim().replace('\\', "/").trim_start_matches('/').to_string();
                    if is_attachment_key(&normalized) {
                        paths.insert(normalized);
                    }
                }
            }
        }
    }

    paths
}

async fn rebuild_user_storage_usage(db: &Database) -> mongodb::error::Result<u64> {
    let mut usage: HashMap<ObjectId, i64> = HashMap::new();

    let pending_cursor = PendingUpload::collection(db).find(doc! {}).await?;
    let pending: Vec<PendingUpload> = pending_cursor.try_collect().await?;
    for entry in pending {
        *usage.entry(entry.user_id).or_insert(0) += entry.file_size as i64;
    }

    let msg_cursor = Message::collection(db)
        .find(doc! {
            "deleted": { "$ne": true },
            "fileUrl": { "$regex": "^attachments/" },
        })
        .await?;
    let messages: Vec<Message> = msg_cursor.try_collect().await?;
    for msg in messages {
        let Some(size) = msg.file_size else {
            continue;
        };
        *usage.entry(msg.sender).or_insert(0) += size as i64;
    }

    let mut updated = 0u64;
    for (user_id, bytes) in usage {
        UserStorageUsage::set_bytes(db, user_id, bytes).await?;
        updated += 1;
    }

    Ok(updated)
}
