use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, DateTime};
use mongodb::Database;

use crate::model::channel_model::Channel;
use crate::model::channel_read_state_model::ChannelReadState;
use crate::model::channel_report_model::ChannelReport;
use crate::model::friend_request_model::FriendRequest;
use crate::model::invite_model::Invite;
use crate::model::messages_model::Message;
use crate::model::pending_upload_model::PendingUpload;
use crate::model::refresh_token_model::RefreshToken;
use crate::model::user_model::User;
use crate::model::warning_model::Warning;
use crate::utils::storage::{avatar_key_owned_by_channel, storage};
use crate::utils::whitelist::is_whitelist_enabled;
use crate::ws::registry::disconnect_user;

pub const DELETION_GRACE_DAYS: i64 = 7;

/// Przy włączonej whitelistcie: zatwierdza konta sprzed wprowadzenia pola isWhitelisted.
pub async fn reconcile_whitelist_fields(db: &Database) -> Result<u64, mongodb::error::Error> {
    if !is_whitelist_enabled() {
        return Ok(0);
    }

    let legacy = User::collection(db)
        .update_many(
            doc! { "isWhitelisted": { "$exists": false } },
            doc! { "$set": { "isWhitelisted": true } },
        )
        .await?;

    Ok(legacy.modified_count)
}

pub async fn repair_broken_account_status_fields(db: &Database) -> Result<u64, mongodb::error::Error> {
    let result = User::collection(db)
        .update_many(
            doc! { "isDisabled": mongodb::bson::Bson::Null },
            doc! {
                "$set": { "isDisabled": false },
                "$unset": { "disabledAt": "" },
            },
        )
        .await?;
    Ok(result.modified_count)
}

#[derive(Debug, Default, Clone, Copy)]
pub struct PurgeRemovedSchemaReport {
    pub users_modified: u64,
    pub messages_modified: u64,
    pub e2e_keys_dropped: bool,
}

/// Strip obsolete E2E / panel-admin fields left in Mongo after those features were removed.
pub async fn purge_removed_schema_fields(
    db: &Database,
) -> Result<PurgeRemovedSchemaReport, mongodb::error::Error> {
    let mut report = PurgeRemovedSchemaReport::default();

    let users = User::collection(db)
        .update_many(
            doc! {
                "$or": [
                    { "e2eEnabled": { "$exists": true } },
                    { "role": { "$exists": true } },
                    { "isAdmin": { "$exists": true } },
                    { "listeningActivity": { "$exists": true } },
                    { "shareListening": { "$exists": true } },
                    { "connectedAccounts": { "$exists": true } },
                ]
            },
            doc! {
                "$unset": {
                    "e2eEnabled": "",
                    "role": "",
                    "isAdmin": "",
                    "listeningActivity": "",
                    "shareListening": "",
                    "connectedAccounts": "",
                }
            },
        )
        .await?;
    report.users_modified = users.modified_count;

    let messages = Message::collection(db)
        .update_many(
            doc! {
                "$or": [
                    { "e2eEncrypted": { "$exists": true } },
                    { "e2eVersion": { "$exists": true } },
                ]
            },
            doc! {
                "$unset": {
                    "e2eEncrypted": "",
                    "e2eVersion": "",
                }
            },
        )
        .await?;
    report.messages_modified = messages.modified_count;

    for collection_name in ["e2e_keys", "oauth_tokens", "push_tokens"] {
        let collection = db.collection::<mongodb::bson::Document>(collection_name);
        match collection.drop().await {
            Ok(()) => {
                if collection_name == "e2e_keys" {
                    report.e2e_keys_dropped = true;
                }
            }
            Err(e) => {
                // NamespaceNotFound is fine when the collection was never created / already gone.
                let msg = e.to_string();
                if !msg.contains("NamespaceNotFound") && !msg.contains("ns not found") {
                    return Err(e);
                }
            }
        }
    }

    Ok(report)
}

async fn delete_message_attachment(storage: &crate::utils::storage::R2Storage, path: &str) {
    let _ = storage.delete_attachment_key(path).await;
    if path.starts_with('/') {
        let _ = storage.delete_attachment_key(&path[1..]).await;
    }
}

async fn delete_user_storage_files(user: &User, user_id: ObjectId, db: &Database) {
    let storage = storage();

    if let Some(image) = user.image.as_deref() {
        let _ = storage.delete_avatar_key(image).await;
    }
    if let Some(banner) = user.banner.as_deref() {
        let _ = storage.delete_public_media_key(banner).await;
    }

    let owned_channels: Vec<Channel> = match Channel::collection(db)
        .find(doc! { "admin": user_id })
        .await
    {
        Ok(cursor) => cursor.try_collect().await.unwrap_or_default(),
        Err(_) => Vec::new(),
    };
    let owned_channel_ids: Vec<ObjectId> = owned_channels
        .iter()
        .filter_map(|channel| channel.id)
        .collect();

    for channel in &owned_channels {
        if channel.image.is_empty() {
            continue;
        }
        let channel_id = channel.id.map(|id| id.to_hex()).unwrap_or_default();
        if avatar_key_owned_by_channel(&channel.image, &channel_id) {
            let _ = storage.delete_avatar_key(&channel.image).await;
        }
    }

    if let Ok(cursor) = PendingUpload::collection(db)
        .find(doc! { "userId": user_id })
        .await
    {
        if let Ok(entries) = cursor.try_collect::<Vec<PendingUpload>>().await {
            for entry in entries {
                let _ = storage.delete_attachment_key(&entry.file_path).await;
            }
        }
    }

    let mut attachment_filter = vec![
        doc! { "sender": user_id },
        doc! { "recipient": user_id },
    ];
    if !owned_channel_ids.is_empty() {
        attachment_filter.push(doc! { "channel": { "$in": &owned_channel_ids } });
    }

    if let Ok(cursor) = Message::collection(db)
        .find(doc! {
            "$or": attachment_filter,
            "fileUrl": { "$exists": true, "$ne": null },
        })
        .await
    {
        if let Ok(messages) = cursor.try_collect::<Vec<Message>>().await {
            for message in messages {
                if let Some(path) = message.file_url.as_deref() {
                    delete_message_attachment(&storage, path).await;
                }
            }
        }
    }
}

async fn purge_user_related_records(db: &Database, user_id: ObjectId) {
    let _ = RefreshToken::revoke_all_for_user(db, user_id).await;
    let _ = Warning::collection(db)
        .delete_many(doc! { "userId": user_id })
        .await;
    let _ = PendingUpload::collection(db)
        .delete_many(doc! { "userId": user_id })
        .await;
    let _ = db
        .collection::<mongodb::bson::Document>("user_storage_usage")
        .delete_many(doc! { "userId": user_id })
        .await;
    let _ = ChannelReadState::collection(db)
        .delete_many(doc! { "userId": user_id })
        .await;
    let _ = ChannelReport::collection(db)
        .delete_many(doc! { "reportedBy": user_id })
        .await;
}

pub async fn purge_user_data(
    db: &Database,
    user_id: ObjectId,
) -> Result<u64, mongodb::error::Error> {
    Message::collection(db)
        .delete_many(doc! {
            "$or": [
                { "sender": user_id },
                { "recipient": user_id },
            ],
        })
        .await?;

    FriendRequest::collection(db)
        .delete_many(doc! {
            "$or": [
                { "from": user_id },
                { "to": user_id },
            ],
        })
        .await?;

    Invite::collection(db)
        .delete_many(doc! { "createdBy": user_id })
        .await?;

    Channel::collection(db)
        .update_many(
            doc! { "members": user_id },
            doc! { "$pull": { "members": user_id } },
        )
        .await?;

    let owned: Vec<ObjectId> = Channel::collection(db)
        .find(doc! { "admin": user_id })
        .await?
        .try_collect::<Vec<Channel>>()
        .await?
        .into_iter()
        .filter_map(|c| c.id)
        .collect();

    let channels_deleted = owned.len() as u64;
    if !owned.is_empty() {
        Message::collection(db)
            .delete_many(doc! { "channel": { "$in": &owned } })
            .await?;
        Invite::collection(db)
            .delete_many(doc! { "channelId": { "$in": &owned } })
            .await?;
        Channel::collection(db)
            .delete_many(doc! { "_id": { "$in": &owned } })
            .await?;
    }

    User::collection(db)
        .delete_one(doc! { "_id": user_id })
        .await?;

    Ok(channels_deleted)
}

pub async fn purge_user_completely(
    db: &Database,
    user_id: ObjectId,
) -> Result<u64, mongodb::error::Error> {
    let user = User::find_by_id(db, user_id).await?.ok_or_else(|| {
        mongodb::error::Error::custom("User not found for purge")
    })?;

    delete_user_storage_files(&user, user_id, db).await;
    purge_user_related_records(db, user_id).await;
    disconnect_user(&user_id.to_hex());
    purge_user_data(db, user_id).await
}

pub async fn process_scheduled_deletions(db: &Database) -> Result<u64, mongodb::error::Error> {
    let now = DateTime::now();
    let users: Vec<User> = User::collection(db)
        .find(doc! {
            "deletionScheduledAt": { "$lte": now },
        })
        .await?
        .try_collect()
        .await?;

    let mut deleted = 0u64;
    for user in users {
        let Some(user_id) = user.id else { continue };
        match purge_user_completely(db, user_id).await {
            Ok(_) => {
                deleted += 1;
                log::info!("Auto-deleted user account {}", user_id.to_hex());
            }
            Err(e) => {
                log::error!(
                    "Failed to auto-delete user {}: {e}",
                    user_id.to_hex()
                );
            }
        }
    }

    Ok(deleted)
}
