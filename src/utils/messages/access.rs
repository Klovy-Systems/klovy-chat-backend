use mongodb::bson::oid::ObjectId;
use mongodb::Database;

use crate::model::pending_upload_model::PendingUpload;
use crate::model::messages_model::Message;
use crate::utils::access::membership_gate::{
    require_channel_message_access, require_dm_access, require_message_participant,
};
use crate::utils::friends::try_are_friends;
use crate::utils::storage::{
    attachment_path_matches_channel, attachment_path_matches_dm, is_attachment_key,
    is_logical_message_path, is_safe_key, storage,
};
use crate::utils::validators::external_url::is_allowed_external_media_url;

#[derive(Debug, Clone)]
pub enum QuoteContext {
    Dm { contact_id: String },
    Channel { channel_id: String },
}

#[derive(Debug, Clone)]
pub enum AttachmentSendContext {
    Dm { recipient_id: String },
    Channel { channel_id: String },
}

pub async fn validate_quote_target(
    db: &Database,
    user_id: &str,
    quoted_message_id: &str,
    context: QuoteContext,
) -> Result<Option<Message>, ()> {
    validate_quote_target_with_access(db, user_id, quoted_message_id, context, false).await
}

/// When `access_already_checked`, skip membership/friend gates (caller already gated send).
pub async fn validate_quote_target_with_access(
    db: &Database,
    user_id: &str,
    quoted_message_id: &str,
    context: QuoteContext,
    access_already_checked: bool,
) -> Result<Option<Message>, ()> {
    let Ok(qid) = ObjectId::parse_str(quoted_message_id) else {
        return Ok(None);
    };

    let quoted = match Message::find_by_id(db, qid).await {
        Ok(Some(m)) => m,
        Ok(None) => return Ok(None),
        Err(_) => return Err(()),
    };
    if quoted.deleted {
        return Ok(None);
    }

    match context {
        QuoteContext::Dm { contact_id } => {
            let sender = quoted.sender.to_hex();
            let recipient = quoted.recipient.map(|r| r.to_hex()).unwrap_or_default();
            let in_conv = (sender == user_id && recipient == contact_id)
                || (sender == contact_id && recipient == user_id);
            if !in_conv || quoted.recipient.is_none() {
                return Ok(None);
            }
            if !access_already_checked {
                match require_dm_access(db, user_id, &contact_id).await {
                    Ok(()) => {}
                    Err(crate::utils::access::membership_gate::AccessDeniedReason::Unavailable) => {
                        return Err(());
                    }
                    Err(_) => return Ok(None),
                }
            }
            Ok(Some(quoted))
        }
        QuoteContext::Channel { channel_id } => {
            if quoted.channel.map(|c| c.to_hex()) != Some(channel_id.clone()) {
                return Ok(None);
            }
            if !access_already_checked {
                match require_channel_message_access(db, &channel_id, user_id).await {
                    Ok(_) => {}
                    Err(crate::utils::access::membership_gate::AccessDeniedReason::Unavailable) => {
                        return Err(());
                    }
                    Err(_) => return Ok(None),
                }
            }
            Ok(Some(quoted))
        }
    }
}

pub async fn can_react_to_message(db: &Database, user_id: &str, msg: &Message) -> bool {
    require_message_participant(db, user_id, msg).await.is_ok()
}

pub async fn can_mark_message_as_read(db: &Database, user_id: &str, msg: &Message) -> bool {
    matches!(try_can_mark_message_as_read(db, user_id, msg).await, Ok(true))
}

pub async fn try_can_mark_message_as_read(
    db: &Database,
    user_id: &str,
    msg: &Message,
) -> Result<bool, ()> {
    if msg.deleted || msg.read || msg.channel.is_some() {
        return Ok(false);
    }
    let Some(recipient) = msg.recipient else {
        return Ok(false);
    };
    if recipient.to_hex() != user_id {
        return Ok(false);
    }
    try_are_friends(db, user_id, &msg.sender.to_hex()).await
}

fn attachment_matches_send_context(
    path: &str,
    user_id: &str,
    context: &AttachmentSendContext,
) -> bool {
    match context {
        AttachmentSendContext::Dm { recipient_id } => {
            attachment_path_matches_dm(path, user_id, recipient_id)
        }
        AttachmentSendContext::Channel { channel_id } => {
            attachment_path_matches_channel(path, channel_id)
        }
    }
}

pub fn user_owns_message_file_url(user_id: &str, file_url: &str) -> bool {
    let normalized = file_url.trim().replace('\\', "/");
    if normalized.is_empty() {
        return true;
    }
    if normalized.starts_with("http://") || normalized.starts_with("https://") {
        return is_allowed_external_media_url(&normalized);
    }

    let path = normalized.trim_start_matches('/');
    is_safe_key(path) && is_attachment_key(path) && !user_id.is_empty()
}

pub fn validate_message_file_url(user_id: &str, file_url: &Option<String>) -> bool {
    match file_url {
        None => true,
        Some(url) if url.trim().is_empty() => true,
        Some(url) => user_owns_message_file_url(user_id, url),
    }
}

pub async fn cleanup_attachment_if_unreferenced(db: &Database, file_url: Option<&str>) {
    let Some(url) = file_url else {
        return;
    };
    let path = url.trim().replace('\\', "/").trim_start_matches('/').to_string();
    if !is_attachment_key(&path) {
        return;
    }

    let with_slash = format!("/{path}");
    let count = Message::collection(db)
        .count_documents(mongodb::bson::doc! {
            "deleted": { "$ne": true },
            "fileUrl": { "$in": [&path, with_slash] },
        })
        .await
        .unwrap_or(1);

    if count == 0 {
        let owner = find_attachment_uploader(db, &path).await;
        let size = storage()
            .head_public_content_length(&path)
            .await
            .ok()
            .flatten()
            .unwrap_or(0);
        let thumb_bytes = if let Some(thumb) = crate::utils::storage::attachment_thumb_key(&path)
        {
            storage()
                .head_public_content_length(&thumb)
                .await
                .ok()
                .flatten()
                .unwrap_or(0)
        } else {
            0
        };

        let _ = storage().delete_attachment_key(&path).await;

        if let Some((user_id, bytes)) = owner {
            let measured = size.saturating_add(thumb_bytes);
            let decrement = if bytes > 0 {
                bytes as i64
            } else {
                measured as i64
            };
            if decrement > 0 {
                let _ = crate::model::user_storage_usage_model::UserStorageUsage::adjust(
                    db, user_id, -decrement,
                )
                .await;
            }
        }
    }
}

async fn find_attachment_uploader(db: &Database, path: &str) -> Option<(ObjectId, u64)> {
    if let Ok(Some(pending)) = PendingUpload::collection(db)
        .find_one(mongodb::bson::doc! { "filePath": path })
        .await
    {
        return Some((pending.user_id, pending.file_size));
    }

    let with_slash = format!("/{path}");
    let message = Message::collection(db)
        .find_one(mongodb::bson::doc! {
            "fileUrl": { "$in": [path, with_slash] },
        })
        .await
        .ok()
        .flatten()?;

    Some((message.sender, message.file_size.unwrap_or(0)))
}

async fn attachment_stored_size_is_valid(
    path: &str,
    claimed_size: Option<u64>,
    pending_size: Option<u64>,
) -> bool {
    let ext = path.rsplit('.').next().unwrap_or("");
    let is_image = matches!(
        ext.to_ascii_lowercase().as_str(),
        "jpg" | "jpeg" | "png" | "webp"
    );

    // Non-image: pending size already verified at upload — skip R2 HEAD on send FIFO.
    if !is_image {
        if let (Some(claimed), Some(expected)) = (claimed_size, pending_size) {
            if expected > 0
                && claimed == expected
                && expected <= crate::utils::upload_limits::MAX_ATTACHMENT_BYTES
            {
                return true;
            }
        }
    }

    let actual = match storage().head_public_content_length(path).await {
        Ok(Some(len)) => len,
        _ => return false,
    };

    let max_bytes = if is_image {
        crate::utils::upload_limits::MAX_IMAGE_ATTACHMENT_BYTES
    } else {
        crate::utils::upload_limits::MAX_ATTACHMENT_BYTES
    };
    if actual > max_bytes {
        return false;
    }

    if let Some(expected) = pending_size {
        if expected > 0 {
            // Pending size for images includes the thumbnail object bytes.
            if is_image {
                if expected < actual {
                    return false;
                }
            } else if actual != expected {
                return false;
            }
        }
    }

    let Some(claimed) = claimed_size else {
        return true;
    };

    // Obrazy są re-enkodowane po stronie serwera do webp, więc zapisany rozmiar
    // różni się od pierwotnego rozmiaru z klienta — nie porównujemy z „claimed"
    // (dokładny rozmiar jest już zweryfikowany powyżej przez pending_size).
    if is_image {
        return true;
    }

    if actual > claimed {
        return false;
    }

    actual == claimed
}

pub async fn claim_pending_upload(user_id: &str, file_url: &Option<String>) {
    let Some(url) = file_url else {
        return;
    };
    let path = url.trim().replace('\\', "/").trim_start_matches('/').to_string();
    if !is_logical_message_path(&path) {
        return;
    }
    let Ok(user_oid) = ObjectId::parse_str(user_id) else {
        return;
    };
    let db = crate::utils::db::get_db();
    let _ = PendingUpload::claim_by_path(&db, user_oid, &path).await;
}

pub async fn validate_message_attachment(
    db: &Database,
    user_id: &str,
    file_url: &Option<String>,
    file_size: Option<u64>,
    send_context: Option<AttachmentSendContext>,
) -> bool {
    if !validate_message_file_url(user_id, file_url) {
        return false;
    }

    match file_url {
        None => true,
        Some(url) if url.trim().is_empty() => true,
        Some(url) => {
            if file_size
                .map(|size| size > crate::utils::upload_limits::MAX_ATTACHMENT_BYTES)
                .unwrap_or(false)
            {
                // Client-reported size is pre-encode; images are capped separately on upload.
                let path = url.trim().replace('\\', "/");
                let ext = path.rsplit('.').next().unwrap_or("");
                let is_image = matches!(
                    ext.to_ascii_lowercase().as_str(),
                    "jpg" | "jpeg" | "png" | "webp"
                );
                if !is_image {
                    return false;
                }
            }

            if url.starts_with("http://") || url.starts_with("https://") {
                return is_allowed_external_media_url(url);
            }

            let path = url.trim().replace('\\', "/").trim_start_matches('/').to_string();
            if !is_attachment_key(&path) {
                return false;
            }

            let Some(send_context) = send_context else {
                return false;
            };
            if !attachment_matches_send_context(&path, user_id, &send_context) {
                return false;
            }

            let Ok(user_oid) = ObjectId::parse_str(user_id) else {
                return false;
            };

            let pending = match PendingUpload::find_for_user_and_path(db, user_oid, &path).await {
                Ok(Some(entry)) => entry,
                _ => return false,
            };

            let context_ok = match send_context {
                AttachmentSendContext::Dm { recipient_id } => {
                    pending.context_type == "dm" && pending.context_id == recipient_id
                }
                AttachmentSendContext::Channel { channel_id } => {
                    pending.context_type == "channel" && pending.context_id == channel_id
                }
            };
            if !context_ok {
                return false;
            }

            if pending.file_hash.is_empty() {
                return false;
            }

            if !attachment_stored_size_is_valid(&path, file_size, Some(pending.file_size)).await {
                return false;
            }

            // Pending upload already stored SHA at upload time + size matches —
            // skip full R2 download/hash on the send hot path (holds user FIFO).
            true
        }
    }
}
