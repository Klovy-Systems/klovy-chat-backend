use actix_multipart::form::{tempfile::TempFile, text::Text, MultipartForm};
use actix_web::{web, HttpRequest, HttpResponse};
use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, DateTime};
use serde::Deserialize;
use serde_json::json;

use crate::middlewares::auth_middleware::request_user_id;
use crate::model::channel_model::Channel;
use crate::model::messages_model::{is_message_content_within_limit, Message};
use crate::model::pending_upload_model::PendingUpload;
use crate::utils::messages::mentions::{has_everyone_mention, resolve_mentions};
use crate::model::user_storage_usage_model::UserStorageUsage;
use crate::utils::file_hash::sha256_hex;
use crate::model::user_model::User;
use crate::utils::attachment_audit::log_attachment_upload;
use crate::utils::access::membership_gate::{authorize_dm_history_read, require_message_participant};
use crate::utils::db::get_db;
use crate::utils::image_reencode::{
    reencode_error_message, reencode_upload_to_webp_variants,
};
use crate::utils::messages::{
    access::cleanup_attachment_if_unreferenced,
    can_access_channel_messages, can_access_dm_messages, can_pin_message, dm_conversation_base_clauses,
    serialize_message, serialize_messages_batch, validate_dm_history_before_cursor,
    message_belongs_to_dm_conversation,
};
use crate::utils::messages::content_storage::inbound_plaintext_for_processing;
use crate::utils::messages::search_text::{search_regex_pattern, search_text_from_incoming};
use crate::utils::storage::{
    attachment_dm_key, attachment_group_key, attachment_thumb_key, storage,
};
use crate::utils::ratelimit::try_consume_chat_attachment_quota;
use crate::utils::upload_limits::{
    file_bytes_within_limit, is_image_extension, local_file_size, MAX_ATTACHMENT_BYTES,
    MAX_CHAT_ATTACHMENTS_PER_WINDOW, MAX_IMAGE_ATTACHMENT_BYTES, CHAT_ATTACHMENT_WINDOW_SECS,
};
use crate::utils::validators::archive_validation::validate_upload_document;
use crate::utils::validators::file_magic::{resolve_upload_content_type, validate_file_magic};
use crate::utils::link_preview::{fetch_link_preview, is_safe_preview_target};
use crate::utils::ratelimit::Store;
use once_cell::sync::Lazy;
use std::time::Duration;

static LINK_PREVIEW_LIMIT: Lazy<Store> = Lazy::new(|| Store::new(40, Duration::from_secs(60)));

const SEARCH_LIMIT: i64 = 50;
const MIN_QUERY_LENGTH: usize = 2;

/// Domyślna i maksymalna liczba wiadomości zwracanych na jedną stronę historii DM.
const DEFAULT_MESSAGE_LIMIT: i64 = 30;
const MAX_MESSAGE_LIMIT: i64 = 50;
const MAX_PINNED_MESSAGES: i64 = 50;

const ALLOWED_EXTENSIONS: &[&str] = &[
    "pdf", "jpg", "jpeg", "png", "webp", "docx", "xlsx", "txt", "webm", "ogg", "wav", "mp4", "m4a",
];

async fn serialize_all(db: &mongodb::Database, msgs: &[Message]) -> Vec<serde_json::Value> {
    serialize_messages_batch(db, msgs).await
}

#[derive(Deserialize)]
pub struct GetMessagesBody {
    pub id: Option<String>,
    /// Liczba wiadomości na stronę (domyślnie 50, maks. 100).
    #[serde(default)]
    pub limit: Option<i64>,
    /// Kursor: pobiera wiadomości starsze niż wskazane `_id` (paginacja w górę).
    #[serde(default)]
    pub before: Option<String>,
}

pub async fn get_messages(req: HttpRequest, body: web::Json<GetMessagesBody>) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({
            "error": "UNAUTHORIZED",
            "message": "Authentication required.",
        }));
    };
    let contact_id = body.id.clone().unwrap_or_default();

    if contact_id.is_empty() {
        return HttpResponse::BadRequest().json(json!({
            "error": "INVALID_REQUEST",
            "message": "Contact id is required.",
        }));
    }

    let db = get_db();
    let (user_oid, contact_oid) = match authorize_dm_history_read(&db, &user_id, &contact_id).await {
        Ok(pair) => pair,
        Err(reason) => {
            return HttpResponse::Forbidden().json(json!({
                "error": "ACCESS_DENIED",
                "message": reason.as_str(),
            }));
        }
    };

    let limit = body
        .limit
        .unwrap_or(DEFAULT_MESSAGE_LIMIT)
        .clamp(1, MAX_MESSAGE_LIMIT);

    let mut and_clauses = dm_conversation_base_clauses(user_oid, contact_oid);

    if let Some(before_id) = body.before.as_deref().filter(|s| !s.is_empty()) {
        let Ok(before_oid) =
            validate_dm_history_before_cursor(&db, user_oid, contact_oid, before_id).await
        else {
            return HttpResponse::BadRequest().json(json!({
                "error": "INVALID_CURSOR",
                "message": "Invalid pagination cursor.",
            }));
        };
        and_clauses.push(doc! { "_id": { "$lt": before_oid } });
    }

    let filter = doc! { "$and": and_clauses };

    // Pobierz najnowszą stronę (malejąco), a następnie odwróć do porządku rosnącego
    // do wyświetlenia. Pobieramy limit+1, aby wykryć czy są starsze wiadomości.
    let mut messages: Vec<Message> = match Message::collection(&db)
        .find(filter)
        .sort(doc! { "_id": -1 })
        .limit(limit + 1)
        .await
    {
        Ok(c) => c.try_collect().await.unwrap_or_default(),
        Err(_) => return HttpResponse::InternalServerError().body("Internal Server Error"),
    };

    let has_more = messages.len() as i64 > limit;
    if has_more {
        messages.truncate(limit as usize);
    }
    // Defense-in-depth: never return messages outside this DM pair.
    messages.retain(|m| message_belongs_to_dm_conversation(m, user_oid, contact_oid));
    messages.reverse();

    let out = serialize_all(&db, &messages).await;
    HttpResponse::Ok().json(json!({ "messages": out, "hasMore": has_more }))
}

#[derive(MultipartForm)]
pub struct UploadFileForm {
    #[multipart(rename = "file", limit = "10 MiB")]
    pub file: TempFile,
    #[multipart(rename = "contextType")]
    pub context_type: Text<String>,
    #[multipart(rename = "contextId")]
    pub context_id: Text<String>,
    #[multipart(rename = "contentType")]
    pub content_type: Option<Text<String>>,
}

pub async fn upload_file(req: HttpRequest, form: MultipartForm<UploadFileForm>) -> HttpResponse {
    let original_name = form
        .file
        .file_name
        .as_deref()
        .map(|n| n.rsplit(['/', '\\']).next().unwrap_or(n).to_string())
        .unwrap_or_default();

    if original_name.is_empty() {
        return HttpResponse::BadRequest().body("File is required.");
    }

    let ext = original_name
        .rsplit('.')
        .next()
        .map(|e| e.to_lowercase())
        .unwrap_or_default();

    if !ALLOWED_EXTENSIONS.contains(&ext.as_str()) {
        return HttpResponse::BadRequest().body("Invalid file type.");
    }
    if !validate_file_magic(form.file.file.path(), &ext) {
        return HttpResponse::BadRequest().body("Invalid file content.");
    }
    if matches!(ext.as_str(), "pdf" | "docx" | "xlsx")
        && !validate_upload_document(form.file.file.path(), &ext)
    {
        return HttpResponse::BadRequest().body("Invalid file content.");
    }

    let is_image = is_image_extension(&ext);
    let max_upload_bytes = if is_image {
        MAX_IMAGE_ATTACHMENT_BYTES
    } else {
        MAX_ATTACHMENT_BYTES
    };
    if local_file_size(form.file.file.path())
        .map(|size| !file_bytes_within_limit(size, max_upload_bytes))
        .unwrap_or(true)
    {
        let limit_mb = max_upload_bytes / (1024 * 1024);
        return HttpResponse::PayloadTooLarge()
            .body(format!("File too large. Maximum size is {limit_mb} MB."));
    }

    if original_name.contains("..") || original_name.contains('/') || original_name.contains('\\') {
        return HttpResponse::BadRequest().body("Invalid file name.");
    }

    let user_id = request_user_id(&req).unwrap_or_default();
    if user_id.is_empty() {
        return HttpResponse::Unauthorized().body("Authentication required.");
    }

    let Ok(user_oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::BadRequest().body("Invalid user.");
    };

    let context_type = form.context_type.0.trim().to_ascii_lowercase();
    let context_id = form.context_id.0.trim().to_string();
    if context_id.is_empty() {
        return HttpResponse::BadRequest().body("Upload context is required.");
    }

    let db = get_db();

    if matches!(context_type.as_str(), "dm" | "channel") {
        if let Err(retry_after) = try_consume_chat_attachment_quota(&user_id) {
            let window_minutes = CHAT_ATTACHMENT_WINDOW_SECS / 60;
            return HttpResponse::TooManyRequests().json(json!({
                "error": "CHAT_ATTACHMENT_LIMIT",
                "message": format!(
                    "Osiągnięto limit {} załączników na {} minut. Spróbuj ponownie później.",
                    MAX_CHAT_ATTACHMENTS_PER_WINDOW,
                    window_minutes,
                ),
                "retryAfter": retry_after,
            }));
        }
    }

    let stored_ext = if is_image { "webp" } else { ext.as_str() };

    let logical_path = match context_type.as_str() {
        "dm" => {
            if ObjectId::parse_str(&context_id).is_err() {
                return HttpResponse::BadRequest().body("Invalid contact ID.");
            }
            if !can_access_dm_messages(&db, &user_id, &context_id).await {
                return HttpResponse::Forbidden().body("You cannot upload to this conversation.");
            }
            let filename = format!("{}.{}", uuid::Uuid::new_v4(), stored_ext);
            attachment_dm_key(&user_id, &context_id, &filename)
        }
        "channel" => {
            if ObjectId::parse_str(&context_id).is_err() {
                return HttpResponse::BadRequest().body("Invalid channel ID.");
            }
            if can_access_channel_messages(&db, &user_id, &context_id)
                .await
                .is_none()
            {
                return HttpResponse::Forbidden().body("You cannot upload to this channel.");
            }
            let filename = format!("{}.{}", uuid::Uuid::new_v4(), stored_ext);
            attachment_group_key(&context_id, &filename)
        }
        _ => return HttpResponse::BadRequest().body("Invalid upload context."),
    };

    let (body, thumb_body) = if is_image {
        match reencode_upload_to_webp_variants(form.file.file.path()) {
            Ok(variants) => (variants.full, Some(variants.thumb)),
            Err(err) => return HttpResponse::BadRequest().body(reencode_error_message(&err)),
        }
    } else {
        match std::fs::read(form.file.file.path()) {
            Ok(bytes) => (bytes, None),
            Err(_) => return HttpResponse::InternalServerError().body("Internal Server Error."),
        }
    };

    let thumb_size = thumb_body.as_ref().map(|b| b.len() as u64).unwrap_or(0);
    let file_size = body.len() as u64;
    let total_stored = file_size.saturating_add(thumb_size);

    if !file_bytes_within_limit(file_size, max_upload_bytes) {
        let limit_mb = max_upload_bytes / (1024 * 1024);
        return HttpResponse::PayloadTooLarge()
            .body(format!("File too large. Maximum size is {limit_mb} MB."));
    }

    if UserStorageUsage::would_exceed(&db, user_oid, total_stored)
        .await
        .unwrap_or(true)
    {
        return HttpResponse::PayloadTooLarge().body(
            "Storage quota exceeded. Delete old attachments or wait for cleanup.",
        );
    }

    let file_hash = sha256_hex(&body);
    let client_mime = form.content_type.as_ref().map(|value| value.0.as_str());
    let content_type = resolve_upload_content_type(stored_ext, client_mime, &body);
    if storage()
        .put_public(&logical_path, body, &content_type)
        .await
        .is_err()
    {
        return HttpResponse::InternalServerError().body("Internal Server Error.");
    }

    let thumb_path = attachment_thumb_key(&logical_path);
    if let (Some(thumb_bytes), Some(thumb_key)) = (thumb_body, thumb_path.as_ref()) {
        if storage()
            .put_public(thumb_key, thumb_bytes, "image/webp")
            .await
            .is_err()
        {
            let _ = storage().delete_public(&logical_path).await;
            return HttpResponse::InternalServerError().body("Internal Server Error.");
        }
    }

    if PendingUpload::register(
        &db,
        user_oid,
        &logical_path,
        &context_type,
        &context_id,
        total_stored,
        &file_hash,
    )
    .await
    .is_err()
    {
        let _ = storage().delete_attachment_key(&logical_path).await;
        if PendingUpload::count_for_user(&db, user_oid)
            .await
            .map(|count| count >= crate::utils::upload_limits::MAX_PENDING_UPLOADS_PER_USER)
            .unwrap_or(false)
        {
            return HttpResponse::TooManyRequests()
                .body("Too many pending uploads. Send or wait before uploading more.");
        }
        return HttpResponse::InternalServerError().body("Internal Server Error.");
    }

    if UserStorageUsage::adjust(&db, user_oid, total_stored as i64)
        .await
        .is_err()
    {
        let _ = storage().delete_attachment_key(&logical_path).await;
        let _ = PendingUpload::claim_by_path(&db, user_oid, &logical_path).await;
        return HttpResponse::InternalServerError().body("Internal Server Error.");
    }

    log_attachment_upload(
        &req,
        &user_id,
        &logical_path,
        &context_type,
        &context_id,
        file_size,
    )
    .await;

    HttpResponse::Ok().json(json!({ "filePath": logical_path }))
}

#[derive(Deserialize)]
pub struct EditMessageBody {
    pub content: Option<String>,
}

pub async fn edit_message(req: HttpRequest, body: web::Json<EditMessageBody>) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };
    let message_id = req.match_info().get("messageId").unwrap_or("");
    let Ok(mid) = ObjectId::parse_str(message_id) else {
        return HttpResponse::NotFound().json(json!({ "error": "Message not found" }));
    };

    let db = get_db();

    if let Ok(uid) = ObjectId::parse_str(&user_id) {
        match User::find_by_id(&db, uid).await {
            Ok(Some(u)) if u.is_login_allowed() => {}
            Ok(Some(_)) => {
                return HttpResponse::Forbidden()
                    .json(json!({ "error": "Account is inactive or blocked" }))
            }
            _ => return HttpResponse::Unauthorized().json(json!({ "error": "User not found" })),
        }
    }

    let message = match Message::find_by_id(&db, mid).await {
        Ok(Some(m)) => m,
        Ok(None) => return HttpResponse::NotFound().json(json!({ "error": "Message not found" })),
        Err(_) => return HttpResponse::InternalServerError().json(json!({ "error": "Internal server error" })),
    };

    if message.sender.to_hex() != user_id {
        return HttpResponse::Forbidden()
            .json(json!({ "error": "Not authorized to edit this message" }));
    }

    if let Err(reason) = require_message_participant(&db, &user_id, &message).await {
        return HttpResponse::Forbidden().json(json!({ "error": reason.as_str() }));
    }

    let content = crate::utils::validators::sanitize_input::sanitize_message_content(
        body.content.as_deref().unwrap_or(""),
    );
    let content = inbound_plaintext_for_processing(&content, false);

    if content.trim().is_empty() {
        return HttpResponse::BadRequest().json(json!({ "error": "Treść wiadomości jest wymagana" }));
    }
    if !is_message_content_within_limit(&content) {
        return HttpResponse::BadRequest()
            .json(json!({ "error": "Wiadomość nie może przekraczać 2000 znaków" }));
    }

    // Przelicz wzmianki tak samo jak ścieżka WS, aby dane nie były nieaktualne po edycji.
    let (mentions, mentions_everyone) = if let Some(channel_id) = message.channel {
        match Channel::find_by_id(&db, channel_id).await.ok().flatten() {
            Some(channel) => {
                let mut ids: Vec<String> = channel.members.iter().map(|m| m.to_hex()).collect();
                ids.push(channel.admin.to_hex());
                (
                    resolve_mentions(&db, &content, &ids).await,
                    has_everyone_mention(&content),
                )
            }
            None => (Vec::new(), false),
        }
    } else if let Some(recipient) = message.recipient {
        (
            resolve_mentions(&db, &content, &[message.sender.to_hex(), recipient.to_hex()]).await,
            false,
        )
    } else {
        (Vec::new(), false)
    };

    let mentions_bson =
        mongodb::bson::to_bson(&mentions).unwrap_or(mongodb::bson::Bson::Array(vec![]));
    let stored_content = match crate::utils::messages::content_storage::prepare_content_for_storage(
        content.trim(),
    ) {
        Ok(c) => c,
        Err(_) => return HttpResponse::InternalServerError().json(json!({ "error": "Internal server error" })),
    };
    let search_text = search_text_from_incoming(content.trim());
    let set_doc = doc! {
        "content": stored_content,
        "searchText": search_text,
        "mentions": mentions_bson,
        "mentionsEveryone": mentions_everyone,
        "edited": true,
        "editedAt": DateTime::now(),
        "updatedAt": DateTime::now(),
    };
    if Message::collection(&db)
        .update_one(
            doc! { "_id": mid },
            doc! { "$set": set_doc },
        )
        .await
        .is_err()
    {
        return HttpResponse::InternalServerError().json(json!({ "error": "Internal server error" }));
    }

    match Message::find_by_id(&db, mid).await {
        Ok(Some(updated)) => HttpResponse::Ok().json(json!({ "message": serialize_message(&db, &updated).await })),
        _ => HttpResponse::InternalServerError().json(json!({ "error": "Internal server error" })),
    }
}

pub async fn delete_message(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "User not authenticated" }));
    };
    let message_id = req.match_info().get("messageId").unwrap_or("");
    let Ok(mid) = ObjectId::parse_str(message_id) else {
        return HttpResponse::NotFound().json(json!({ "error": "Message not found" }));
    };

    let db = get_db();
    let message = match Message::find_by_id(&db, mid).await {
        Ok(Some(m)) => m,
        Ok(None) => return HttpResponse::NotFound().json(json!({ "error": "Message not found" })),
        Err(_) => return HttpResponse::InternalServerError().json(json!({ "error": "Internal server error" })),
    };

    if message.sender.to_hex() != user_id {
        return HttpResponse::Forbidden()
            .json(json!({ "error": "Not authorized to delete this message" }));
    }

    if let Err(reason) = require_message_participant(&db, &user_id, &message).await {
        return HttpResponse::Forbidden().json(json!({ "error": reason.as_str() }));
    }

    let _ = Message::soft_delete(&db, mid).await;
    cleanup_attachment_if_unreferenced(&db, message.file_url.as_deref()).await;
    HttpResponse::Ok().json(json!({ "success": true }))
}

pub async fn pin_message(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };
    let message_id = req.match_info().get("messageId").unwrap_or("");
    let Ok(mid) = ObjectId::parse_str(message_id) else {
        return HttpResponse::NotFound().json(json!({ "error": "Message not found" }));
    };

    let db = get_db();
    let message = match Message::find_by_id(&db, mid).await {
        Ok(Some(m)) if !m.deleted => m,
        _ => return HttpResponse::NotFound().json(json!({ "error": "Message not found" })),
    };

    if !can_pin_message(&db, &user_id, &message).await {
        return HttpResponse::Forbidden().json(json!({
            "error": "FORBIDDEN",
            "message": "Nie masz uprawnień do przypinania tej wiadomości.",
        }));
    }

    let Ok(user_oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::BadRequest().json(json!({ "error": "Invalid user id" }));
    };
    let _ = Message::collection(&db)
        .update_one(
            doc! { "_id": mid },
            doc! { "$set": {
                "pinned": true,
                "pinnedAt": DateTime::now(),
                "pinnedBy": user_oid,
                "updatedAt": DateTime::now(),
            }},
        )
        .await;

    match Message::find_by_id(&db, mid).await {
        Ok(Some(updated)) => HttpResponse::Ok().json(json!({ "message": serialize_message(&db, &updated).await })),
        _ => HttpResponse::InternalServerError().json(json!({ "error": "Internal Server Error" })),
    }
}

pub async fn unpin_message(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };
    let message_id = req.match_info().get("messageId").unwrap_or("");
    let Ok(mid) = ObjectId::parse_str(message_id) else {
        return HttpResponse::NotFound().json(json!({ "error": "Message not found" }));
    };

    let db = get_db();
    let message = match Message::find_by_id(&db, mid).await {
        Ok(Some(m)) if !m.deleted => m,
        _ => return HttpResponse::NotFound().json(json!({ "error": "Message not found" })),
    };

    if !can_pin_message(&db, &user_id, &message).await {
        return HttpResponse::Forbidden().json(json!({
            "error": "FORBIDDEN",
            "message": "Nie masz uprawnień do odpięcia tej wiadomości.",
        }));
    }

    let _ = Message::collection(&db)
        .update_one(
            doc! { "_id": mid },
            doc! {
                "$set": { "pinned": false, "updatedAt": DateTime::now() },
                "$unset": { "pinnedAt": "", "pinnedBy": "" },
            },
        )
        .await;

    match Message::find_by_id(&db, mid).await {
        Ok(Some(updated)) => HttpResponse::Ok().json(json!({ "message": serialize_message(&db, &updated).await })),
        _ => HttpResponse::InternalServerError().json(json!({ "error": "Internal Server Error" })),
    }
}

#[derive(Deserialize)]
pub struct PinnedBody {
    #[serde(rename = "contactId")]
    pub contact_id: Option<String>,
    #[serde(rename = "channelId")]
    pub channel_id: Option<String>,
}

pub async fn get_pinned_messages(req: HttpRequest, body: web::Json<PinnedBody>) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };

    let db = get_db();

    if let Some(channel_id) = body.channel_id.as_deref().filter(|s| !s.is_empty()) {
        if can_access_channel_messages(&db, &user_id, channel_id).await.is_none() {
            return HttpResponse::Forbidden().json(json!({ "error": "Access denied" }));
        }
        let Ok(channel_oid) = ObjectId::parse_str(channel_id) else {
            return HttpResponse::BadRequest().json(json!({ "error": "Invalid channel id" }));
        };
        let messages: Vec<Message> = match Message::collection(&db)
            .find(doc! { "channel": channel_oid, "pinned": true, "deleted": { "$ne": true } })
            .sort(doc! { "pinnedAt": -1 })
            .limit(MAX_PINNED_MESSAGES)
            .await
        {
            Ok(c) => c.try_collect().await.unwrap_or_default(),
            Err(_) => return HttpResponse::InternalServerError().json(json!({ "error": "Internal Server Error" })),
        };
        let out = serialize_all(&db, &messages).await;
        return HttpResponse::Ok().json(json!({ "messages": out }));
    }

    if let Some(contact_id) = body.contact_id.as_deref().filter(|s| !s.is_empty()) {
        let (uid, cid) = match authorize_dm_history_read(&db, &user_id, contact_id).await {
            Ok(pair) => pair,
            Err(_) => {
                return HttpResponse::Forbidden().json(json!({ "error": "Access denied" }));
            }
        };
        let filter = doc! {
            "$and": [
                { "$or": [
                    { "sender": uid, "recipient": cid },
                    { "sender": cid, "recipient": uid },
                ]},
                { "pinned": true },
                { "deleted": { "$ne": true } },
            ]
        };
        let messages: Vec<Message> = match Message::collection(&db)
            .find(filter)
            .sort(doc! { "pinnedAt": -1 })
            .limit(MAX_PINNED_MESSAGES)
            .await
        {
            Ok(c) => c.try_collect().await.unwrap_or_default(),
            Err(_) => return HttpResponse::InternalServerError().json(json!({ "error": "Internal Server Error" })),
        };
        let mut messages = messages;
        messages.retain(|m| message_belongs_to_dm_conversation(m, uid, cid));
        let out = serialize_all(&db, &messages).await;
        return HttpResponse::Ok().json(json!({ "messages": out }));
    }

    HttpResponse::BadRequest().json(json!({ "error": "contactId or channelId required" }))
}

#[derive(Deserialize)]
pub struct SearchMessagesBody {
    pub query: Option<String>,
    #[serde(rename = "contactId")]
    pub contact_id: Option<String>,
    #[serde(rename = "channelId")]
    pub channel_id: Option<String>,
}

pub async fn search_messages(req: HttpRequest, body: web::Json<SearchMessagesBody>) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };

    let trimmed = body.query.clone().unwrap_or_default().trim().to_string();
    if trimmed.chars().count() < MIN_QUERY_LENGTH {
        return HttpResponse::BadRequest().json(json!({
            "error": "QUERY_TOO_SHORT",
            "message": format!("Wpisz co najmniej {} znaki.", MIN_QUERY_LENGTH),
        }));
    }

    // Content is sealed at rest — match against server-only `searchText` index instead
    // of decrypting thousands of message bodies in memory.
    let pattern = search_regex_pattern(&trimmed);
    let db = get_db();

    if let Some(channel_id) = body.channel_id.as_deref().filter(|s| !s.is_empty()) {
        if can_access_channel_messages(&db, &user_id, channel_id).await.is_none() {
            return HttpResponse::Forbidden().json(json!({ "error": "Access denied" }));
        }
        let Ok(channel_oid) = ObjectId::parse_str(channel_id) else {
            return HttpResponse::BadRequest().json(json!({ "error": "Invalid channel id" }));
        };
        let filter = doc! {
            "channel": channel_oid,
            "deleted": { "$ne": true },
            "messageType": "TEXT",
            "searchText": { "$regex": &pattern },
        };
        let messages: Vec<Message> = match Message::collection(&db)
            .find(filter)
            .sort(doc! { "timestamp": -1 })
            .limit(SEARCH_LIMIT)
            .await
        {
            Ok(c) => c.try_collect().await.unwrap_or_default(),
            Err(_) => {
                return HttpResponse::InternalServerError()
                    .json(json!({ "error": "Internal Server Error" }))
            }
        };
        let out = serialize_all(&db, &messages).await;
        return HttpResponse::Ok().json(json!({ "messages": out }));
    }

    if let Some(contact_id) = body.contact_id.as_deref().filter(|s| !s.is_empty()) {
        let (uid, cid) = match authorize_dm_history_read(&db, &user_id, contact_id).await {
            Ok(pair) => pair,
            Err(_) => {
                return HttpResponse::Forbidden().json(json!({ "error": "Access denied" }));
            }
        };
        let filter = doc! {
            "$and": [
                { "$or": [
                    { "sender": uid, "recipient": cid },
                    { "sender": cid, "recipient": uid },
                ]},
                { "deleted": { "$ne": true } },
                { "messageType": "TEXT" },
                { "searchText": { "$regex": &pattern } },
            ]
        };
        let mut messages: Vec<Message> = match Message::collection(&db)
            .find(filter)
            .sort(doc! { "timestamp": -1 })
            .limit(SEARCH_LIMIT)
            .await
        {
            Ok(c) => c.try_collect().await.unwrap_or_default(),
            Err(_) => {
                return HttpResponse::InternalServerError()
                    .json(json!({ "error": "Internal Server Error" }))
            }
        };
        messages.retain(|m| message_belongs_to_dm_conversation(m, uid, cid));
        let out = serialize_all(&db, &messages).await;
        return HttpResponse::Ok().json(json!({ "messages": out }));
    }

    HttpResponse::BadRequest().json(json!({ "error": "contactId or channelId required" }))
}

#[derive(Deserialize)]
pub struct LinkPreviewBody {
    pub url: Option<String>,
}

pub async fn link_preview(req: HttpRequest, body: web::Json<LinkPreviewBody>) -> HttpResponse {
    let user_id = request_user_id(&req).unwrap_or_default();
    if user_id.is_empty() {
        return HttpResponse::Unauthorized().json(json!({
            "error": "UNAUTHORIZED",
            "message": "Authentication required.",
        }));
    }

    let rate_key = format!("link-preview:{user_id}");
    if !LINK_PREVIEW_LIMIT.check_and_increment_with_window(&rate_key, 40, Duration::from_secs(60)) {
        return HttpResponse::TooManyRequests().json(json!({
            "error": "TOO_MANY_REQUESTS",
            "message": "Too many preview requests.",
        }));
    }

    let url = body.url.clone().unwrap_or_default().trim().to_string();
    if url.is_empty() || !is_safe_preview_target(&url) {
        return HttpResponse::BadRequest().json(json!({
            "error": "INVALID_URL",
            "message": "Invalid preview URL.",
        }));
    }

    match fetch_link_preview(&url).await {
        Ok(preview) => HttpResponse::Ok().json(preview),
        Err(message) => HttpResponse::BadGateway().json(json!({
            "error": "PREVIEW_UNAVAILABLE",
            "message": message,
        })),
    }
}
