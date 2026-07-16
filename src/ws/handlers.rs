use mongodb::bson::{doc, oid::ObjectId, DateTime, Bson};
use mongodb::Database;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::model::channel_model::Channel;
use crate::model::messages_model::{CreateMessageInput, Message, MessageType};
use crate::model::user_model::{AvailabilityStatus, User};
use crate::ws::registry;
use crate::ws::state::{is_valid_object_id, now_ms, SocketState};
use crate::utils::access::membership_gate::{
    channel_admin_bypasses_slowmode, require_channel_access, require_channel_message_access,
    require_dm_access, require_message_participant,
};
use crate::utils::ratelimit::slowmode::check_channel_slowmode;
use crate::utils::db::get_db;
use crate::utils::friends::{are_friends, is_dm_blocked};
use crate::utils::voice::call_sessions::{
    accept_session, cancel_session, create_ringing_session, end_session, reject_session,
    CallPhase, CallSessionError,
};
use crate::utils::validators::sanitize_input::sanitize_message_content;
use crate::utils::messages::access::{
    can_mark_message_as_read, can_react_to_message, claim_pending_upload,
    cleanup_attachment_if_unreferenced, validate_message_attachment, AttachmentSendContext,
    QuoteContext, validate_quote_target,
};
use crate::utils::messages::mentions::{has_everyone_mention, resolve_mentions};
use crate::utils::messages::{dm_only_or_clause, serialize_message};
use crate::utils::unread::{
    emit_channel_unread_updated, emit_dm_unread_updated, mark_channel_as_read_for_user,
};
use crate::utils::user::serialize_user::resolve_display_name;

fn parse_message_type(s: &str) -> MessageType {
    match s.to_uppercase().as_str() {
        "FILE" => MessageType::File,
        "IMAGE" => MessageType::Image,
        "VIDEO" => MessageType::Video,
        "AUDIO" => MessageType::Audio,
        "STICKER" => MessageType::Sticker,
        _ => MessageType::Text,
    }
}

fn is_connected_user(connected: &str, claimed: &str) -> bool {
    !claimed.is_empty() && connected == claimed
}

fn reactions_json(msg: &Message) -> Value {
    let mut map = serde_json::Map::new();
    for (emoji, reaction) in &msg.reactions {
        map.insert(
            emoji.clone(),
            json!(reaction.users.iter().map(|u| u.to_hex()).collect::<Vec<_>>()),
        );
    }
    Value::Object(map)
}

async fn set_user_online(user_id: &str) {
    if !is_valid_object_id(user_id) {
        return;
    }
    if let Ok(oid) = ObjectId::parse_str(user_id) {
        let _ = User::set_fields(&get_db(), oid, doc! { "isOnline": true }).await;
    }
}

async fn set_user_offline(user_id: &str) {
    if !is_valid_object_id(user_id) {
        return;
    }
    if let Ok(oid) = ObjectId::parse_str(user_id) {
        let now = DateTime::now();
        let _ = User::set_fields(
            &get_db(),
            oid,
            doc! { "isOnline": false, "lastSeen": now },
        )
        .await;
    }
}

fn normalize_availability_status(status: &str) -> &'static str {
    match status.to_lowercase().as_str() {
        "away" => "away",
        "brb" => "brb",
        "dnd" => "dnd",
        _ => "online",
    }
}

async fn set_availability(user_id: &str, status: &str) -> &'static str {
    let normalized = normalize_availability_status(status);
    if !is_valid_object_id(user_id) {
        return normalized;
    }
    if let Ok(oid) = ObjectId::parse_str(user_id) {
        // Store as plain string (same as HTTP /availability-status).
        let _ = User::set_fields(
            &get_db(),
            oid,
            doc! { "availabilityStatus": normalized },
        )
        .await;
    }
    normalized
}

async fn availability_status_for_user(user_id: &str) -> &'static str {
    let Ok(oid) = ObjectId::parse_str(user_id) else {
        return "online";
    };
    match User::find_by_id(&get_db(), oid).await {
        Ok(Some(user)) => match user.availability_status {
            AvailabilityStatus::Away => "away",
            AvailabilityStatus::Brb => "brb",
            AvailabilityStatus::Dnd => "dnd",
            AvailabilityStatus::Online => "online",
        },
        _ => "online",
    }
}

async fn broadcast_user_status(user_id: &str, status: Value) {
    crate::utils::friends::emit_to_friends(
        &get_db(),
        user_id,
        "user-status-changed",
        json!({ "userId": user_id, "status": status }),
    )
    .await;
}

fn emit_mention(
    target_user_id: &str,
    scope: &str,
    source_id: &str,
    source_name: Option<&str>,
    message_id: &str,
    from_user: &Value,
    content: &str,
) {
    let preview = content.trim();
    let preview = if preview.chars().count() > 140 {
        format!("{}…", preview.chars().take(140).collect::<String>())
    } else {
        preview.to_string()
    };
    registry::emit_to_user(
        target_user_id,
        "message-mention",
        json!({
            "scope": scope,
            "sourceId": source_id,
            "sourceName": source_name,
            "messageId": message_id,
            "from": from_user,
            "preview": preview,
        }),
    );
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SendMessagePayload {
    sender: String,
    recipient: String,
    content: Option<String>,
    message_type: Option<String>,
    file_url: Option<String>,
    file_type: Option<String>,
    file_size: Option<u64>,
    file_name: Option<String>,
    duration_ms: Option<u32>,
    quoted_message: Option<String>,
}

async fn handle_send_message(connected: &str, payload: SendMessagePayload) {
    let db = get_db();
    if !is_connected_user(connected, &payload.sender) || payload.recipient.is_empty() {
        return;
    }
    if !are_friends(&db, &payload.sender, &payload.recipient).await {
        registry::emit_to_user(
            &payload.sender,
            "dm-error",
            json!({
                "code": "NOT_FRIENDS",
                "message": "Możesz pisać tylko do znajomych. Wyślij zaproszenie, aby dodać kontakt.",
            }),
        );
        return;
    }
    if is_dm_blocked(&db, &payload.sender, &payload.recipient).await {
        registry::emit_to_user(
            &payload.sender,
            "dm-error",
            json!({
                "code": "USER_BLOCKED",
                "message": "Nie możesz wysłać wiadomości — użytkownik jest zablokowany lub zablokował Cię.",
            }),
        );
        return;
    }
    if !validate_message_attachment(
        &db,
        &payload.sender,
        &payload.file_url,
        payload.file_size,
        Some(AttachmentSendContext::Dm {
            recipient_id: payload.recipient.clone(),
        }),
    )
    .await
    {
        registry::emit_to_user(
            &payload.sender,
            "dm-error",
            json!({
                "code": "INVALID_FILE",
                "message": "Nie można dołączyć tego pliku do wiadomości.",
            }),
        );
        return;
    }
    claim_pending_upload(&payload.sender, &payload.file_url).await;

    let quoted = if let Some(ref q) = payload.quoted_message {
        validate_quote_target(
            &db,
            &payload.sender,
            q,
            QuoteContext::Dm {
                contact_id: payload.recipient.clone(),
            },
        )
        .await
        .and_then(|m| m.id)
    } else {
        None
    };

    let (Ok(sender), Ok(recipient)) = (
        ObjectId::parse_str(&payload.sender),
        ObjectId::parse_str(&payload.recipient),
    ) else {
        return;
    };

    let content = sanitize_message_content(payload.content.as_deref().unwrap_or(""));

    let mentions = resolve_mentions(
        &db,
        &content,
        &[payload.sender.clone(), payload.recipient.clone()],
    )
    .await;

    let input = CreateMessageInput {
        sender,
        recipient: Some(recipient),
        channel: None,
        content,
        message_type: Some(parse_message_type(payload.message_type.as_deref().unwrap_or("TEXT"))),
        file_url: payload.file_url,
        file_type: payload.file_type,
        file_size: payload.file_size,
        file_name: payload.file_name,
        duration_ms: payload.duration_ms,
        quoted_message: quoted,
        mentions: Some(mentions.clone()),
        mentions_everyone: Some(false),
    };

    let created = match Message::create(&db, input).await {
        Ok(m) => m,
        Err(e) => {
            log::error!("sendMessage create error: {}", e);
            return;
        }
    };

    let populated = serialize_message(&db, &created).await;

    let recipient_muted = User::find_by_id(&db, recipient)
        .await
        .ok()
        .flatten()
        .map(|u| u.muted_contacts.iter().any(|c| *c == sender))
        .unwrap_or(false);

    registry::emit_to_user(&payload.recipient, "receiveMessage", populated.clone());
    registry::emit_to_user(&payload.sender, "receiveMessage", populated.clone());

    if payload.sender != payload.recipient && !recipient_muted {
        emit_dm_unread_updated(&db, &payload.recipient, &payload.sender).await;
        if mentions.iter().any(|m| m.to_hex() == payload.recipient) {
            emit_mention(
                &payload.recipient,
                "dm",
                &payload.sender,
                None,
                &created.id.map(|o| o.to_hex()).unwrap_or_default(),
                &populated.get("sender").cloned().unwrap_or(Value::Null),
                created.content.as_str(),
            );
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ChannelMessagePayload {
    channel_id: String,
    sender: String,
    content: Option<String>,
    message_type: Option<String>,
    file_url: Option<String>,
    file_type: Option<String>,
    file_size: Option<u64>,
    file_name: Option<String>,
    duration_ms: Option<u32>,
    quoted_message: Option<String>,
}

async fn handle_send_channel_message(connected: &str, payload: ChannelMessagePayload) {
    let db = get_db();
    if !is_connected_user(connected, &payload.sender) || payload.channel_id.is_empty() {
        return;
    }

    let channel = match require_channel_message_access(&db, &payload.channel_id, &payload.sender).await
    {
        Ok(channel) => channel,
        Err(reason) => {
            registry::emit_to_user(
                connected,
                "error",
                json!({ "message": reason.as_str(), "code": "FORBIDDEN" }),
            );
            return;
        }
    };

    let bypass = channel_admin_bypasses_slowmode(&channel, &payload.sender);
    if crate::utils::channel::is_channel_chat_locked_for_sender(&channel, &payload.sender) {
        registry::emit_to_user(
            connected,
            "error",
            json!({
                "message": "Czat na tym kanale jest zablokowany.",
                "code": "CHAT_LOCKED",
            }),
        );
        return;
    }
    if let Err(retry_after) = check_channel_slowmode(
        &payload.sender,
        &payload.channel_id,
        channel.rate_limit_per_user,
        bypass,
    )
    .await
    {
        registry::emit_to_user(
            connected,
            "error",
            json!({
                "message": "Slowmode is enabled for this channel.",
                "code": "SLOWMODE",
                "retryAfter": retry_after,
            }),
        );
        return;
    }

    if !validate_message_attachment(
        &db,
        &payload.sender,
        &payload.file_url,
        payload.file_size,
        Some(AttachmentSendContext::Channel {
            channel_id: payload.channel_id.clone(),
        }),
    )
    .await
    {
        registry::emit_to_user(
            connected,
            "error",
            json!({
                "code": "INVALID_FILE",
                "message": "Nie udało się wysłać załącznika. Spróbuj ponownie.",
            }),
        );
        return;
    }
    claim_pending_upload(&payload.sender, &payload.file_url).await;

    let Ok(channel_oid) = ObjectId::parse_str(&payload.channel_id) else {
        return;
    };

    let quoted = if let Some(ref q) = payload.quoted_message {
        validate_quote_target(
            &db,
            &payload.sender,
            q,
            QuoteContext::Channel {
                channel_id: payload.channel_id.clone(),
            },
        )
        .await
        .and_then(|m| m.id)
    } else {
        None
    };

    let Ok(sender) = ObjectId::parse_str(&payload.sender) else {
        return;
    };

    create_and_broadcast_channel_message(
        &db,
        ChannelBroadcastInput {
            channel,
            channel_oid,
            sender,
            content: payload.content.clone().unwrap_or_default(),
            message_type: parse_message_type(payload.message_type.as_deref().unwrap_or("TEXT")),
            file_url: payload.file_url,
            file_type: payload.file_type,
            file_size: payload.file_size,
            file_name: payload.file_name,
            duration_ms: payload.duration_ms,
            quoted_message: quoted,
        },
    )
    .await;
}

/// Parametry współdzielonej wysyłki wiadomości kanałowej.
pub struct ChannelBroadcastInput {
    pub channel: Channel,
    pub channel_oid: ObjectId,
    pub sender: ObjectId,
    /// Surowa treść — zostanie zsanityzowana wewnątrz funkcji.
    pub content: String,
    pub message_type: MessageType,
    pub file_url: Option<String>,
    pub file_type: Option<String>,
    pub file_size: Option<u64>,
    pub file_name: Option<String>,
    pub duration_ms: Option<u32>,
    pub quoted_message: Option<ObjectId>,
}

/// Rdzeń tworzenia i rozgłaszania wiadomości kanałowej — współdzielony przez
/// gniazdo WS (użytkownicy) oraz runtime HTTP botów. Zakłada, że dostęp do
/// kanału został już zweryfikowany przez wywołującego. Zwraca zserializowaną
/// wiadomość (z polem `channelId`).
pub async fn create_and_broadcast_channel_message(
    db: &Database,
    input: ChannelBroadcastInput,
) -> Option<Value> {
    let ChannelBroadcastInput {
        channel,
        channel_oid,
        sender,
        content,
        message_type,
        file_url,
        file_type,
        file_size,
        file_name,
        duration_ms,
        quoted_message,
    } = input;

    let channel_id_str = channel_oid.to_hex();
    let sender_hex = sender.to_hex();

    let mut member_ids: Vec<String> = channel.members.iter().map(|m| m.to_hex()).collect();
    member_ids.push(channel.admin.to_hex());

    let content = sanitize_message_content(&content);
    let mentions = resolve_mentions(db, &content, &member_ids).await;
    let mentions_everyone = has_everyone_mention(&content);

    let create_input = CreateMessageInput {
        sender,
        recipient: None,
        channel: Some(channel_oid),
        content,
        message_type: Some(message_type),
        file_url,
        file_type,
        file_size,
        file_name,
        duration_ms,
        quoted_message,
        mentions: Some(mentions.clone()),
        mentions_everyone: Some(mentions_everyone),
    };

    let created = match Message::create(db, create_input).await {
        Ok(m) => m,
        Err(e) => {
            log::error!("create_and_broadcast_channel_message error: {}", e);
            return None;
        }
    };

    if let Some(mid) = created.id {
        let _ = Channel::collection(db)
            .update_one(
                doc! { "_id": channel_oid },
                doc! { "$push": { "messages": mid }, "$set": { "updatedAt": DateTime::now() } },
            )
            .await;
    }

    let mut populated = serialize_message(db, &created).await;
    if let Some(obj) = populated.as_object_mut() {
        obj.insert("channelId".into(), json!(channel_id_str));
    }

    let mentioned: std::collections::HashSet<String> =
        mentions.iter().map(|m| m.to_hex()).collect();

    let mut muted_ids = std::collections::HashSet::new();
    for mid in &channel.members {
        if let Ok(Some(u)) = User::find_by_id(db, *mid).await {
            if u.muted_channels.iter().any(|c| *c == channel_oid) {
                muted_ids.insert(mid.to_hex());
            }
        }
    }
    if let Ok(Some(admin_u)) = User::find_by_id(db, channel.admin).await {
        if admin_u.muted_channels.iter().any(|c| *c == channel_oid) {
            muted_ids.insert(channel.admin.to_hex());
        }
    }

    let mut notified = std::collections::HashSet::new();
    for member_id in member_ids {
        if !notified.insert(member_id.clone()) {
            continue;
        }
        registry::emit_to_user(&member_id, "receive-channel-message", populated.clone());
        if member_id != sender_hex && !muted_ids.contains(&member_id) {
            emit_channel_unread_updated(db, &member_id, &channel_id_str).await;
            if mentioned.contains(&member_id) || mentions_everyone {
                emit_mention(
                    &member_id,
                    "channel",
                    &channel_id_str,
                    Some(&channel.name),
                    &created.id.map(|o| o.to_hex()).unwrap_or_default(),
                    &populated.get("sender").cloned().unwrap_or(Value::Null),
                    &created.content,
                );
            }
        }
    }

    Some(populated)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TypingPayload {
    chat_id: Option<String>,
    is_typing: Option<bool>,
}

async fn handle_typing(state: SocketState, connected: &str, payload: TypingPayload) {
    let Some(chat_id) = payload.chat_id.filter(|s| !s.is_empty()) else {
        return;
    };
    let user_id = connected;
    let is_typing = payload.is_typing.unwrap_or(false);

    if chat_id.starts_with("channel_") {
        let channel_id = chat_id.trim_start_matches("channel_");
        if require_channel_message_access(&get_db(), channel_id, &user_id)
            .await
            .is_err()
        {
            return;
        }
    } else if require_dm_access(&get_db(), &user_id, &chat_id).await.is_err() {
        return;
    }

    {
        let mut typing = state.typing_users.lock().await;
        // Drop stale typing entries (no heartbeat for ~8s).
        let now = crate::ws::state::now_ms();
        typing.retain(|_, users| {
            users.retain(|_, last_ms| now.saturating_sub(*last_ms) < 8_000);
            !users.is_empty()
        });
        let chat = typing.entry(chat_id.clone()).or_default();
        if is_typing {
            chat.insert(user_id.to_string(), now);
        } else {
            chat.remove(user_id);
        }
    }

    let event = json!({ "chatId": chat_id, "userId": user_id, "isTyping": is_typing });

    if chat_id.starts_with("channel_") {
        let channel_id = chat_id.trim_start_matches("channel_");
        if let Ok(oid) = ObjectId::parse_str(channel_id) {
            if let Ok(Some(channel)) = Channel::find_by_id(&get_db(), oid).await {
                for recipient in registry::channel_recipient_ids(&channel) {
                    if recipient != user_id {
                        registry::emit_to_user(&recipient, "typing", event.clone());
                    }
                }
            }
        }
    } else {
        registry::emit_to_user(&chat_id, "typing", event);
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReactionPayload {
    message_id: Option<String>,
    emoji: Option<String>,
}

async fn handle_reaction(connected: &str, payload: ReactionPayload) {
    let Some(message_id) = payload.message_id else { return };
    let Some(emoji) = payload.emoji else { return };
    let user_id = connected.to_string();
    let emoji = emoji.trim().to_string();
    if emoji.is_empty() || emoji.len() > 32 {
        return;
    }
    let Ok(mid) = ObjectId::parse_str(&message_id) else { return };
    let db = get_db();
    let Some(mut msg) = Message::find_by_id(&db, mid).await.ok().flatten() else {
        return;
    };
    if !can_react_to_message(&db, &user_id, &msg).await {
        return;
    }

    let entry = msg.reactions.entry(emoji.clone()).or_insert_with(|| {
        crate::model::messages_model::Reaction {
            emoji: emoji.clone(),
            users: vec![],
        }
    });
    if let Ok(uid) = ObjectId::parse_str(&user_id) {
        if let Some(pos) = entry.users.iter().position(|u| *u == uid) {
            entry.users.remove(pos);
        } else {
            entry.users.push(uid);
        }
    }
    if entry.users.is_empty() {
        msg.reactions.remove(&emoji);
    }

    let reactions_bson = mongodb::bson::to_bson(&msg.reactions).unwrap_or(Bson::Document(doc! {}));
    let _ = Message::collection(&db)
        .update_one(
            doc! { "_id": mid },
            doc! { "$set": { "reactions": reactions_bson, "updatedAt": DateTime::now() } },
        )
        .await;

    let payload_json = json!({
        "messageId": message_id,
        "reactions": reactions_json(&msg),
        "channelId": msg.channel.map(|c| c.to_hex()),
    });

    if let Some(channel_id) = msg.channel {
        if let Ok(Some(channel)) = Channel::find_by_id(&db, channel_id).await {
            let mut recipients = vec![channel.admin.to_hex()];
            recipients.extend(channel.members.iter().map(|m| m.to_hex()));
            for r in recipients {
                registry::emit_to_user(&r, "message-reaction", payload_json.clone());
            }
        }
    } else if let Some(recipient) = msg.recipient {
        registry::emit_to_user(&msg.sender.to_hex(), "message-reaction", payload_json.clone());
        registry::emit_to_user(&recipient.to_hex(), "message-reaction", payload_json);
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MarkMessageReadPayload {
    message_id: Option<String>,
    user_id: Option<String>,
}

async fn handle_mark_message_read(connected: &str, payload: MarkMessageReadPayload) {
    let Some(message_id) = payload.message_id else { return };
    let Some(user_id) = payload.user_id else { return };
    if !is_connected_user(connected, &user_id) {
        return;
    }
    let Ok(mid) = ObjectId::parse_str(&message_id) else { return };
    let db = get_db();
    let Some(msg) = Message::find_by_id(&db, mid).await.ok().flatten() else {
        return;
    };
    if !can_mark_message_as_read(&db, &user_id, &msg).await {
        return;
    }
    let Ok(uid) = ObjectId::parse_str(&user_id) else { return };
    let now = DateTime::now();
    let _ = Message::collection(&db)
        .update_one(
            doc! { "_id": mid },
            doc! {
                "$set": { "read": true, "updatedAt": now },
                "$push": { "readBy": { "user": uid, "readAt": now } },
            },
        )
        .await;
    registry::emit_to_user(
        &msg.sender.to_hex(),
        "message-read",
        json!({ "messageId": message_id, "read": true }),
    );
    emit_dm_unread_updated(&db, &user_id, &msg.sender.to_hex()).await;
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MarkConversationReadPayload {
    user_id: Option<String>,
    contact_id: Option<String>,
}

async fn handle_mark_conversation_read(connected: &str, payload: MarkConversationReadPayload) {
    let Some(user_id) = payload.user_id else { return };
    let Some(contact_id) = payload.contact_id else { return };
    if !is_connected_user(connected, &user_id) {
        return;
    }
    let db = get_db();
    if !are_friends(&db, &user_id, &contact_id).await {
        return;
    }
    let (Ok(uid), Ok(cid)) = (ObjectId::parse_str(&user_id), ObjectId::parse_str(&contact_id)) else {
        return;
    };

    let unread: Vec<Message> = match Message::collection(&db)
        .find(doc! {
            "sender": cid,
            "recipient": uid,
            "read": false,
            "deleted": { "$ne": true },
            "$or": dm_only_or_clause(),
        })
        .await
    {
        Ok(c) => futures_util::TryStreamExt::try_collect(c).await.unwrap_or_default(),
        Err(_) => return,
    };
    if unread.is_empty() {
        return;
    }
    let ids: Vec<ObjectId> = unread.iter().filter_map(|m| m.id).collect();
    let message_ids: Vec<String> = ids.iter().map(|i| i.to_hex()).collect();
    let now = DateTime::now();
    let _ = Message::collection(&db)
        .update_many(
            doc! { "_id": { "$in": &ids } },
            doc! {
                "$set": { "read": true },
                "$push": { "readBy": { "user": uid, "readAt": now } },
            },
        )
        .await;

    registry::emit_to_user(
        &contact_id,
        "messages-read",
        json!({ "messageIds": message_ids, "read": true, "readerId": user_id }),
    );
    emit_dm_unread_updated(&db, &user_id, &contact_id).await;
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MarkChannelReadPayload {
    user_id: Option<String>,
    channel_id: Option<String>,
}

async fn handle_mark_channel_read(connected: &str, payload: MarkChannelReadPayload) {
    let Some(user_id) = payload.user_id else { return };
    let Some(channel_id) = payload.channel_id else { return };
    if !is_connected_user(connected, &user_id) {
        return;
    }
    let db = get_db();
    if require_channel_access(&db, &channel_id, &user_id)
        .await
        .is_err()
    {
        return;
    }
    mark_channel_as_read_for_user(&db, &user_id, &channel_id).await;
    emit_channel_unread_updated(&db, &user_id, &channel_id).await;
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EditMessagePayload {
    message_id: Option<String>,
    content: Option<String>,
    user_id: Option<String>,
}

async fn handle_edit_message(connected: &str, payload: EditMessagePayload) {
    let Some(message_id) = payload.message_id else { return };
    let Some(content_raw) = payload.content else { return };
    let Some(user_id) = payload.user_id else { return };
    if !is_connected_user(connected, &user_id) {
        return;
    }
    let content = sanitize_message_content(&content_raw);
    if content.is_empty() {
        return;
    }
    if !crate::model::messages_model::is_message_content_within_limit(&content) {
        registry::emit_to_user(
            connected,
            "error",
            json!({ "message": "Wiadomość nie może przekraczać 2000 znaków", "code": "CONTENT_TOO_LONG" }),
        );
        return;
    }
    let Ok(mid) = ObjectId::parse_str(&message_id) else { return };
    let db = get_db();
    let Some(msg) = Message::find_by_id(&db, mid).await.ok().flatten() else {
        return;
    };
    if msg.sender.to_hex() != user_id {
        return;
    }
    if require_message_participant(&db, &user_id, &msg)
        .await
        .is_err()
    {
        return;
    }

    let previous_mentions: std::collections::HashSet<String> =
        msg.mentions.iter().map(|id| id.to_hex()).collect();
    let previous_everyone = msg.mentions_everyone;
    let sender_id = msg.sender.to_hex();

    let mentions;
    let mentions_everyone;
    let channel_doc;
    if let Some(channel_id) = msg.channel {
        channel_doc = Channel::find_by_id(&db, channel_id).await.ok().flatten();
        if let Some(ref channel) = channel_doc {
            let mut ids: Vec<String> = channel.members.iter().map(|m| m.to_hex()).collect();
            ids.push(channel.admin.to_hex());
            mentions = resolve_mentions(&db, &content, &ids).await;
            mentions_everyone = has_everyone_mention(&content);
        } else {
            return;
        }
    } else if msg.recipient.is_some() {
        channel_doc = None;
        mentions = resolve_mentions(
            &db,
            &content,
            &[msg.sender.to_hex(), msg.recipient.unwrap().to_hex()],
        )
        .await;
        mentions_everyone = false;
    } else {
        return;
    };

    let mentions_bson = mongodb::bson::to_bson(&mentions).unwrap_or(Bson::Array(vec![]));
    let _ = Message::collection(&db)
        .update_one(
            doc! { "_id": mid },
            doc! { "$set": {
                "content": content.trim(),
                "mentions": mentions_bson,
                "mentionsEveryone": mentions_everyone,
                "edited": true,
                "editedAt": DateTime::now(),
                "updatedAt": DateTime::now(),
            }},
        )
        .await;

    if let Ok(Some(updated)) = Message::find_by_id(&db, mid).await {
        let populated = serialize_message(&db, &updated).await;
        let from_user = populated
            .get("sender")
            .cloned()
            .unwrap_or(json!({ "_id": sender_id }));
        let preview_content = updated.content.clone();

        let ping_if_new = |member_id: &str, source_id: &str, source_name: Option<&str>| {
            if member_id == sender_id {
                return;
            }
            let newly_mentioned = (mentions.iter().any(|id| id.to_hex() == member_id)
                && !previous_mentions.contains(member_id))
                || (mentions_everyone && !previous_everyone);
            if !newly_mentioned {
                return;
            }
            emit_mention(
                member_id,
                if updated.channel.is_some() {
                    "channel"
                } else {
                    "dm"
                },
                source_id,
                source_name,
                &message_id,
                &from_user,
                &preview_content,
            );
        };

        if let Some(channel_id) = updated.channel {
            if let Some(ref channel) = channel_doc {
                let channel_id_hex = channel_id.to_hex();
                let mut recipients = vec![channel.admin.to_hex()];
                recipients.extend(channel.members.iter().map(|m| m.to_hex()));
                for r in recipients {
                    registry::emit_to_user(&r, "message-edited", populated.clone());
                    ping_if_new(&r, &channel_id_hex, Some(&channel.name));
                }
            }
        } else if let Some(recipient) = updated.recipient {
            let recipient_hex = recipient.to_hex();
            registry::emit_to_user(&recipient_hex, "message-edited", populated.clone());
            registry::emit_to_user(&updated.sender.to_hex(), "message-edited", populated.clone());
            ping_if_new(&recipient_hex, &sender_id, None);
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeleteMessagePayload {
    message_id: Option<String>,
    user_id: Option<String>,
}

async fn handle_delete_message(connected: &str, payload: DeleteMessagePayload) {
    let Some(message_id) = payload.message_id else { return };
    let Some(user_id) = payload.user_id else { return };
    if !is_connected_user(connected, &user_id) {
        return;
    }
    let Ok(mid) = ObjectId::parse_str(&message_id) else { return };
    let db = get_db();
    let Some(msg) = Message::find_by_id(&db, mid).await.ok().flatten() else {
        return;
    };
    if msg.sender.to_hex() != user_id {
        return;
    }
    if require_message_participant(&db, &user_id, &msg)
        .await
        .is_err()
    {
        return;
    }
    let _ = Message::soft_delete(&db, mid).await;
    cleanup_attachment_if_unreferenced(&db, msg.file_url.as_deref()).await;
    let body = json!({ "_id": message_id });
    if let Some(channel_id) = msg.channel {
        if let Ok(Some(channel)) = Channel::find_by_id(&db, channel_id).await {
            let mut recipients = vec![channel.admin.to_hex()];
            recipients.extend(channel.members.iter().map(|m| m.to_hex()));
            for r in recipients {
                registry::emit_to_user(&r, "message-deleted", body.clone());
            }
        } else {
            registry::emit_to_user(&msg.sender.to_hex(), "message-deleted", body.clone());
        }
    } else if let Some(recipient) = msg.recipient {
        registry::emit_to_user(&recipient.to_hex(), "message-deleted", body.clone());
        registry::emit_to_user(&msg.sender.to_hex(), "message-deleted", body);
    } else {
        registry::emit_to_user(&msg.sender.to_hex(), "message-deleted", body);
    }
}

#[derive(Debug, Deserialize)]
struct CallPayload {
    from: Option<String>,
    to: Option<String>,
    mode: Option<String>,
}

async fn handle_call_invite(connected: &str, payload: CallPayload, state: &SocketState) {
    let Some(from) = payload.from else { return };
    let Some(to) = payload.to else { return };
    if !is_connected_user(connected, &from) || from == to {
        return;
    }
    let db = get_db();
    if !are_friends(&db, &from, &to).await {
        registry::emit_to_user(&from, "call:unavailable", json!({ "to": to, "reason": "NOT_FRIENDS" }));
        return;
    }

    let mode = if payload.mode.as_deref() == Some("video") {
        "video"
    } else {
        "audio"
    };

    // Allow ringing even when the peer is offline / away — they may reconnect,
    // and a missed-call log is written if nobody answers.
    let session_id = match create_ringing_session(&from, &to, mode) {
        Ok(id) => id,
        Err(CallSessionError::InProgress) => {
            registry::emit_to_user(
                &from,
                "call:unavailable",
                json!({ "to": to, "reason": "BUSY" }),
            );
            return;
        }
        Err(_) => return,
    };

    let caller = User::find_by_id(&db, ObjectId::parse_str(&from).unwrap_or_default())
        .await
        .ok()
        .flatten();
    let caller_json = caller.map(|u| {
        json!({
            "_id": from,
            "username": u.username,
            "displayName": resolve_display_name(&u),
            "image": u.image,
            "color": u.color,
        })
    }).unwrap_or(json!({ "_id": from }));

    if state.is_user_connected(&to).await {
        registry::emit_to_user(
            &to,
            "call:incoming",
            json!({
                "from": from,
                "mode": mode,
                "caller": caller_json,
                "callSessionId": session_id,
            }),
        );
    }
}

async fn handle_call_simple(connected: &str, incoming_event: &str, payload: CallPayload) {
    let outgoing = match incoming_event {
        "call:accept" => "call:accepted",
        "call:reject" => "call:rejected",
        "call:cancel" => "call:cancelled",
        "call:end" => "call:ended",
        _ => return,
    };
    let Some(from) = payload.from else { return };
    let Some(to) = payload.to else { return };
    if !is_connected_user(connected, &from) || from == to {
        return;
    }

    let db = get_db();
    if !are_friends(&db, &from, &to).await {
        return;
    }

    let session_ok = match incoming_event {
        "call:accept" => {
            if accept_session(&from, &to).is_ok() {
                registry::emit_to_user(&to, outgoing, json!({ "from": from }));
                registry::emit_to_user(&from, outgoing, json!({ "from": from }));
            }
            return;
        }
        "call:reject" => {
            if reject_session(&from, &to).is_ok() {
                // Callee declined → missed call for the caller.
                create_missed_call_log_message(&db, &to, &from).await;
                true
            } else {
                false
            }
        }
        "call:cancel" => {
            // Caller hung up before answer — no chat log.
            cancel_session(&from, &to).is_ok()
        }
        "call:end" => {
            match end_session(&from, &to) {
                Ok(session) => {
                    registry::emit_to_user(&to, outgoing, json!({ "from": from }));
                    // Answered call log only when both parties were connected.
                    if session.phase == CallPhase::Accepted {
                        if let Some(accepted_at) = session.accepted_at {
                            let secs = accepted_at.elapsed().as_secs();
                            create_call_log_message(
                                &db,
                                &session.caller_id,
                                &session.callee_id,
                                secs,
                            )
                            .await;
                        }
                    }
                    return;
                }
                Err(_) => return,
            }
        }
        _ => false,
    };
    if !session_ok {
        return;
    }

    registry::emit_to_user(&to, outgoing, json!({ "from": from }));
}

/// Client signals that ringing timed out without an answer.
async fn handle_call_timeout(connected: &str, payload: CallPayload) {
    let Some(from) = payload.from else { return };
    let Some(to) = payload.to else { return };
    if !is_connected_user(connected, &from) || from == to {
        return;
    }
    let db = get_db();
    if !are_friends(&db, &from, &to).await {
        return;
    }
    // Only the caller may timeout a ringing session.
    if cancel_session(&from, &to).is_ok() {
        registry::emit_to_user(&to, "call:cancelled", json!({ "from": from }));
        create_missed_call_log_message(&db, &from, &to).await;
    }
}

/// Formats a call duration as `H:MM:SS` or `M:SS`.
fn format_call_duration(total_secs: u64) -> String {
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;
    if hours > 0 {
        format!("{}:{:02}:{:02}", hours, minutes, seconds)
    } else {
        format!("{}:{:02}", minutes, seconds)
    }
}

/// Creates a system "voice call" log entry in the DM conversation and broadcasts
/// it to both participants. Duration is authoritative (server-side).
async fn create_call_log_message(db: &Database, caller_id: &str, callee_id: &str, duration_secs: u64) {
    persist_call_log(
        db,
        caller_id,
        callee_id,
        format!("Voice call · {}", format_call_duration(duration_secs)),
        duration_secs.saturating_mul(1000).min(u32::MAX as u64) as u32,
    )
    .await;
}

/// Missed / unanswered call — `duration_ms = 0` so the client can render a distinct label.
async fn create_missed_call_log_message(db: &Database, caller_id: &str, callee_id: &str) {
    persist_call_log(db, caller_id, callee_id, "Missed call".to_string(), 0).await;
}

async fn persist_call_log(
    db: &Database,
    caller_id: &str,
    callee_id: &str,
    content: String,
    duration_ms: u32,
) {
    let (Ok(caller), Ok(callee)) = (
        ObjectId::parse_str(caller_id),
        ObjectId::parse_str(callee_id),
    ) else {
        return;
    };

    let input = CreateMessageInput {
        sender: caller,
        recipient: Some(callee),
        channel: None,
        content,
        message_type: Some(MessageType::Call),
        file_url: None,
        file_type: None,
        file_size: None,
        file_name: None,
        duration_ms: Some(duration_ms),
        quoted_message: None,
        mentions: None,
        mentions_everyone: Some(false),
    };

    let created = match Message::create(db, input).await {
        Ok(m) => m,
        Err(e) => {
            log::error!("call log create error: {}", e);
            return;
        }
    };

    let populated = serialize_message(db, &created).await;
    registry::emit_to_user(caller_id, "receiveMessage", populated.clone());
    registry::emit_to_user(callee_id, "receiveMessage", populated);
}

fn emit_rate_limit_error(user_id: &str) {
    registry::emit_to_user(
        user_id,
        "error",
        json!({ "message": "Rate limit exceeded" }),
    );
}

pub async fn on_user_connected(user_id: &str) {
    set_user_online(user_id).await;
    // Preserve the user's chosen availability (dnd/away/brb) — only presence flips online.
    let availability = availability_status_for_user(user_id).await;
    broadcast_user_status(
        user_id,
        json!({
            "isOnline": true,
            "availabilityStatus": availability,
            "lastSeen": Value::Null,
        }),
    )
    .await;
}

pub async fn on_user_disconnected(user_id: &str) {
    crate::utils::voice::call_sessions::clear_sessions_for_user(user_id);
    set_user_offline(user_id).await;
    broadcast_user_status(
        user_id,
        json!({ "isOnline": false, "lastSeen": now_ms() }),
    )
    .await;
}

pub async fn dispatch_message(connected: &str, msg_type: &str, payload: Value, state: &SocketState) {
    match msg_type {
        "sendMessage" => {
            if !state.check_rate_limit(connected, "sendMessage", 60, 60_000).await {
                emit_rate_limit_error(connected);
                return;
            }
            if let Ok(p) = serde_json::from_value::<SendMessagePayload>(payload) {
                handle_send_message(connected, p).await;
            }
        }
        "send-channel-message" => {
            if !state
                .check_rate_limit(connected, "send-channel-message", 60, 60_000)
                .await
            {
                emit_rate_limit_error(connected);
                return;
            }
            if let Ok(p) = serde_json::from_value::<ChannelMessagePayload>(payload) {
                handle_send_channel_message(connected, p).await;
            }
        }
        "typing" => {
            if let Ok(p) = serde_json::from_value::<TypingPayload>(payload) {
                // Never rate-limit a "stopped typing" signal: dropping it would
                // leave the peer's "typing…" indicator stuck on screen. Only
                // throttle the "started/keeps typing" heartbeats, per chat.
                if p.is_typing.unwrap_or(false) {
                    let chat_key = p
                        .chat_id
                        .as_deref()
                        .filter(|s| !s.is_empty())
                        .unwrap_or("unknown");
                    let action = format!("typing:{chat_key}");
                    if !state.check_rate_limit(connected, &action, 20, 60_000).await {
                        return;
                    }
                }
                handle_typing(state.clone(), connected, p).await;
            }
        }
        "message-reaction" => {
            if !state
                .check_rate_limit(connected, "message-reaction", 120, 60_000)
                .await
            {
                emit_rate_limit_error(connected);
                return;
            }
            if let Ok(p) = serde_json::from_value::<ReactionPayload>(payload) {
                handle_reaction(connected, p).await;
            }
        }
        "mark-message-read" => {
            if !state
                .check_rate_limit(connected, "mark-message-read", 300, 60_000)
                .await
            {
                emit_rate_limit_error(connected);
                return;
            }
            if let Ok(p) = serde_json::from_value::<MarkMessageReadPayload>(payload) {
                handle_mark_message_read(connected, p).await;
            }
        }
        "mark-conversation-read" => {
            if !state
                .check_rate_limit(connected, "mark-conversation-read", 60, 60_000)
                .await
            {
                emit_rate_limit_error(connected);
                return;
            }
            if let Ok(p) = serde_json::from_value::<MarkConversationReadPayload>(payload) {
                handle_mark_conversation_read(connected, p).await;
            }
        }
        "mark-channel-read" => {
            if !state
                .check_rate_limit(connected, "mark-channel-read", 60, 60_000)
                .await
            {
                emit_rate_limit_error(connected);
                return;
            }
            if let Ok(p) = serde_json::from_value::<MarkChannelReadPayload>(payload) {
                handle_mark_channel_read(connected, p).await;
            }
        }
        "editMessage" => {
            if !state.check_rate_limit(connected, "editMessage", 60, 60_000).await {
                emit_rate_limit_error(connected);
                return;
            }
            if let Ok(p) = serde_json::from_value::<EditMessagePayload>(payload) {
                handle_edit_message(connected, p).await;
            }
        }
        "deleteMessage" => {
            if !state.check_rate_limit(connected, "deleteMessage", 60, 60_000).await {
                emit_rate_limit_error(connected);
                return;
            }
            if let Ok(p) = serde_json::from_value::<DeleteMessagePayload>(payload) {
                handle_delete_message(connected, p).await;
            }
        }
        "set-online" => {
            set_user_online(connected).await;
            broadcast_user_status(
                connected,
                json!({ "isOnline": true, "lastSeen": Value::Null }),
            )
            .await;
        }
        "set-offline" => {
            set_user_offline(connected).await;
            broadcast_user_status(
                connected,
                json!({ "isOnline": false, "lastSeen": now_ms() }),
            )
            .await;
        }
        "set-status" => {
            let status = payload.get("availabilityStatus").and_then(|v| v.as_str());
            if let Some(st) = status {
                let normalized = set_availability(connected, st).await;
                broadcast_user_status(
                    connected,
                    json!({
                        "isOnline": true,
                        "availabilityStatus": normalized,
                        "lastSeen": Value::Null,
                    }),
                )
                .await;
            }
        }
        "call:invite" => {
            if !state.check_rate_limit(connected, "call:invite", 20, 60_000).await {
                emit_rate_limit_error(connected);
                return;
            }
            if let Ok(p) = serde_json::from_value::<CallPayload>(payload) {
                handle_call_invite(connected, p, state).await;
            }
        }
        "call:accept" | "call:reject" | "call:cancel" | "call:end" => {
            if !state.check_rate_limit(connected, msg_type, 30, 60_000).await {
                emit_rate_limit_error(connected);
                return;
            }
            if let Ok(p) = serde_json::from_value::<CallPayload>(payload) {
                handle_call_simple(connected, msg_type, p).await;
            }
        }
        "call:timeout" => {
            if !state.check_rate_limit(connected, "call:timeout", 20, 60_000).await {
                emit_rate_limit_error(connected);
                return;
            }
            if let Ok(p) = serde_json::from_value::<CallPayload>(payload) {
                handle_call_timeout(connected, p).await;
            }
        }
        _ => {}
    }
}
