use mongodb::bson::oid::ObjectId;
use mongodb::Database;
use serde_json::json;

use crate::model::push_token_model::PushToken;

const EXPO_PUSH_URL: &str = "https://exp.host/--/api/v2/push/send";

fn truncate_preview(text: &str, max: usize) -> String {
    let trimmed = text.trim();
    if trimmed.chars().count() <= max {
        return trimmed.to_string();
    }
    trimmed.chars().take(max).collect::<String>() + "…"
}

async fn send_expo_messages(messages: Vec<serde_json::Value>) {
    if messages.is_empty() {
        return;
    }

    let client = reqwest::Client::new();
    for chunk in messages.chunks(100) {
        let payload = json!({ "messages": chunk });
        match client.post(EXPO_PUSH_URL).json(&payload).send().await {
            Ok(resp) if !resp.status().is_success() => {
                log::warn!(
                    "Expo push API returned {}: {}",
                    resp.status(),
                    resp.text().await.unwrap_or_default()
                );
            }
            Err(e) => log::warn!("Expo push request failed: {e}"),
            _ => {}
        }
    }
}

pub async fn send_push_to_user(
    db: &Database,
    user_id: ObjectId,
    title: &str,
    body: &str,
    data: serde_json::Value,
) {
    let tokens = match PushToken::find_tokens_for_user(db, user_id).await {
        Ok(tokens) => tokens,
        Err(e) => {
            log::warn!("Failed to load push tokens for {}: {e}", user_id.to_hex());
            return;
        }
    };

    let messages: Vec<serde_json::Value> = tokens
        .into_iter()
        .map(|token| {
            json!({
                "to": token,
                "title": title,
                "body": body,
                "sound": "default",
                "data": data,
            })
        })
        .collect();

    send_expo_messages(messages).await;
}

pub async fn send_dm_notification(
    db: &Database,
    recipient_id: ObjectId,
    sender_name: &str,
    body_preview: &str,
    sender_id: &str,
    message_id: &str,
) {
    let title = sender_name.to_string();
    let body = truncate_preview(body_preview, 140);
    let data = json!({
        "targetType": "dm",
        "targetId": sender_id,
        "messageId": message_id,
        "senderDisplayName": sender_name,
    });
    send_push_to_user(db, recipient_id, &title, &body, data).await;
}
