use mongodb::{
    bson::{doc, oid::ObjectId, DateTime},
    Collection, Database, IndexModel,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;


#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MessageType {
    Text,
    File,
    Image,
    Video,
    Audio,
    Sticker,
    /// System-generated voice/video call log entry (rendered centered in DM).
    Call,
}

impl Default for MessageType {
    fn default() -> Self {
        Self::Text
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reaction {
    pub emoji: String,
    #[serde(default)]
    pub users: Vec<ObjectId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadBy {
    pub user: ObjectId,
    #[serde(rename = "readAt")]
    pub read_at: DateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub sender: ObjectId,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<ObjectId>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<ObjectId>,


    pub content: String,

    #[serde(rename = "messageType", default)]
    pub message_type: MessageType,

    #[serde(rename = "fileUrl", skip_serializing_if = "Option::is_none")]
    pub file_url: Option<String>,

    #[serde(rename = "fileType", skip_serializing_if = "Option::is_none")]
    pub file_type: Option<String>,

    #[serde(rename = "fileSize", skip_serializing_if = "Option::is_none")]
    pub file_size: Option<u64>,

    #[serde(rename = "fileName", skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,

    #[serde(rename = "durationMs", skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u32>,

    pub timestamp: DateTime,

    #[serde(default)]
    pub read: bool,

    #[serde(rename = "readBy", default)]
    pub read_by: Vec<ReadBy>,

    #[serde(default)]
    pub reactions: HashMap<String, Reaction>,

    #[serde(rename = "quotedMessage", skip_serializing_if = "Option::is_none")]
    pub quoted_message: Option<ObjectId>,

    #[serde(default)]
    pub mentions: Vec<ObjectId>,

    #[serde(rename = "mentionsEveryone", default)]
    pub mentions_everyone: bool,

    #[serde(default)]
    pub edited: bool,

    #[serde(rename = "editedAt", skip_serializing_if = "Option::is_none")]
    pub edited_at: Option<DateTime>,

    #[serde(default)]
    pub deleted: bool,

    #[serde(rename = "deletedAt", skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<DateTime>,

    #[serde(default)]
    pub pinned: bool,

    #[serde(rename = "pinnedAt", skip_serializing_if = "Option::is_none")]
    pub pinned_at: Option<DateTime>,

    #[serde(rename = "pinnedBy", skip_serializing_if = "Option::is_none")]
    pub pinned_by: Option<ObjectId>,

    #[serde(rename = "createdAt")]
    pub created_at: DateTime,

    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime,

    #[serde(
        rename = "e2eEncrypted",
        default,
        deserialize_with = "super::user_model::deserialize_bool_default_false"
    )]
    pub e2e_encrypted: bool,

    #[serde(rename = "e2eVersion", skip_serializing_if = "Option::is_none")]
    pub e2e_version: Option<u8>,
}

#[derive(Debug)]
pub enum MessageValidationError {
    ContentRequired,
    ContentTooLong,
    FileUrlRequired,
}

impl std::fmt::Display for MessageValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::ContentRequired => "Treść wiadomości jest wymagana",
            Self::ContentTooLong  => "Wiadomość nie może przekraczać 2000 znaków",
            Self::FileUrlRequired => "URL pliku jest wymagany dla wiadomości typu FILE, IMAGE, VIDEO lub AUDIO",
        };
        write!(f, "{}", msg)
    }
}

impl std::error::Error for MessageValidationError {}

pub struct CreateMessageInput {
    pub sender: ObjectId,
    pub recipient: Option<ObjectId>,
    pub channel: Option<ObjectId>,
    pub content: String,
    pub message_type: Option<MessageType>,
    pub file_url: Option<String>,
    pub file_type: Option<String>,
    pub file_size: Option<u64>,
    pub file_name: Option<String>,
    pub duration_ms: Option<u32>,
    pub quoted_message: Option<ObjectId>,
    pub mentions: Option<Vec<ObjectId>>,
    pub mentions_everyone: Option<bool>,
    pub e2e_encrypted: Option<bool>,
    pub e2e_version: Option<u8>,
}

/// Maksymalna długość treści wiadomości (znaki). Wspólny limit dla tworzenia i edycji.
pub const MAX_MESSAGE_CONTENT_LEN: usize = 2000;

/// Czy treść mieści się w limicie (liczone w znakach Unicode, nie bajtach).
pub fn is_message_content_within_limit(content: &str) -> bool {
    content.trim().chars().count() <= MAX_MESSAGE_CONTENT_LEN
}

pub fn validate_message(input: &CreateMessageInput) -> Result<(), MessageValidationError> {
    let msg_type = input.message_type.as_ref().unwrap_or(&MessageType::Text);
    let e2e = input.e2e_encrypted.unwrap_or(false);

    if e2e {
        if !crate::utils::e2e::is_valid_e2e_ciphertext(&input.content) {
            return Err(MessageValidationError::ContentRequired);
        }
        return Ok(());
    }

    // Call log entries are system-generated: no file, content acts as a label.
    if *msg_type == MessageType::Call {
        if !is_message_content_within_limit(&input.content) {
            return Err(MessageValidationError::ContentTooLong);
        }
        return Ok(());
    }

    if *msg_type != MessageType::Text && input.file_url.is_none() {
        return Err(MessageValidationError::FileUrlRequired);
    }

    if *msg_type == MessageType::Audio {
        if !is_message_content_within_limit(&input.content) {
            return Err(MessageValidationError::ContentTooLong);
        }
        return Ok(());
    }

    if input.content.trim().is_empty() {
        return Err(MessageValidationError::ContentRequired);
    }
    if !is_message_content_within_limit(&input.content) {
        return Err(MessageValidationError::ContentTooLong);
    }
    Ok(())
}

impl Message {
    pub fn collection(db: &Database) -> Collection<Message> {
        db.collection("messages")
    }

    pub async fn create_indexes(db: &Database) -> mongodb::error::Result<()> {
        let col = Self::collection(db);

        let indexes = vec![
            IndexModel::builder().keys(doc! { "sender": 1, "recipient": 1 }).build(),
            IndexModel::builder().keys(doc! { "channel": 1 }).build(),
            IndexModel::builder().keys(doc! { "channel": 1, "pinned": 1 }).build(),
            IndexModel::builder().keys(doc! { "sender": 1, "recipient": 1, "pinned": 1 }).build(),
            IndexModel::builder().keys(doc! { "timestamp": -1 }).build(),
            IndexModel::builder().keys(doc! { "recipient": 1, "read": 1, "channel": 1, "deleted": 1 }).build(),
            IndexModel::builder().keys(doc! { "channel": 1, "timestamp": -1, "sender": 1, "deleted": 1 }).build(),
            IndexModel::builder().keys(doc! { "mentions": 1, "read": 1 }).build(),
        ];

        col.create_indexes(indexes).await?;
        Ok(())
    }

    pub async fn create(
        db: &Database,
        input: CreateMessageInput,
    ) -> Result<Message, Box<dyn std::error::Error>> {
        validate_message(&input)?;

        let now = DateTime::now();
        let msg = Message {
            id: None,
            sender: input.sender,
            recipient: input.recipient,
            channel: input.channel,
            content: input.content.trim().to_string(),
            message_type: input.message_type.unwrap_or_default(),
            file_url: input.file_url,
            file_type: input.file_type,
            file_size: input.file_size,
            file_name: input.file_name,
            duration_ms: input.duration_ms,
            timestamp: now,
            read: false,
            read_by: vec![],
            reactions: HashMap::new(),
            quoted_message: input.quoted_message,
            mentions: input.mentions.unwrap_or_default(),
            mentions_everyone: input.mentions_everyone.unwrap_or(false),
            edited: false,
            edited_at: None,
            deleted: false,
            deleted_at: None,
            pinned: false,
            pinned_at: None,
            pinned_by: None,
            created_at: now,
            updated_at: now,
            e2e_encrypted: input.e2e_encrypted.unwrap_or(false),
            e2e_version: input.e2e_version,
        };

        let result = Self::collection(db).insert_one(&msg).await?;
        let id = result.inserted_id.as_object_id();

        Ok(Message { id, ..msg })
    }

    pub async fn find_by_id(
        db: &Database,
        id: ObjectId,
    ) -> mongodb::error::Result<Option<Message>> {
        Self::collection(db).find_one(doc! { "_id": id }).await
    }

    pub async fn soft_delete(
        db: &Database,
        id: ObjectId,
    ) -> mongodb::error::Result<()> {
        Self::collection(db)
            .update_one(
                doc! { "_id": id },
                doc! { "$set": {
                    "deleted": true,
                    "deletedAt": DateTime::now(),
                    "updatedAt": DateTime::now(),
                }},
            )
            .await?;

        Ok(())
    }
}