use mongodb::{
    bson::{doc, oid::ObjectId, DateTime},
    Collection, Database, IndexModel,
};
use serde::{Deserialize, Serialize};

use crate::model::channel_moderation::{
    deserialize_moderation_entries, ChannelModerationEntry,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Channel {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub name: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(default)]
    pub members: Vec<ObjectId>,

    pub admin: ObjectId,

    #[serde(
        rename = "bannedMembers",
        default,
        deserialize_with = "deserialize_moderation_entries"
    )]
    pub banned_members: Vec<ChannelModerationEntry>,

    #[serde(
        rename = "mutedMembers",
        default,
        deserialize_with = "deserialize_moderation_entries"
    )]
    pub muted_members: Vec<ChannelModerationEntry>,

    #[serde(default)]
    pub image: String,

    #[serde(default)]
    pub messages: Vec<ObjectId>,

    #[serde(rename = "isPrivate", default)]
    pub is_private: bool,

    /// Per-user message cooldown in seconds (0 = disabled).
    #[serde(rename = "rateLimitPerUser", default)]
    pub rate_limit_per_user: u32,

    /// When true, only the channel admin can send messages.
    #[serde(rename = "chatLocked", default)]
    pub chat_locked: bool,

    #[serde(rename = "createdAt")]
    pub created_at: DateTime,

    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateChannelInput {
    pub name: String,
    pub description: Option<String>,
    pub admin: ObjectId,
    pub members: Option<Vec<ObjectId>>,
    pub is_private: Option<bool>,
    pub image: Option<String>,
}

#[derive(Debug)]
pub enum ChannelValidationError {
    NameRequired,
    NameTooShort,
    NameTooLong,
    DescriptionTooLong,
}

impl std::fmt::Display for ChannelValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::NameRequired      => "Nazwa kanału jest wymagana",
            Self::NameTooShort      => "Nazwa kanału musi mieć minimum 3 znaki",
            Self::NameTooLong       => "Nazwa kanału nie może przekraczać 50 znaków",
            Self::DescriptionTooLong => "Opis nie może przekraczać 200 znaków",
        };
        write!(f, "{}", msg)
    }
}

impl std::error::Error for ChannelValidationError {}

pub fn validate_channel(input: &CreateChannelInput) -> Result<(), ChannelValidationError> {
    let name = input.name.trim();

    if name.is_empty() {
        return Err(ChannelValidationError::NameRequired);
    }
    if name.len() < 3 {
        return Err(ChannelValidationError::NameTooShort);
    }
    if name.len() > 50 {
        return Err(ChannelValidationError::NameTooLong);
    }
    if let Some(desc) = &input.description {
        if desc.trim().len() > 200 {
            return Err(ChannelValidationError::DescriptionTooLong);
        }
    }

    Ok(())
}

impl Channel {
    pub fn collection(db: &Database) -> Collection<Channel> {
        db.collection("channels")
    }

    pub async fn create_indexes(db: &Database) -> mongodb::error::Result<()> {
        let col = Self::collection(db);

        col.create_index(IndexModel::builder().keys(doc! { "name": 1 }).build()).await?;
        col.create_index(IndexModel::builder().keys(doc! { "members": 1 }).build()).await?;
        col.create_index(IndexModel::builder().keys(doc! { "admin": 1 }).build()).await?;

        Ok(())
    }

    pub async fn find_by_id(
        db: &Database,
        id: ObjectId,
    ) -> mongodb::error::Result<Option<Channel>> {
        Self::collection(db).find_one(doc! { "_id": id }).await
    }

    pub async fn find_by_member(
        db: &Database,
        user_id: ObjectId,
    ) -> mongodb::error::Result<Vec<Channel>> {
        use futures_util::TryStreamExt;
        Self::collection(db)
            .find(doc! { "members": user_id })
            .await?
            .try_collect()
            .await
    }

    pub async fn create(
        db: &Database,
        input: CreateChannelInput,
    ) -> Result<Channel, Box<dyn std::error::Error>> {
        validate_channel(&input)?;

        let now = DateTime::now();
        let channel = Channel {
            id: None,
            name: input.name.trim().to_string(),
            description: input.description
                .map(|d| d.trim().to_string())
                .filter(|d| !d.is_empty()),
            members: input.members.unwrap_or_default(),
            admin: input.admin,
            banned_members: vec![],
            muted_members: vec![],
            image: input.image.unwrap_or_default(),
            messages: vec![],
            is_private: input.is_private.unwrap_or(false),
            rate_limit_per_user: 0,
            chat_locked: false,
            created_at: now,
            updated_at: now,
        };

        let result = Self::collection(db).insert_one(&channel).await?;
        let id = result.inserted_id.as_object_id();

        Ok(Channel { id, ..channel })
    }
}