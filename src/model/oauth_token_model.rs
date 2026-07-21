use mongodb::bson::{doc, oid::ObjectId, DateTime};
use mongodb::{Collection, Database, IndexModel};
use mongodb::options::{IndexOptions, UpdateOptions};
use serde::{Deserialize, Serialize};

use crate::utils::crypto::field_encrypt::{decrypt_field, encrypt_field};

pub const PROVIDER_SPOTIFY: &str = "spotify";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OauthToken {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    #[serde(rename = "userId")]
    pub user_id: ObjectId,
    pub provider: String,
    #[serde(rename = "accessTokenEnc")]
    pub access_token_enc: String,
    #[serde(rename = "refreshTokenEnc")]
    pub refresh_token_enc: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTime,
    pub scopes: Vec<String>,
    #[serde(rename = "providerUserId", skip_serializing_if = "Option::is_none")]
    pub provider_user_id: Option<String>,
    #[serde(rename = "providerDisplayName", skip_serializing_if = "Option::is_none")]
    pub provider_display_name: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime,
}

impl OauthToken {
    fn collection(db: &Database) -> Collection<Self> {
        db.collection("oauth_tokens")
    }

    pub async fn create_indexes(db: &Database) -> mongodb::error::Result<()> {
        let collection = Self::collection(db);
        collection
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "userId": 1, "provider": 1 })
                    .options(IndexOptions::builder().unique(true).build())
                    .build(),
            )
            .await?;
        Ok(())
    }

    pub async fn find_by_user_provider(
        db: &Database,
        user_id: ObjectId,
        provider: &str,
    ) -> mongodb::error::Result<Option<Self>> {
        Self::collection(db)
            .find_one(doc! { "userId": user_id, "provider": provider })
            .await
    }

    pub async fn upsert(
        db: &Database,
        user_id: ObjectId,
        provider: &str,
        access_token: &str,
        refresh_token: &str,
        expires_at: DateTime,
        scopes: Vec<String>,
        provider_user_id: Option<String>,
        provider_display_name: Option<String>,
    ) -> Result<Self, String> {
        let access_token_enc = encrypt_field(access_token)?;
        let refresh_token_enc = encrypt_field(refresh_token)?;
        let now = DateTime::now();

        let mut set_doc = doc! {
            "accessTokenEnc": access_token_enc,
            "refreshTokenEnc": refresh_token_enc,
            "expiresAt": expires_at,
            "scopes": scopes,
            "updatedAt": now,
        };
        if let Some(pid) = provider_user_id {
            set_doc.insert("providerUserId", pid);
        }
        if let Some(name) = provider_display_name {
            set_doc.insert("providerDisplayName", name);
        }

        Self::collection(db)
            .update_one(
                doc! { "userId": user_id, "provider": provider },
                doc! {
                    "$set": set_doc,
                    "$setOnInsert": {
                        "userId": user_id,
                        "provider": provider,
                        "createdAt": now,
                    },
                },
            )
            .with_options(UpdateOptions::builder().upsert(true).build())
            .await
            .map_err(|e| e.to_string())?;

        Self::find_by_user_provider(db, user_id, provider)
            .await
            .map_err(|e| format!("Failed to load oauth token after upsert: {e}"))?
            .ok_or_else(|| "Failed to load oauth token after upsert".to_string())
    }

    pub async fn delete_for_user_provider(
        db: &Database,
        user_id: ObjectId,
        provider: &str,
    ) -> mongodb::error::Result<()> {
        Self::collection(db)
            .delete_one(doc! { "userId": user_id, "provider": provider })
            .await?;
        Ok(())
    }

    pub fn access_token(&self) -> Result<String, String> {
        decrypt_field(&self.access_token_enc)
    }

    pub fn refresh_token(&self) -> Result<String, String> {
        decrypt_field(&self.refresh_token_enc)
    }

    pub async fn update_tokens(
        db: &Database,
        id: ObjectId,
        access_token: &str,
        refresh_token: &str,
        expires_at: DateTime,
    ) -> Result<(), String> {
        let access_token_enc = encrypt_field(access_token)?;
        let refresh_token_enc = encrypt_field(refresh_token)?;
        Self::collection(db)
            .update_one(
                doc! { "_id": id },
                doc! {
                    "$set": {
                        "accessTokenEnc": access_token_enc,
                        "refreshTokenEnc": refresh_token_enc,
                        "expiresAt": expires_at,
                        "updatedAt": DateTime::now(),
                    }
                },
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}
