use mongodb::bson::{doc, oid::ObjectId, DateTime};
use mongodb::{Collection, Database, IndexModel};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserStorageUsage {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    #[serde(rename = "userId")]
    pub user_id: ObjectId,
    #[serde(rename = "bytesUsed", default)]
    pub bytes_used: i64,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime,
}

impl UserStorageUsage {
    fn collection(db: &Database) -> Collection<Self> {
        db.collection("user_storage_usage")
    }

    pub async fn create_indexes(db: &Database) -> mongodb::error::Result<()> {
        Self::collection(db)
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "userId": 1 })
                    .build(),
            )
            .await?;
        Ok(())
    }

    pub async fn bytes_used(db: &Database, user_id: ObjectId) -> mongodb::error::Result<i64> {
        Ok(Self::collection(db)
            .find_one(doc! { "userId": user_id })
            .await?
            .map(|entry| entry.bytes_used.max(0))
            .unwrap_or(0))
    }

    pub async fn would_exceed(
        db: &Database,
        user_id: ObjectId,
        additional: u64,
    ) -> mongodb::error::Result<bool> {
        let max = crate::utils::upload_limits::max_user_storage_bytes();
        let current = Self::bytes_used(db, user_id).await?;
        Ok(current.saturating_add(additional as i64) > max as i64)
    }

    pub async fn adjust(
        db: &Database,
        user_id: ObjectId,
        delta: i64,
    ) -> mongodb::error::Result<()> {
        if delta == 0 {
            return Ok(());
        }
        Self::collection(db)
            .update_one(
                doc! { "userId": user_id },
                doc! {
                    "$inc": { "bytesUsed": delta },
                    "$set": { "updatedAt": DateTime::now() },
                    "$setOnInsert": { "userId": user_id },
                },
            )
            .upsert(true)
            .await?;
        Ok(())
    }

    pub async fn set_bytes(
        db: &Database,
        user_id: ObjectId,
        bytes: i64,
    ) -> mongodb::error::Result<()> {
        Self::collection(db)
            .update_one(
                doc! { "userId": user_id },
                doc! {
                    "$set": {
                        "bytesUsed": bytes.max(0),
                        "updatedAt": DateTime::now(),
                    },
                    "$setOnInsert": { "userId": user_id },
                },
            )
            .upsert(true)
            .await?;
        Ok(())
    }
}
