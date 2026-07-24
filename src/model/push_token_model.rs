use futures::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, DateTime};
use mongodb::{Collection, Database, IndexModel};
use mongodb::options::{IndexOptions, UpdateOptions};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushToken {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    #[serde(rename = "userId")]
    pub user_id: ObjectId,
    pub token: String,
    pub platform: String,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime,
}

impl PushToken {
    fn collection(db: &Database) -> Collection<Self> {
        db.collection("push_tokens")
    }

    pub async fn create_indexes(db: &Database) -> mongodb::error::Result<()> {
        let collection = Self::collection(db);
        collection
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "token": 1 })
                    .options(IndexOptions::builder().unique(true).build())
                    .build(),
            )
            .await?;
        collection
            .create_index(
                IndexModel::builder().keys(doc! { "userId": 1 }).build(),
            )
            .await?;
        Ok(())
    }

    pub async fn upsert_for_user(
        db: &Database,
        user_id: ObjectId,
        token: &str,
        platform: &str,
    ) -> mongodb::error::Result<()> {
        let now = DateTime::now();
        Self::collection(db)
            .update_one(
                doc! { "token": token },
                doc! {
                    "$set": {
                        "userId": user_id,
                        "token": token,
                        "platform": platform,
                        "updatedAt": now,
                    },
                    "$setOnInsert": {
                        "createdAt": now,
                    },
                },
            )
            .with_options(UpdateOptions::builder().upsert(true).build())
            .await?;
        Ok(())
    }

    pub async fn delete_token(db: &Database, user_id: ObjectId, token: &str) -> mongodb::error::Result<()> {
        Self::collection(db)
            .delete_one(doc! { "userId": user_id, "token": token })
            .await?;
        Ok(())
    }

    pub async fn delete_all_for_user(db: &Database, user_id: ObjectId) -> mongodb::error::Result<u64> {
        let result = Self::collection(db)
            .delete_many(doc! { "userId": user_id })
            .await?;
        Ok(result.deleted_count)
    }

    pub async fn find_tokens_for_user(
        db: &Database,
        user_id: ObjectId,
    ) -> mongodb::error::Result<Vec<String>> {
        let mut cursor = Self::collection(db)
            .find(doc! { "userId": user_id })
            .await?;
        let mut out = Vec::new();
        while let Some(doc) = cursor.try_next().await? {
            out.push(doc.token);
        }
        Ok(out)
    }
}
