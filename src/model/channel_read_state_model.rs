use mongodb::{
    bson::{doc, oid::ObjectId, DateTime},
    options::IndexOptions,
    Collection, Database, IndexModel,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelReadState {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    #[serde(rename = "userId")]
    pub user_id: ObjectId,

    #[serde(rename = "channelId")]
    pub channel_id: ObjectId,

    #[serde(rename = "lastReadAt")]
    pub last_read_at: DateTime,

    #[serde(rename = "createdAt")]
    pub created_at: DateTime,

    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime,
}

impl ChannelReadState {
    pub fn collection(db: &Database) -> Collection<ChannelReadState> {
        db.collection("channelreadstates")
    }

    pub async fn create_indexes(db: &Database) -> mongodb::error::Result<()> {
        let col = Self::collection(db);

        col.create_index(
            IndexModel::builder()
                .keys(doc! { "userId": 1, "channelId": 1 })
                .options(IndexOptions::builder().unique(true).build())
                .build(),
        )
        .await?;

        col.create_index(
            IndexModel::builder()
                .keys(doc! { "channelId": 1 })
                .build(),
        )
        .await?;

        Ok(())
    }

    pub async fn find(
        db: &Database,
        user_id: ObjectId,
        channel_id: ObjectId,
    ) -> mongodb::error::Result<Option<ChannelReadState>> {
        Self::collection(db)
            .find_one(doc! { "userId": user_id, "channelId": channel_id })
            .await
    }

    pub async fn upsert(
        db: &Database,
        user_id: ObjectId,
        channel_id: ObjectId,
    ) -> mongodb::error::Result<()> {
        use mongodb::options::UpdateOptions;

        let now = DateTime::now();
        Self::collection(db)
            .update_one(
                doc! { "userId": user_id, "channelId": channel_id },
                doc! {
                    "$set": { "lastReadAt": now, "updatedAt": now },
                    "$setOnInsert": { "createdAt": now },
                },
            )
            .with_options(UpdateOptions::builder().upsert(true).build())
            .await?;

        Ok(())
    }
}