// friend_requests.rs
// Para użytkowników: pending/accepted/blocked.
// Zakres:
//  - unikalność relacji
//  - pending/accepted/blocked; unikalność pary
// Zmiana statusu: inwaliduj friends/cache i typing.rs.
// Przy zmianach: controllers/friends.rs, utils/friends/*.

use mongodb::{
    bson::{doc, oid::ObjectId, DateTime},
    options::IndexOptions,
    Collection, Database, IndexModel,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FriendRequestStatus {
    Pending,
    Accepted,
    Rejected,
}

impl Default for FriendRequestStatus {
    fn default() -> Self {
        Self::Pending
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriendRequest {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub from: ObjectId,

    pub to: ObjectId,

    #[serde(default)]
    pub status: FriendRequestStatus,

    #[serde(rename = "createdAt")]
    pub created_at: DateTime,

    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime,
}

impl FriendRequest {
    pub fn collection(db: &Database) -> Collection<FriendRequest> {
        db.collection("friendrequests")
    }

    pub async fn create_indexes(db: &Database) -> mongodb::error::Result<()> {
        let col = Self::collection(db);

        col.create_index(IndexModel::builder().keys(doc! { "from": 1 }).build()).await?;
        col.create_index(IndexModel::builder().keys(doc! { "to": 1 }).build()).await?;
        col.create_index(IndexModel::builder().keys(doc! { "status": 1 }).build()).await?;
        col.create_index(
            IndexModel::builder()
                .keys(doc! { "status": 1, "from": 1 })
                .build(),
        )
        .await?;
        col.create_index(
            IndexModel::builder()
                .keys(doc! { "status": 1, "to": 1 })
                .build(),
        )
        .await?;

        col.create_index(
            IndexModel::builder()
                .keys(doc! { "from": 1, "to": 1 })
                .options(IndexOptions::builder().unique(true).build())
                .build(),
        ).await?;

        Ok(())
    }

    pub async fn create(
        db: &Database,
        from: ObjectId,
        to: ObjectId,
    ) -> mongodb::error::Result<FriendRequest> {
        let now = DateTime::now();
        let doc = FriendRequest {
            id: None,
            from,
            to,
            status: FriendRequestStatus::Pending,
            created_at: now,
            updated_at: now,
        };

        let result = Self::collection(db).insert_one(&doc).await?;
        let id = result.inserted_id.as_object_id();

        Ok(FriendRequest { id, ..doc })
    }
}
