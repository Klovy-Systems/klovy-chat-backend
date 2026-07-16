use mongodb::{
    bson::{doc, oid::ObjectId, DateTime, Bson},
    options::{FindOneAndUpdateOptions, ReturnDocument},
    Collection, Database, IndexModel,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invite {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    #[serde(rename = "inviteId")]
    pub invite_id: String,

    #[serde(rename = "channelId")]
    pub channel_id: ObjectId,

    #[serde(rename = "createdBy")]
    pub created_by: ObjectId,

    #[serde(rename = "createdAt")]
    pub created_at: DateTime,

    #[serde(rename = "expiresAt", skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime>,

    #[serde(default)]
    pub used: bool,
}

impl Invite {
    pub fn collection(db: &Database) -> Collection<Invite> {
        db.collection("invites")
    }

    pub async fn create_indexes(db: &Database) -> mongodb::error::Result<()> {
        use mongodb::options::IndexOptions;

        Self::collection(db)
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "inviteId": 1 })
                    .options(IndexOptions::builder().unique(true).build())
                    .build(),
            )
            .await?;

        Ok(())
    }

    pub async fn create(
        db: &Database,
        channel_id: ObjectId,
        created_by: ObjectId,
        expires_at: Option<DateTime>,
    ) -> mongodb::error::Result<Invite> {
        const SEVEN_DAYS_MS: i64 = 7 * 24 * 60 * 60 * 1000;
        let expires_at = expires_at.or_else(|| {
            Some(DateTime::from_millis(
                DateTime::now().timestamp_millis() + SEVEN_DAYS_MS,
            ))
        });

        let invite = Invite {
            id: None,
            invite_id: Uuid::new_v4().to_string(), 
            channel_id,
            created_by,
            created_at: DateTime::now(),
            expires_at,
            used: false,
        };

        let result = Self::collection(db).insert_one(&invite).await?;
        let id = result.inserted_id.as_object_id();

        Ok(Invite { id, ..invite })
    }

    pub async fn find_by_invite_id(
        db: &Database,
        invite_id: &str,
    ) -> mongodb::error::Result<Option<Invite>> {
        Self::collection(db)
            .find_one(doc! { "inviteId": invite_id })
            .await
    }

    pub async fn try_consume(
        db: &Database,
        invite_id: &str,
    ) -> mongodb::error::Result<Option<Invite>> {
        let now = DateTime::now();
        let filter = doc! {
            "inviteId": invite_id,
            "used": false,
            "$or": [
                { "expiresAt": { "$exists": false } },
                { "expiresAt": Bson::Null },
                { "expiresAt": { "$gt": now } },
            ],
        };
        let update = doc! { "$set": { "used": true } };
        let options = FindOneAndUpdateOptions::builder()
            .return_document(ReturnDocument::After)
            .build();

        Self::collection(db)
            .find_one_and_update(filter, update)
            .with_options(options)
            .await
    }

}