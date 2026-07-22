use mongodb::{
    bson::{doc, oid::ObjectId, DateTime},
    options::{FindOneAndUpdateOptions, IndexOptions, ReturnDocument},
    Collection, Database, IndexModel,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPreKeyRecord {
    pub id: u32,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneTimePreKeyRecord {
    pub id: u32,
    #[serde(rename = "publicKey")]
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct E2eKeyBundle {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    #[serde(rename = "userId")]
    pub user_id: ObjectId,

    #[serde(rename = "registrationId")]
    pub registration_id: u32,

    #[serde(rename = "identityKey")]
    pub identity_key: String,

    #[serde(rename = "identityFingerprint")]
    pub identity_fingerprint: String,

    #[serde(rename = "signedPreKey")]
    pub signed_pre_key: SignedPreKeyRecord,

    #[serde(rename = "oneTimePreKeys", default)]
    pub one_time_pre_keys: Vec<OneTimePreKeyRecord>,

    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicPreKeyBundle {
    #[serde(rename = "userId")]
    pub user_id: String,
    #[serde(rename = "registrationId")]
    pub registration_id: u32,
    #[serde(rename = "identityKey")]
    pub identity_key: String,
    #[serde(rename = "identityFingerprint")]
    pub identity_fingerprint: String,
    #[serde(rename = "signedPreKey")]
    pub signed_pre_key: SignedPreKeyRecord,
    #[serde(rename = "oneTimePreKey", skip_serializing_if = "Option::is_none")]
    pub one_time_pre_key: Option<OneTimePreKeyRecord>,
    #[serde(rename = "e2eEnabled")]
    pub e2e_enabled: bool,
}

pub struct UpsertE2eKeysInput {
    pub user_id: ObjectId,
    pub registration_id: u32,
    pub identity_key: String,
    pub identity_fingerprint: String,
    pub signed_pre_key: SignedPreKeyRecord,
    pub one_time_pre_keys: Vec<OneTimePreKeyRecord>,
}

impl E2eKeyBundle {
    pub fn collection(db: &Database) -> Collection<Self> {
        db.collection("e2e_keys")
    }

    pub async fn create_indexes(db: &Database) -> mongodb::error::Result<()> {
        let col = Self::collection(db);
        col.create_indexes(vec![IndexModel::builder()
            .keys(doc! { "userId": 1 })
            .options(IndexOptions::builder().unique(true).build())
            .build()])
            .await?;
        Ok(())
    }

    pub async fn upsert(
        db: &Database,
        input: UpsertE2eKeysInput,
    ) -> mongodb::error::Result<E2eKeyBundle> {
        let now = DateTime::now();
        let filter = doc! { "userId": input.user_id };
        let update = doc! {
            "$set": {
                "registrationId": input.registration_id as i64,
                "identityKey": &input.identity_key,
                "identityFingerprint": &input.identity_fingerprint,
                "signedPreKey": mongodb::bson::to_bson(&input.signed_pre_key).unwrap_or_default(),
                "oneTimePreKeys": mongodb::bson::to_bson(&input.one_time_pre_keys).unwrap_or_default(),
                "updatedAt": now,
            },
            "$setOnInsert": {
                "userId": input.user_id,
            }
        };
        let opts = FindOneAndUpdateOptions::builder()
            .upsert(true)
            .return_document(ReturnDocument::After)
            .build();
        Self::collection(db)
            .find_one_and_update(filter, update)
            .with_options(opts)
            .await
            .map(|opt| opt.unwrap_or(E2eKeyBundle {
                id: None,
                user_id: input.user_id,
                registration_id: input.registration_id,
                identity_key: input.identity_key,
                identity_fingerprint: input.identity_fingerprint,
                signed_pre_key: input.signed_pre_key,
                one_time_pre_keys: input.one_time_pre_keys,
                updated_at: now,
            }))
    }

    pub async fn find_by_user_id(
        db: &Database,
        user_id: ObjectId,
    ) -> mongodb::error::Result<Option<Self>> {
        Self::collection(db)
            .find_one(doc! { "userId": user_id })
            .await
    }

    pub async fn append_one_time_prekeys(
        db: &Database,
        user_id: ObjectId,
        keys: Vec<OneTimePreKeyRecord>,
    ) -> mongodb::error::Result<()> {
        if keys.is_empty() {
            return Ok(());
        }
        Self::collection(db)
            .update_one(
                doc! { "userId": user_id },
                doc! {
                    "$push": { "oneTimePreKeys": { "$each": mongodb::bson::to_bson(&keys).unwrap_or_default() } },
                    "$set": { "updatedAt": DateTime::now() },
                },
            )
            .await?;
        Ok(())
    }

    /// Atomically pop one one-time prekey for session setup.
    pub async fn consume_public_bundle(
        db: &Database,
        user_id: ObjectId,
        e2e_enabled: bool,
    ) -> mongodb::error::Result<Option<PublicPreKeyBundle>> {
        let now = DateTime::now();
        let opts = FindOneAndUpdateOptions::builder()
            .return_document(ReturnDocument::Before)
            .build();

        let before = Self::collection(db)
            .find_one_and_update(
                doc! {
                    "userId": user_id,
                    "oneTimePreKeys.0": { "$exists": true },
                },
                doc! {
                    "$pop": { "oneTimePreKeys": -1 },
                    "$set": { "updatedAt": now },
                },
            )
            .with_options(opts)
            .await?;

        if let Some(bundle) = before {
            let one_time = bundle.one_time_pre_keys.first().cloned();
            return Ok(Some(PublicPreKeyBundle {
                user_id: user_id.to_hex(),
                registration_id: bundle.registration_id,
                identity_key: bundle.identity_key,
                identity_fingerprint: bundle.identity_fingerprint,
                signed_pre_key: bundle.signed_pre_key,
                one_time_pre_key: one_time,
                e2e_enabled,
            }));
        }

        let bundle = Self::find_by_user_id(db, user_id).await?;
        let Some(bundle) = bundle else {
            return Ok(None);
        };

        Ok(Some(PublicPreKeyBundle {
            user_id: user_id.to_hex(),
            registration_id: bundle.registration_id,
            identity_key: bundle.identity_key,
            identity_fingerprint: bundle.identity_fingerprint,
            signed_pre_key: bundle.signed_pre_key,
            one_time_pre_key: None,
            e2e_enabled,
        }))
    }

    pub async fn delete_for_user(db: &Database, user_id: ObjectId) -> mongodb::error::Result<()> {
        Self::collection(db)
            .delete_one(doc! { "userId": user_id })
            .await?;
        Ok(())
    }

    pub async fn find_fingerprints_bulk(
        db: &Database,
        user_ids: &[ObjectId],
    ) -> mongodb::error::Result<Vec<(ObjectId, String, u32)>> {
        if user_ids.is_empty() {
            return Ok(vec![]);
        }
        let mut cursor = Self::collection(db)
            .find(doc! { "userId": { "$in": user_ids } })
            .await?;
        let mut out = Vec::new();
        while let Some(doc) = cursor.try_next().await? {
            out.push((doc.user_id, doc.identity_fingerprint, doc.registration_id));
        }
        Ok(out)
    }
}

use futures::TryStreamExt;
