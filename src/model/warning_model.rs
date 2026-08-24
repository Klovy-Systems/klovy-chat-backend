use mongodb::{
    bson::{doc, oid::ObjectId, DateTime},
    Collection, Database, IndexModel,
};
use serde::{Deserialize, Serialize};

/// Poziom ostrzeżenia — zgodny z gradacją naruszeń w regulaminie.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WarningSeverity {
    Low,
    Medium,
    High,
}

impl Default for WarningSeverity {
    fn default() -> Self {
        WarningSeverity::Medium
    }
}

pub fn severity_str(severity: &WarningSeverity) -> &'static str {
    match severity {
        WarningSeverity::Low => "low",
        WarningSeverity::Medium => "medium",
        WarningSeverity::High => "high",
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Warning {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    #[serde(rename = "userId")]
    pub user_id: ObjectId,

    pub reason: String,

    #[serde(default)]
    pub severity: WarningSeverity,

    /// Etykieta wystawiającego (np. "admin"). Panel admina jest bezimienny,
    /// więc nie przechowujemy tożsamości konkretnego administratora.
    #[serde(rename = "issuedBy", default = "default_issued_by")]
    pub issued_by: String,

    #[serde(default)]
    pub acknowledged: bool,

    #[serde(rename = "acknowledgedAt", skip_serializing_if = "Option::is_none")]
    pub acknowledged_at: Option<DateTime>,

    #[serde(rename = "createdAt")]
    pub created_at: DateTime,
}

fn default_issued_by() -> String {
    "admin".to_string()
}

impl Warning {
    pub fn collection(db: &Database) -> Collection<Warning> {
        db.collection("warnings")
    }

    pub async fn create_indexes(db: &Database) -> mongodb::error::Result<()> {
        let col = Self::collection(db);

        col.create_index(
            IndexModel::builder()
                .keys(doc! { "userId": 1, "createdAt": -1 })
                .build(),
        )
        .await?;

        col.create_index(
            IndexModel::builder()
                .keys(doc! { "userId": 1, "acknowledged": 1 })
                .build(),
        )
        .await?;

        Ok(())
    }

    pub async fn list_for_user(
        db: &Database,
        user_id: ObjectId,
    ) -> mongodb::error::Result<Vec<Warning>> {
        use futures_util::TryStreamExt;
        Self::collection(db)
            .find(doc! { "userId": user_id })
            .sort(doc! { "createdAt": -1 })
            .limit(200)
            .await?
            .try_collect()
            .await
    }

    pub async fn acknowledge_all_for_user(
        db: &Database,
        user_id: ObjectId,
    ) -> mongodb::error::Result<u64> {
        let result = Self::collection(db)
            .update_many(
                doc! { "userId": user_id, "acknowledged": false },
                doc! { "$set": { "acknowledged": true, "acknowledgedAt": DateTime::now() } },
            )
            .await?;
        Ok(result.modified_count)
    }
}
