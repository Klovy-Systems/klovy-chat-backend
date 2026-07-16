//! Tokeny uwierzytelniające boty (runtime API `/api/bot/*`).
//!
//! Token ma postać `"{botIdHex}.{sekret}"`. W bazie przechowujemy wyłącznie
//! `token_hash = sha256(sekret)` — surowy token pokazujemy właścicielowi tylko
//! raz (przy utworzeniu/regeneracji). Każdy bot ma najwyżej jeden aktywny token
//! (regeneracja zastępuje poprzedni).

use mongodb::bson::{doc, oid::ObjectId, DateTime};
use mongodb::options::IndexOptions;
use mongodb::{Collection, Database, IndexModel};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotToken {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    #[serde(rename = "botId")]
    pub bot_id: ObjectId,

    #[serde(rename = "tokenHash")]
    pub token_hash: String,

    #[serde(rename = "tokenPrefix")]
    pub token_prefix: String,

    #[serde(rename = "createdAt")]
    pub created_at: DateTime,

    #[serde(rename = "lastUsedAt", skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime>,
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

fn random_secret() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill(&mut bytes);
    hex::encode(bytes)
}

/// Porównanie ciągów odporne na atak czasowy (oba argumenty to heksy sha256).
fn constant_time_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

impl BotToken {
    pub fn collection(db: &Database) -> Collection<BotToken> {
        db.collection("bot_tokens")
    }

    pub async fn create_indexes(db: &Database) -> mongodb::error::Result<()> {
        Self::collection(db)
            .create_index(
                IndexModel::builder()
                    .keys(doc! { "botId": 1 })
                    .options(IndexOptions::builder().unique(true).build())
                    .build(),
            )
            .await?;
        Ok(())
    }

    /// Wydaje nowy token dla bota, zastępując ewentualny istniejący.
    /// Zwraca surowy token (widoczny tylko teraz).
    pub async fn issue(db: &Database, bot_id: ObjectId) -> mongodb::error::Result<String> {
        let secret = random_secret();
        let token_hash = sha256_hex(&secret);
        let bot_hex = bot_id.to_hex();
        let token_prefix = bot_hex.chars().take(6).collect::<String>();

        Self::collection(db)
            .delete_many(doc! { "botId": bot_id })
            .await?;

        let record = BotToken {
            id: None,
            bot_id,
            token_hash,
            token_prefix,
            created_at: DateTime::now(),
            last_used_at: None,
        };
        Self::collection(db).insert_one(&record).await?;

        Ok(format!("{bot_hex}.{secret}"))
    }

    /// Weryfikuje surowy token i zwraca id bota, jeśli poprawny.
    pub async fn verify(db: &Database, raw: &str) -> Option<ObjectId> {
        let (bot_hex, secret) = raw.split_once('.')?;
        if bot_hex.is_empty() || secret.is_empty() {
            return None;
        }
        let bot_id = ObjectId::parse_str(bot_hex).ok()?;

        let record = Self::collection(db)
            .find_one(doc! { "botId": bot_id })
            .await
            .ok()
            .flatten()?;

        let computed = sha256_hex(secret);
        if constant_time_eq(&computed, &record.token_hash) {
            Some(bot_id)
        } else {
            None
        }
    }

    pub async fn revoke_for_bot(db: &Database, bot_id: ObjectId) -> mongodb::error::Result<()> {
        Self::collection(db)
            .delete_many(doc! { "botId": bot_id })
            .await?;
        Ok(())
    }

    pub async fn touch_last_used(db: &Database, bot_id: ObjectId) {
        let _ = Self::collection(db)
            .update_one(
                doc! { "botId": bot_id },
                doc! { "$set": { "lastUsedAt": DateTime::now() } },
            )
            .await;
    }
}
