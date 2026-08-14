//! Server-only searchable index for message bodies.
//!
//! Message `content` stays sealed at rest. `searchText` is AES-GCM encrypted
//! normalized plaintext; substring search uses HMAC token n-grams in
//! `searchTokens`. Neither field is returned by API serializers.

use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, Document};
use mongodb::Database;
use std::sync::OnceLock;

use crate::model::messages_model::Message;
use crate::utils::crypto::field_encrypt::{decrypt_field, encrypt_field};
use crate::utils::crypto::keyed_hash::{derive_subkey, hmac_sha256_hex};
use crate::utils::messages::content_storage::{
    inbound_plaintext_for_processing, reveal_content_internal,
};

const SEARCH_NGRAM_LEN: usize = 2;
const SEARCH_TOKEN_CONTEXT: &str = "search-token-v1";

/// Encrypted `searchText` plus HMAC n-gram tokens for Mongo `$all` queries.
#[derive(Debug, Clone)]
pub struct SearchIndex {
    pub encrypted_text: String,
    pub tokens: Vec<String>,
}

impl SearchIndex {
    pub fn empty() -> Self {
        Self {
            encrypted_text: String::new(),
            tokens: Vec::new(),
        }
    }
}

fn search_token_key() -> Result<[u8; 32], String> {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    if let Some(key) = KEY.get() {
        return Ok(*key);
    }
    let raw = std::env::var("FIELD_ENCRYPTION_KEY")
        .or_else(|_| std::env::var("JWT_KEY"))
        .map_err(|_| "FIELD_ENCRYPTION_KEY or JWT_KEY is required".to_string())?;
    let trimmed = raw.trim();
    if trimmed.len() < 32 {
        return Err("Encryption key must be at least 32 characters".to_string());
    }
    Ok(*KEY.get_or_init(|| derive_subkey(trimmed, SEARCH_TOKEN_CONTEXT)))
}

/// Normalize plaintext for case-insensitive substring search.
pub fn normalize_search_text(plain: &str) -> String {
    plain.trim().to_lowercase()
}

fn search_token_hex(gram: &str) -> String {
    match search_token_key() {
        Ok(key) => hmac_sha256_hex(&key, gram),
        Err(_) => String::new(),
    }
}

/// HMAC n-grams for a normalized (lowercase) query or message body.
pub fn search_tokens_from_normalized(normalized: &str) -> Vec<String> {
    let normalized = normalized.trim();
    if normalized.is_empty() {
        return Vec::new();
    }

    let chars: Vec<char> = normalized.chars().collect();
    let n = SEARCH_NGRAM_LEN.min(chars.len());
    let mut tokens = Vec::new();
    if chars.len() <= n {
        let token = search_token_hex(normalized);
        if !token.is_empty() {
            tokens.push(token);
        }
        return tokens;
    }

    for window in chars.windows(n) {
        let gram: String = window.iter().collect();
        let token = search_token_hex(&gram);
        if token.is_empty() {
            return Vec::new();
        }
        if tokens.last().is_none_or(|last| last != &token) {
            tokens.push(token);
        }
    }
    tokens
}

/// Tokens required for a user search query (empty when query too short after normalize).
pub fn search_tokens_for_query(query: &str) -> Vec<String> {
    search_tokens_from_normalized(&query.trim().to_lowercase())
}

pub fn is_search_text_sealed(stored: &str) -> bool {
    let trimmed = stored.trim();
    !trimmed.is_empty() && decrypt_field(trimmed).is_ok()
}

pub fn build_search_index_from_normalized(normalized: &str) -> Result<SearchIndex, String> {
    let normalized = normalized.trim();
    if normalized.is_empty() {
        return Ok(SearchIndex::empty());
    }
    Ok(SearchIndex {
        encrypted_text: encrypt_field(normalized)?,
        tokens: search_tokens_from_normalized(normalized),
    })
}

pub fn build_search_index_from_incoming(incoming: &str) -> Result<SearchIndex, String> {
    let plain = inbound_plaintext_for_processing(incoming.trim(), false);
    build_search_index_from_normalized(&normalize_search_text(&plain))
}

pub fn search_text_from_incoming(incoming: &str) -> String {
    build_search_index_from_incoming(incoming)
        .map(|idx| idx.encrypted_text)
        .unwrap_or_default()
}

pub fn search_text_from_stored(stored: &str) -> String {
    normalize_search_text(&reveal_content_internal(stored))
}

fn normalized_from_legacy_search_field(search_text: &str, content: &str) -> String {
    let trimmed = search_text.trim();
    if is_search_text_sealed(trimmed) {
        return decrypt_field(trimmed).unwrap_or_default();
    }
    if !trimmed.is_empty() {
        return trimmed.to_string();
    }
    search_text_from_stored(content)
}

/// Backfill sealed `searchText` + `searchTokens` for TEXT messages missing the index.
/// Runs in bounded batches so startup stays responsive.
pub async fn backfill_message_search_text(db: &Database) -> mongodb::error::Result<u64> {
    const BATCH: i64 = 200;
    const MAX_BATCHES: u32 = 50;

    let mut updated = 0u64;
    for _ in 0..MAX_BATCHES {
        let cursor = Message::collection(db)
            .find(doc! {
                "messageType": "TEXT",
                "deleted": { "$ne": true },
                "$or": [
                    { "searchTokens": { "$exists": false } },
                    { "searchTokens": { "$size": 0 } },
                    {
                        "$and": [
                            { "searchText": { "$type": "string", "$ne": "" } },
                            { "searchText": { "$not": { "$regex": "^[A-Z2-7]+$" } } },
                        ]
                    },
                ],
            })
            .limit(BATCH)
            .await?;

        let batch: Vec<Message> = cursor.try_collect().await?;
        if batch.is_empty() {
            break;
        }

        let mut batch_updated = 0u64;
        for msg in batch {
            let Some(id) = msg.id else { continue };
            let normalized = normalized_from_legacy_search_field(&msg.search_text, &msg.content);
            let index = match build_search_index_from_normalized(&normalized) {
                Ok(index) => index,
                Err(e) => {
                    log::warn!("searchText backfill encrypt failed for {id}: {e}");
                    continue;
                }
            };
            let _ = Message::collection(db)
                .update_one(
                    doc! { "_id": id },
                    doc! {
                        "$set": {
                            "searchText": &index.encrypted_text,
                            "searchTokens": &index.tokens,
                        }
                    },
                )
                .await?;
            batch_updated += 1;
        }
        updated += batch_updated;
        if batch_updated == 0 {
            break;
        }
    }

    Ok(updated)
}

/// Projection-only `_id` fetch for mark-read (avoids loading sealed content).
pub async fn collect_message_ids(
    db: &Database,
    filter: Document,
) -> mongodb::error::Result<Vec<ObjectId>> {
    collect_message_ids_limited(db, filter, None).await
}

/// Same as [`collect_message_ids`], optionally capped (e.g. mark-read emit budget).
pub async fn collect_message_ids_limited(
    db: &Database,
    filter: Document,
    limit: Option<i64>,
) -> mongodb::error::Result<Vec<ObjectId>> {
    let coll = db.collection::<Document>("messages");
    let mut find = coll.find(filter).projection(doc! { "_id": 1 });
    if let Some(limit) = limit {
        find = find.limit(limit);
    }
    let mut cursor = find.await?;

    let mut ids = Vec::new();
    while let Some(doc) = cursor.try_next().await? {
        if let Ok(id) = doc.get_object_id("_id") {
            ids.push(id);
        }
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ngram_tokens_cover_substring_query() {
        std::env::set_var("JWT_KEY", "test-jwt-key-for-search-text-unit-test-xx");
        let body = normalize_search_text("Hello World");
        let tokens = search_tokens_from_normalized(&body);
        let query = search_tokens_for_query("lo wo");
        assert!(!tokens.is_empty());
        assert!(!query.is_empty());
        for token in &query {
            assert!(tokens.contains(token));
        }
    }

    #[test]
    fn sealed_search_text_is_not_plaintext() {
        std::env::set_var("JWT_KEY", "test-jwt-key-for-search-text-unit-test-xx");
        let index = build_search_index_from_normalized("secret phrase").expect("index");
        assert_ne!(index.encrypted_text, "secret phrase");
        assert!(is_search_text_sealed(&index.encrypted_text));
        assert!(!index.tokens.is_empty());
    }
}
