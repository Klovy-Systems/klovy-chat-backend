//! Server-only searchable plaintext index for message bodies.
//!
//! Message `content` stays sealed at rest. `searchText` is a normalized lowercase
//! copy used exclusively for MongoDB regex search so we do not AES-decrypt up to
//! 2000 documents on every query. It is never returned by the API serializers.

use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, Bson, Document};
use mongodb::Database;

use crate::model::messages_model::Message;
use crate::utils::messages::content_storage::reveal_content_internal;
use crate::utils::messages::escape_regex;

/// Normalize plaintext for case-insensitive substring search.
pub fn normalize_search_text(plain: &str) -> String {
    plain.trim().to_lowercase()
}

pub fn search_text_from_incoming(incoming: &str) -> String {
    let plain = crate::utils::messages::content_storage::inbound_plaintext_for_processing(
        incoming.trim(),
        false,
    );
    normalize_search_text(&plain)
}

pub fn search_text_from_stored(stored: &str) -> String {
    normalize_search_text(&reveal_content_internal(stored))
}

/// Escape user query for a case-insensitive Mongo `$regex` contains match.
pub fn search_regex_pattern(query: &str) -> String {
    escape_regex(&query.trim().to_lowercase())
}

/// Backfill `searchText` for TEXT messages that were stored before the index existed.
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
                    { "searchText": { "$exists": false } },
                    { "searchText": Bson::Null },
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
            let search_text = search_text_from_stored(&msg.content);
            let _ = Message::collection(db)
                .update_one(
                    doc! { "_id": id },
                    doc! { "$set": { "searchText": &search_text } },
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
    let mut cursor = db
        .collection::<Document>("messages")
        .find(filter)
        .projection(doc! { "_id": 1 })
        .await?;

    let mut ids = Vec::new();
    while let Some(doc) = cursor.try_next().await? {
        if let Ok(id) = doc.get_object_id("_id") {
            ids.push(id);
        }
    }
    Ok(ids)
}
