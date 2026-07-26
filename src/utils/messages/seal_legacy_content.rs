use futures_util::TryStreamExt;
use mongodb::bson::{doc, DateTime};
use mongodb::Database;

use crate::model::messages_model::Message;
use crate::utils::e2e::{is_valid_e2e_ciphertext, rejects_plaintext_storage};
use crate::utils::messages::content_storage::{
    inbound_plaintext_for_processing, is_client_opaque, is_content_server_sealed,
    prepare_content_for_storage, reveal_content_internal, unwrap_client_opaque,
};

#[derive(Debug, Default, Clone, Copy)]
pub struct MigrateContentSealReport {
    pub scanned: u64,
    pub skipped_already_sealed: u64,
    pub skipped_e2e: u64,
    pub skipped_empty: u64,
    pub skipped_unchanged: u64,
    pub skipped_concurrent_update: u64,
    pub migrated: u64,
    pub errors: u64,
}

#[derive(Debug, Clone)]
pub struct MigrateContentSealOptions {
    pub dry_run: bool,
    pub batch_size: u32,
    pub limit: Option<u64>,
}

impl Default for MigrateContentSealOptions {
    fn default() -> Self {
        Self {
            dry_run: true,
            batch_size: 200,
            limit: None,
        }
    }
}

fn is_likely_plain_chat_text(text: &str) -> bool {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return false;
    }
    let total = trimmed.chars().count();
    let readable = trimmed
        .chars()
        .filter(|c| {
            c.is_alphanumeric()
                || c.is_whitespace()
                || ".,!?…@#:;/-_'\"()[]{}+=*&%$<>".contains(*c)
        })
        .count();
    readable * 10 >= total * 7
}

/// Whether a non-E2E message body should be sealed in MongoDB.
pub fn message_content_needs_seal_migration(stored: &str, e2e_encrypted: bool) -> bool {
    if e2e_encrypted || stored.trim().is_empty() {
        return false;
    }
    if is_content_server_sealed(stored) {
        return false;
    }
    if is_client_opaque(stored) {
        let inner = unwrap_client_opaque(stored);
        if is_likely_plain_chat_text(&inner) {
            return true;
        }
    } else if is_valid_e2e_ciphertext(stored) && !rejects_plaintext_storage(stored) {
        return false;
    }
    !is_valid_e2e_ciphertext(stored) || rejects_plaintext_storage(stored)
}

/// Seal legacy plaintext / client-opaque content for DB storage. Returns `None` when unchanged.
pub fn seal_legacy_message_content(
    stored: &str,
    e2e_encrypted: bool,
) -> Result<Option<String>, String> {
    if !message_content_needs_seal_migration(stored, e2e_encrypted) {
        return Ok(None);
    }

    let before = inbound_plaintext_for_processing(stored, false);
    let sealed = prepare_content_for_storage(stored, false)?;
    let after = reveal_content_internal(&sealed, false);
    if before != after {
        return Err("content roundtrip mismatch after seal".to_string());
    }
    if sealed == stored {
        return Ok(None);
    }
    Ok(Some(sealed))
}

pub async fn migrate_message_content_seal(
    db: &Database,
    options: MigrateContentSealOptions,
) -> Result<MigrateContentSealReport, mongodb::error::Error> {
    let mut report = MigrateContentSealReport::default();
    let filter = doc! {
        "$and": [
            {
                "$or": [
                    { "e2eEncrypted": { "$exists": false } },
                    { "e2eEncrypted": false },
                ]
            },
            { "content": { "$exists": true, "$type": "string", "$ne": "" } },
        ]
    };

    let batch_size = options.batch_size.max(1) as u64;
    let mut cursor = Message::collection(db)
        .find(filter)
        .batch_size(options.batch_size)
        .await?;

    while let Some(result) = cursor.try_next().await? {
        if options.limit.is_some_and(|limit| report.scanned >= limit) {
            break;
        }

        let msg = result;
        report.scanned += 1;

        let Some(id) = msg.id else {
            report.errors += 1;
            log::warn!("message without _id skipped");
            continue;
        };

        if msg.e2e_encrypted {
            report.skipped_e2e += 1;
            continue;
        }

        if msg.content.trim().is_empty() {
            report.skipped_empty += 1;
            continue;
        }

        if is_content_server_sealed(&msg.content) {
            report.skipped_already_sealed += 1;
            continue;
        }

        if !message_content_needs_seal_migration(&msg.content, false) {
            report.skipped_e2e += 1;
            continue;
        }

        let original = msg.content.clone();
        let sealed = match seal_legacy_message_content(&original, false) {
            Ok(Some(value)) => value,
            Ok(None) => {
                report.skipped_unchanged += 1;
                continue;
            }
            Err(e) => {
                report.errors += 1;
                log::error!("message {id}: seal failed: {e}");
                continue;
            }
        };

        if options.dry_run {
            report.migrated += 1;
            if report.migrated <= 5 {
                log::info!(
                    "[dry-run] would seal message {id} (len {} -> {})",
                    original.len(),
                    sealed.len()
                );
            }
            continue;
        }

        let update = Message::collection(db)
            .update_one(
                doc! { "_id": id, "content": &original },
                doc! {
                    "$set": {
                        "content": &sealed,
                        "updatedAt": DateTime::now(),
                    }
                },
            )
            .await?;

        if update.modified_count == 0 {
            report.skipped_concurrent_update += 1;
            log::warn!("message {id}: content changed during migration, skipped");
            continue;
        }

        report.migrated += 1;
        if report.migrated % batch_size == 0 {
            log::info!("sealed {} messages so far...", report.migrated);
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use base64::Engine;

    use super::*;

    #[test]
    fn migrates_legacy_plaintext() {
        assert!(message_content_needs_seal_migration("cześć", false));
    }

    #[test]
    fn skips_already_sealed() {
        std::env::set_var("JWT_KEY", "test-jwt-key-for-seal-legacy-migration");
        let stored =
            prepare_content_for_storage("hello", false).expect("seal");
        assert!(!message_content_needs_seal_migration(&stored, false));
    }

    #[test]
    fn skips_e2e_flagged() {
        assert!(!message_content_needs_seal_migration("anything", true));
    }

    #[test]
    fn skips_signal_like_without_flag() {
        let fake_signal_blob = base64::engine::general_purpose::STANDARD.encode([0x08_u8; 64]);
        assert!(!message_content_needs_seal_migration(&fake_signal_blob, false));
    }

    #[test]
    fn migrates_client_opaque_not_sealed() {
        let opaque = crate::utils::messages::content_storage::wrap_client_opaque("witaj");
        assert!(message_content_needs_seal_migration(&opaque, false));
    }

    #[test]
    fn migrates_long_client_opaque_chat_text() {
        let long_text = "A".repeat(120);
        let opaque = crate::utils::messages::content_storage::wrap_client_opaque(&long_text);
        assert!(message_content_needs_seal_migration(&opaque, false));
    }

    #[test]
    fn seal_roundtrip_preserves_plaintext() {
        std::env::set_var("JWT_KEY", "test-jwt-key-for-seal-legacy-migration-roundtrip");
        let sealed = seal_legacy_message_content("test wiadomość", false)
            .expect("ok")
            .expect("some");
        assert_eq!(
            reveal_content_internal(&sealed, false),
            "test wiadomość"
        );
    }
}
