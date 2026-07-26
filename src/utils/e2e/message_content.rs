use crate::utils::messages::content_storage::inbound_plaintext_for_processing;
use crate::utils::e2e::is_valid_e2e_ciphertext;
use crate::utils::validators::sanitize_input::sanitize_message_content;

pub struct PreparedMessageContent {
    pub content: String,
    pub e2e_encrypted: bool,
    pub e2e_version: Option<u8>,
    pub skip_mentions: bool,
}

pub fn prepare_inbound_content(
    raw: Option<&str>,
    e2e_encrypted: bool,
    e2e_version: Option<u8>,
) -> Result<PreparedMessageContent, &'static str> {
    if e2e_encrypted {
        let content = raw.unwrap_or("").trim().to_string();
        if !is_valid_e2e_ciphertext(&content) {
            return Err("INVALID_E2E_CIPHERTEXT");
        }
        Ok(PreparedMessageContent {
            content,
            e2e_encrypted: true,
            e2e_version,
            skip_mentions: true,
        })
    } else {
        let sanitized = sanitize_message_content(raw.unwrap_or(""));
        let content = inbound_plaintext_for_processing(&sanitized, false);
        Ok(PreparedMessageContent {
            content,
            e2e_encrypted: false,
            e2e_version: None,
            skip_mentions: false,
        })
    }
}
