//! Ochrona przed nadużyciami Unicode (Zalgo / combining marks, bidi override, zero-width).

use unicode_general_category::{get_general_category, GeneralCategory};

pub const MAX_MESSAGE_CHARS: usize = 2000;
pub const MAX_MESSAGE_BYTES: usize = 8192;
pub const MAX_MESSAGE_COMBINING: usize = 12;

pub const MAX_DISPLAY_NAME_CHARS: usize = 32;
pub const MAX_DISPLAY_NAME_BYTES: usize = 128;
pub const MAX_DISPLAY_NAME_COMBINING: usize = 0;

pub const MAX_BIO_CHARS: usize = 500;
pub const MAX_BIO_BYTES: usize = 2048;
pub const MAX_BIO_COMBINING: usize = 8;

pub const MAX_CHANNEL_NAME_CHARS: usize = 50;
pub const MAX_CHANNEL_NAME_BYTES: usize = 200;
pub const MAX_CHANNEL_NAME_COMBINING: usize = 0;

pub const MAX_CHANNEL_DESC_CHARS: usize = 200;
pub const MAX_CHANNEL_DESC_BYTES: usize = 800;
pub const MAX_CHANNEL_DESC_COMBINING: usize = 8;

fn is_combining_mark(c: char) -> bool {
    matches!(
        get_general_category(c),
        GeneralCategory::NonspacingMark
            | GeneralCategory::SpacingMark
            | GeneralCategory::EnclosingMark
    )
}

fn is_variation_selector(c: char) -> bool {
    matches!(c as u32, 0xFE00..=0xFE0F)
}

fn is_disallowed_char(c: char) -> bool {
    if c.is_control() && c != '\n' && c != '\r' && c != '\t' {
        return true;
    }

    let cp = c as u32;
    matches!(
        cp,
        0x200B..=0x200F // ZWSP, ZWNJ, ZWJ, LRM, RLM
            | 0x202A..=0x202E // bidi embedding / override
            | 0x2060..=0x2069 // word joiner, bidi isolates
            | 0xFEFF // BOM
            | 0xFFF9..=0xFFFB // interlinear annotation anchors
    )
}

fn truncate_utf8_bytes(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Filtruje niebezpieczne znaki Unicode i ogranicza długość (skalarów, bajtów, combining marks).
pub fn sanitize_unicode_text(
    input: &str,
    max_chars: usize,
    max_bytes: usize,
    max_combining: usize,
) -> String {
    let mut combining = 0usize;
    let mut char_count = 0usize;
    let mut out = String::with_capacity(input.len().min(max_bytes));

    for c in input.chars() {
        if is_disallowed_char(c) {
            continue;
        }

        let mark_like = is_combining_mark(c) || is_variation_selector(c);
        if mark_like {
            if combining >= max_combining {
                continue;
            }
            combining += 1;
        }

        out.push(c);
        char_count += 1;

        if char_count >= max_chars {
            break;
        }
    }

    truncate_utf8_bytes(&out, max_bytes)
}

pub fn sanitize_display_name(input: &str) -> String {
    sanitize_unicode_text(
        input.trim(),
        MAX_DISPLAY_NAME_CHARS,
        MAX_DISPLAY_NAME_BYTES,
        MAX_DISPLAY_NAME_COMBINING,
    )
}

pub fn sanitize_bio(input: &str) -> String {
    sanitize_unicode_text(
        input.trim(),
        MAX_BIO_CHARS,
        MAX_BIO_BYTES,
        MAX_BIO_COMBINING,
    )
}

pub fn sanitize_channel_name(input: &str) -> String {
    sanitize_unicode_text(
        input.trim(),
        MAX_CHANNEL_NAME_CHARS,
        MAX_CHANNEL_NAME_BYTES,
        MAX_CHANNEL_NAME_COMBINING,
    )
}

pub fn sanitize_channel_description(input: &str) -> String {
    sanitize_unicode_text(
        input.trim(),
        MAX_CHANNEL_DESC_CHARS,
        MAX_CHANNEL_DESC_BYTES,
        MAX_CHANNEL_DESC_COMBINING,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::validators::sanitize_input::sanitize_message_content;

    #[test]
    fn strips_zalgo_from_display_name() {
        let zalgo = "e\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}\u{0301}";
        let out = sanitize_display_name(zalgo);
        assert_eq!(out, "e");
    }

    #[test]
    fn limits_combining_in_messages() {
        let base = "hi";
        let marks: String = (0..40).map(|_| '\u{0301}').collect();
        let input = format!("{base}{marks}");
        let out = sanitize_message_content(&input);
        assert!(out.starts_with("hi"));
        assert!(out.chars().filter(|c| is_combining_mark(*c)).count() <= MAX_MESSAGE_COMBINING);
    }

    #[test]
    fn removes_bidi_override() {
        let input = "hello\u{202E}world";
        let out = sanitize_message_content(input);
        assert!(!out.contains('\u{202E}'));
    }
}
