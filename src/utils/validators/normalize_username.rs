use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    static ref USERNAME_PATTERN: Regex = Regex::new(r"^[a-z0-9_]{3,32}$").unwrap();
}

pub fn normalize_username(raw: &str) -> String {
    let trimmed = raw.trim();
    let without_at = trimmed.strip_prefix('@').unwrap_or(trimmed);
    without_at.to_lowercase()
}

pub fn is_valid_username(username: &str) -> bool {
    USERNAME_PATTERN.is_match(username)
}

pub fn looks_like_email(raw: &str) -> bool {
    raw.trim().contains('@')
}
