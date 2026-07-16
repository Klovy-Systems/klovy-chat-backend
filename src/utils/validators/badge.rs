use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    static ref HEX_COLOR: Regex = Regex::new(r"^#[0-9A-Fa-f]{6}$").unwrap();
    static ref LUCIDE_ICON: Regex = Regex::new(r"^[A-Z][A-Za-z0-9]{0,63}$").unwrap();
}

pub fn is_valid_badge_color(color: &str) -> bool {
    HEX_COLOR.is_match(color.trim())
}

pub fn is_valid_badge_icon(icon: &str) -> bool {
    LUCIDE_ICON.is_match(icon.trim())
}

pub fn normalize_badge_color(color: Option<&str>) -> Option<String> {
    match color.map(str::trim).filter(|s| !s.is_empty()) {
        Some(value) if is_valid_badge_color(value) => Some(value.to_ascii_uppercase()),
        _ => None,
    }
}
