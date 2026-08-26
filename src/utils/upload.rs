// upload.rs
// MAX body HTTP i konteksty pending (avatar vs chat).
// Zakres:
//  - middleware czyta ten limit
//  - MAX body i kontekst pending (avatar vs chat)
// Actix wewnętrzny nie przechodzi przez limit Axum — ten MAX jest krytyczny.
// Przy zmianach: middlewares/mod.rs, PendingUpload.

pub const MAX_ATTACHMENT_BYTES: u64 = 10 * 1024 * 1024;

pub const MAX_IMAGE_ATTACHMENT_BYTES: u64 = MAX_ATTACHMENT_BYTES;

pub const MAX_AVATAR_BYTES: u64 = 6 * 1024 * 1024;

pub const MAX_BANNER_BYTES: u64 = 7 * 1024 * 1024;

pub const MAX_IMAGE_DIMENSION: u32 = 4096;

pub const MAX_CHAT_IMAGE_EDGE: u32 = 2048;

pub const MAX_CHAT_THUMB_EDGE: u32 = 480;

pub const MAX_AVATAR_EDGE: u32 = 512;

pub const MAX_BANNER_EDGE: u32 = 1024;

pub const CHAT_IMAGE_WEBP_QUALITY: f32 = 80.0;

pub const CHAT_THUMB_WEBP_QUALITY: f32 = 70.0;

pub const AVATAR_WEBP_QUALITY: f32 = 85.0;

pub const MAX_PENDING_UPLOADS_PER_USER: u64 = 20;

pub const MAX_CHAT_ATTACHMENTS_PER_WINDOW: u32 = 20;

pub const CHAT_ATTACHMENT_WINDOW_SECS: u64 = 40 * 60;

pub fn chat_attachment_window() -> std::time::Duration {
    std::time::Duration::from_secs(CHAT_ATTACHMENT_WINDOW_SECS)
}

pub const DEFAULT_USER_STORAGE_BYTES: u64 = 100 * 1024 * 1024;

pub fn max_user_storage_bytes() -> u64 {
    std::env::var("USER_STORAGE_QUOTA_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_USER_STORAGE_BYTES)
}

pub const MAX_JSON_PAYLOAD_BYTES: u64 = 10 * 1024 * 1024;

pub const MAX_HTTP_BODY_BYTES: usize = 11 * 1024 * 1024;

pub const MAX_EMPTY_METHOD_BODY_BYTES: usize = 16 * 1024;

pub const MAX_PROXY_URI_BYTES: usize = 8192;

pub fn max_proxy_body_bytes(method: &str, content_type: Option<&str>) -> usize {
    if method.eq_ignore_ascii_case("GET")
        || method.eq_ignore_ascii_case("HEAD")
        || method.eq_ignore_ascii_case("OPTIONS")
        || method.eq_ignore_ascii_case("DELETE")
    {
        return MAX_EMPTY_METHOD_BODY_BYTES;
    }
    let is_multipart = content_type
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
        .starts_with("multipart/");
    if is_multipart {
        MAX_HTTP_BODY_BYTES
    } else {
        MAX_JSON_PAYLOAD_BYTES as usize
    }
}

pub fn file_bytes_within_limit(size: u64, max: u64) -> bool {
    size <= max
}

pub fn local_file_size(path: impl AsRef<std::path::Path>) -> Option<u64> {
    std::fs::metadata(path.as_ref()).ok().map(|m| m.len())
}

pub fn is_image_extension(ext: &str) -> bool {
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "jpg" | "jpeg" | "png" | "webp"
    )
}
