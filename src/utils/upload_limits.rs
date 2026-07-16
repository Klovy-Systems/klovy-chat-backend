/// Maximum size for chat message attachments (10 MB).
pub const MAX_ATTACHMENT_BYTES: u64 = 10 * 1024 * 1024;

/// Maximum size for profile/channel avatars and banners (5 MB).
pub const MAX_AVATAR_BYTES: u64 = 5 * 1024 * 1024;

/// Maximum width/height for uploaded images (decompression bomb protection).
pub const MAX_IMAGE_DIMENSION: u32 = 4096;

/// Maximum pending (not yet sent in a message) attachment uploads per user.
pub const MAX_PENDING_UPLOADS_PER_USER: u64 = 20;

/// Default total attachment storage per user (100 MB).
pub const DEFAULT_USER_STORAGE_BYTES: u64 = 100 * 1024 * 1024;

pub fn max_user_storage_bytes() -> u64 {
    std::env::var("USER_STORAGE_QUOTA_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_USER_STORAGE_BYTES)
}

/// JSON and url-encoded form body limit (10 MB).
pub const MAX_JSON_PAYLOAD_BYTES: u64 = 10 * 1024 * 1024;

/// HTTP proxy buffer — 10 MB file plus multipart overhead.
pub const MAX_HTTP_BODY_BYTES: usize = 11 * 1024 * 1024;

pub fn file_bytes_within_limit(size: u64, max: u64) -> bool {
    size <= max
}

pub fn local_file_size(path: impl AsRef<std::path::Path>) -> Option<u64> {
    std::fs::metadata(path.as_ref()).ok().map(|m| m.len())
}
