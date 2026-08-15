/// Maximum size for non-image chat attachments (10 MB).
pub const MAX_ATTACHMENT_BYTES: u64 = 10 * 1024 * 1024;

/// Maximum size for chat image uploads before re-encode (10 MB).
pub const MAX_IMAGE_ATTACHMENT_BYTES: u64 = MAX_ATTACHMENT_BYTES;

/// Maximum size for profile/channel avatars (6 MB).
pub const MAX_AVATAR_BYTES: u64 = 6 * 1024 * 1024;

/// Maximum size for profile banners (7 MB).
pub const MAX_BANNER_BYTES: u64 = 7 * 1024 * 1024;

/// Maximum width/height for uploaded source images (decompression bomb protection).
pub const MAX_IMAGE_DIMENSION: u32 = 4096;

/// Max edge length for stored chat images (full).
pub const MAX_CHAT_IMAGE_EDGE: u32 = 2048;

/// Max edge length for chat image thumbnails.
pub const MAX_CHAT_THUMB_EDGE: u32 = 480;

/// Max edge length for avatars after re-encode.
pub const MAX_AVATAR_EDGE: u32 = 512;

/// Max edge length for profile banners after re-encode (matches crop 1024×384).
pub const MAX_BANNER_EDGE: u32 = 1024;

/// Lossy WebP quality for chat full images (0–100).
pub const CHAT_IMAGE_WEBP_QUALITY: f32 = 80.0;

/// Lossy WebP quality for chat thumbnails (0–100).
pub const CHAT_THUMB_WEBP_QUALITY: f32 = 70.0;

/// Lossy WebP quality for avatars/banners (0–100).
pub const AVATAR_WEBP_QUALITY: f32 = 85.0;

/// Maximum pending (not yet sent in a message) attachment uploads per user.
pub const MAX_PENDING_UPLOADS_PER_USER: u64 = 20;

/// Maximum chat attachments (DM + channel) a user may upload within the rolling window.
pub const MAX_CHAT_ATTACHMENTS_PER_WINDOW: u32 = 20;

/// Rolling window for chat attachment uploads (40 minutes).
pub const CHAT_ATTACHMENT_WINDOW_SECS: u64 = 40 * 60;

pub fn chat_attachment_window() -> std::time::Duration {
    std::time::Duration::from_secs(CHAT_ATTACHMENT_WINDOW_SECS)
}

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

/// GET/HEAD/OPTIONS/DELETE should not carry a large body.
pub const MAX_EMPTY_METHOD_BODY_BYTES: usize = 16 * 1024;

/// Path + query at the public hop. Bigger URIs are scanner/DoS noise.
pub const MAX_PROXY_URI_BYTES: usize = 8192;

/// Buffer limit at the public Axum hop, before bytes are read into RAM.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_body_limit_is_small_for_reads() {
        assert_eq!(max_proxy_body_bytes("GET", None), MAX_EMPTY_METHOD_BODY_BYTES);
        assert_eq!(
            max_proxy_body_bytes("DELETE", Some("application/json")),
            MAX_EMPTY_METHOD_BODY_BYTES
        );
        assert_eq!(max_proxy_body_bytes("get", None), MAX_EMPTY_METHOD_BODY_BYTES);
        assert_eq!(
            max_proxy_body_bytes("POST", Some(" Multipart/Form-Data; boundary=x")),
            MAX_HTTP_BODY_BYTES
        );
    }

    #[test]
    fn proxy_body_limit_allows_multipart_uploads() {
        assert_eq!(
            max_proxy_body_bytes("POST", Some("multipart/form-data; boundary=x")),
            MAX_HTTP_BODY_BYTES
        );
        assert_eq!(
            max_proxy_body_bytes("POST", Some("application/json")),
            MAX_JSON_PAYLOAD_BYTES as usize
        );
    }
}
