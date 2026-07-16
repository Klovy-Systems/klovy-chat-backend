const ALLOWED_ATTACHMENT_EXTENSIONS: &[&str] = &[
    "pdf", "jpg", "jpeg", "png", "webp", "docx", "xlsx", "txt", "webm", "ogg", "wav", "mp4", "m4a",
];

pub fn normalize_storage_key(path: &str) -> String {
    path.trim().replace('\\', "/").trim_start_matches('/').to_string()
}

pub fn is_safe_key(path: &str) -> bool {
    let normalized = normalize_storage_key(path);
    !normalized.is_empty() && !normalized.contains("..")
}

pub fn dm_conversation_id(user_a: &str, user_b: &str) -> String {
    let (first, second) = if user_a <= user_b {
        (user_a, user_b)
    } else {
        (user_b, user_a)
    };
    format!("conv_{first}_{second}")
}

pub fn avatar_user_key(user_id: &str) -> String {
    format!("avatars/users/{user_id}.webp")
}

pub fn avatar_channel_key(channel_id: &str) -> String {
    format!("avatars/channels/{channel_id}.webp")
}

pub fn banner_user_key(user_id: &str) -> String {
    format!("banners/users/{user_id}.webp")
}

pub fn attachment_dm_key(user_id: &str, recipient_id: &str, filename: &str) -> String {
    let conv = dm_conversation_id(user_id, recipient_id);
    format!("attachments/dm/{conv}/{filename}")
}

pub fn attachment_group_key(channel_id: &str, filename: &str) -> String {
    format!("attachments/groups/group_{channel_id}/{filename}")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AvatarKind {
    User { user_id: String },
    Channel { channel_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicMediaKind {
    UserBanner { user_id: String },
}

pub fn avatar_key_parts(path: &str) -> Option<AvatarKind> {
    let normalized = normalize_storage_key(path);
    if normalized.starts_with("avatars/users/") {
        let rest = normalized.strip_prefix("avatars/users/")?;
        let id = rest.strip_suffix(".webp")?;
        if !is_object_id_hex(id) {
            return None;
        }
        return Some(AvatarKind::User {
            user_id: id.to_string(),
        });
    }
    if normalized.starts_with("avatars/channels/") {
        let rest = normalized.strip_prefix("avatars/channels/")?;
        let id = rest.strip_suffix(".webp")?;
        if !is_object_id_hex(id) {
            return None;
        }
        return Some(AvatarKind::Channel {
            channel_id: id.to_string(),
        });
    }
    None
}

pub fn is_avatar_key(path: &str) -> bool {
    avatar_key_parts(path).is_some()
}

pub fn avatar_key_owned_by_user(path: &str, user_id: &str) -> bool {
    matches!(
        avatar_key_parts(path),
        Some(AvatarKind::User { user_id: id }) if id == user_id
    )
}

pub fn avatar_key_owned_by_channel(path: &str, channel_id: &str) -> bool {
    matches!(
        avatar_key_parts(path),
        Some(AvatarKind::Channel { channel_id: id }) if id == channel_id
    )
}

pub fn public_media_key_parts(path: &str) -> Option<PublicMediaKind> {
    let normalized = normalize_storage_key(path);
    if normalized.starts_with("banners/users/") {
        let rest = normalized.strip_prefix("banners/users/")?;
        let id = rest.strip_suffix(".webp")?;
        if !is_object_id_hex(id) {
            return None;
        }
        return Some(PublicMediaKind::UserBanner {
            user_id: id.to_string(),
        });
    }
    None
}

pub fn is_public_media_key(path: &str) -> bool {
    public_media_key_parts(path).is_some()
}

pub fn public_media_key_owned_by_user(path: &str, user_id: &str) -> bool {
    matches!(
        public_media_key_parts(path),
        Some(PublicMediaKind::UserBanner { user_id: id }) if id == user_id
    )
}

pub fn is_attachment_key(path: &str) -> bool {
    attachment_key_parts(path).is_some()
}

fn is_object_id_hex(value: &str) -> bool {
    value.len() == 24 && value.chars().all(|c| c.is_ascii_hexdigit())
}

fn attachment_filename_is_valid(filename: &str) -> bool {
    let Some((name, ext)) = filename.rsplit_once('.') else {
        return false;
    };
    if ext.is_empty() || ext.len() > 8 || ext.contains('/') || ext.contains("..") {
        return false;
    }
    if !ALLOWED_ATTACHMENT_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()) {
        return false;
    }
    uuid::Uuid::parse_str(name).is_ok()
}

pub fn attachment_key_parts(path: &str) -> Option<(String, String)> {
    let normalized = normalize_storage_key(path);
    if normalized.starts_with("attachments/dm/") {
        let rest = normalized.strip_prefix("attachments/dm/")?;
        let (conv, filename) = rest.split_once('/')?;
        if !conv.starts_with("conv_") {
            return None;
        }
        let ids = conv.strip_prefix("conv_")?;
        let (a, b) = ids.split_once('_')?;
        if !is_object_id_hex(a) || !is_object_id_hex(b) || !attachment_filename_is_valid(filename) {
            return None;
        }
        return Some(("dm".to_string(), conv.to_string()));
    }

    if normalized.starts_with("attachments/groups/group_") {
        let rest = normalized.strip_prefix("attachments/groups/group_")?;
        let (channel_id, filename) = rest.split_once('/')?;
        if !is_object_id_hex(channel_id) || !attachment_filename_is_valid(filename) {
            return None;
        }
        return Some(("channel".to_string(), channel_id.to_string()));
    }

    None
}

pub fn attachment_path_matches_dm(path: &str, user_id: &str, contact_id: &str) -> bool {
    let Some((kind, conv)) = attachment_key_parts(path) else {
        return false;
    };
    kind == "dm" && conv == dm_conversation_id(user_id, contact_id)
}

pub fn attachment_path_matches_channel(path: &str, channel_id: &str) -> bool {
    let Some((kind, id)) = attachment_key_parts(path) else {
        return false;
    };
    kind == "channel" && id == channel_id
}

pub fn is_logical_message_path(path: &str) -> bool {
    is_attachment_key(path)
}

pub fn attachment_prefers_download(path: &str) -> bool {
    let normalized = normalize_storage_key(path);
    let Some(ext) = normalized.rsplit('.').next() else {
        return false;
    };
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "txt" | "pdf" | "docx" | "xlsx"
    )
}

pub fn content_type_for_ext(ext: &str) -> &'static str {
    match ext.to_ascii_lowercase().as_str() {
        "webp" => "image/webp",
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "pdf" => "application/pdf",
        "docx" => {
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        }
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "txt" => "text/plain",
        "webm" => "audio/webm",
        "ogg" => "audio/ogg",
        "wav" => "audio/wav",
        "mp4" | "m4a" => "audio/mp4",
        _ => "application/octet-stream",
    }
}
