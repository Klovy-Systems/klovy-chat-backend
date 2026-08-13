//! Short-TTL typing authorization cache (DM/channel).
//! Global so HTTP friendship/block/channel-membership changes can invalidate
//! without SocketState.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use once_cell::sync::Lazy;

const ALLOW_TTL_MS: i64 = 45_000;
const DENY_TTL_MS: i64 = 3_000;

#[derive(Clone)]
pub enum TypingAccess {
    Denied {
        checked_at_ms: i64,
    },
    Dm {
        checked_at_ms: i64,
    },
    Channel {
        checked_at_ms: i64,
        recipients: Vec<String>,
    },
}

static TYPING_ACCESS: Lazy<Mutex<HashMap<String, TypingAccess>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn key(user_id: &str, chat_id: &str) -> String {
    format!("{user_id}:{chat_id}")
}

fn channel_chat_id(channel_id: &str) -> String {
    if channel_id.starts_with("channel_") {
        channel_id.to_string()
    } else {
        format!("channel_{channel_id}")
    }
}

pub fn get(user_id: &str, chat_id: &str) -> Option<TypingAccess> {
    let guard = TYPING_ACCESS.lock().ok()?;
    let entry = guard.get(&key(user_id, chat_id))?.clone();
    let checked_at = match &entry {
        TypingAccess::Denied { checked_at_ms }
        | TypingAccess::Dm { checked_at_ms }
        | TypingAccess::Channel { checked_at_ms, .. } => *checked_at_ms,
    };
    let ttl = match &entry {
        TypingAccess::Denied { .. } => DENY_TTL_MS,
        TypingAccess::Dm { .. } | TypingAccess::Channel { .. } => ALLOW_TTL_MS,
    };
    if now_ms().saturating_sub(checked_at) > ttl {
        return None;
    }
    Some(entry)
}

pub fn put(user_id: &str, chat_id: &str, entry: TypingAccess) {
    if let Ok(mut guard) = TYPING_ACCESS.lock() {
        guard.insert(key(user_id, chat_id), entry);
    }
}

pub fn invalidate_user(user_id: &str) {
    if let Ok(mut guard) = TYPING_ACCESS.lock() {
        let prefix = format!("{user_id}:");
        let dm_suffix = format!(":{user_id}");
        guard.retain(|k, _| !k.starts_with(&prefix) && !k.ends_with(&dm_suffix));
    }
}

/// Drop DM typing authorization both directions after friend/block changes.
pub fn invalidate_pair(user_a: &str, user_b: &str) {
    if let Ok(mut guard) = TYPING_ACCESS.lock() {
        guard.remove(&key(user_a, user_b));
        guard.remove(&key(user_b, user_a));
    }
}

/// Drop every cached typing decision for a channel (leave/kick/ban/mute/join/delete).
pub fn invalidate_channel(channel_id: &str) {
    let chat_id = channel_chat_id(channel_id);
    let suffix = format!(":{chat_id}");
    if let Ok(mut guard) = TYPING_ACCESS.lock() {
        guard.retain(|k, _| !k.ends_with(&suffix));
    }
    crate::utils::access::channel_access_cache::invalidate_channel(channel_id);
}

/// Drop one user's channel typing entry (e.g. self-leave).
pub fn invalidate_user_channel(user_id: &str, channel_id: &str) {
    let chat_id = channel_chat_id(channel_id);
    if let Ok(mut guard) = TYPING_ACCESS.lock() {
        guard.remove(&key(user_id, &chat_id));
    }
    crate::utils::access::channel_access_cache::invalidate_channel(channel_id);
}

pub fn clear_user(user_id: &str) {
    invalidate_user(user_id);
}

pub fn now_access_ms() -> i64 {
    now_ms()
}
