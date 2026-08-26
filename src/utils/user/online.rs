// online.rs
// Process-wide cache availability.
// Zakres:
//  - HTTP+WS
//  - availability process-wide; SET_STATUS inwaliduje
// SET_STATUS musi inwalidować; reconnect grace w handlers.
// Przy zmianach: handlers.rs presence, PresenceContext.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use once_cell::sync::Lazy;

const TTL_MS: i64 = 300_000;
const CACHE_MAX: usize = 20_000;

struct Entry {
    status: String,
    at_ms: i64,
}

static CACHE: Lazy<Mutex<HashMap<String, Entry>>> = Lazy::new(|| Mutex::new(HashMap::new()));

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn get(user_id: &str) -> Option<String> {
    let guard = CACHE.lock().ok()?;
    let entry = guard.get(user_id)?;
    if now_ms().saturating_sub(entry.at_ms) > TTL_MS {
        return None;
    }
    Some(entry.status.clone())
}

pub fn put(user_id: &str, status: &str) {
    if let Ok(mut guard) = CACHE.lock() {
        guard.insert(
            user_id.to_string(),
            Entry {
                status: status.to_string(),
                at_ms: now_ms(),
            },
        );
        if guard.len() > CACHE_MAX {
            let overflow = guard.len() - CACHE_MAX;
            let keys: Vec<String> = guard.keys().take(overflow).cloned().collect();
            for key in keys {
                guard.remove(&key);
            }
        }
    }
}

pub fn clear(user_id: &str) {
    if let Ok(mut guard) = CACHE.lock() {
        guard.remove(user_id);
    }
}
