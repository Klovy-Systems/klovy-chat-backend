use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use aes_gcm::aead::OsRng;
use once_cell::sync::Lazy;
use rand::RngCore;
use uuid::Uuid;

const TOKEN_TTL: Duration = Duration::from_secs(30);

struct PendingKey {
    key: [u8; 32],
    user_id: String,
    expires_at: Instant,
}

static STORE: Lazy<Mutex<HashMap<String, PendingKey>>> = Lazy::new(|| Mutex::new(HashMap::new()));

fn purge_expired(map: &mut HashMap<String, PendingKey>) {
    let now = Instant::now();
    map.retain(|_, entry| entry.expires_at > now);
}

pub fn issue_ws_crypto_key(user_id: &str) -> (String, String) {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    let token = Uuid::new_v4().to_string();

    let mut map = STORE.lock().unwrap_or_else(|e| e.into_inner());
    purge_expired(&mut map);
    map.insert(
        token.clone(),
        PendingKey {
            key,
            user_id: user_id.to_string(),
            expires_at: Instant::now() + TOKEN_TTL,
        },
    );

    (token, hex::encode(key))
}

pub fn consume_ws_crypto_key(token: &str, user_id: &str) -> Option<[u8; 32]> {
    let mut map = STORE.lock().unwrap_or_else(|e| e.into_inner());
    purge_expired(&mut map);
    let entry = map.remove(token)?;
    if entry.expires_at <= Instant::now() || entry.user_id != user_id {
        return None;
    }
    Some(entry.key)
}

pub fn ws_frame_encryption_required() -> bool {
    if crate::utils::app_env::is_production() {
        return true;
    }
    std::env::var("WS_FRAME_ENCRYPTION")
        .map(|v| {
            let v = v.trim();
            v == "1"
                || v.eq_ignore_ascii_case("true")
                || v.eq_ignore_ascii_case("yes")
                || v.eq_ignore_ascii_case("on")
        })
        .unwrap_or(false)
}
