use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::Mutex;

#[derive(Clone, Default)]
pub struct RateLimitEntry {
    pub count: u32,
    pub reset_at_ms: i64,
}

#[derive(Clone, Default)]
pub struct SocketState {
    pub typing_users: Arc<Mutex<HashMap<String, HashMap<String, bool>>>>,
    pub rate_limits: Arc<Mutex<HashMap<String, HashMap<String, RateLimitEntry>>>>,
    pub connections: Arc<Mutex<HashMap<String, u32>>>,
    pub ip_connections: Arc<Mutex<HashMap<String, u32>>>,
}

const MAX_CONNECTIONS_PER_USER: u32 = 3;
const MAX_CONNECTIONS_PER_IP: u32 = 15;

impl SocketState {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn check_rate_limit(
        &self,
        user_id: &str,
        action: &str,
        max_requests: u32,
        window_ms: i64,
    ) -> bool {
        let now = now_ms();
        let mut limits = self.rate_limits.lock().await;
        let user_limits = limits.entry(user_id.to_string()).or_default();
        let entry = user_limits.entry(action.to_string()).or_insert(RateLimitEntry {
            count: 0,
            reset_at_ms: now + window_ms,
        });

        if now > entry.reset_at_ms {
            entry.count = 0;
            entry.reset_at_ms = now + window_ms;
        }
        if entry.count >= max_requests {
            return false;
        }
        entry.count += 1;
        true
    }

    pub async fn register_connection(&self, user_id: &str) -> bool {
        let mut map = self.connections.lock().await;
        let count = map.entry(user_id.to_string()).or_insert(0);
        if *count >= MAX_CONNECTIONS_PER_USER {
            return false;
        }
        *count += 1;
        true
    }

    pub async fn register_ip_connection(&self, ip: &str) -> bool {
        let mut map = self.ip_connections.lock().await;
        let count = map.entry(ip.to_string()).or_insert(0);
        if *count >= MAX_CONNECTIONS_PER_IP {
            return false;
        }
        *count += 1;
        true
    }

    pub async fn unregister_ip_connection(&self, ip: &str) {
        let mut map = self.ip_connections.lock().await;
        if let Some(count) = map.get_mut(ip) {
            if *count <= 1 {
                map.remove(ip);
            } else {
                *count -= 1;
            }
        }
    }

    pub async fn unregister_connection(&self, user_id: &str) {
        let mut map = self.connections.lock().await;
        if let Some(count) = map.get_mut(user_id) {
            if *count <= 1 {
                map.remove(user_id);
            } else {
                *count -= 1;
            }
        }
    }

    pub async fn is_user_connected(&self, user_id: &str) -> bool {
        self.connections
            .lock()
            .await
            .get(user_id)
            .copied()
            .unwrap_or(0)
            > 0
    }

    /// Zwalnia efemeryczny stan powiązany z użytkownikiem po ostatnim rozłączeniu,
    /// aby uniknąć wycieku pamięci w długo działającym procesie.
    pub async fn clear_user_state(&self, user_id: &str) {
        self.rate_limits.lock().await.remove(user_id);
        let mut typing = self.typing_users.lock().await;
        for users in typing.values_mut() {
            users.remove(user_id);
        }
        typing.retain(|_, users| !users.is_empty());
    }
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn is_valid_object_id(s: &str) -> bool {
    s.len() == 24 && s.chars().all(|c| c.is_ascii_hexdigit())
}
