use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use once_cell::sync::OnceCell;
use serde::Serialize;
use serde_json::{json, Value};
use tokio::sync::{Mutex, mpsc, watch};

use crate::model::channel_model::Channel;

pub type WsSender = mpsc::Sender<String>;

/// Maksymalna liczba zakolejkowanych ramek na jedno połączenie WS.
/// Chroni przed nieograniczonym wzrostem pamięci przy wolnym kliencie —
/// po przepełnieniu ramki są odrzucane (best-effort), a klient po
/// ponownym połączeniu i tak odświeży stan.
pub const WS_SEND_BUFFER: usize = 512;

static REGISTRY: OnceCell<ConnectionRegistry> = OnceCell::new();
static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

struct Connection {
    id: u64,
    tx: WsSender,
    revoke: watch::Sender<bool>,
    session_family_id: Option<String>,
}

#[derive(Clone, Default)]
pub struct ConnectionRegistry {
    connections: Arc<Mutex<HashMap<String, Vec<Connection>>>>,
}

impl ConnectionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn register(
        &self,
        user_id: &str,
        tx: WsSender,
        revoke: watch::Sender<bool>,
        session_family_id: Option<String>,
    ) -> u64 {
        let id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
        self.connections
            .lock()
            .await
            .entry(user_id.to_string())
            .or_default()
            .push(Connection {
                id,
                tx,
                revoke,
                session_family_id,
            });
        id
    }

    pub async fn unregister(&self, user_id: &str, conn_id: u64) {
        let mut map = self.connections.lock().await;
        if let Some(senders) = map.get_mut(user_id) {
            senders.retain(|c| c.id != conn_id);
            if senders.is_empty() {
                map.remove(user_id);
            }
        }
    }

    async fn send_to_family(&self, user_id: &str, family_id: &str, msg_type: &str, payload: Value) {
        let msg = match serde_json::to_string(&json!({ "type": msg_type, "payload": payload })) {
            Ok(s) => s,
            Err(_) => return,
        };
        let senders: Vec<WsSender> = self
            .connections
            .lock()
            .await
            .get(user_id)
            .map(|conns| {
                conns
                    .iter()
                    .filter(|c| c.session_family_id.as_deref() == Some(family_id))
                    .map(|c| c.tx.clone())
                    .collect()
            })
            .unwrap_or_default();
        for tx in senders {
            let _ = tx.try_send(msg.clone());
        }
    }

    async fn send_to_user(&self, user_id: &str, msg_type: &str, payload: Value) {
        let msg = match serde_json::to_string(&json!({ "type": msg_type, "payload": payload })) {
            Ok(s) => s,
            Err(_) => return,
        };
        let senders: Vec<WsSender> = self
            .connections
            .lock()
            .await
            .get(user_id)
            .map(|conns| conns.iter().map(|c| c.tx.clone()).collect())
            .unwrap_or_default();
        for tx in senders {
            let _ = tx.try_send(msg.clone());
        }
    }

    pub async fn disconnect_family(&self, user_id: &str, family_id: &str) {
        let connections = {
            let mut map = self.connections.lock().await;
            let Some(conns) = map.get_mut(user_id) else {
                return;
            };
            let (to_revoke, remaining): (Vec<_>, Vec<_>) = conns
                .drain(..)
                .partition(|c| c.session_family_id.as_deref() == Some(family_id));
            *conns = remaining;
            if conns.is_empty() {
                map.remove(user_id);
            }
            to_revoke
        };
        for conn in connections {
            let _ = conn.revoke.send(true);
            drop(conn.tx);
        }
    }

    pub async fn disconnect_user(&self, user_id: &str) {
        let connections = {
            let mut map = self.connections.lock().await;
            map.remove(user_id).unwrap_or_default()
        };
        for conn in connections {
            let _ = conn.revoke.send(true);
            drop(conn.tx);
        }
    }

    pub async fn broadcast_to_all(&self, msg_type: &str, payload: Value) {
        let user_ids: Vec<String> = self.connections.lock().await.keys().cloned().collect();
        for uid in user_ids {
            self.send_to_user(&uid, msg_type, payload.clone()).await;
        }
    }
}

pub fn revoke_session_remotely(user_id: &str, family_id: &str) {
    let Some(reg) = registry() else {
        return;
    };
    let uid = user_id.to_string();
    let fid = family_id.to_string();
    let reg = reg.clone();
    tokio::spawn(async move {
        reg.send_to_family(&uid, &fid, "session:revoked", json!({}))
            .await;
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        reg.disconnect_family(&uid, &fid).await;
    });
}

pub fn disconnect_user(user_id: &str) {
    let Some(reg) = registry() else {
        return;
    };
    let uid = user_id.to_string();
    let reg = reg.clone();
    tokio::spawn(async move {
        reg.disconnect_user(&uid).await;
    });
}

pub fn set_registry(registry: ConnectionRegistry) {
    let _ = REGISTRY.set(registry);
}

fn registry() -> Option<&'static ConnectionRegistry> {
    REGISTRY.get()
}

pub fn emit_to_user(user_id: &str, event: &str, data: impl Serialize + Send + Sync + 'static) {
    let Some(reg) = registry() else {
        return;
    };
    let uid = user_id.to_string();
    let ev = event.to_string();
    let data = serde_json::to_value(data).unwrap_or(Value::Null);
    let reg = reg.clone();
    tokio::spawn(async move {
        reg.send_to_user(&uid, &ev, data).await;
    });
}

pub async fn user_is_connected(user_id: &str) -> bool {
    let Some(reg) = registry() else {
        return false;
    };
    let map = reg.connections.lock().await;
    map.get(user_id).is_some_and(|entries| !entries.is_empty())
}

pub fn emit_to_users(user_ids: &[String], event: &str, data: Value) {
    for uid in user_ids {
        emit_to_user(uid, event, data.clone());
    }
}

pub fn emit_to_all_connected(event: &str, data: impl Serialize + Send + Sync + 'static) {
    let Some(reg) = registry() else {
        return;
    };
    let ev = event.to_string();
    let data = serde_json::to_value(data).unwrap_or(Value::Null);
    let reg = reg.clone();
    tokio::spawn(async move {
        reg.broadcast_to_all(&ev, data).await;
    });
}

// UWAGA: usunięto `broadcast_to_others` i `emit_broadcast`. Rozgłaszanie do
// wszystkich zalogowanych klientów wyciekało obecność/profil do nie-znajomych.
// Do zdarzeń obecności/profilu używaj `crate::utils::friends::emit_to_friends`,
// a do kanałów `emit_to_users(&channel_recipient_ids(...), ...)`.

pub fn channel_recipient_ids(channel: &Channel) -> Vec<String> {
    let mut ids: Vec<String> = channel.members.iter().map(|m| m.to_hex()).collect();
    let admin = channel.admin.to_hex();
    if !ids.iter().any(|id| id == &admin) {
        ids.push(admin);
    }
    ids
}
