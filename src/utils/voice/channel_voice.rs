use std::collections::{HashMap, HashSet};
use std::sync::{LazyLock, Mutex};

/// channel_id → set of user_ids currently in voice.
static CHANNEL_VOICE: LazyLock<Mutex<HashMap<String, HashSet<String>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// user_id → (channel_id, conn_id) that owns their voice membership.
/// Lets a crashed tab leave voice without waiting for every other tab to close.
static VOICE_OWNER: LazyLock<Mutex<HashMap<String, (String, u64)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Join `channel_id` from `conn_id`. Returns `(participants_in_joined, other_channels_left)`.
pub fn join_channel_voice(
    channel_id: &str,
    user_id: &str,
    conn_id: u64,
) -> (Vec<String>, Vec<String>) {
    let mut map = CHANNEL_VOICE.lock().unwrap_or_else(|e| e.into_inner());
    let mut owners = VOICE_OWNER.lock().unwrap_or_else(|e| e.into_inner());
    let mut left = Vec::new();
    // One channel voice at a time — leave other rooms first.
    map.retain(|cid, users| {
        if cid == channel_id {
            return true;
        }
        if users.remove(user_id) {
            left.push(cid.clone());
        }
        !users.is_empty()
    });
    let entry = map.entry(channel_id.to_string()).or_default();
    entry.insert(user_id.to_string());
    owners.insert(user_id.to_string(), (channel_id.to_string(), conn_id));
    let mut participants: Vec<String> = entry.iter().cloned().collect();
    participants.sort();
    (participants, left)
}

/// Remove the channel voice roster entirely (e.g. channel deleted).
pub fn clear_channel_voice(channel_id: &str) {
    let mut map = CHANNEL_VOICE.lock().unwrap_or_else(|e| e.into_inner());
    let mut owners = VOICE_OWNER.lock().unwrap_or_else(|e| e.into_inner());
    map.remove(channel_id);
    owners.retain(|_, (cid, _)| cid != channel_id);
}

pub fn leave_channel_voice(channel_id: &str, user_id: &str) -> Vec<String> {
    let mut map = CHANNEL_VOICE.lock().unwrap_or_else(|e| e.into_inner());
    let mut owners = VOICE_OWNER.lock().unwrap_or_else(|e| e.into_inner());
    if owners
        .get(user_id)
        .is_some_and(|(cid, _)| cid == channel_id)
    {
        owners.remove(user_id);
    }
    if let Some(entry) = map.get_mut(channel_id) {
        entry.remove(user_id);
        if entry.is_empty() {
            map.remove(channel_id);
            return Vec::new();
        }
        let mut participants: Vec<String> = entry.iter().cloned().collect();
        participants.sort();
        return participants;
    }
    Vec::new()
}

pub fn clear_user_from_all_channels(user_id: &str) -> Vec<String> {
    let mut map = CHANNEL_VOICE.lock().unwrap_or_else(|e| e.into_inner());
    let mut owners = VOICE_OWNER.lock().unwrap_or_else(|e| e.into_inner());
    owners.remove(user_id);
    let mut cleared = Vec::new();
    map.retain(|channel_id, users| {
        if users.remove(user_id) {
            cleared.push(channel_id.clone());
        }
        !users.is_empty()
    });
    cleared
}

/// Drop voice membership owned by a specific connection (tab crash / close).
/// Returns channel ids the user left.
///
/// Holds both locks for the whole remove so a concurrent re-join cannot claim
/// ownership and then get wiped by a stale leave (TOCTOU).
pub fn clear_connection(user_id: &str, conn_id: u64) -> Vec<String> {
    let mut map = CHANNEL_VOICE.lock().unwrap_or_else(|e| e.into_inner());
    let mut owners = VOICE_OWNER.lock().unwrap_or_else(|e| e.into_inner());
    let Some((channel_id, owned_conn)) = owners.get(user_id).cloned() else {
        return Vec::new();
    };
    if owned_conn != conn_id {
        return Vec::new();
    }
    owners.remove(user_id);
    if let Some(entry) = map.get_mut(&channel_id) {
        entry.remove(user_id);
        if entry.is_empty() {
            map.remove(&channel_id);
        }
    }
    vec![channel_id]
}

pub fn participants_in_channel(channel_id: &str) -> Vec<String> {
    let map = CHANNEL_VOICE.lock().unwrap_or_else(|e| e.into_inner());
    map.get(channel_id)
        .map(|users| {
            let mut participants: Vec<String> = users.iter().cloned().collect();
            participants.sort();
            participants
        })
        .unwrap_or_default()
}
