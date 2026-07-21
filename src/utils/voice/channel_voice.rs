use std::collections::{HashMap, HashSet};
use std::sync::{LazyLock, Mutex};

static CHANNEL_VOICE: LazyLock<Mutex<HashMap<String, HashSet<String>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub fn join_channel_voice(channel_id: &str, user_id: &str) -> Vec<String> {
    let mut map = CHANNEL_VOICE.lock().unwrap_or_else(|e| e.into_inner());
    let entry = map.entry(channel_id.to_string()).or_default();
    entry.insert(user_id.to_string());
    let mut participants: Vec<String> = entry.iter().cloned().collect();
    participants.sort();
    participants
}

pub fn leave_channel_voice(channel_id: &str, user_id: &str) -> Vec<String> {
    let mut map = CHANNEL_VOICE.lock().unwrap_or_else(|e| e.into_inner());
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
    let mut cleared = Vec::new();
    map.retain(|channel_id, users| {
        if users.remove(user_id) {
            cleared.push(channel_id.clone());
        }
        !users.is_empty()
    });
    cleared
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
