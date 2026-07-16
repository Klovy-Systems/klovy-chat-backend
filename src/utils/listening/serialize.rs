use serde_json::{json, Value};

use crate::model::user_model::{ListeningActivity, User};
use crate::utils::listening::resolve;
use crate::utils::validators::external_url::is_allowed_listening_url;

pub fn listening_activity_json(activity: &ListeningActivity) -> Value {
    json!({
        "platform": activity.platform,
        "trackTitle": activity.track_title,
        "artist": activity.artist,
        "albumArt": activity
            .album_art
            .as_ref()
            .filter(|url| is_allowed_listening_url(url)),
        "externalUrl": activity
            .external_url
            .as_ref()
            .filter(|url| is_allowed_listening_url(url)),
        "isPlaying": activity.is_playing,
        "updatedAt": activity.updated_at.try_to_rfc3339_string().ok(),
    })
}

pub fn effective_listening(user: &User) -> Option<&ListeningActivity> {
    if !user.share_listening {
        return None;
    }
    match &user.listening_activity {
        Some(a) if a.is_playing && !resolve::is_expired(a) => Some(a),
        _ => None,
    }
}

pub fn listening_for_viewer(user: &User, is_self: bool) -> Option<Value> {
    if is_self {
        user.listening_activity
            .as_ref()
            .filter(|a| a.is_playing && !resolve::is_expired(a))
            .map(listening_activity_json)
    } else {
        effective_listening(user).map(listening_activity_json)
    }
}
