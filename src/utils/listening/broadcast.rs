use serde_json::json;

use crate::model::user_model::User;
use crate::utils::db::get_db;
use crate::utils::friends::emit_to_friends;
use crate::utils::listening::serialize::{effective_listening, listening_activity_json};

pub async fn broadcast_listening_change(user_id: &str, user: &User) {
    let activity = effective_listening(user).map(listening_activity_json);
    emit_to_friends(
        &get_db(),
        user_id,
        "user-listening-changed",
        json!({
            "userId": user_id,
            "listeningActivity": activity,
        }),
    )
    .await;
}
