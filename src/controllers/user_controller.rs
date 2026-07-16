use actix_web::{HttpRequest, HttpResponse};
use mongodb::bson::oid::ObjectId;
use serde_json::json;

use crate::middlewares::auth_middleware::request_user_id;
use crate::model::user_model::User;
use crate::utils::db::get_db;
use crate::utils::friends::are_friends;
use crate::utils::listening::serialize::{effective_listening, listening_activity_json};
use crate::utils::user::serialize_user::availability_status_str;

pub async fn get_user_status(req: HttpRequest) -> HttpResponse {
    let viewer_id = match request_user_id(&req) {
        Some(id) if !id.is_empty() => id,
        _ => {
            return HttpResponse::Unauthorized()
                .json(json!({ "error": "Authentication required" }));
        }
    };

    let user_id = req.match_info().get("userId").unwrap_or("");
    let Ok(oid) = ObjectId::parse_str(user_id) else {
        return HttpResponse::NotFound().json(json!({ "error": "User not found" }));
    };

    let db = get_db();
    if viewer_id != user_id && !are_friends(&db, &viewer_id, user_id).await {
        return HttpResponse::Forbidden().json(json!({ "error": "Forbidden" }));
    }

    match User::find_by_id(&db, oid).await {
        Ok(Some(user)) => {
            let listening_activity = effective_listening(&user).map(listening_activity_json);
            HttpResponse::Ok().json(json!({
                "isOnline": user.is_online,
                "lastSeen": user.last_seen.as_ref().and_then(|d| d.try_to_rfc3339_string().ok()),
                "image": user.image,
                "color": user.color,
                "availabilityStatus": availability_status_str(&user.availability_status),
                "listeningActivity": listening_activity,
            }))
        }
        Ok(None) => HttpResponse::NotFound().json(json!({ "error": "User not found" })),
        Err(_) => HttpResponse::InternalServerError().json(json!({ "error": "Server error" })),
    }
}
