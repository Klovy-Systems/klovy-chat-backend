use actix_web::{web, HttpRequest, HttpResponse};
use mongodb::bson::{doc, oid::ObjectId};
use serde::Deserialize;
use serde_json::json;

use crate::middlewares::auth_middleware::request_user_id;
use crate::model::user_model::User;
use crate::utils::friends::emit_status_event;
use crate::utils::db::get_db;

#[derive(Deserialize)]
pub struct UpdateStatusBody {
    #[serde(rename = "availabilityStatus")]
    pub availability_status: Option<String>,
}

pub async fn update_user_status(req: HttpRequest, body: web::Json<UpdateStatusBody>) -> HttpResponse {
    let status = match body.availability_status.as_deref() {
        Some(s) if matches!(s, "online" | "away" | "brb" | "dnd") => s.to_string(),
        _ => return HttpResponse::BadRequest().json(json!({ "error": "Invalid availability status" })),
    };

    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::InternalServerError().json(json!({ "error": "Server error" }));
    };
    let Ok(oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::InternalServerError().json(json!({ "error": "Server error" }));
    };

    let db = get_db();
    let user = match User::find_by_id(&db, oid).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return HttpResponse::NotFound().json(json!({ "error": "User not found" }));
        }
        Err(_) => {
            return HttpResponse::ServiceUnavailable()
                .json(json!({ "error": "Temporarily unavailable. Retry." }));
        }
    };
    let online = user.is_online;
    let last_seen = user
        .last_seen
        .map(|ts| json!(ts.timestamp_millis()))
        .unwrap_or(json!(null));
    // Availability only — do not force online (respect appear-offline).
    match User::set_fields(
        &db,
        oid,
        doc! { "availabilityStatus": &status },
    )
    .await
    {
        Ok(Some(_)) => {}
        Ok(None) => {
            return HttpResponse::NotFound().json(json!({ "error": "User not found" }));
        }
        Err(_) => {
            return HttpResponse::ServiceUnavailable()
                .json(json!({ "error": "Temporarily unavailable. Retry." }));
        }
    }

    emit_status_event(
        &db,
        &user_id,
        json!({
            "userId": user_id,
            "status": {
                "isOnline": online,
                "availabilityStatus": status,
                "lastSeen": if online { json!(null) } else { last_seen },
            },
        }),
    )
    .await;
    crate::utils::user::availability_cache::put(&user_id, &status);
    HttpResponse::Ok().json(json!({ "success": true, "availabilityStatus": status }))
}
