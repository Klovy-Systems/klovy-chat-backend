use actix_web::{web, HttpResponse};
use mongodb::bson::{doc, oid::ObjectId};
use serde::Deserialize;
use serde_json::json;

use crate::model::user_model::User;
use crate::utils::db::get_db;
use crate::utils::user::serialize_user::serialize_user;
use crate::utils::whitelist::is_whitelist_enabled;

#[derive(Deserialize)]
pub struct ApproveUserBody {
    #[serde(rename = "userId")]
    pub user_id: Option<String>,
}

pub async fn approve_user(body: web::Json<ApproveUserBody>) -> HttpResponse {
    let Some(user_id) = body.user_id.clone() else {
        return HttpResponse::BadRequest().json(json!({ "message": "User ID required." }));
    };
    let Ok(oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::NotFound().json(json!({ "message": "User not found." }));
    };

    let db = get_db();
    match User::set_fields(&db, oid, doc! { "isWhitelisted": true }).await {
        Ok(Some(user)) => HttpResponse::Ok()
            .json(json!({ "message": "User approved.", "user": serialize_user(&user, Some(is_whitelist_enabled())) })),
        Ok(None) => HttpResponse::NotFound().json(json!({ "message": "User not found." })),
        Err(_) => HttpResponse::InternalServerError().json(json!({ "message": "Error approving user." })),
    }
}
