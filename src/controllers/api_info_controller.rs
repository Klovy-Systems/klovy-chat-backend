use actix_web::HttpResponse;
use serde_json::json;

pub async fn get_api_info() -> HttpResponse {
    HttpResponse::Ok().json(json!({
        "message": "Welcome",
    }))
}
