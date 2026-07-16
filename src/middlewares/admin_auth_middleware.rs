use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    HttpMessage, HttpResponse,
};
use actix_web_lab::middleware::Next;

use crate::middlewares::auth_middleware::RequestUserId;
use crate::utils::auth::admin_session::{admin_user_ids_configured, resolve_admin_user};

pub async fn verify_admin_session(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    let user = match resolve_admin_user(req.request()).await {
        Some(user) => user,
        None => {
            let (req, _) = req.into_parts();
            let res = HttpResponse::Unauthorized()
                .json(serde_json::json!({ "error": "Brak uprawnień administratora." }));
            return Ok(ServiceResponse::new(req, res));
        }
    };

    let user_id = user.id.map(|id| id.to_hex()).unwrap_or_default();
    if !user_id.is_empty() {
        req.extensions_mut().insert(RequestUserId(user_id));
    }

    Ok(next.call(req).await?.map_into_boxed_body())
}

pub async fn check_admin_configured(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    if !admin_user_ids_configured() {
        let (req, _) = req.into_parts();
        let res = HttpResponse::ServiceUnavailable().json(serde_json::json!({
            "error": "Panel administratora nie jest skonfigurowany (ustaw ADMIN_USER_IDS w .env)."
        }));
        return Ok(ServiceResponse::new(req, res));
    }

    Ok(next.call(req).await?.map_into_boxed_body())
}
