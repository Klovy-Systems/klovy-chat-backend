// whitelist.rs
// Blokuje pending userów przed czatem/WS.
// Zakres:
//  - isWhitelisted
//  - pending user nie wchodzi na czat/WS
// PendingApproval na FE pollingiem, nie WS.
// Przy zmianach: utils/whitelist/mod.rs, ws/mod.rs.

use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    HttpResponse,
};
use actix_web_lab::middleware::Next;

use crate::middlewares::auth::resolve_authenticated_user;
use crate::utils::auth::jwt::JwtUserError;
use crate::utils::whitelist::is_whitelist_enabled;

pub async fn whitelist_check(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    if !is_whitelist_enabled() {
        return Ok(next.call(req).await?.map_into_boxed_body());
    }

    let user = match resolve_authenticated_user(&req).await {
        Ok(user) => user,
        Err(JwtUserError::Unavailable) => {
            let (req, _) = req.into_parts();
            let res = HttpResponse::ServiceUnavailable().json(serde_json::json!({
                "message": "Temporarily unavailable. Retry."
            }));
            return Ok(ServiceResponse::new(req, res));
        }
        Err(JwtUserError::Denied) => {
            let (req, _) = req.into_parts();
            let res = HttpResponse::Unauthorized()
                .json(serde_json::json!({ "message": "User not authenticated." }));
            return Ok(ServiceResponse::new(req, res));
        }
    };

    if user.is_whitelisted {
        Ok(next.call(req).await?.map_into_boxed_body())
    } else {
        let (req, _) = req.into_parts();
        let res = HttpResponse::Forbidden()
            .json(serde_json::json!({ "message": "User not whitelisted." }));
        Ok(ServiceResponse::new(req, res))
    }
}
