use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    HttpResponse,
};
use actix_web_lab::middleware::Next;

use crate::middlewares::auth_middleware::resolve_authenticated_user;
use crate::utils::whitelist::is_whitelist_enabled;

pub async fn whitelist_check(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    if !is_whitelist_enabled() {
        return Ok(next.call(req).await?.map_into_boxed_body());
    }

    let user = match resolve_authenticated_user(&req).await {
        Some(user) => user,
        None => {
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
