use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    HttpResponse,
};
use actix_web_lab::middleware::Next;

use crate::middlewares::auth_middleware::resolve_authenticated_user;
use crate::utils::auth::admin_session::is_admin_user_id;
use crate::utils::whitelist::is_whitelist_enabled;

/// OAuth browser redirects (Spotify) land here without session cookies —
/// the signed `state` already identifies the user inside the handler.
fn is_whitelist_exempt(path: &str) -> bool {
    path.starts_with("/api/integrations/spotify/callback")
}

pub async fn whitelist_check(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    if !is_whitelist_enabled() || is_whitelist_exempt(req.path()) {
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

    let user_id = user.id.map(|id| id.to_hex()).unwrap_or_default();
    if user.is_whitelisted || is_admin_user_id(&user_id) {
        Ok(next.call(req).await?.map_into_boxed_body())
    } else {
        let (req, _) = req.into_parts();
        let res = HttpResponse::Forbidden()
            .json(serde_json::json!({ "message": "User not whitelisted." }));
        Ok(ServiceResponse::new(req, res))
    }
}
