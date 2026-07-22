use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    http::Method,
    HttpMessage, HttpResponse,
};
use actix_web_lab::middleware::Next;

use crate::middlewares::auth_middleware::RequestUserId;
use crate::utils::auth::admin_session::{
    admin_elevation_required, admin_elevation_valid, admin_ip_allowlist_configured,
    admin_user_ids_configured, is_admin_ip_allowed, resolve_admin_user,
    resolve_panel_admin_account, user_id_from_request,
};
use crate::utils::client_ip::client_ip_from_service_request;

fn is_admin_session_status_request(req: &ServiceRequest) -> bool {
    req.method() == Method::GET
        && matches!(
            req.path(),
            "/api/admin" | "/api/admin/" | "/api/admin/session"
        )
}

pub async fn check_admin_ip_allowlist(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    if !admin_ip_allowlist_configured() || is_admin_ip_allowed(&client_ip_from_service_request(&req))
    {
        return Ok(next.call(req).await?.map_into_boxed_body());
    }

    let client_ip = client_ip_from_service_request(&req);
    log::warn!("Admin panel access denied for IP {client_ip}");

    let is_session_probe = is_admin_session_status_request(&req);
    let (http_req, _) = req.into_parts();
    let res = if is_session_probe {
        HttpResponse::Ok().json(serde_json::json!({
            "authenticated": false,
            "configured": admin_user_ids_configured(),
            "reason": "ip_not_allowed",
        }))
    } else {
        HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Dostęp do panelu administratora z tego adresu IP jest zablokowany.",
            "code": "ADMIN_IP_NOT_ALLOWED",
        }))
    };
    Ok(ServiceResponse::new(http_req, res))
}

pub async fn verify_admin_session(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, actix_web::Error> {
    if admin_ip_allowlist_configured() && !is_admin_ip_allowed(&client_ip_from_service_request(&req))
    {
        let client_ip = client_ip_from_service_request(&req);
        log::warn!("Admin panel access denied for IP {client_ip}");
        let (http_req, _) = req.into_parts();
        let res = HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Dostęp do panelu administratora z tego adresu IP jest zablokowany.",
            "code": "ADMIN_IP_NOT_ALLOWED",
        }));
        return Ok(ServiceResponse::new(http_req, res));
    }

    let user = match resolve_admin_user(req.request()).await {
        Some(user) => user,
        None => {
            let (http_req, _) = req.into_parts();
            let has_session = user_id_from_request(&http_req).is_some();
            if has_session {
                if let Some(account) = resolve_panel_admin_account(&http_req).await {
                    let user_id = account.id.map(|id| id.to_hex()).unwrap_or_default();
                    if admin_elevation_required() && !admin_elevation_valid(&http_req, &user_id) {
                        let res = HttpResponse::Forbidden().json(serde_json::json!({
                            "error": "Wymagane potwierdzenie dostępu administratora (ADMIN_SECRET).",
                            "code": "ADMIN_ELEVATION_REQUIRED",
                        }));
                        return Ok(ServiceResponse::new(http_req, res));
                    }
                }
            }
            let status = if has_session {
                actix_web::http::StatusCode::FORBIDDEN
            } else {
                actix_web::http::StatusCode::UNAUTHORIZED
            };
            let res = HttpResponse::build(status)
                .json(serde_json::json!({ "error": "Brak uprawnień administratora." }));
            return Ok(ServiceResponse::new(http_req, res));
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
