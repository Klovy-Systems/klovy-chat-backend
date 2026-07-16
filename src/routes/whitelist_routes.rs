use crate::middlewares::admin_auth_middleware::{check_admin_configured, verify_admin_session};
use crate::middlewares::auth_middleware::log_suspicious_activity;
use crate::utils::ratelimit::admin_action_limiter;

pub fn configure(cfg: &mut actix_web::web::ServiceConfig) {
    use actix_web::web;
    use actix_web_lab::middleware::from_fn;

    use crate::controllers::whitelist_controller::approve_user;

    cfg.service(
        web::resource("")
            .wrap(from_fn(log_suspicious_activity("whitelist-approval")))
            .wrap(from_fn(check_admin_configured))
            .wrap(from_fn(verify_admin_session))
            .wrap(from_fn(admin_action_limiter))
            .route(web::post().to(approve_user)),
    );
    cfg.service(
        web::resource("/")
            .wrap(from_fn(log_suspicious_activity("whitelist-approval")))
            .wrap(from_fn(check_admin_configured))
            .wrap(from_fn(verify_admin_session))
            .wrap(from_fn(admin_action_limiter))
            .route(web::post().to(approve_user)),
    );
    cfg.service(
        web::resource("/approve-user")
            .wrap(from_fn(log_suspicious_activity("whitelist-approval")))
            .wrap(from_fn(check_admin_configured))
            .wrap(from_fn(verify_admin_session))
            .wrap(from_fn(admin_action_limiter))
            .route(web::post().to(approve_user)),
    );
}
