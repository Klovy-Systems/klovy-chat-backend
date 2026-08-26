// status.rs
// Routing health.
// Zakres:
//  - GET /api lub status
//  - health bez JWT (wait-on, LB)
// Musi działać bez JWT (wait-on, LB).
// Przy zmianach: controllers/status.rs.

use actix_web::web;
use actix_web_lab::middleware::from_fn;

use crate::controllers::status::update_user_status;
use crate::middlewares::auth::{require_active_account, verify_token};
use crate::utils::ratelimit::status_update_limiter;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .wrap(from_fn(status_update_limiter))
            .route(web::post().to(update_user_status)),
    );
    cfg.service(
        web::resource("/")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .wrap(from_fn(status_update_limiter))
            .route(web::post().to(update_user_status)),
    );
    cfg.service(
        web::resource("/update")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .wrap(from_fn(status_update_limiter))
            .route(web::post().to(update_user_status)),
    );
}
