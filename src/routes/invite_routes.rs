use actix_web::web;
use actix_web_lab::middleware::from_fn;

use crate::controllers::invite_controller::{accept_invite, get_invite};
use crate::middlewares::auth_middleware::{require_active_account, verify_token};
use crate::utils::ratelimit::{invite_accept_limiter, invite_preview_limiter};

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/{inviteId}")
            .wrap(from_fn(invite_preview_limiter))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_invite)),
    );
    cfg.service(
        web::resource("/{inviteId}/accept")
            .wrap(from_fn(invite_accept_limiter))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(accept_invite)),
    );
    cfg.service(
        web::resource("/{inviteId}/join")
            .wrap(from_fn(invite_accept_limiter))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(accept_invite)),
    );
}
