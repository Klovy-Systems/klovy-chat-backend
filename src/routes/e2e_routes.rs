use actix_web::web;
use actix_web_lab::middleware::from_fn;

use crate::controllers::e2e_controller::{
    append_e2e_prekeys, delete_e2e_keys, get_e2e_capabilities, get_e2e_key_bulk,
    get_e2e_key_bundle, get_e2e_status, patch_e2e_settings, put_e2e_keys,
};
use crate::middlewares::auth_middleware::{require_active_account, verify_token};
use crate::utils::ratelimit::e2e_key_fetch_limiter;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/status")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_e2e_status)),
    )
    .service(
        web::resource("/settings")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::patch().to(patch_e2e_settings)),
    )
    .service(
        web::resource("/keys")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::put().to(put_e2e_keys))
            .route(web::delete().to(delete_e2e_keys)),
    )
    .service(
        web::resource("/keys/prekeys")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(append_e2e_prekeys)),
    )
    .service(
        web::resource("/keys/bulk")
            .wrap(from_fn(e2e_key_fetch_limiter))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_e2e_key_bulk)),
    )
    .service(
        web::resource("/capabilities")
            .wrap(from_fn(e2e_key_fetch_limiter))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_e2e_capabilities)),
    )
    .service(
        web::resource("/keys/{user_id}")
            .wrap(from_fn(e2e_key_fetch_limiter))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_e2e_key_bundle)),
    );
}
