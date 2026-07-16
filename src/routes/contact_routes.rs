use actix_web::web;
use actix_web_lab::middleware::from_fn;

use crate::controllers::contacts_controller::{
    delete_conversation, get_blocked_contacts, get_contacts_for_list, search_contacts,
    toggle_contact_block, toggle_contact_mute,
};
use crate::middlewares::auth_middleware::{require_active_account, verify_token};
use crate::utils::ratelimit::discovery_limiter;

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/search")
            .wrap(from_fn(discovery_limiter))
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(search_contacts)),
    );
    cfg.service(
        web::resource("")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_contacts_for_list)),
    );
    cfg.service(
        web::resource("/")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_contacts_for_list)),
    );
    cfg.service(
        web::resource("/list")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_contacts_for_list)),
    );
    cfg.service(
        web::resource("/get-contacts-for-list")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_contacts_for_list)),
    );
    cfg.service(
        web::resource("/blocked")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(get_blocked_contacts)),
    );
    cfg.service(
        web::resource("/{contactId}/block")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(toggle_contact_block)),
    );
    cfg.service(
        web::resource("/{contactId}/mute")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::post().to(toggle_contact_mute)),
    );
    cfg.service(
        web::resource("/conversation/{contactId}")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::delete().to(delete_conversation)),
    );
    cfg.service(
        web::resource("/{contactId}/conversation")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::delete().to(delete_conversation)),
    );
}
