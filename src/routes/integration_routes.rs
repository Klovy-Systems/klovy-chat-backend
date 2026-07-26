use actix_web::web;
use actix_web_lab::middleware::from_fn;

use crate::controllers::oauth_integration_controller::{
    integration_catalog, oauth_callback, oauth_connect_url, oauth_disconnect, oauth_status,
    oauth_sync, update_listening_settings,
};
use crate::middlewares::auth_middleware::{require_active_account, verify_token};

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/catalog")
            .wrap(from_fn(require_active_account))
            .wrap(from_fn(verify_token))
            .route(web::get().to(integration_catalog)),
    )
    .service(
        web::scope("/listening")
            .service(
                web::resource("/settings")
                    .wrap(from_fn(require_active_account))
                    .wrap(from_fn(verify_token))
                    .route(web::patch().to(update_listening_settings)),
            ),
    )
    .service(
        web::scope("/{provider}")
            .service(
                web::resource("/status")
                    .wrap(from_fn(require_active_account))
                    .wrap(from_fn(verify_token))
                    .route(web::get().to(oauth_status)),
            )
            .service(
                web::resource("/connect-url")
                    .wrap(from_fn(require_active_account))
                    .wrap(from_fn(verify_token))
                    .route(web::get().to(oauth_connect_url)),
            )
            .service(web::resource("/callback").route(web::get().to(oauth_callback)))
            .service(
                web::resource("/sync")
                    .wrap(from_fn(require_active_account))
                    .wrap(from_fn(verify_token))
                    .route(web::post().to(oauth_sync)),
            )
            .service(
                web::resource("/disconnect")
                    .wrap(from_fn(require_active_account))
                    .wrap(from_fn(verify_token))
                    .route(web::delete().to(oauth_disconnect)),
            ),
    );
}
