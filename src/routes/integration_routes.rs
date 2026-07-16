use actix_web::web;
use actix_web_lab::middleware::from_fn;

use crate::controllers::spotify_controller::{
    spotify_callback, spotify_connect, spotify_connect_url, spotify_disconnect, spotify_status,
    spotify_sync, update_listening_settings,
};
use crate::middlewares::auth_middleware::{require_active_account, verify_token};

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/spotify")
            .service(
                web::resource("/status")
                    .wrap(from_fn(require_active_account))
                    .wrap(from_fn(verify_token))
                    .route(web::get().to(spotify_status)),
            )
            .service(
                web::resource("/connect-url")
                    .wrap(from_fn(require_active_account))
                    .wrap(from_fn(verify_token))
                    .route(web::get().to(spotify_connect_url)),
            )
            .service(
                web::resource("/connect")
                    .wrap(from_fn(require_active_account))
                    .wrap(from_fn(verify_token))
                    .route(web::get().to(spotify_connect)),
            )
            .service(web::resource("/callback").route(web::get().to(spotify_callback)))
            .service(
                web::resource("/sync")
                    .wrap(from_fn(require_active_account))
                    .wrap(from_fn(verify_token))
                    .route(web::post().to(spotify_sync)),
            )
            .service(
                web::resource("/disconnect")
                    .wrap(from_fn(require_active_account))
                    .wrap(from_fn(verify_token))
                    .route(web::delete().to(spotify_disconnect)),
            ),
    )
    .service(
        web::scope("/listening")
            .service(
                web::resource("/settings")
                    .wrap(from_fn(require_active_account))
                    .wrap(from_fn(verify_token))
                    .route(web::patch().to(update_listening_settings)),
            ),
    );
}
