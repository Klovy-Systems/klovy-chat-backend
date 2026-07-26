use actix_web::{web, HttpRequest, HttpResponse};

use mongodb::bson::{doc, oid::ObjectId, Bson};

use once_cell::sync::Lazy;

use serde::Deserialize;

use serde_json::json;

use std::env;

use std::time::Duration;



use crate::middlewares::auth_middleware::request_user_id;

use crate::model::oauth_token_model::OauthToken;

use crate::model::user_model::User;

use crate::utils::db::get_db;

use crate::utils::friends::emit_profile_event;

use crate::utils::integrations::connected_accounts::{

    remove_user_connected_account, upsert_connected_account, upsert_user_connected_account,

};

use crate::utils::integrations::listening_sync::{

    fetch_active_listening_activity, map_oauth_error, map_token_exchange_error, SPOTIFY_REAUTH_HINT,

};

use crate::utils::integrations::oauth::{

    build_auth_url, build_oauth_state, ensure_access_token, exchange_code, generate_pkce_pair,

    is_connected, revoke_provider_token, store_tokens, verify_oauth_state_flexible,

};

use crate::utils::integrations::profiles::fetch_provider_profile;

use crate::utils::integrations::{find_provider, provider_enabled, PROVIDERS};

use crate::utils::listening::broadcast::broadcast_listening_change;

use crate::utils::listening::resolve::{should_apply_report, ListeningReport};

use crate::utils::listening::serialize::listening_activity_json;

use crate::utils::ratelimit::Store;

use crate::utils::user::serialize_user::connected_accounts_json;



static INTEGRATION_STATUS: Lazy<Store> = Lazy::new(|| Store::new(15, Duration::from_secs(60)));

static INTEGRATION_SYNC: Lazy<Store> = Lazy::new(|| Store::new(8, Duration::from_secs(60)));



fn frontend_url() -> String {

    env::var("FRONTEND_URL").unwrap_or_else(|_| "http://127.0.0.1:5173".to_string())

}



fn allowed_return_origins() -> Vec<String> {

    let mut origins = Vec::new();

    if crate::utils::app_env::is_development() {

        origins.push("http://127.0.0.1:5173".to_string());

    }

    for key in ["FRONTEND_URL", "ORIGIN"] {

        if let Ok(value) = env::var(key) {

            origins.push(value.trim_end_matches('/').to_string());

        }

    }

    origins.sort();

    origins.dedup();

    origins

}



fn normalize_return_origin(return_to: Option<&str>) -> String {

    let fallback = frontend_url().trim_end_matches('/').to_string();

    let Some(raw) = return_to.map(str::trim).filter(|s| !s.is_empty()) else {

        return fallback;

    };

    let normalized = raw.trim_end_matches('/');

    if allowed_return_origins()

        .iter()

        .any(|allowed| allowed == normalized)

    {

        normalized.to_string()

    } else {

        fallback

    }

}



fn url_encode(value: &str) -> String {

    crate::utils::integrations::oauth::url_encode(value)

}



async fn load_active_user(user_id: &str) -> Result<User, HttpResponse> {

    let Ok(oid) = ObjectId::parse_str(user_id) else {

        return Err(HttpResponse::Unauthorized().json(json!({ "error": "Authentication required" })));

    };

    let db = get_db();

    match User::find_by_id(&db, oid).await {

        Ok(Some(user)) if user.is_login_allowed() => Ok(user),

        Ok(Some(_)) => Err(HttpResponse::Forbidden().json(json!({ "error": "Forbidden" }))),

        Ok(None) => Err(HttpResponse::Unauthorized().json(json!({ "error": "Authentication required" }))),

        Err(_) => Err(HttpResponse::InternalServerError().json(json!({ "error": "Server error" }))),

    }

}



async fn backfill_connected_account(user: &mut User, def: &crate::utils::integrations::providers::OAuthProviderDef) {

    let Some(oid) = user.id else {

        return;

    };

    if !is_connected(oid, def.id).await {

        return;

    }

    if user.connected_accounts.iter().any(|a| a.provider == def.id) {

        return;

    }

    let db = get_db();

    let Ok(Some(token_doc)) = OauthToken::find_by_user_provider(&db, oid, def.id).await else {

        return;

    };

    let Some(provider_user_id) = token_doc.provider_user_id.clone() else {

        return;

    };

    let account_name = token_doc

        .provider_display_name

        .clone()

        .unwrap_or_else(|| def.name.to_string());

    let profile_url = match def.id {

        "spotify" => format!("https://open.spotify.com/user/{provider_user_id}"),

        _ => return,

    };

    let connected_account = crate::model::user_model::ConnectedAccount {

        provider: def.id.to_string(),

        account_name,

        profile_url,

    };

    if let Ok(Some(updated)) = upsert_user_connected_account(&db, oid, connected_account.clone()).await {

        *user = updated;

    } else {

        upsert_connected_account(&mut user.connected_accounts, connected_account);

    }

}



pub async fn integration_catalog(_req: HttpRequest) -> HttpResponse {

    let items: Vec<_> = PROVIDERS

        .iter()

        .map(|p| {

            json!({

                "id": p.id,

                "name": p.name,

                "oauthSupported": p.oauth_supported,

                "enabled": provider_enabled(p),

                "listeningSync": p.listening_sync,

            })

        })

        .collect();

    HttpResponse::Ok().json(json!({ "providers": items }))

}



pub async fn oauth_status(req: HttpRequest, path: web::Path<String>) -> HttpResponse {

    let provider_id = path.into_inner();

    let Some(def) = find_provider(&provider_id) else {

        return HttpResponse::NotFound().json(json!({ "error": "Unknown integration" }));

    };

    let Some(user_id) = request_user_id(&req) else {

        return HttpResponse::Unauthorized().json(json!({ "error": "Authentication required" }));

    };

    if !INTEGRATION_STATUS.check_and_increment_with_window(

        &format!("integration-status:{provider_id}:{user_id}"),

        15,

        Duration::from_secs(60),

    ) {

        return HttpResponse::TooManyRequests().json(json!({ "error": "Rate limit exceeded" }));

    }



    let mut user = match load_active_user(&user_id).await {

        Ok(u) => u,

        Err(resp) => return resp,

    };

    let Some(user_oid) = user.id else {

        return HttpResponse::InternalServerError().json(json!({ "error": "Server error" }));

    };



    if def.listening_sync {

        backfill_connected_account(&mut user, def).await;

    }



    let connected = is_connected(user_oid, def.id).await;

    let account = user

        .connected_accounts

        .iter()

        .find(|a| a.provider == def.id);



    let mut body = json!({

        "provider": def.id,

        "connected": connected,

        "enabled": provider_enabled(def),

        "oauthSupported": def.oauth_supported,

        "accountName": account.map(|a| a.account_name.clone()),

        "profileUrl": account.map(|a| a.profile_url.clone()),

    });

    if def.listening_sync {

        body["shareListening"] = json!(user.share_listening);

    }

    HttpResponse::Ok().json(body)

}



#[derive(Deserialize)]

pub struct ConnectQuery {

    #[serde(rename = "returnTo")]

    pub return_to: Option<String>,

}



pub async fn oauth_connect_url(

    req: HttpRequest,

    path: web::Path<String>,

    query: web::Query<ConnectQuery>,

) -> HttpResponse {

    let provider_id = path.into_inner();

    let Some(def) = find_provider(&provider_id) else {

        return HttpResponse::NotFound().json(json!({ "error": "Unknown integration" }));

    };

    if !def.oauth_supported {

        return HttpResponse::ServiceUnavailable().json(json!({

            "error": format!("Integracja {} nie ma publicznego OAuth API", def.name),

        }));

    }

    if !provider_enabled(def) {

        return HttpResponse::ServiceUnavailable().json(json!({

            "error": format!("Integracja {} nie jest skonfigurowana", def.name),

        }));

    }

    let Some(user_id) = request_user_id(&req) else {

        return HttpResponse::Unauthorized().json(json!({ "error": "Authentication required" }));

    };

    if load_active_user(&user_id).await.is_err() {

        return HttpResponse::Unauthorized().json(json!({ "error": "Authentication required" }));

    }



    let return_origin = normalize_return_origin(query.return_to.as_deref());

    let (code_verifier, code_challenge) = if def.use_pkce {

        generate_pkce_pair()

    } else {

        (String::new(), String::new())

    };

    let state = match build_oauth_state(def.id, &user_id, &return_origin, &code_verifier) {

        Ok(s) => s,

        Err(e) => return HttpResponse::InternalServerError().json(json!({ "error": e })),

    };

    let challenge = if def.use_pkce {

        Some(code_challenge.as_str())

    } else {

        None

    };

    let url = match build_auth_url(def, &state, challenge) {

        Ok(u) => u,

        Err(e) => return HttpResponse::InternalServerError().json(json!({ "error": e })),

    };

    HttpResponse::Ok().json(json!({ "url": url }))

}



#[derive(Deserialize)]

pub struct CallbackQuery {

    pub code: Option<String>,

    pub state: Option<String>,

    pub error: Option<String>,

    #[serde(rename = "error_description")]

    pub error_description: Option<String>,

}



pub async fn oauth_callback(

    path: web::Path<String>,

    query: web::Query<CallbackQuery>,

) -> HttpResponse {

    let provider_id = path.into_inner();

    let Some(def) = find_provider(&provider_id) else {

        return oauth_fail(&frontend_url(), &provider_id, "Nieznana integracja");

    };



    let fail = |frontend: &str, msg: &str| oauth_fail(frontend, def.id, msg);

    let succeed = |frontend: &str| oauth_success(frontend, def.id);



    if !provider_enabled(def) {

        return fail(

            &frontend_url().trim_end_matches('/'),

            &format!("Integracja {} nie jest skonfigurowana", def.name),

        );

    }



    if let Some(err) = &query.error {

        let desc = query.error_description.as_deref().unwrap_or("");

        log::warn!("OAuth callback error ({provider_id}): {err} — {desc}");

        return fail(

            &frontend_url().trim_end_matches('/'),

            &map_oauth_error(def.id, err, desc),

        );

    }



    let Some(code) = query.code.as_deref() else {

        return fail(&frontend_url().trim_end_matches('/'), "Brak kodu autoryzacji");

    };

    let Some(state) = query.state.as_deref() else {

        return fail(&frontend_url().trim_end_matches('/'), "Brak stanu OAuth");

    };



    let (user_oid, return_origin, code_verifier) = match verify_oauth_state_flexible(def.id, state) {

        Ok(result) => result,

        Err(e) => return fail(&frontend_url().trim_end_matches('/'), &e),

    };



    let verifier = if def.use_pkce {

        code_verifier.as_deref()

    } else {

        None

    };



    let tokens = match exchange_code(def, code, verifier).await {

        Ok(t) => t,

        Err(e) => {

            log::warn!("Token exchange failed ({provider_id}): {e}");

            return fail(&return_origin, &map_token_exchange_error(def, &e));

        }

    };



    let refresh = match resolve_refresh_token(user_oid, def, &tokens).await {

        Ok(r) => r,

        Err(e) => return fail(&return_origin, &e),

    };



    let profile = fetch_provider_profile(def, &tokens.access_token, &tokens)

        .await

        .ok();



    let (provider_user_id, provider_display_name, account) = if let Some(p) = profile {

        (

            p.provider_user_id,

            p.provider_display_name,

            Some(p.account),

        )

    } else {

        (None, Some(def.name.to_string()), None)

    };



    if let Err(e) = store_tokens(

        user_oid,

        def.id,

        &tokens.access_token,

        &refresh,

        tokens.expires_in,

        def.scopes.split_whitespace().map(str::to_string).collect(),

        provider_user_id,

        provider_display_name,

    )

    .await

    {

        log::error!("store_tokens failed ({provider_id}, {user_oid}): {e}");

        let msg = if def.id == "spotify" {

            "Nie udało się zapisać połączenia Spotify. Spróbuj połączyć ponownie."

        } else {

            "Nie udało się zapisać połączenia"

        };

        return fail(&return_origin, msg);

    }



    if let Some(account) = account {

        if let Ok(Some(updated)) =

            upsert_user_connected_account(&get_db(), user_oid, account).await

        {

            emit_profile_event(

                &get_db(),

                &user_oid.to_hex(),

                "profile-updated",

                json!({

                    "userId": user_oid.to_hex(),

                    "connectedAccounts": connected_accounts_json(&updated.connected_accounts),

                }),

            )

            .await;

        }

    }



    log::info!("{provider_id} connected for user {user_oid}");

    succeed(&return_origin)

}



async fn resolve_refresh_token(

    user_oid: ObjectId,

    def: &crate::utils::integrations::providers::OAuthProviderDef,

    tokens: &crate::utils::integrations::oauth::GenericTokenResponse,

) -> Result<String, String> {

    if let Some(refresh) = tokens.refresh_token.clone() {

        return Ok(refresh);

    }

    if def.id == "spotify" {

        match OauthToken::find_by_user_provider(&get_db(), user_oid, def.id).await {

            Ok(Some(existing)) => existing.refresh_token(),

            Ok(None) => Err(SPOTIFY_REAUTH_HINT.to_string()),

            Err(e) => {

                log::error!("Refresh lookup failed for {user_oid} ({provider}): {e}", provider = def.id);

                Err(SPOTIFY_REAUTH_HINT.to_string())

            }

        }

    } else {

        Ok(tokens.access_token.clone())

    }

}



fn oauth_fail(frontend: &str, provider: &str, msg: &str) -> HttpResponse {

    HttpResponse::Found()

        .append_header((

            "Location",

            format!(

                "{frontend}/?integration={provider}&status=error&message={}",

                url_encode(msg)

            ),

        ))

        .finish()

}



fn oauth_success(frontend: &str, provider: &str) -> HttpResponse {

    HttpResponse::Found()

        .append_header((

            "Location",

            format!("{frontend}/?integration={provider}&status=connected"),

        ))

        .finish()

}



pub async fn oauth_disconnect(req: HttpRequest, path: web::Path<String>) -> HttpResponse {

    let provider_id = path.into_inner();

    let Some(def) = find_provider(&provider_id) else {

        return HttpResponse::NotFound().json(json!({ "error": "Unknown integration" }));

    };

    let Some(user_id) = request_user_id(&req) else {

        return HttpResponse::Unauthorized().json(json!({ "error": "Authentication required" }));

    };

    let user = match load_active_user(&user_id).await {

        Ok(u) => u,

        Err(resp) => return resp,

    };

    let Some(user_oid) = user.id else {

        return HttpResponse::InternalServerError().json(json!({ "error": "Server error" }));

    };



    let db = get_db();

    if let Ok(Some(token_doc)) = OauthToken::find_by_user_provider(&db, user_oid, def.id).await {

        if def.revoke_on_disconnect {

            if let Ok(access) = token_doc.access_token() {

                let _ = revoke_provider_token(def, &access).await;

            }

        }

        let _ = OauthToken::delete_for_user_provider(&db, user_oid, def.id).await;

    }



    let mut updated = match remove_user_connected_account(&db, user_oid, def.id).await {

        Ok(Some(u)) => u,

        Ok(None) => {

            return HttpResponse::InternalServerError().json(json!({ "error": "Server error" }));

        }

        Err(_) => return HttpResponse::InternalServerError().json(json!({ "error": "Server error" })),

    };



    if def.listening_sync {

        updated = match User::set_fields(&db, user_oid, doc! { "listeningActivity": Bson::Null }).await {

            Ok(Some(u)) => u,

            _ => updated,

        };

        broadcast_listening_change(&user_id, &updated).await;

    }



    emit_profile_event(

        &db,

        &user_oid.to_hex(),

        "profile-updated",

        json!({

            "userId": user_oid.to_hex(),

            "connectedAccounts": connected_accounts_json(&updated.connected_accounts),

        }),

    )

    .await;



    HttpResponse::Ok().json(json!({

        "success": true,

        "connected": false,

        "provider": def.id,

    }))

}



#[derive(Deserialize)]

pub struct ListeningSyncBody {

    #[serde(rename = "clientType", default = "default_client_type")]

    pub client_type: String,

    #[serde(rename = "clientInstanceId")]

    pub client_instance_id: String,

}



fn default_client_type() -> String {

    "web".to_string()

}



pub async fn oauth_sync(

    req: HttpRequest,

    path: web::Path<String>,

    body: web::Json<ListeningSyncBody>,

) -> HttpResponse {

    let provider_id = path.into_inner();

    let Some(def) = find_provider(&provider_id) else {

        return HttpResponse::NotFound().json(json!({ "error": "Unknown integration" }));

    };

    if !def.listening_sync {

        return HttpResponse::BadRequest().json(json!({ "error": "Listening sync not supported" }));

    }



    let Some(user_id) = request_user_id(&req) else {

        return HttpResponse::Unauthorized().json(json!({ "error": "Authentication required" }));

    };

    if !INTEGRATION_SYNC.check_and_increment(&format!("integration-sync:{provider_id}:{user_id}")) {

        return HttpResponse::TooManyRequests().json(json!({

            "error": "Rate limit exceeded",

            "retryAfter": 15,

        }));

    }



    let Ok(user) = load_active_user(&user_id).await else {

        return HttpResponse::Unauthorized().json(json!({ "error": "Authentication required" }));

    };

    let Some(oid) = user.id else {

        return HttpResponse::InternalServerError().json(json!({ "error": "Server error" }));

    };



    if body.client_instance_id.trim().is_empty() || body.client_instance_id.len() > 128 {

        return HttpResponse::BadRequest().json(json!({ "error": "Invalid clientInstanceId" }));

    }

    let client_type = match body.client_type.as_str() {

        "web" | "desktop" | "mobile" => body.client_type.clone(),

        _ => return HttpResponse::BadRequest().json(json!({ "error": "Invalid clientType" })),

    };



    if !user.share_listening {

        if user.listening_activity.is_some() {

            let _ = User::set_fields(

                &get_db(),

                oid,

                doc! { "listeningActivity": Bson::Null },

            )

            .await;

            if let Ok(Some(updated)) = User::find_by_id(&get_db(), oid).await {

                broadcast_listening_change(&user_id, &updated).await;

            }

        }

        return HttpResponse::Ok().json(json!({

            "listeningActivity": null,

            "shareListening": false,

        }));

    }



    let Some(token_doc) = OauthToken::find_by_user_provider(&get_db(), oid, def.id)

        .await

        .ok()

        .flatten()

    else {

        return HttpResponse::BadRequest().json(json!({ "error": "Integration not connected" }));

    };



    let access = match ensure_access_token(&token_doc, def).await {

        Ok(t) => t,

        Err(e) => return HttpResponse::BadGateway().json(json!({ "error": e })),

    };



    let new_activity = match fetch_active_listening_activity(

        def,

        &access,

        &client_type,

        &body.client_instance_id,

    )

    .await

    {

        Ok(activity) => activity,

        Err(e) => return HttpResponse::BadGateway().json(json!({ "error": e })),

    };



    let report = ListeningReport {

        activity: new_activity,

        client_type: client_type.clone(),

        client_instance_id: body.client_instance_id.clone(),

    };



    if !should_apply_report(&user.listening_activity, &report) {

        let current = user

            .listening_activity

            .as_ref()

            .filter(|a| a.is_playing)

            .map(listening_activity_json);

        return HttpResponse::Ok().json(json!({

            "listeningActivity": current,

            "shareListening": user.share_listening,

            "applied": false,

        }));

    }



    let set_doc = if let Some(activity) = report.activity {

        let bson = mongodb::bson::to_bson(&activity).unwrap_or(Bson::Null);

        doc! { "listeningActivity": bson }

    } else {

        doc! { "listeningActivity": Bson::Null }

    };



    let updated = match User::set_fields(&get_db(), oid, set_doc).await {

        Ok(Some(u)) => u,

        _ => return HttpResponse::InternalServerError().json(json!({ "error": "Server error" })),

    };



    broadcast_listening_change(&user_id, &updated).await;



    let listening = updated

        .listening_activity

        .as_ref()

        .filter(|a| a.is_playing)

        .map(listening_activity_json);



    HttpResponse::Ok().json(json!({

        "listeningActivity": listening,

        "shareListening": updated.share_listening,

        "applied": true,

    }))

}



#[derive(Deserialize)]

pub struct ListeningSettingsBody {

    #[serde(rename = "shareListening")]

    pub share_listening: bool,

}



pub async fn update_listening_settings(

    req: HttpRequest,

    body: web::Json<ListeningSettingsBody>,

) -> HttpResponse {

    let Some(user_id) = request_user_id(&req) else {

        return HttpResponse::Unauthorized().json(json!({ "error": "Authentication required" }));

    };

    let Ok(user) = load_active_user(&user_id).await else {

        return HttpResponse::Unauthorized().json(json!({ "error": "Authentication required" }));

    };

    let Some(oid) = user.id else {

        return HttpResponse::InternalServerError().json(json!({ "error": "Server error" }));

    };



    let mut set = doc! { "shareListening": body.share_listening };

    if !body.share_listening {

        set.insert("listeningActivity", Bson::Null);

    }



    let updated = match User::set_fields(&get_db(), oid, set).await {

        Ok(Some(u)) => u,

        _ => return HttpResponse::InternalServerError().json(json!({ "error": "Server error" })),

    };



    if !body.share_listening {

        broadcast_listening_change(&user_id, &updated).await;

    }



    HttpResponse::Ok().json(json!({

        "success": true,

        "shareListening": updated.share_listening,

    }))

}

