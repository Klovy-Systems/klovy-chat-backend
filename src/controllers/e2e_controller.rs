use actix_web::{web, HttpRequest, HttpResponse};
use mongodb::bson::{doc, oid::ObjectId};
use serde::Deserialize;
use serde_json::json;

use crate::middlewares::auth_middleware::request_user_id;
use crate::model::e2e_keys_model::{
    E2eKeyBundle, OneTimePreKeyRecord, SignedPreKeyRecord, UpsertE2eKeysInput,
};
use crate::model::user_model::User;
use crate::utils::db::get_db;
use crate::utils::e2e::compute_identity_fingerprint;
use crate::utils::e2e::verify::{PutKeyBundleInput, validate_put_key_bundle, validate_one_time_prekeys};

#[derive(Deserialize)]
pub struct PutE2eKeysBody {
    #[serde(rename = "registrationId")]
    pub registration_id: u32,
    #[serde(rename = "identityKey")]
    pub identity_key: String,
    #[serde(rename = "signedPreKey")]
    pub signed_pre_key: SignedPreKeyRecord,
    #[serde(rename = "oneTimePreKeys", default)]
    pub one_time_pre_keys: Vec<OneTimePreKeyRecord>,
}

#[derive(Deserialize)]
pub struct PatchE2eSettingsBody {
    pub enabled: bool,
}

#[derive(Deserialize)]
pub struct AppendPreKeysBody {
    #[serde(rename = "oneTimePreKeys", default)]
    pub one_time_pre_keys: Vec<OneTimePreKeyRecord>,
}

#[derive(Deserialize)]
pub struct BulkQuery {
    pub ids: String,
}

fn invalid_keys_response() -> HttpResponse {
    HttpResponse::BadRequest().json(json!({
        "error": "INVALID_E2E_KEYS",
        "message": "Invalid key bundle payload.",
    }))
}

fn identity_rotation_required_response() -> HttpResponse {
    HttpResponse::BadRequest().json(json!({
        "error": "E2E_IDENTITY_ROTATION_REQUIRED",
        "message": "Identity key changed. Delete existing keys before uploading a new bundle.",
    }))
}

pub async fn get_e2e_status(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };
    let Ok(oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::BadRequest().json(json!({ "error": "Invalid user id" }));
    };

    let db = get_db();
    let user = match User::find_by_id(&db, oid).await {
        Ok(Some(u)) => u,
        Ok(None) => return HttpResponse::NotFound().json(json!({ "error": "User not found" })),
        Err(_) => return HttpResponse::InternalServerError().json(json!({ "error": "Server error" })),
    };

    let bundle = E2eKeyBundle::find_by_user_id(&db, oid).await.ok().flatten();
    HttpResponse::Ok().json(json!({
        "enabled": user.e2e_enabled,
        "hasKeys": bundle.is_some(),
        "registrationId": bundle.as_ref().map(|b| b.registration_id),
        "fingerprint": bundle.as_ref().map(|b| b.identity_fingerprint.clone()),
        "oneTimePreKeysRemaining": bundle.as_ref().map(|b| b.one_time_pre_keys.len()).unwrap_or(0),
    }))
}

pub async fn patch_e2e_settings(
    req: HttpRequest,
    body: web::Json<PatchE2eSettingsBody>,
) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };
    let Ok(oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::BadRequest().json(json!({ "error": "Invalid user id" }));
    };

    let db = get_db();
    if body.enabled {
        let bundle = match E2eKeyBundle::find_by_user_id(&db, oid).await {
            Ok(b) => b,
            Err(_) => return HttpResponse::InternalServerError().json(json!({ "error": "Server error" })),
        };
        if bundle.is_none() {
            return HttpResponse::BadRequest().json(json!({
                "error": "E2E_KEYS_REQUIRED",
                "message": "Upload key bundle before enabling end-to-end encryption.",
            }));
        }
    }

    if User::set_fields(&db, oid, doc! { "e2eEnabled": body.enabled })
        .await
        .is_err()
    {
        return HttpResponse::InternalServerError().json(json!({ "error": "Server error" }));
    }

    HttpResponse::Ok().json(json!({ "enabled": body.enabled }))
}

pub async fn put_e2e_keys(req: HttpRequest, body: web::Json<PutE2eKeysBody>) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };
    let Ok(oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::BadRequest().json(json!({ "error": "Invalid user id" }));
    };

    if !validate_one_time_prekeys(&body.one_time_pre_keys) {
        return invalid_keys_response();
    }

    let db = get_db();
    let existing = E2eKeyBundle::find_by_user_id(&db, oid).await.ok().flatten();
    let input = PutKeyBundleInput {
        identity_key: &body.identity_key,
        signed_pre_key: &body.signed_pre_key,
        one_time_pre_keys: &body.one_time_pre_keys,
    };
    if existing.is_some() {
        let Some(fingerprint) = compute_identity_fingerprint(&body.identity_key) else {
            return invalid_keys_response();
        };
        if existing.as_ref().unwrap().identity_fingerprint != fingerprint {
            return identity_rotation_required_response();
        }
    }
    if !validate_put_key_bundle(&input, existing.as_ref()) {
        return invalid_keys_response();
    }

    let Some(fingerprint) = compute_identity_fingerprint(&body.identity_key) else {
        return invalid_keys_response();
    };

    let upsert = UpsertE2eKeysInput {
        user_id: oid,
        registration_id: body.registration_id,
        identity_key: body.identity_key.trim().to_string(),
        identity_fingerprint: fingerprint,
        signed_pre_key: body.signed_pre_key.clone(),
        one_time_pre_keys: body.one_time_pre_keys.clone(),
    };

    match E2eKeyBundle::upsert(&db, upsert).await {
        Ok(bundle) => HttpResponse::Ok().json(json!({
            "success": true,
            "fingerprint": bundle.identity_fingerprint,
            "oneTimePreKeysRemaining": bundle.one_time_pre_keys.len(),
        })),
        Err(_) => HttpResponse::InternalServerError().json(json!({ "error": "Server error" })),
    }
}

pub async fn append_e2e_prekeys(
    req: HttpRequest,
    body: web::Json<AppendPreKeysBody>,
) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };
    let Ok(oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::BadRequest().json(json!({ "error": "Invalid user id" }));
    };
    if body.one_time_pre_keys.is_empty() {
        return HttpResponse::BadRequest().json(json!({ "error": "No prekeys provided" }));
    }
    if !validate_one_time_prekeys(&body.one_time_pre_keys) {
        return invalid_keys_response();
    }

    let db = get_db();
    if E2eKeyBundle::append_one_time_prekeys(&db, oid, body.one_time_pre_keys.clone())
        .await
        .is_err()
    {
        return HttpResponse::InternalServerError().json(json!({ "error": "Server error" }));
    }

    let remaining = E2eKeyBundle::find_by_user_id(&db, oid)
        .await
        .ok()
        .flatten()
        .map(|b| b.one_time_pre_keys.len())
        .unwrap_or(0);

    HttpResponse::Ok().json(json!({ "oneTimePreKeysRemaining": remaining }))
}

pub async fn delete_e2e_keys(req: HttpRequest) -> HttpResponse {
    let Some(user_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };
    let Ok(oid) = ObjectId::parse_str(&user_id) else {
        return HttpResponse::BadRequest().json(json!({ "error": "Invalid user id" }));
    };

    let db = get_db();
    let _ = E2eKeyBundle::delete_for_user(&db, oid).await;
    let _ = User::set_fields(&db, oid, doc! { "e2eEnabled": false }).await;
    HttpResponse::Ok().json(json!({ "success": true }))
}

pub async fn get_e2e_key_bundle(
    req: HttpRequest,
    path: web::Path<String>,
) -> HttpResponse {
    let Some(requester_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };
    let target_id = path.into_inner();
    if target_id.is_empty() {
        return HttpResponse::BadRequest().json(json!({ "error": "Invalid user id" }));
    }
    let Ok(target_oid) = ObjectId::parse_str(&target_id) else {
        return HttpResponse::BadRequest().json(json!({ "error": "Invalid user id" }));
    };

    let db = get_db();
    let user = match User::find_by_id(&db, target_oid).await {
        Ok(Some(u)) => u,
        Ok(None) => return HttpResponse::NotFound().json(json!({ "error": "User not found" })),
        Err(_) => return HttpResponse::InternalServerError().json(json!({ "error": "Server error" })),
    };

    if !user.e2e_enabled {
        return HttpResponse::NotFound().json(json!({ "error": "E2E not enabled for user" }));
    }

    if requester_id != target_id {
        if !crate::utils::friends::are_friends(&db, &requester_id, &target_id).await {
            return HttpResponse::Forbidden().json(json!({ "error": "Access denied" }));
        }
    }

    match E2eKeyBundle::consume_public_bundle(&db, target_oid, user.e2e_enabled).await {
        Ok(Some(bundle)) => HttpResponse::Ok().json(bundle),
        Ok(None) => HttpResponse::NotFound().json(json!({ "error": "No key bundle" })),
        Err(_) => HttpResponse::InternalServerError().json(json!({ "error": "Server error" })),
    }
}

pub async fn get_e2e_key_bulk(req: HttpRequest, query: web::Query<BulkQuery>) -> HttpResponse {
    let Some(requester_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };

    let ids: Vec<ObjectId> = query
        .ids
        .split(',')
        .filter_map(|s| ObjectId::parse_str(s.trim()).ok())
        .take(50)
        .collect();

    if ids.is_empty() {
        return HttpResponse::Ok().json(json!({ "bundles": [] }));
    }

    let db = get_db();
    let mut bundles = Vec::new();
    for id in ids {
        let id_hex = id.to_hex();
        let user = match User::find_by_id(&db, id).await {
            Ok(Some(u)) if u.e2e_enabled => u,
            _ => continue,
        };
        if requester_id != id_hex
            && !crate::utils::friends::are_friends(&db, &requester_id, &id_hex).await
        {
            continue;
        }
        if let Ok(Some(bundle)) =
            E2eKeyBundle::consume_public_bundle(&db, id, user.e2e_enabled).await
        {
            bundles.push(bundle);
        }
    }

    HttpResponse::Ok().json(json!({ "bundles": bundles }))
}

pub async fn get_e2e_capabilities(req: HttpRequest, query: web::Query<BulkQuery>) -> HttpResponse {
    let Some(requester_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };

    let ids: Vec<ObjectId> = query
        .ids
        .split(',')
        .filter_map(|s| ObjectId::parse_str(s.trim()).ok())
        .take(100)
        .collect();

    if ids.is_empty() {
        return HttpResponse::Ok().json(json!({ "users": [] }));
    }

    let db = get_db();
    let mut users = Vec::new();
    let fingerprint_rows = E2eKeyBundle::find_fingerprints_bulk(&db, &ids)
        .await
        .unwrap_or_default();
    let fingerprint_by_id: std::collections::HashMap<String, String> = fingerprint_rows
        .into_iter()
        .map(|(oid, fingerprint, _)| (oid.to_hex(), fingerprint))
        .collect();

    for id in ids {
        let id_hex = id.to_hex();
        if requester_id != id_hex
            && !crate::utils::friends::are_friends(&db, &requester_id, &id_hex).await
        {
            continue;
        }
        if let Ok(Some(user)) = User::find_by_id(&db, id).await {
            let has_keys = E2eKeyBundle::find_by_user_id(&db, id)
                .await
                .ok()
                .flatten()
                .is_some();
            users.push(json!({
                "userId": id.to_hex(),
                "e2eEnabled": user.e2e_enabled,
                "hasKeys": has_keys,
                "fingerprint": fingerprint_by_id.get(&id_hex),
            }));
        }
    }

    HttpResponse::Ok().json(json!({ "users": users }))
}

pub async fn get_e2e_key_fingerprint(
    req: HttpRequest,
    path: web::Path<String>,
) -> HttpResponse {
    let Some(requester_id) = request_user_id(&req) else {
        return HttpResponse::Unauthorized().json(json!({ "error": "Unauthorized" }));
    };
    let target_id = path.into_inner();
    if target_id.is_empty() {
        return HttpResponse::BadRequest().json(json!({ "error": "Invalid user id" }));
    }
    let Ok(target_oid) = ObjectId::parse_str(&target_id) else {
        return HttpResponse::BadRequest().json(json!({ "error": "Invalid user id" }));
    };

    let db = get_db();
    let user = match User::find_by_id(&db, target_oid).await {
        Ok(Some(u)) => u,
        Ok(None) => return HttpResponse::NotFound().json(json!({ "error": "User not found" })),
        Err(_) => return HttpResponse::InternalServerError().json(json!({ "error": "Server error" })),
    };

    if !user.e2e_enabled {
        return HttpResponse::NotFound().json(json!({ "error": "E2E not enabled for user" }));
    }

    if requester_id != target_id {
        if !crate::utils::friends::are_friends(&db, &requester_id, &target_id).await {
            return HttpResponse::Forbidden().json(json!({ "error": "Access denied" }));
        }
    }

    let bundle = match E2eKeyBundle::find_by_user_id(&db, target_oid).await {
        Ok(b) => b,
        Err(_) => return HttpResponse::InternalServerError().json(json!({ "error": "Server error" })),
    };

    let Some(bundle) = bundle else {
        return HttpResponse::NotFound().json(json!({ "error": "No key bundle" }));
    };

    HttpResponse::Ok().json(json!({
        "userId": target_id,
        "fingerprint": bundle.identity_fingerprint,
    }))
}
