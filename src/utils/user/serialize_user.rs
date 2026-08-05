use serde_json::{json, Value};

use crate::model::user_model::{AvailabilityStatus, ConnectedAccount, User};
use crate::utils::auth::admin_session::user_is_panel_admin;
use crate::utils::auth::panel_permissions::panel_role_label;
use crate::utils::listening::serialize::listening_for_viewer;

pub const BIO_MAX_LENGTH: usize = 500;
pub const DISPLAY_NAME_MAX_LENGTH: usize = 32;

pub fn availability_status_str(status: &AvailabilityStatus) -> &'static str {
    match status {
        AvailabilityStatus::Online => "online",
        AvailabilityStatus::Away => "away",
        AvailabilityStatus::Brb => "brb",
        AvailabilityStatus::Dnd => "dnd",
    }
}

pub fn resolve_display_name(user: &User) -> Option<String> {
    user.display_name
        .as_ref()
        .map(|dn| dn.trim())
        .filter(|dn| !dn.is_empty())
        .map(|dn| dn.to_string())
}

fn iso(dt: &mongodb::bson::DateTime) -> Option<String> {
    dt.try_to_rfc3339_string().ok()
}

pub fn connected_accounts_json(accounts: &[ConnectedAccount]) -> Value {
    if accounts.is_empty() {
        return json!([]);
    }
    json!(accounts
        .iter()
        .map(|account| {
            json!({
                "provider": account.provider,
                "accountName": account.account_name,
                "profileUrl": account.profile_url,
            })
        })
        .collect::<Vec<_>>())
}

pub fn serialize_user(user: &User, is_whitelist_enabled: Option<bool>) -> Value {
    serialize_user_for_viewer(user, is_whitelist_enabled, true)
}

pub fn serialize_user_for_viewer(
    user: &User,
    is_whitelist_enabled: Option<bool>,
    is_self: bool,
) -> Value {
    let bio = user
        .bio
        .as_ref()
        .map(|b| b.trim().to_string())
        .filter(|b| !b.is_empty());

    let mut payload = json!({
        "id": user.id.map(|o| o.to_hex()),
        "username": user.username,
        "displayName": resolve_display_name(user),
        "bio": bio,
        "image": user.image,
        "banner": user.banner,
        "profileSetup": user.profile_setup,
        "color": user.color,
        "isOnline": user.is_online,
        "lastSeen": user.last_seen.as_ref().and_then(iso),
        "availabilityStatus": availability_status_str(&user.availability_status),
        "createdAt": iso(&user.created_at),
        "isWhitelisted": user.is_whitelisted,
        "isWhitelistEnabled": is_whitelist_enabled,
        "twoFactorEnabled": user.two_factor_enabled,
        "connectedAccounts": connected_accounts_json(&user.connected_accounts),
    });

    if is_self {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("isPanelAdmin".to_string(), json!(user_is_panel_admin(user)));
            obj.insert(
                "panelRole".to_string(),
                json!(panel_role_label(user)),
            );
            obj.insert("shareListening".to_string(), json!(user.share_listening));
            obj.insert("language".to_string(), json!(user.language));
            obj.insert("isDisabled".to_string(), json!(user.is_disabled));
            obj.insert(
                "deletionScheduledAt".to_string(),
                json!(user.deletion_scheduled_at.as_ref().and_then(iso)),
            );
            obj.insert("e2eEnabled".to_string(), json!(user.e2e_enabled));
            if let Some(listening) = listening_for_viewer(user, true) {
                obj.insert("listeningActivity".to_string(), listening);
            }
        }
    } else if let Some(listening) = listening_for_viewer(user, false) {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("listeningActivity".to_string(), listening);
        }
    }

    payload
}
