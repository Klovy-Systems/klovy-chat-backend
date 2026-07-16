use mongodb::bson::Bson;

use crate::model::user_model::User;
use crate::utils::auth::totp::{
    decrypt_totp_secret, is_totp_code, verify_and_consume_backup_code, verify_totp_code,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepUpResult {
    NotRequired,
    Verified,
    BackupConsumed { index: usize },
}

pub async fn verify_step_up_auth(user: &User, code: Option<&str>) -> Result<StepUpResult, &'static str> {
    if !user.two_factor_enabled {
        return Ok(StepUpResult::NotRequired);
    }

    let Some(code) = code.map(str::trim).filter(|c| !c.is_empty()) else {
        return Err("Authentication code is required when two-factor is enabled.");
    };

    if is_totp_code(code) {
        if let Some(encrypted) = user.totp_secret.as_deref() {
            if let Ok(secret) = decrypt_totp_secret(encrypted) {
                if verify_totp_code(&user.username, &secret, code) {
                    return Ok(StepUpResult::Verified);
                }
            }
        }
        return Err("Invalid authentication code.");
    }

    if let Some(hashes) = user.backup_codes.as_ref() {
        if let Some(index) = verify_and_consume_backup_code(code, hashes).await {
            return Ok(StepUpResult::BackupConsumed { index });
        }
    }

    Err("Invalid authentication code.")
}

pub fn backup_codes_bson_after_consumption(user: &User, index: usize) -> Bson {
    let Some(codes) = user.backup_codes.as_ref() else {
        return Bson::Null;
    };
    let mut codes = codes.clone();
    if index >= codes.len() {
        return Bson::Null;
    }
    codes.remove(index);
    if codes.is_empty() {
        Bson::Null
    } else {
        Bson::Array(codes.into_iter().map(Bson::String).collect())
    }
}
