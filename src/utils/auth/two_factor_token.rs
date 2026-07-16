use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey};
use serde::{Deserialize, Serialize};
use std::env;

use crate::utils::auth::jwt_validation::{hs256_header, hs256_validation, JWT_AUDIENCE, JWT_ISSUER};

pub const CHALLENGE_MAX_AGE_SECS: i64 = 5 * 60;

#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorChallengePayload {
    #[serde(rename = "type")]
    pub token_type: String,
    #[serde(rename = "userId")]
    pub user_id: String,
    // `iss`/`aud` są wymagane przez `hs256_validation()`; bez nich dekodowanie
    // tokena zawsze się nie powiodło i logowanie z 2FA było zablokowane.
    pub iss: String,
    pub aud: String,
    pub exp: usize,
}

pub fn create_two_factor_challenge_token(user_id: &str) -> Result<String, String> {
    let key = env::var("JWT_KEY").map_err(|_| "JWT_KEY is not defined".to_string())?;
    let exp = (chrono::Utc::now().timestamp() + CHALLENGE_MAX_AGE_SECS) as usize;
    let claims = TwoFactorChallengePayload {
        token_type: "2fa_challenge".to_string(),
        user_id: user_id.to_string(),
        iss: JWT_ISSUER.to_string(),
        aud: JWT_AUDIENCE.to_string(),
        exp,
    };
    encode(
        &hs256_header(),
        &claims,
        &EncodingKey::from_secret(key.as_bytes()),
    )
    .map_err(|e| e.to_string())
}

pub fn decode_two_factor_challenge_token(token: &str) -> Result<TwoFactorChallengePayload, String> {
    let key = env::var("JWT_KEY").map_err(|_| "JWT_KEY is not defined".to_string())?;
    let data = decode::<TwoFactorChallengePayload>(
        token,
        &DecodingKey::from_secret(key.as_bytes()),
        &hs256_validation(),
    )
    .map_err(|_| "Invalid or expired two-factor token".to_string())?;

    if data.claims.token_type != "2fa_challenge" {
        return Err("Invalid two-factor token".to_string());
    }

    Ok(data.claims)
}
