use std::env;

use mongodb::{
    bson::{doc, DateTime},
    options::{FindOneAndUpdateOptions, ReturnDocument},
    Collection, Database,
};

use crate::utils::app_env::is_production;

fn env_flag(name: &str) -> bool {
    env::var(name)
        .map(|v| {
            let v = v.trim();
            v == "1"
                || v.eq_ignore_ascii_case("true")
                || v.eq_ignore_ascii_case("yes")
                || v.eq_ignore_ascii_case("on")
        })
        .unwrap_or(false)
}

fn env_u64(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(default)
}

fn env_u32(name: &str, default: u32) -> u32 {
    env_u64(name, default as u64) as u32
}

/// Całkowite wyłączenie rejestracji (REGISTRATION_DISABLED=true).
pub fn is_registration_disabled() -> bool {
    env_flag("REGISTRATION_DISABLED")
}

pub fn signup_max_per_ip_hour() -> u32 {
    env_u32("SIGNUP_MAX_PER_IP_HOUR", if is_production() { 3 } else { 10 })
}

pub fn signup_max_global_per_hour() -> u64 {
    env_u64("SIGNUP_MAX_GLOBAL_PER_HOUR", if is_production() { 25 } else { 200 })
}

pub fn signup_max_global_per_day() -> u64 {
    env_u64("SIGNUP_MAX_GLOBAL_PER_DAY", if is_production() { 100 } else { 1000 })
}

pub fn is_registration_open() -> bool {
    !is_registration_disabled()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignupQuotaError {
    HourlyLimit,
    DailyLimit,
}

impl SignupQuotaError {
    pub fn user_message(self) -> &'static str {
        match self {
            Self::HourlyLimit | Self::DailyLimit => {
                "Rejestracja jest tymczasowo niedostępna z powodu dużego obciążenia. Spróbuj ponownie później."
            }
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            Self::HourlyLimit => "SIGNUP_HOURLY_LIMIT",
            Self::DailyLimit => "SIGNUP_DAILY_LIMIT",
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct SignupQuotaDoc {
    #[serde(rename = "_id")]
    id: String,
    count: i64,
    #[serde(rename = "updatedAt")]
    updated_at: DateTime,
}

fn quota_collection(db: &Database) -> Collection<SignupQuotaDoc> {
    db.collection("signup_quotas")
}

fn utc_window_keys(now: DateTime) -> (String, String) {
    let millis = now.timestamp_millis();
    let secs = millis / 1000;
    let hour = secs / 3600;
    let day = secs / 86_400;
    (format!("hour:{hour}"), format!("day:{day}"))
}

async fn try_consume_window(
    db: &Database,
    key: &str,
    max: u64,
) -> mongodb::error::Result<bool> {
    let now = DateTime::now();
    let filter = doc! {
        "_id": key,
        "$or": [
            { "count": { "$exists": false } },
            { "count": { "$lt": max as i64 } }
        ]
    };
    let update = doc! {
        "$inc": { "count": 1 },
        "$set": { "updatedAt": now },
    };
    let options = FindOneAndUpdateOptions::builder()
        .upsert(true)
        .return_document(ReturnDocument::After)
        .build();

    let result = quota_collection(db)
        .find_one_and_update(filter, update)
        .with_options(options)
        .await?;

    Ok(result.is_some_and(|doc| doc.count <= max as i64))
}

/// Atomically reserves a global signup slot shared across all backend instances.
pub async fn try_consume_global_signup_slot(
    db: &Database,
) -> Result<(), SignupQuotaError> {
    let now = DateTime::now();
    let (hour_key, day_key) = utc_window_keys(now);

    let hour_ok = try_consume_window(db, &hour_key, signup_max_global_per_hour())
        .await
        .unwrap_or(false);
    if !hour_ok {
        return Err(SignupQuotaError::HourlyLimit);
    }

    let day_ok = try_consume_window(db, &day_key, signup_max_global_per_day())
        .await
        .unwrap_or(false);
    if !day_ok {
        // Best-effort rollback of the hour slot so failed day checks don't skew hourly stats.
        let _ = quota_collection(db)
            .update_one(
                doc! { "_id": &hour_key, "count": { "$gt": 0 } },
                doc! { "$inc": { "count": -1 } },
            )
            .await;
        return Err(SignupQuotaError::DailyLimit);
    }

    Ok(())
}

pub async fn create_indexes(db: &Database) -> mongodb::error::Result<()> {
    quota_collection(db)
        .create_index(
            mongodb::IndexModel::builder()
                .keys(doc! { "updatedAt": 1 })
                .options(
                    mongodb::options::IndexOptions::builder()
                        .expire_after(std::time::Duration::from_secs(8 * 24 * 3600))
                        .build(),
                )
                .build(),
        )
        .await?;

    Ok(())
}
