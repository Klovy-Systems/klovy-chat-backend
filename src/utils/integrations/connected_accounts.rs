use mongodb::bson::{doc, oid::ObjectId, Bson};
use mongodb::Database;

use crate::model::user_model::{ConnectedAccount, User};

pub fn upsert_connected_account(accounts: &mut Vec<ConnectedAccount>, account: ConnectedAccount) {
    accounts.retain(|a| a.provider != account.provider);
    accounts.push(account);
}

pub fn remove_connected_account(accounts: &mut Vec<ConnectedAccount>, provider: &str) {
    accounts.retain(|a| a.provider != provider);
}

pub async fn upsert_user_connected_account(
    db: &Database,
    user_oid: ObjectId,
    account: ConnectedAccount,
) -> mongodb::error::Result<Option<User>> {
    let Some(user) = User::find_by_id(db, user_oid).await? else {
        return Ok(None);
    };
    let mut accounts = user.connected_accounts.clone();
    upsert_connected_account(&mut accounts, account);
    let accounts_bson = mongodb::bson::to_bson(&accounts).unwrap_or(Bson::Array(vec![]));
    User::set_fields(db, user_oid, doc! { "connectedAccounts": accounts_bson }).await
}

pub async fn remove_user_connected_account(
    db: &Database,
    user_oid: ObjectId,
    provider: &str,
) -> mongodb::error::Result<Option<User>> {
    let Some(user) = User::find_by_id(db, user_oid).await? else {
        return Ok(None);
    };
    let mut accounts = user.connected_accounts.clone();
    remove_connected_account(&mut accounts, provider);
    let accounts_bson = mongodb::bson::to_bson(&accounts).unwrap_or(Bson::Array(vec![]));
    User::set_fields(db, user_oid, doc! { "connectedAccounts": accounts_bson }).await
}
