use mongodb::bson::oid::ObjectId;
use mongodb::Database;

use crate::model::channel_model::Channel;
use crate::utils::channel::{
    can_access_channel, is_channel_admin, is_channel_muted_member,
};
use crate::utils::friends::{are_friends, is_dm_blocked};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessDeniedReason {
    InvalidId,
    NotFound,
    NotMember,
    Banned,
    Muted,
    NotFriends,
    Blocked,
}

impl AccessDeniedReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidId => "Invalid ID",
            Self::NotFound => "Resource not found",
            Self::NotMember => "Access denied",
            Self::Banned => "You are banned from this channel",
            Self::Muted => "You are muted in this channel",
            Self::NotFriends => "Not friends with this user",
            Self::Blocked => "This conversation is not available",
        }
    }
}

pub async fn require_channel_access(
    db: &Database,
    channel_id: &str,
    user_id: &str,
) -> Result<Channel, AccessDeniedReason> {
    let channel_oid = ObjectId::parse_str(channel_id).map_err(|_| AccessDeniedReason::InvalidId)?;
    let channel = Channel::find_by_id(db, channel_oid)
        .await
        .map_err(|_| AccessDeniedReason::NotFound)?
        .ok_or(AccessDeniedReason::NotFound)?;
    let channel = crate::utils::channel::moderation::maybe_prune_channel_moderation(db, &channel).await;

    if !can_access_channel(&channel, Some(user_id)) {
        if crate::utils::channel::is_channel_banned(&channel, Some(user_id)) {
            return Err(AccessDeniedReason::Banned);
        }
        return Err(AccessDeniedReason::NotMember);
    }

    Ok(channel)
}

pub async fn require_channel_message_access(
    db: &Database,
    channel_id: &str,
    user_id: &str,
) -> Result<Channel, AccessDeniedReason> {
    let channel = require_channel_access(db, channel_id, user_id).await?;
    if is_channel_muted_member(&channel, Some(user_id)) {
        return Err(AccessDeniedReason::Muted);
    }
    Ok(channel)
}

pub fn channel_admin_bypasses_slowmode(channel: &Channel, user_id: &str) -> bool {
    is_channel_admin(channel, Some(user_id))
}

pub async fn require_dm_access(
    db: &Database,
    user_id: &str,
    contact_id: &str,
) -> Result<(), AccessDeniedReason> {
    if ObjectId::parse_str(user_id).is_err() || ObjectId::parse_str(contact_id).is_err() {
        return Err(AccessDeniedReason::InvalidId);
    }
    if !are_friends(db, user_id, contact_id).await {
        return Err(AccessDeniedReason::NotFriends);
    }
    if is_dm_blocked(db, user_id, contact_id).await {
        return Err(AccessDeniedReason::Blocked);
    }
    Ok(())
}

pub async fn require_message_participant(
    db: &Database,
    user_id: &str,
    msg: &crate::model::messages_model::Message,
) -> Result<(), AccessDeniedReason> {
    if msg.deleted {
        return Err(AccessDeniedReason::NotFound);
    }
    if let Some(channel_id) = msg.channel {
        require_channel_message_access(db, &channel_id.to_hex(), user_id).await?;
        return Ok(());
    }
    if let Some(recipient) = msg.recipient {
        let sender_id = msg.sender.to_hex();
        let recipient_id = recipient.to_hex();
        let is_participant = user_id == sender_id || user_id == recipient_id;
        if !is_participant {
            return Err(AccessDeniedReason::NotMember);
        }
        let other = if user_id == sender_id {
            recipient_id
        } else {
            sender_id
        };
        if !are_friends(db, user_id, &other).await {
            return Err(AccessDeniedReason::NotFriends);
        }
        if is_dm_blocked(db, user_id, &other).await {
            return Err(AccessDeniedReason::Blocked);
        }
        return Ok(());
    }
    Err(AccessDeniedReason::NotFound)
}
