use serde_json::{json, Value};

use crate::model::user_model::{User, UserRole};

use super::admin_session::{user_id_is_env_root, user_is_root};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PanelPermission {
    AccessPanel,
    SupportTickets,
    ViewUsers,
    WarnUser,
    DeleteWarning,
    BanUser,
    DeleteUser,
    ResetPassword,
    ManageWhitelist,
    ViewChannels,
    DeleteChannel,
    ViewReports,
    ManageReports,
    ViewBadges,
    ManageBadges,
    ManageAnnouncements,
    ManageRoles,
}

pub fn effective_role(user: &User) -> UserRole {
    if user_is_root(user) {
        return UserRole::Root;
    }
    if user.legacy_is_admin && user.role == UserRole::User {
        return UserRole::Admin;
    }
    user.role.clone()
}

pub fn user_has_panel_access(user: &User) -> bool {
    effective_role(user) != UserRole::User
}

pub fn user_can_manage_panel_roles(user: &User) -> bool {
    effective_role(user) == UserRole::Root
}

pub fn panel_role_label(user: &User) -> Option<&'static str> {
    match effective_role(user) {
        UserRole::Root => Some("root"),
        UserRole::Admin => Some("admin"),
        UserRole::Moderator => Some("moderator"),
        UserRole::Support => Some("support"),
        UserRole::User => None,
    }
}

pub fn user_has_permission(user: &User, permission: PanelPermission) -> bool {
    role_has_permission(effective_role(user), permission)
}

pub fn role_has_permission(role: UserRole, permission: PanelPermission) -> bool {
    use PanelPermission::*;
    use UserRole::*;

    match permission {
        AccessPanel => role >= Support,
        // support + moderator + admin + root (aligned with dashboard role matrix)
        SupportTickets => role >= Support,
        ViewUsers => role >= Support,
        WarnUser | DeleteWarning => role >= Moderator,
        BanUser | DeleteUser | ResetPassword | ManageWhitelist => role >= Admin,
        ViewChannels => role >= Moderator,
        DeleteChannel => role >= Admin,
        ViewReports => role >= Moderator,
        ManageReports => role >= Admin,
        ViewBadges => role >= Moderator,
        ManageBadges | ManageAnnouncements => role >= Admin,
        ManageRoles => role == Root,
    }
}

pub fn permissions_for_user(user: &User) -> Vec<&'static str> {
    const ALL: [PanelPermission; 17] = [
        PanelPermission::AccessPanel,
        PanelPermission::SupportTickets,
        PanelPermission::ViewUsers,
        PanelPermission::WarnUser,
        PanelPermission::DeleteWarning,
        PanelPermission::BanUser,
        PanelPermission::DeleteUser,
        PanelPermission::ResetPassword,
        PanelPermission::ManageWhitelist,
        PanelPermission::ViewChannels,
        PanelPermission::DeleteChannel,
        PanelPermission::ViewReports,
        PanelPermission::ManageReports,
        PanelPermission::ViewBadges,
        PanelPermission::ManageBadges,
        PanelPermission::ManageAnnouncements,
        PanelPermission::ManageRoles,
    ];

    ALL.iter()
        .filter(|perm| user_has_permission(user, **perm))
        .map(|perm| permission_key(*perm))
        .collect()
}

pub fn permission_key(permission: PanelPermission) -> &'static str {
    match permission {
        PanelPermission::AccessPanel => "access_panel",
        PanelPermission::SupportTickets => "support_tickets",
        PanelPermission::ViewUsers => "view_users",
        PanelPermission::WarnUser => "warn_user",
        PanelPermission::DeleteWarning => "delete_warning",
        PanelPermission::BanUser => "ban_user",
        PanelPermission::DeleteUser => "delete_user",
        PanelPermission::ResetPassword => "reset_password",
        PanelPermission::ManageWhitelist => "manage_whitelist",
        PanelPermission::ViewChannels => "view_channels",
        PanelPermission::DeleteChannel => "delete_channel",
        PanelPermission::ViewReports => "view_reports",
        PanelPermission::ManageReports => "manage_reports",
        PanelPermission::ViewBadges => "view_badges",
        PanelPermission::ManageBadges => "manage_badges",
        PanelPermission::ManageAnnouncements => "manage_announcements",
        PanelPermission::ManageRoles => "manage_roles",
    }
}

pub fn parse_assignable_role(raw: &str) -> Result<UserRole, &'static str> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "user" => Ok(UserRole::User),
        "support" => Ok(UserRole::Support),
        "moderator" => Ok(UserRole::Moderator),
        "admin" => Ok(UserRole::Admin),
        _ => Err("Nieprawidłowa rola. Dozwolone: user, support, moderator, admin."),
    }
}

pub fn role_to_bson(role: &UserRole) -> mongodb::bson::Bson {
    let value = match role {
        UserRole::User => "user",
        UserRole::Support => "support",
        UserRole::Moderator => "moderator",
        UserRole::Admin => "admin",
        UserRole::Root => "root",
    };
    mongodb::bson::Bson::String(value.to_string())
}

/// Staff accounts with equal or higher rank cannot be moderated by the actor.
pub fn actor_can_moderate_target(actor: &User, target: &User) -> bool {
    if user_is_root(target) {
        return false;
    }
    let actor_role = effective_role(actor);
    let target_role = effective_role(target);
    if target_role == UserRole::User {
        return true;
    }
    actor_role > target_role
}

pub fn permissions_json(user: &User) -> Value {
    json!(permissions_for_user(user))
}

pub fn env_root_user_id(user_id: &str) -> bool {
    user_id_is_env_root(user_id)
}
