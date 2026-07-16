use mongodb::bson::DateTime;

use crate::model::user_model::ListeningActivity;

pub const LISTENING_TTL_MS: i64 = 60_000;

pub fn is_expired(activity: &ListeningActivity) -> bool {
    let now = DateTime::now().timestamp_millis();
    now - activity.updated_at.timestamp_millis() > LISTENING_TTL_MS
}

pub fn client_priority(client_type: &str) -> u8 {
    match client_type {
        "desktop" => 2,
        _ => 1,
    }
}

pub struct ListeningReport {
    pub activity: Option<ListeningActivity>,
    pub client_type: String,
    pub client_instance_id: String,
}

pub fn should_apply_report(
    existing: &Option<ListeningActivity>,
    report: &ListeningReport,
) -> bool {
    if report.activity.is_none() {
        return match existing {
            None => false,
            Some(ex) => {
                ex.client_instance_id == report.client_instance_id
                    || client_priority(&report.client_type) >= client_priority(&ex.client_type)
            }
        };
    }

    let new_act = report.activity.as_ref().expect("activity present");
    match existing {
        None => true,
        Some(ex) => {
            if is_expired(ex) {
                return true;
            }
            let new_pri = client_priority(&new_act.client_type);
            let ex_pri = client_priority(&ex.client_type);
            if new_pri > ex_pri {
                true
            } else if new_pri < ex_pri {
                false
            } else {
                new_act.updated_at.timestamp_millis() >= ex.updated_at.timestamp_millis()
            }
        }
    }
}
