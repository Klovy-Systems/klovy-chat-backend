// monitor.rs
// Raport floodu na webhook (SECURITY_REPORT_SECRET).
// Zakres:
//  - nie PII treści
//  - webhook floodu; bez PII treści; brak sekretu = log
// Brak sekretu = tylko log.
// Przy zmianach: ip_block.rs, config.rs.

use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

static WEBHOOK_COOLDOWN: LazyLock<Mutex<HashMap<String, Instant>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
const WEBHOOK_COOLDOWN_SECS: u64 = 15 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecurityEventType {
    LoginFailures,
    SuspiciousRequests,
    BlockedRequests,
    AuthFailure,
}

impl SecurityEventType {
    fn as_str(&self) -> &'static str {
        match self {
            Self::LoginFailures => "loginFailures",
            Self::SuspiciousRequests => "suspiciousRequests",
            Self::BlockedRequests => "blockedRequests",
            Self::AuthFailure => "authFailure",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub timestamp: String,
    #[serde(flatten)]
    pub details: Value,
}

pub struct SecurityMonitor {
    events: Mutex<Vec<SecurityEvent>>,
    max_events: usize,
    alert_thresholds: HashMap<&'static str, usize>,
}

impl SecurityMonitor {
    pub fn new() -> Self {
        let mut alert_thresholds = HashMap::new();
        alert_thresholds.insert("loginFailures", 10);
        alert_thresholds.insert("suspiciousRequests", 20);
        alert_thresholds.insert("blockedRequests", 5);

        Self {
            events: Mutex::new(Vec::new()),
            max_events: 1000,
            alert_thresholds,
        }
    }

    pub fn log_event(&self, event_type: SecurityEventType, details: Value) {
        let event = SecurityEvent {
            event_type: event_type.as_str().to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            details,
        };

        {
            let mut events = self.events.lock().unwrap_or_else(|e| e.into_inner());
            events.push(event);
            if events.len() > self.max_events {
                events.remove(0);
            }
        }

        self.check_alerts();
    }

    fn recent_counts(&self, window_ms: i64) -> HashMap<String, usize> {
        let cutoff = chrono::Utc::now() - chrono::Duration::milliseconds(window_ms);
        let events = self.events.lock().unwrap_or_else(|e| e.into_inner());
        let mut counts: HashMap<String, usize> = HashMap::new();
        for ev in events.iter() {
            if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(&ev.timestamp) {
                if ts.with_timezone(&chrono::Utc) > cutoff {
                    *counts.entry(ev.event_type.clone()).or_insert(0) += 1;
                }
            }
        }
        counts
    }

    fn check_alerts(&self) {
        let counts = self.recent_counts(15 * 60 * 1000);
        for (event_type, threshold) in &self.alert_thresholds {
            let count = counts.get(*event_type).copied().unwrap_or(0);
            if count >= *threshold {
                log::error!(
                    "SECURITY ALERT: {count} {event_type} events detected (threshold: {threshold})"
                );
                Self::notify_webhook(event_type, count, *threshold);
            }
        }
    }

    fn should_send_webhook(event_type: &str) -> bool {
        let now = Instant::now();
        let mut map = WEBHOOK_COOLDOWN.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(last) = map.get(event_type) {
            if now.duration_since(*last) < Duration::from_secs(WEBHOOK_COOLDOWN_SECS) {
                return false;
            }
        }
        map.insert(event_type.to_string(), now);
        true
    }

    fn notify_webhook(event_type: &str, count: usize, threshold: usize) {
        if !Self::should_send_webhook(event_type) {
            return;
        }
        let Some(url) = crate::utils::security::urls::resolve_security_webhook_url() else {
            return;
        };
        let payload = json!({
            "source": "klovy-chat",
            "eventType": event_type,
            "count": count,
            "threshold": threshold,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        tokio::spawn(async move {
            if let Err(e) = reqwest::Client::new()
                .post(&url)
                .json(&payload)
                .timeout(std::time::Duration::from_secs(10))
                .send()
                .await
            {
                log::warn!("Failed to deliver security webhook: {e}");
            }
        });
    }

    pub fn get_security_report(&self) -> Value {
        let counts = self.recent_counts(24 * 60 * 60 * 1000);
        let events = self.events.lock().unwrap_or_else(|e| e.into_inner());
        let last_events: Vec<&SecurityEvent> = events.iter().rev().take(10).collect();
        let total: usize = counts.values().sum();

        json!({
            "totalEvents": total,
            "eventTypes": counts,
            "lastEvents": last_events,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        })
    }
}

impl Default for SecurityMonitor {
    fn default() -> Self {
        Self::new()
    }
}
