use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use uuid::Uuid;

const RINGING_TTL: Duration = Duration::from_secs(60);
const ACCEPTED_TOKEN_WINDOW: Duration = Duration::from_secs(5 * 60);
const PURGE_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallPhase {
    Ringing,
    Accepted,
}

#[derive(Debug, Clone)]
pub struct CallSession {
    pub session_id: String,
    pub caller_id: String,
    pub callee_id: String,
    pub mode: String,
    pub phase: CallPhase,
    pub created_at: Instant,
    pub accepted_at: Option<Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallSessionError {
    NotFound,
    WrongRole,
    InvalidPhase,
    InProgress,
}

fn pair_key(a: &str, b: &str) -> String {
    let mut ids = [a, b];
    ids.sort();
    format!("{}:{}", ids[0], ids[1])
}

static SESSIONS: LazyLock<Mutex<HashMap<String, CallSession>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static LAST_PURGE: LazyLock<Mutex<Instant>> =
    LazyLock::new(|| Mutex::new(Instant::now()));

fn maybe_purge_expired() {
    let mut last = LAST_PURGE.lock().unwrap_or_else(|e| e.into_inner());
    if last.elapsed() < PURGE_INTERVAL {
        return;
    }
    *last = Instant::now();
    drop(last);

    let mut sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    sessions.retain(|_, session| {
        match session.phase {
            CallPhase::Ringing => session.created_at.elapsed() < RINGING_TTL,
            CallPhase::Accepted => session
                .accepted_at
                .map(|t| t.elapsed() < ACCEPTED_TOKEN_WINDOW)
                .unwrap_or(false),
        }
    });
}

pub fn create_ringing_session(caller_id: &str, callee_id: &str, mode: &str) -> Result<String, CallSessionError> {
    maybe_purge_expired();
    let key = pair_key(caller_id, callee_id);
    let mut sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());

    if let Some(existing) = sessions.get(&key) {
        let active = match existing.phase {
            CallPhase::Ringing => existing.created_at.elapsed() < RINGING_TTL,
            CallPhase::Accepted => existing
                .accepted_at
                .map(|t| t.elapsed() < ACCEPTED_TOKEN_WINDOW)
                .unwrap_or(false),
        };
        if active {
            return Err(CallSessionError::InProgress);
        }
        sessions.remove(&key);
    }

    let session_id = Uuid::new_v4().to_string();
    sessions.insert(
        key,
        CallSession {
            session_id: session_id.clone(),
            caller_id: caller_id.to_string(),
            callee_id: callee_id.to_string(),
            mode: mode.to_string(),
            phase: CallPhase::Ringing,
            created_at: Instant::now(),
            accepted_at: None,
        },
    );
    Ok(session_id)
}

pub fn accept_session(callee_id: &str, caller_id: &str) -> Result<CallSession, CallSessionError> {
    maybe_purge_expired();
    let key = pair_key(caller_id, callee_id);
    let mut sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    let Some(session) = sessions.get_mut(&key) else {
        return Err(CallSessionError::NotFound);
    };
    if session.callee_id != callee_id || session.caller_id != caller_id {
        return Err(CallSessionError::WrongRole);
    }
    if session.phase != CallPhase::Ringing || session.created_at.elapsed() >= RINGING_TTL {
        sessions.remove(&key);
        return Err(CallSessionError::InvalidPhase);
    }
    session.phase = CallPhase::Accepted;
    session.accepted_at = Some(Instant::now());
    Ok(session.clone())
}

pub fn reject_session(callee_id: &str, caller_id: &str) -> Result<(), CallSessionError> {
    maybe_purge_expired();
    let key = pair_key(caller_id, callee_id);
    let mut sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    let Some(session) = sessions.get(&key) else {
        return Err(CallSessionError::NotFound);
    };
    if session.callee_id != callee_id || session.caller_id != caller_id {
        return Err(CallSessionError::WrongRole);
    }
    if session.phase != CallPhase::Ringing {
        return Err(CallSessionError::InvalidPhase);
    }
    sessions.remove(&key);
    Ok(())
}

pub fn cancel_session(caller_id: &str, callee_id: &str) -> Result<(), CallSessionError> {
    maybe_purge_expired();
    let key = pair_key(caller_id, callee_id);
    let mut sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    let Some(session) = sessions.get(&key) else {
        return Err(CallSessionError::NotFound);
    };
    if session.caller_id != caller_id || session.callee_id != callee_id {
        return Err(CallSessionError::WrongRole);
    }
    if session.phase != CallPhase::Ringing {
        return Err(CallSessionError::InvalidPhase);
    }
    sessions.remove(&key);
    Ok(())
}

pub fn end_session(user_id: &str, peer_id: &str) -> Result<CallSession, CallSessionError> {
    maybe_purge_expired();
    let key = pair_key(user_id, peer_id);
    let mut sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    let Some(session) = sessions.get(&key) else {
        return Err(CallSessionError::NotFound);
    };
    let is_participant =
        (session.caller_id == user_id && session.callee_id == peer_id)
            || (session.callee_id == user_id && session.caller_id == peer_id);
    if !is_participant {
        return Err(CallSessionError::WrongRole);
    }
    let session = sessions.remove(&key);
    session.ok_or(CallSessionError::NotFound)
}

pub fn token_allowed(user_id: &str, peer_id: &str) -> Result<CallSession, CallSessionError> {
    maybe_purge_expired();
    let key = pair_key(user_id, peer_id);
    let sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    let Some(session) = sessions.get(&key) else {
        return Err(CallSessionError::NotFound);
    };
    let is_participant =
        (session.caller_id == user_id && session.callee_id == peer_id)
            || (session.callee_id == user_id && session.caller_id == peer_id);
    if !is_participant {
        return Err(CallSessionError::WrongRole);
    }
    if session.phase != CallPhase::Accepted {
        return Err(CallSessionError::InvalidPhase);
    }
    let accepted_at = session.accepted_at.ok_or(CallSessionError::InvalidPhase)?;
    if accepted_at.elapsed() >= ACCEPTED_TOKEN_WINDOW {
        return Err(CallSessionError::InvalidPhase);
    }
    Ok(session.clone())
}

pub fn clear_sessions_for_user(user_id: &str) {
    let mut sessions = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
    sessions.retain(|_, session| {
        session.caller_id != user_id && session.callee_id != user_id
    });
}
