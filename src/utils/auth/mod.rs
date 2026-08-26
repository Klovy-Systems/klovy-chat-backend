// mod.rs
// Reeksport JWT, sesji, 2FA, tokenów.
// Zakres:
//  - warstwa auth
//  - nowy mechanizm logowania = podmoduł tutaj
// Nowy mechanizm logowania: podmoduł tutaj.
// Przy zmianach: controllers/auth.rs.

pub mod jwt;
pub mod validation;
pub mod refresh;
pub mod client;
pub mod user_agent;
pub mod session;
pub mod fingerprint;
pub mod metadata;
pub mod step_up;
pub mod tokens;
pub mod totp;
pub mod two_factor;
