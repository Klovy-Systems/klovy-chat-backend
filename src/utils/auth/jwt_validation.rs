use jsonwebtoken::{Algorithm, Header, Validation};

pub const JWT_ISSUER: &str = "klovy-chat";
pub const JWT_AUDIENCE: &str = "klovy-chat-api";

const JWT_CLOCK_SKEW_SECS: u64 = 60;

pub fn hs256_validation() -> Validation {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.leeway = JWT_CLOCK_SKEW_SECS;
    validation.set_issuer(&[JWT_ISSUER]);
    validation.set_audience(&[JWT_AUDIENCE]);
    validation
}

pub fn hs256_header() -> Header {
    Header::new(Algorithm::HS256)
}
