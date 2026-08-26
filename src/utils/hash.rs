// hash.rs
// Skróty i porównania timing-safe.
// Zakres:
//  - ogólne, nie Argon2
//  - ogólne skróty timing-safe; hasła → passwords.rs
// Hasła: crypto/passwords.rs.
// Przy zmianach: fingerprint.rs, token_hash.rs.

use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}
