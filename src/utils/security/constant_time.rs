pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn constant_time_eq_str(a: &str, b: &str) -> bool {
    a.len() == b.len() && constant_time_eq(a.as_bytes(), b.as_bytes())
}
