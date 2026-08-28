// clamd.rs
// Klient protokołu clamd INSTREAM (TCP).
// Zakres:
//  - CLAMAV_HOST=host:port; brak zmiennej = fail-closed (brak skanu)
//  - nie VirusTotal — pliki zostają u nas
// StreamMaxLength w clamd.conf musi być >= limitu załącznika.
// Przy zmianach: worker.rs, docker-compose.yml.

use std::env;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const CHUNK: usize = 8192;
const SCAN_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClamVerdict {
    Clean,
    Infected,
}

#[derive(Debug)]
pub enum ClamError {
    Unavailable(String),
    Protocol(String),
}

impl std::fmt::Display for ClamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(msg) => write!(f, "clamd unavailable: {msg}"),
            Self::Protocol(msg) => write!(f, "clamd protocol: {msg}"),
        }
    }
}

pub fn clamd_addr() -> Option<String> {
    let raw = env::var("CLAMAV_HOST").ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

pub fn parse_clamd_response(response: &str) -> Result<ClamVerdict, ClamError> {
    let lower = response.to_ascii_lowercase();
    if lower.contains("found") {
        Ok(ClamVerdict::Infected)
    } else if lower.contains("ok") {
        Ok(ClamVerdict::Clean)
    } else {
        Err(ClamError::Protocol(response.trim().to_string()))
    }
}

pub async fn scan_bytes(data: &[u8]) -> Result<ClamVerdict, ClamError> {
    let Some(addr) = clamd_addr() else {
        return Err(ClamError::Unavailable("CLAMAV_HOST not set".into()));
    };

    let scan = async {
        let mut stream = TcpStream::connect(&addr)
            .await
            .map_err(|e| ClamError::Unavailable(e.to_string()))?;
        stream
            .write_all(b"zINSTREAM\0")
            .await
            .map_err(|e| ClamError::Unavailable(e.to_string()))?;
        for chunk in data.chunks(CHUNK) {
            let len = (chunk.len() as u32).to_be_bytes();
            stream
                .write_all(&len)
                .await
                .map_err(|e| ClamError::Unavailable(e.to_string()))?;
            stream
                .write_all(chunk)
                .await
                .map_err(|e| ClamError::Unavailable(e.to_string()))?;
        }
        stream
            .write_all(&0u32.to_be_bytes())
            .await
            .map_err(|e| ClamError::Unavailable(e.to_string()))?;
        let mut buf = Vec::new();
        stream
            .read_to_end(&mut buf)
            .await
            .map_err(|e| ClamError::Unavailable(e.to_string()))?;
        let response = String::from_utf8_lossy(&buf);
        parse_clamd_response(&response)
    };

    match tokio::time::timeout(SCAN_TIMEOUT, scan).await {
        Ok(result) => result,
        Err(_) => Err(ClamError::Unavailable("scan timed out".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ok_and_found() {
        assert_eq!(
            parse_clamd_response("stream: OK").unwrap(),
            ClamVerdict::Clean
        );
        assert_eq!(
            parse_clamd_response("stream: Eicar-Test-File FOUND").unwrap(),
            ClamVerdict::Infected
        );
        assert!(parse_clamd_response("nope").is_err());
    }
}
