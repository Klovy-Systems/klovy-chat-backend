use std::fs::File;
use std::io::Read;
use std::path::Path;

fn detect_image_type(data: &[u8]) -> Option<&'static str> {
    if data.starts_with(b"\xff\xd8\xff") {
        return Some("jpeg");
    }
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some("png");
    }
    if data.len() >= 12 && &data[0..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        return Some("webp");
    }
    if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        return Some("gif");
    }
    None
}

fn read_header(path: &Path) -> Option<Vec<u8>> {
    let mut file = File::open(path).ok()?;
    let mut buf = [0u8; 512];
    let n = file.read(&mut buf).ok()?;
    Some(buf[..n].to_vec())
}

fn detect_audio_type(data: &[u8]) -> Option<&'static str> {
    if data.starts_with(b"OggS") {
        return Some("ogg");
    }
    if data.starts_with(b"\x1a\x45\xdf\xa3") {
        return Some("webm");
    }
    if data.len() >= 12 && data.starts_with(b"RIFF") && &data[8..12] == b"WAVE" {
        return Some("wav");
    }
    None
}

pub fn validate_file_magic(path: &Path, ext: &str) -> bool {
    let Some(data) = read_header(path) else {
        return false;
    };

    match ext.to_ascii_lowercase().as_str() {
        "jpg" | "jpeg" => detect_image_type(&data) == Some("jpeg"),
        "png" => detect_image_type(&data) == Some("png"),
        "webp" => detect_image_type(&data) == Some("webp"),
        "gif" => detect_image_type(&data) == Some("gif"),
        "pdf" => data.starts_with(b"%PDF"),
        "txt" => !data.contains(&0),
        "docx" | "xlsx" => data.starts_with(b"PK\x03\x04"),
        "webm" | "ogg" | "wav" => detect_audio_type(&data) == Some(ext),
        _ => false,
    }
}
