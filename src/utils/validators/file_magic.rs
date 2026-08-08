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
    // MP4 / M4A (Safari & iOS voice notes): an ISO-BMFF `ftyp` box.
    if data.len() >= 12 && &data[4..8] == b"ftyp" {
        return Some("mp4");
    }
    None
}

pub fn mp4_has_video_track(data: &[u8]) -> bool {
    const VIDEO_CODEC_MARKERS: &[&[u8]] = &[b"avc1", b"hvc1", b"hev1", b"vp09", b"mp4v", b"av01"];
    VIDEO_CODEC_MARKERS
        .iter()
        .any(|marker| data.windows(marker.len()).any(|window| window == *marker))
}

pub fn webm_has_video_track(data: &[u8]) -> bool {
    const VIDEO_CODEC_MARKERS: &[&[u8]] = &[b"V_VP8", b"V_VP9", b"V_AV1", b"V_MPEG", b"V_THEORA"];
    VIDEO_CODEC_MARKERS
        .iter()
        .any(|marker| data.windows(marker.len()).any(|window| window == *marker))
}

fn normalize_mime_type(mime: &str) -> String {
    mime.trim()
        .to_ascii_lowercase()
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_string()
}

pub fn mime_allowed_for_extension(ext: &str, mime: &str) -> bool {
    let ext = ext.to_ascii_lowercase();
    let mime = normalize_mime_type(mime);
    if mime.is_empty() {
        return false;
    }

    match ext.as_str() {
        "pdf" => mime == "application/pdf",
        "jpg" | "jpeg" => mime == "image/jpeg",
        "png" => mime == "image/png",
        "webp" => mime == "image/webp",
        "docx" => {
            mime == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        }
        "xlsx" => mime == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "txt" => mime == "text/plain",
        "webm" => mime == "audio/webm" || mime == "video/webm",
        "ogg" => mime == "audio/ogg" || mime == "video/ogg" || mime == "application/ogg",
        "wav" => {
            matches!(
                mime.as_str(),
                "audio/wav" | "audio/x-wav" | "audio/wave" | "audio/vnd.wave"
            )
        }
        "mp4" => {
            matches!(
                mime.as_str(),
                "audio/mp4" | "audio/aac" | "audio/x-m4a" | "video/mp4" | "video/quicktime"
                    | "application/mp4" | "application/octet-stream"
            )
        }
        "m4a" => {
            matches!(
                mime.as_str(),
                "audio/mp4" | "audio/aac" | "audio/x-m4a" | "video/mp4"
            )
        }
        _ => false,
    }
}

pub fn resolve_upload_content_type(ext: &str, client_mime: Option<&str>, data: &[u8]) -> String {
    if let Some(mime) = client_mime {
        if mime_allowed_for_extension(ext, mime) {
            return normalize_mime_type(mime);
        }
    }

    match ext.to_ascii_lowercase().as_str() {
        "webm" if webm_has_video_track(data) => "video/webm".to_string(),
        "mp4" if mp4_has_video_track(data) => "video/mp4".to_string(),
        "mp4" => "audio/mp4".to_string(),
        "m4a" => "audio/mp4".to_string(),
        other => crate::utils::storage::content_type_for_ext(other).to_string(),
    }
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
        "mp4" | "m4a" => detect_audio_type(&data) == Some("mp4"),
        _ => false,
    }
}
