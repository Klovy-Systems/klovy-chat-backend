use std::io::Cursor;
use std::path::Path;

use image::codecs::webp::WebPEncoder;
use image::GenericImageView;
use image::ImageEncoder;

#[derive(Debug)]
pub enum ImageReencodeError {
    DecodeFailed,
    DimensionTooLarge,
    EncodeFailed,
    IoFailed,
}

impl std::fmt::Display for ImageReencodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DecodeFailed => write!(f, "Failed to decode image"),
            Self::DimensionTooLarge => write!(f, "Image dimensions too large"),
            Self::EncodeFailed => write!(f, "Failed to encode image"),
            Self::IoFailed => write!(f, "Failed to read or write image file"),
        }
    }
}

impl std::error::Error for ImageReencodeError {}

pub fn reencode_error_message(err: &ImageReencodeError) -> &'static str {
    match err {
        ImageReencodeError::DimensionTooLarge => {
            "Image dimensions too large. Maximum size is 4096×4096 pixels."
        }
        _ => "Invalid image file.",
    }
}

fn read_image_dimensions(bytes: &[u8]) -> Result<(u32, u32), ImageReencodeError> {
    image::ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|_| ImageReencodeError::DecodeFailed)?
        .into_dimensions()
        .map_err(|_| ImageReencodeError::DecodeFailed)
}

fn ensure_dimensions_ok(width: u32, height: u32) -> Result<(), ImageReencodeError> {
    let max = crate::utils::upload_limits::MAX_IMAGE_DIMENSION;
    if width == 0 || height == 0 || width > max || height > max {
        return Err(ImageReencodeError::DimensionTooLarge);
    }
    Ok(())
}

fn reencode_decoded_image(img: image::DynamicImage) -> Result<Vec<u8>, ImageReencodeError> {
    let (width, height) = img.dimensions();
    ensure_dimensions_ok(width, height)?;
    let rgba = img.to_rgba8();

    let mut out = Vec::new();
    WebPEncoder::new_lossless(&mut out)
        .write_image(rgba.as_raw(), width, height, image::ExtendedColorType::Rgba8)
        .map_err(|_| ImageReencodeError::EncodeFailed)?;

    Ok(out)
}

/// Decode an uploaded image and re-encode it as WebP to strip embedded payloads.
pub fn reencode_upload_to_webp(source: &Path) -> Result<Vec<u8>, ImageReencodeError> {
    let bytes = std::fs::read(source).map_err(|_| ImageReencodeError::IoFailed)?;
    let (width, height) = read_image_dimensions(&bytes)?;
    ensure_dimensions_ok(width, height)?;
    let img = image::load_from_memory(&bytes).map_err(|_| ImageReencodeError::DecodeFailed)?;
    reencode_decoded_image(img)
}
