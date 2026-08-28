//! Shared provider-input media normalization (DR-0080).
//!
//! Surfaces supply already-authorized bytes plus provenance. This module owns
//! the deterministic representation sent to model adapters; it does not resolve
//! paths, handles, credentials, or any other ambient authority.

use std::io::Cursor;

use image::ImageFormat;
use office_oxide::{Document, DocumentFormat};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::harness_loop::{ImageBlock, LoopObservation, MediaInput};

const MAX_MEDIA_BYTES: usize = 25 * 1024 * 1024;
const MAX_IMAGE_PIXELS: u64 = 40_000_000;
const MAX_DOCUMENT_TEXT_BYTES: usize = 200_000;
const MAX_OFFICE_EXPANDED_BYTES: u64 = 100 * 1024 * 1024;
const MAX_OFFICE_PARTS: usize = 10_000;

/// Provider-neutral output consumed by `agent.tell`, `coerce`, and `prompt`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NormalizedProviderInput {
    pub images: Vec<ImageBlock>,
    /// Provenance-wrapped document derivatives and explicit unsupported items.
    pub text_parts: Vec<String>,
    pub observations: Vec<LoopObservation>,
}

#[derive(Serialize)]
struct DocumentPart<'a> {
    kind: &'static str,
    artifact_ref: &'a str,
    original_media_type: &'a str,
    normalization: &'static str,
    text: &'a str,
}

#[derive(Serialize)]
struct UnsupportedPart<'a> {
    kind: &'static str,
    artifact_ref: &'a str,
    original_media_type: &'a str,
    normalization: &'static str,
    reason: &'a str,
}

/// Normalize already-resolved media without surface-specific policy.
pub fn normalize_provider_media(media: &[MediaInput]) -> NormalizedProviderInput {
    let mut output = NormalizedProviderInput::default();
    for item in media {
        normalize_one(item, &mut output);
    }
    output
}

fn normalize_one(item: &MediaInput, output: &mut NormalizedProviderInput) {
    let Some(encoded) = item.data_base64.as_deref().filter(|data| !data.is_empty()) else {
        push_unsupported(item, "media body is unavailable", output);
        return;
    };
    let Some(bytes) = crate::exec_http::base64_decode(encoded) else {
        push_unsupported(item, "media body is not valid base64", output);
        return;
    };
    if bytes.len() > MAX_MEDIA_BYTES {
        push_unsupported(
            item,
            "media body exceeds the 25 MiB normalization limit",
            output,
        );
        return;
    }

    match item.media_type.as_str() {
        "image/png" | "image/jpeg" | "image/webp" | "image/gif" => {
            push_image(
                item,
                &bytes,
                item.media_type.clone(),
                encoded.to_owned(),
                "provider_image",
                output,
            );
        }
        media_type if image_format(media_type).is_some() => {
            let Some(format) = image_format(media_type) else {
                push_unsupported(item, "image format classifier failed", output);
                return;
            };
            match convert_image_to_png(&bytes, format) {
                Ok(png) => {
                    let encoded = crate::exec_http::base64_encode(&png);
                    push_image(
                        item,
                        &png,
                        "image/png".to_owned(),
                        encoded,
                        "image_to_png",
                        output,
                    );
                }
                Err(reason) => push_unsupported(item, &reason, output),
            }
        }
        "application/pdf" => match extract_pdf(&bytes) {
            Ok(text) => push_document(item, &text, "pdf_to_text", output),
            Err(reason) => push_unsupported(item, &reason, output),
        },
        media_type if office_format(media_type).is_some() => {
            let Some(format) = office_format(media_type) else {
                push_unsupported(item, "Office format classifier failed", output);
                return;
            };
            match extract_office(&bytes, format) {
                Ok(text) => push_document(item, &text, "office_to_text", output),
                Err(reason) => push_unsupported(item, &reason, output),
            }
        }
        media_type if media_type.starts_with("audio/") => {
            push_unsupported(item, "audio input is unsupported", output)
        }
        media_type if media_type.starts_with("video/") => {
            push_unsupported(item, "video input is unsupported", output)
        }
        "" => push_unsupported(item, "media type is missing", output),
        _ => push_unsupported(
            item,
            "media type has no admitted provider representation",
            output,
        ),
    }
}

fn push_image(
    item: &MediaInput,
    derivative: &[u8],
    media_type: String,
    data_base64: String,
    normalization: &str,
    output: &mut NormalizedProviderInput,
) {
    output.images.push(ImageBlock {
        media_type,
        data_base64,
    });
    output.observations.push(LoopObservation::MediaNormalized {
        artifact_ref: item.artifact_ref.clone(),
        media_type: item.media_type.clone(),
        normalization: normalization.to_owned(),
        derivative_hash: Some(hash_bytes(derivative)),
    });
}

fn push_document(
    item: &MediaInput,
    text: &str,
    normalization: &'static str,
    output: &mut NormalizedProviderInput,
) {
    let text = bounded_text(text);
    if text.trim().is_empty() {
        push_unsupported(item, "document contains no extractable text", output);
        return;
    }
    let part = DocumentPart {
        kind: "document_derivative",
        artifact_ref: &item.artifact_ref,
        original_media_type: &item.media_type,
        normalization,
        text: &text,
    };
    let rendered = serde_json::to_string(&part).unwrap_or_else(|_| {
        "{\"kind\":\"unsupported_media\",\"reason\":\"document derivative serialization failed\"}".to_owned()
    });
    output
        .text_parts
        .push(format!("[Document derivative]\n{rendered}"));
    output.observations.push(LoopObservation::MediaNormalized {
        artifact_ref: item.artifact_ref.clone(),
        media_type: item.media_type.clone(),
        normalization: normalization.to_owned(),
        derivative_hash: Some(hash_bytes(rendered.as_bytes())),
    });
}

fn push_unsupported(item: &MediaInput, reason: &str, output: &mut NormalizedProviderInput) {
    let part = UnsupportedPart {
        kind: "unsupported_media",
        artifact_ref: &item.artifact_ref,
        original_media_type: if item.media_type.is_empty() {
            "unknown"
        } else {
            &item.media_type
        },
        normalization: "unsupported_explicit",
        reason,
    };
    let rendered = serde_json::to_string(&part).unwrap_or_else(|_| {
        "{\"kind\":\"unsupported_media\",\"reason\":\"media notice serialization failed\"}"
            .to_owned()
    });
    output
        .text_parts
        .push(format!("[Unsupported media]\n{rendered}"));
    output.observations.push(LoopObservation::MediaNormalized {
        artifact_ref: item.artifact_ref.clone(),
        media_type: item.media_type.clone(),
        normalization: "unsupported_explicit".to_owned(),
        derivative_hash: None,
    });
}

fn image_format(media_type: &str) -> Option<ImageFormat> {
    match media_type {
        "image/bmp" | "image/x-ms-bmp" => Some(ImageFormat::Bmp),
        "image/tiff" => Some(ImageFormat::Tiff),
        "image/x-icon" | "image/vnd.microsoft.icon" => Some(ImageFormat::Ico),
        "image/x-portable-anymap"
        | "image/x-portable-bitmap"
        | "image/x-portable-graymap"
        | "image/x-portable-pixmap" => Some(ImageFormat::Pnm),
        "image/x-tga" | "image/tga" => Some(ImageFormat::Tga),
        "image/qoi" => Some(ImageFormat::Qoi),
        _ => None,
    }
}

fn convert_image_to_png(bytes: &[u8], format: ImageFormat) -> Result<Vec<u8>, String> {
    let image = image::load_from_memory_with_format(bytes, format)
        .map_err(|error| format!("image conversion failed: {error}"))?;
    if u64::from(image.width()).saturating_mul(u64::from(image.height())) > MAX_IMAGE_PIXELS {
        return Err("image exceeds the 40 megapixel normalization limit".to_owned());
    }
    let mut png = Cursor::new(Vec::new());
    image
        .write_to(&mut png, ImageFormat::Png)
        .map_err(|error| format!("PNG encoding failed: {error}"))?;
    Ok(png.into_inner())
}

fn office_format(media_type: &str) -> Option<DocumentFormat> {
    match media_type {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => {
            Some(DocumentFormat::Docx)
        }
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => {
            Some(DocumentFormat::Xlsx)
        }
        "application/vnd.openxmlformats-officedocument.presentationml.presentation" => {
            Some(DocumentFormat::Pptx)
        }
        "application/msword" => Some(DocumentFormat::Doc),
        "application/vnd.ms-excel" => Some(DocumentFormat::Xls),
        "application/vnd.ms-powerpoint" => Some(DocumentFormat::Ppt),
        _ => None,
    }
}

fn extract_pdf(bytes: &[u8]) -> Result<String, String> {
    std::panic::catch_unwind(|| pdf_extract::extract_text_from_mem(bytes))
        .map_err(|_| "PDF text extraction failed: parser panicked".to_owned())?
        .map_err(|error| format!("PDF text extraction failed: {error}"))
}

fn extract_office(bytes: &[u8], format: DocumentFormat) -> Result<String, String> {
    if matches!(
        format,
        DocumentFormat::Docx | DocumentFormat::Xlsx | DocumentFormat::Pptx
    ) {
        preflight_ooxml(bytes)?;
    }
    let document =
        std::panic::catch_unwind(|| Document::from_reader(Cursor::new(bytes.to_vec()), format))
            .map_err(|_| "Office text extraction failed: parser panicked".to_owned())?
            .map_err(|error| format!("Office text extraction failed: {error}"))?;
    Ok(document.to_markdown())
}

fn preflight_ooxml(bytes: &[u8]) -> Result<(), String> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|error| format!("Office container inspection failed: {error}"))?;
    if archive.len() > MAX_OFFICE_PARTS {
        return Err("Office document has too many package parts".to_owned());
    }
    let mut expanded = 0_u64;
    for index in 0..archive.len() {
        let part = archive
            .by_index(index)
            .map_err(|error| format!("Office package part is unreadable: {error}"))?;
        expanded = expanded.saturating_add(part.size());
        if expanded > MAX_OFFICE_EXPANDED_BYTES {
            return Err("Office document exceeds the 100 MiB expanded-size limit".to_owned());
        }
    }
    Ok(())
}

fn bounded_text(text: &str) -> String {
    if text.len() <= MAX_DOCUMENT_TEXT_BYTES {
        return text.to_owned();
    }
    let mut end = MAX_DOCUMENT_TEXT_BYTES;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!(
        "{}\n[Document derivative truncated after {end} of {} UTF-8 bytes]",
        &text[..end],
        text.len()
    )
}

fn hash_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(7 + digest.len() * 2);
    hex.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn input(media_type: &str, bytes: &[u8]) -> MediaInput {
        MediaInput {
            artifact_ref: "artifact:test".to_owned(),
            media_type: media_type.to_owned(),
            data_base64: Some(crate::exec_http::base64_encode(bytes)),
            metadata: BTreeMap::new(),
        }
    }

    fn text_pdf(text: &str) -> Vec<u8> {
        let stream = format!("BT /F1 12 Tf 72 720 Td ({text}) Tj ET");
        let objects = [
            "<< /Type /Catalog /Pages 2 0 R >>".to_owned(),
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned(),
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>".to_owned(),
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_owned(),
            format!("<< /Length {} >>\nstream\n{stream}\nendstream", stream.len()),
        ];
        let mut pdf = "%PDF-1.4\n".to_owned();
        let mut offsets = Vec::new();
        for (index, object) in objects.iter().enumerate() {
            offsets.push(pdf.len());
            pdf.push_str(&format!("{} 0 obj\n{object}\nendobj\n", index + 1));
        }
        let xref = pdf.len();
        pdf.push_str("xref\n0 6\n0000000000 65535 f \n");
        for offset in offsets {
            pdf.push_str(&format!("{offset:010} 00000 n \n"));
        }
        pdf.push_str(&format!(
            "trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n"
        ));
        pdf.into_bytes()
    }

    #[test]
    fn audio_and_video_are_explicit_not_erased() {
        let normalized =
            normalize_provider_media(&[input("audio/wav", b"audio"), input("video/mp4", b"video")]);
        assert!(normalized.images.is_empty());
        assert_eq!(normalized.text_parts.len(), 2);
        assert!(normalized.text_parts[0].contains("audio input is unsupported"));
        assert!(normalized.text_parts[1].contains("video input is unsupported"));
    }

    #[test]
    fn bmp_becomes_png_with_derivative_provenance() {
        let source = image::DynamicImage::new_rgb8(2, 2);
        let mut bmp = Cursor::new(Vec::new());
        source
            .write_to(&mut bmp, ImageFormat::Bmp)
            .expect("encode BMP");
        let normalized = normalize_provider_media(&[input("image/bmp", &bmp.into_inner())]);
        assert_eq!(normalized.images.len(), 1);
        assert_eq!(normalized.images[0].media_type, "image/png");
        assert!(matches!(
            &normalized.observations[0],
            LoopObservation::MediaNormalized { normalization, derivative_hash: Some(_), .. }
                if normalization == "image_to_png"
        ));
    }

    #[test]
    fn docx_becomes_a_provenance_wrapped_text_derivative() {
        let mut bytes = Cursor::new(Vec::new());
        office_oxide::create::create_from_markdown_to_writer(
            "# Inspection\n\nBearing temperature is nominal.",
            DocumentFormat::Docx,
            &mut bytes,
        )
        .expect("create DOCX fixture");
        let normalized = normalize_provider_media(&[input(
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            &bytes.into_inner(),
        )]);
        assert!(normalized.images.is_empty());
        assert_eq!(normalized.text_parts.len(), 1);
        assert!(normalized.text_parts[0].contains("document_derivative"));
        assert!(normalized.text_parts[0].contains("Bearing temperature is nominal"));
        assert!(matches!(
            &normalized.observations[0],
            LoopObservation::MediaNormalized { normalization, derivative_hash: Some(_), .. }
                if normalization == "office_to_text"
        ));
    }

    #[test]
    fn pdf_becomes_a_provenance_wrapped_text_derivative() {
        let normalized =
            normalize_provider_media(&[input("application/pdf", &text_pdf("Whipple PDF text"))]);
        assert!(normalized.images.is_empty());
        assert_eq!(normalized.text_parts.len(), 1);
        assert!(normalized.text_parts[0].contains("Whipple PDF text"));
        assert!(matches!(
            &normalized.observations[0],
            LoopObservation::MediaNormalized { normalization, derivative_hash: Some(_), .. }
                if normalization == "pdf_to_text"
        ));
    }
}
