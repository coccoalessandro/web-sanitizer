//! Active document inspection and DoS image bomb detection.
//!
//! Mitigates:
//! - Active code embedded in documents (JavaScript in PDF or SVG files).
//! - XML entity bombs ("Billion Laughs" attack) in SVG/XML assets.
//! - Image decompression bombs (pixel flood attacks in PNG, JPEG, GIF, and WebP).

use crate::policy::Policy;
use crate::report::SanitizationAction;

/// Result of inspecting an active document (PDF, SVG).
#[derive(Debug, Clone)]
pub struct ActiveContentCheckResult {
    /// Whether dangerous active content or DoS bombs were detected.
    pub is_threat_detected: bool,
    /// Detailed descriptions of detected threats.
    pub threats: Vec<String>,
}

/// Inspects PDF bytes for active content vectors such as JavaScript or execution launches.
pub fn inspect_pdf(data: &[u8]) -> ActiveContentCheckResult {
    let mut threats = Vec::new();

    // Fast check: verify PDF signature
    if !data.starts_with(b"%PDF-") {
        return ActiveContentCheckResult {
            is_threat_detected: false,
            threats,
        };
    }

    // Convert bytes lossily to string to search for standard PDF active markers
    let text = String::from_utf8_lossy(data);

    let dangerous_tokens = [
        ("/JavaScript", "Embedded PDF JavaScript action"),
        ("/JS", "Abbreviated PDF JavaScript action"),
        ("/Launch", "PDF OS process launch action"),
        ("/OpenAction", "PDF automatic execution on document open"),
        ("/EmbeddedFiles", "Hidden executable attachment in PDF"),
        ("/AcroForm", "Dynamic active form in PDF"),
    ];

    for (token, desc) in &dangerous_tokens {
        if text.contains(token) {
            threats.push(format!("{}: matched marker '{}'", desc, token));
        }
    }

    let is_threat_detected = !threats.is_empty();
    ActiveContentCheckResult {
        is_threat_detected,
        threats,
    }
}

/// Inspects and sanitizes SVG bytes, stripping `<script>`, inline event handlers, and XML entity bombs.
pub fn inspect_and_sanitize_svg(
    svg_data: &[u8],
    policy: &Policy,
) -> (Vec<u8>, Vec<SanitizationAction>, bool) {
    let mut actions = Vec::new();
    let mut blocked = false;

    let text = String::from_utf8_lossy(svg_data);

    // 1. XML Entity Bomb (Billion Laughs) check
    if text.contains("<!ENTITY") {
        // Count entity declarations or detect recursive references
        let entity_count = text.matches("<!ENTITY").count();
        if entity_count > 5 || text.contains("&lol;") || text.contains("&entity") {
            actions.push(SanitizationAction {
                rule_fired: "XML Entity Bomb / XXE mitigation".to_string(),
                location: (0, 0),
                original_fragment: "<!ENTITY...>".to_string(),
                replaced_fragment: "Blocked entity expansion".to_string(),
            });
            blocked = true;
            return (Vec::new(), actions, blocked);
        }
    }

    // 2. Active content in SVG: scripts, onload, etc.
    let dangerous_svg_tokens = [
        ("<script", "SVG script element"),
        ("onload=", "SVG onload handler"),
        ("onerror=", "SVG onerror handler"),
        ("onclick=", "SVG onclick handler"),
        ("onmouseover=", "SVG onmouseover handler"),
        ("xlink:href=\"javascript:", "SVG javascript link"),
        ("href=\"javascript:", "SVG javascript link"),
        ("<foreignobject", "SVG foreignObject container"),
    ];

    let mut sanitized_text = text.to_string();
    let lower = text.to_ascii_lowercase();

    for (token, desc) in &dangerous_svg_tokens {
        if lower.contains(token) {
            actions.push(SanitizationAction {
                rule_fired: format!("Active SVG vector blocked: {}", desc),
                location: (0, 0),
                original_fragment: token.to_string(),
                replaced_fragment: "Removed active SVG construct".to_string(),
            });

            if !policy.html.rewrite_active_content {
                blocked = true;
            }
        }
    }

    if blocked {
        return (Vec::new(), actions, true);
    }

    // Rewrite/sanitize simple SVG script blocks if rewriting is allowed
    if sanitized_text.contains("<script") {
        while let Some(start) = sanitized_text.to_ascii_lowercase().find("<script") {
            if let Some(end) = sanitized_text.to_ascii_lowercase()[start..].find("</script>") {
                let full_end = start + end + 9;
                sanitized_text.replace_range(start..full_end, "<!-- script removed -->");
            } else {
                sanitized_text.replace_range(start.., "");
                break;
            }
        }
    }

    (sanitized_text.into_bytes(), actions, false)
}

/// Parses the image header to extract `(width, height)` and verifies it does not exceed `max_pixels`.
///
/// Prevents image decompression bombs (pixel flood attacks) in PNG, GIF, JPEG, and WebP.
pub fn check_image_dimensions(data: &[u8], max_pixels: usize) -> Result<(u32, u32), String> {
    if data.len() < 8 {
        return Err("Payload too small to be a valid image".to_string());
    }

    // 1. PNG: 8-byte signature, followed by 4-byte chunk len, 4-byte 'IHDR', 4-byte width, 4-byte height
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        if data.len() < 24 {
            return Err("Truncated PNG header".to_string());
        }
        let chunk_type = &data[12..16];
        if chunk_type != b"IHDR" {
            return Err("Invalid PNG: first chunk must be IHDR".to_string());
        }
        let width = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
        let height = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
        validate_dimensions(width, height, max_pixels)?;
        return Ok((width, height));
    }

    // 2. GIF: GIF87a or GIF89a
    if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        if data.len() < 10 {
            return Err("Truncated GIF header".to_string());
        }
        let width = u16::from_le_bytes([data[6], data[7]]) as u32;
        let height = u16::from_le_bytes([data[8], data[9]]) as u32;
        validate_dimensions(width, height, max_pixels)?;
        return Ok((width, height));
    }

    // 3. JPEG: Starts with 0xFF, 0xD8
    if data.starts_with(b"\xFF\xD8") {
        let mut idx = 2;
        while idx + 4 < data.len() {
            if data[idx] != 0xFF {
                idx += 1;
                continue;
            }
            let marker = data[idx + 1];
            idx += 2;

            // SOF0 (0xC0) or SOF2 (0xC2) markers contain dimensions
            if marker == 0xC0 || marker == 0xC1 || marker == 0xC2 {
                if idx + 7 > data.len() {
                    break;
                }
                // Skip length (2 bytes) and data precision (1 byte)
                let height = u16::from_be_bytes([data[idx + 3], data[idx + 4]]) as u32;
                let width = u16::from_be_bytes([data[idx + 5], data[idx + 6]]) as u32;
                validate_dimensions(width, height, max_pixels)?;
                return Ok((width, height));
            } else if marker == 0xD9 || marker == 0xDA {
                // End of image or Start of Scan: SOF must precede this
                break;
            } else if idx + 2 <= data.len() {
                // Skip marker segment length
                let len = u16::from_be_bytes([data[idx], data[idx + 1]]) as usize;
                idx += len;
            } else {
                break;
            }
        }
        return Ok((0, 0)); // JPEG without recognizable SOF or baseline
    }

    // 4. WebP: Starts with RIFF....WEBP
    if data.starts_with(b"RIFF") && data.len() >= 30 && &data[8..12] == b"WEBP" {
        let format_chunk = &data[12..16];
        if format_chunk == b"VP8 " && data.len() >= 30 {
            // Lossy VP8
            let width = (u16::from_le_bytes([data[26], data[27]]) & 0x3FFF) as u32;
            let height = (u16::from_le_bytes([data[28], data[29]]) & 0x3FFF) as u32;
            validate_dimensions(width, height, max_pixels)?;
            return Ok((width, height));
        } else if format_chunk == b"VP8L" && data.len() >= 25 {
            // Lossless VP8L
            let b1 = data[21] as u32;
            let b2 = data[22] as u32;
            let b3 = data[23] as u32;
            let b4 = data[24] as u32;
            let width = 1 + (b1 | ((b2 & 0x3F) << 8));
            let height = 1 + ((b2 >> 6) | (b3 << 2) | ((b4 & 0xF) << 10));
            validate_dimensions(width, height, max_pixels)?;
            return Ok((width, height));
        } else if format_chunk == b"VP8X" && data.len() >= 30 {
            // Extended VP8X
            let width =
                1 + (data[24] as u32 | ((data[25] as u32) << 8) | ((data[26] as u32) << 16));
            let height =
                1 + (data[27] as u32 | ((data[28] as u32) << 8) | ((data[29] as u32) << 16));
            validate_dimensions(width, height, max_pixels)?;
            return Ok((width, height));
        }
    }

    // Not an image format requiring dimension validation or unrecognized
    Ok((0, 0))
}

fn validate_dimensions(width: u32, height: u32, max_pixels: usize) -> Result<(), String> {
    let total_pixels = (width as u64) * (height as u64);
    if total_pixels > max_pixels as u64 {
        return Err(format!(
            "Image dimensions {}x{} ({} pixels) exceed maximum safe budget of {} pixels (possible decompression bomb)",
            width, height, total_pixels, max_pixels
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pdf_javascript_detection() {
        let clean_pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF";
        assert!(!inspect_pdf(clean_pdf).is_threat_detected);

        let evil_pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert('PWNED');) >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF";
        let res = inspect_pdf(evil_pdf);
        assert!(res.is_threat_detected);
        assert!(res.threats.iter().any(|t| t.contains("JavaScript")));
    }

    #[test]
    fn test_svg_script_detection() {
        let policy = Policy::strict();
        let evil_svg = b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert('XSS')</script><circle cx=\"50\" cy=\"50\" r=\"40\"/></svg>";
        let (_sanitized, actions, blocked) = inspect_and_sanitize_svg(evil_svg, &policy);
        assert!(blocked);
        assert!(!actions.is_empty());
    }

    #[test]
    fn test_svg_xml_bomb_detection() {
        let policy = Policy::balanced();
        let bomb_svg = b"<?xml version=\"1.0\"?>\n<!DOCTYPE lolz [\n<!ENTITY lol \"lol\">\n<!ENTITY lol2 \"&lol;&lol;&lol;&lol;\">\n]>\n<svg><text>&lol2;</text></svg>";
        let (_sanitized, actions, blocked) = inspect_and_sanitize_svg(bomb_svg, &policy);
        assert!(blocked);
        assert!(
            actions
                .iter()
                .any(|a| a.rule_fired.contains("XML Entity Bomb"))
        );
    }

    #[test]
    fn test_png_dimension_validation() {
        // Construct minimal valid PNG header with 100x200 dimensions
        let mut png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]; // 8 bytes signature
        png.extend_from_slice(&[0, 0, 0, 13]); // IHDR chunk length
        png.extend_from_slice(b"IHDR"); // Chunk type
        png.extend_from_slice(&100u32.to_be_bytes()); // Width 100
        png.extend_from_slice(&200u32.to_be_bytes()); // Height 200
        png.extend_from_slice(&[8, 2, 0, 0, 0]); // Bit depth, color type, compression, filter, interlace

        // Allowed within 50,000 pixels (100 * 200 = 20,000)
        let res = check_image_dimensions(&png, 50_000);
        assert_eq!(res.unwrap(), (100, 200));

        // Rejected with 10,000 pixel cap
        let err = check_image_dimensions(&png, 10_000);
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("exceed maximum safe budget"));
    }

    #[test]
    fn test_gif_dimension_validation() {
        // Construct GIF89a header with 400x300
        let mut gif = b"GIF89a".to_vec();
        gif.extend_from_slice(&400u16.to_le_bytes()); // Width 400
        gif.extend_from_slice(&300u16.to_le_bytes()); // Height 300

        let res = check_image_dimensions(&gif, 200_000);
        assert_eq!(res.unwrap(), (400, 300));

        let err = check_image_dimensions(&gif, 50_000);
        assert!(err.is_err());
    }
}
