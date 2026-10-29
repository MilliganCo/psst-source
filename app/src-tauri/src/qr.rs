//! QR codes from a screenshot: sites show the 2FA secret as a QR code (`otpauth://…`).

/// Text of the first readable QR code in an RGBA image.
pub fn decode(width: usize, height: usize, rgba: &[u8]) -> Option<String> {
    if width == 0 || height == 0 || rgba.len() < width * height * 4 {
        return None;
    }
    let mut img = rqrr::PreparedImage::prepare_from_greyscale(width, height, |x, y| {
        let p = &rgba[(y * width + x) * 4..][..3];
        ((p[0] as u16 * 3 + p[1] as u16 * 6 + p[2] as u16) / 10) as u8
    });
    img.detect_grids().into_iter().find_map(|g| g.decode().ok().map(|(_, text)| text))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RGBA pixels of a QR code with a quiet zone, the way a screenshot would hold it.
    fn render(text: &str, scale: usize) -> (usize, usize, Vec<u8>) {
        let code = qrcode::QrCode::new(text.as_bytes()).unwrap();
        let modules = code.to_colors();
        let (n, quiet) = (code.width(), 4);
        let side = (n + 2 * quiet) * scale;
        let mut rgba = vec![255u8; side * side * 4];
        for y in 0..side {
            for x in 0..side {
                let (mx, my) = ((x / scale) as isize - quiet as isize, (y / scale) as isize - quiet as isize);
                let dark = mx >= 0 && my >= 0 && (mx as usize) < n && (my as usize) < n && modules[my as usize * n + mx as usize] == qrcode::Color::Dark;
                if dark {
                    rgba[(y * side + x) * 4..][..3].fill(0);
                }
            }
        }
        (side, side, rgba)
    }

    #[test]
    fn reads_an_otpauth_qr_code() {
        let url = "otpauth://totp/GitHub:cody?secret=JBSWY3DPEHPK3PXP&issuer=GitHub";
        let (w, h, rgba) = render(url, 5);
        assert_eq!(decode(w, h, &rgba).as_deref(), Some(url));
    }

    #[test]
    fn none_without_a_code() {
        assert_eq!(decode(40, 40, &vec![255u8; 40 * 40 * 4]), None);
        assert_eq!(decode(10, 10, &[0u8; 3]), None, "short buffer");
    }
}
