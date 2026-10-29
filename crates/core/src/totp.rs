//! TOTP codes (RFC 6238) from a base32 secret or an `otpauth://totp/...` link.

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use zeroize::Zeroizing;

use crate::{Error, Result};

enum Alg {
    Sha1,
    Sha256,
    Sha512,
}

struct Spec {
    secret: Zeroizing<Vec<u8>>,
    alg: Alg,
    digits: u32,
    period: u64,
}

fn parse(spec: &str) -> Result<Spec> {
    let spec = spec.trim();
    let (mut alg, mut digits, mut period) = (Alg::Sha1, 6u32, 30u64);
    let secret = match spec.strip_prefix("otpauth://") {
        Some(rest) => {
            let rest = rest.strip_prefix("totp/").ok_or(Error::Invalid("only TOTP links are supported"))?;
            let query = rest.split_once('?').map_or("", |(_, q)| q);
            let mut secret = None;
            for (k, v) in query.split('&').filter_map(|kv| kv.split_once('=')) {
                match k.to_ascii_lowercase().as_str() {
                    "secret" => secret = Some(v.to_string()),
                    "algorithm" => {
                        alg = match v.to_ascii_uppercase().as_str() {
                            "SHA1" => Alg::Sha1,
                            "SHA256" => Alg::Sha256,
                            "SHA512" => Alg::Sha512,
                            _ => return Err(Error::Invalid("unsupported TOTP algorithm")),
                        }
                    }
                    "digits" => digits = v.parse().map_err(|_| Error::Invalid("invalid TOTP parameters"))?,
                    "period" => period = v.parse().map_err(|_| Error::Invalid("invalid TOTP parameters"))?,
                    _ => {}
                }
            }
            secret.ok_or(Error::Invalid("TOTP link has no secret"))?
        }
        None => spec.to_string(),
    };
    let clean: String = secret
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=' && *c != '-')
        .collect::<String>()
        .to_ascii_uppercase();
    let secret = Zeroizing::new(BASE32_NOPAD.decode(clean.as_bytes()).map_err(|_| Error::Invalid("TOTP secret is not base32"))?);
    if secret.is_empty() || !(6..=8).contains(&digits) || period == 0 {
        return Err(Error::Invalid("invalid TOTP parameters"));
    }
    Ok(Spec { secret, alg, digits, period })
}

fn mac<M: Mac + hmac::digest::KeyInit>(key: &[u8], msg: &[u8]) -> Vec<u8> {
    <M as Mac>::new_from_slice(key)
        .expect("HMAC accepts keys of any length")
        .chain_update(msg)
        .finalize()
        .into_bytes()
        .to_vec()
}

/// Current code, seconds until it changes, and the period.
pub fn code(spec: &str, unix_time: u64) -> Result<(String, u64, u64)> {
    let s = parse(spec)?;
    let counter = (unix_time / s.period).to_be_bytes();
    let h = match s.alg {
        Alg::Sha1 => mac::<Hmac<sha1::Sha1>>(&s.secret, &counter),
        Alg::Sha256 => mac::<Hmac<sha2::Sha256>>(&s.secret, &counter),
        Alg::Sha512 => mac::<Hmac<sha2::Sha512>>(&s.secret, &counter),
    };
    let off = (h[h.len() - 1] & 0x0f) as usize;
    let bin = u32::from_be_bytes(h[off..off + 4].try_into().expect("4 bytes")) & 0x7fff_ffff;
    let value = bin % 10u32.pow(s.digits);
    Ok((format!("{value:0width$}", width = s.digits as usize), s.period - unix_time % s.period, s.period))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    // RFC 6238 appendix B test vectors (8 digits).
    const SHA1_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; // "12345678901234567890"

    #[test]
    fn rfc6238_vectors() {
        let link = |alg: &str, secret: &str| format!("otpauth://totp/x?secret={secret}&algorithm={alg}&digits=8");
        assert_eq!(code(&link("SHA1", SHA1_SECRET), 59).unwrap().0, "94287082");
        assert_eq!(code(&link("SHA1", SHA1_SECRET), 59).unwrap().2, 30);
        assert_eq!(code(&link("SHA1", SHA1_SECRET), 1111111109).unwrap().0, "07081804");
        let s256 = data_encoding::BASE32_NOPAD.encode(b"12345678901234567890123456789012");
        assert_eq!(code(&link("SHA256", &s256), 59).unwrap().0, "46119246");
        let s512 = data_encoding::BASE32_NOPAD.encode(b"1234567890123456789012345678901234567890123456789012345678901234");
        assert_eq!(code(&link("SHA512", &s512), 59).unwrap().0, "90693936");
    }

    #[test]
    fn plain_secret_defaults_and_countdown() {
        let (c, left, _) = code("gezd gnbv gy3t qojq gezd gnbv gy3t qojq", 59).unwrap();
        assert_eq!(c, "287082", "6 digits by default");
        assert_eq!(left, 1);
        assert_eq!(code(SHA1_SECRET, 60).unwrap().1, 30);
        let (_, left, period) = code(&format!("otpauth://totp/Acme:me?secret={SHA1_SECRET}&period=60&issuer=Acme"), 59).unwrap();
        assert_eq!(period, 60);
        assert_eq!(left, 1);
    }

    #[test]
    fn rejects_garbage() {
        for bad in ["", "not base32!", "otpauth://totp/x?digits=6", "otpauth://totp/x?secret=GEZDGNBV&digits=12", "otpauth://hotp/x?secret=GEZDGNBV"] {
            assert!(matches!(code(bad, 0), Err(Error::Invalid(_))), "{bad}");
        }
    }
}
