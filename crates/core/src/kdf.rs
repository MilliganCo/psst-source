//! Argon2id key derivation and HKDF sub-keys.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{Error, Result};

/// 32-byte secret key wiped from memory on drop.
pub type Key = Zeroizing<[u8; 32]>;

/// Argon2id cost parameters, stored next to the salt so they can be raised later.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl KdfParams {
    pub const DEFAULT: KdfParams = KdfParams { m_kib: 65536, t: 3, p: 4 };
    #[cfg(test)]
    pub(crate) const FAST: KdfParams = KdfParams { m_kib: 1024, t: 1, p: 1 };
}

impl KdfParams {
    /// Bounds for params read from untrusted sources (server responses, old files).
    fn validate(self) -> Result<()> {
        let ok = (1..=16).contains(&self.p)
            && (1..=10).contains(&self.t)
            && self.m_kib >= 8 * self.p
            && self.m_kib <= 1024 * 1024;
        if ok { Ok(()) } else { Err(Error::KdfParams) }
    }
}

pub fn argon2id(secret: &[u8], salt: &[u8], params: KdfParams) -> Result<Key> {
    params.validate()?;
    let p = Params::new(params.m_kib, params.t, params.p, Some(32)).map_err(|_| Error::KdfParams)?;
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, p)
        .hash_password_into(secret, salt, &mut out[..])
        .map_err(|_| Error::KdfParams)?;
    Ok(out)
}

pub fn hkdf(ikm: &[u8], info: &str) -> Key {
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, ikm)
        .expand(info.as_bytes(), &mut out[..])
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    // Python v1: argon2.low_level.hash_secret_raw(b"pass", bytes([7]*32), 3, 65536, 4, 32, Type.ID)
    #[test]
    fn argon2id_matches_python_argon2_cffi() {
        let k = argon2id(b"pass", &[7u8; 32], KdfParams::DEFAULT).unwrap();
        assert_eq!(
            data_encoding::HEXLOWER.encode(&k[..]),
            "235a113701ca38a7087b3cb77942ea6ad831ce1adb4446ffe346f32b0ff5d44c"
        );
    }

    #[test]
    fn rejects_hostile_params() {
        let huge = KdfParams { m_kib: 4 * 1024 * 1024, t: 3, p: 4 };
        assert!(matches!(argon2id(b"x", &[0; 16], huge), Err(Error::KdfParams)));
        let zero_time = KdfParams { m_kib: 1024, t: 0, p: 1 };
        assert!(matches!(argon2id(b"x", &[0; 16], zero_time), Err(Error::KdfParams)));
        let many_lanes = KdfParams { m_kib: 65536, t: 3, p: 255 };
        assert!(matches!(argon2id(b"x", &[0; 16], many_lanes), Err(Error::KdfParams)));
    }

    #[test]
    fn hkdf_infos_give_different_keys() {
        assert_ne!(*hkdf(b"ikm", "pwd/auth"), *hkdf(b"ikm", "pwd/wrap"));
        assert_eq!(*hkdf(b"ikm", "pwd/auth"), *hkdf(b"ikm", "pwd/auth"));
    }

    #[test]
    fn random_bytes_differ() {
        assert_ne!(random_bytes::<32>(), random_bytes::<32>());
    }
}
