//! XChaCha20-Poly1305 blobs: `version(1) ‖ nonce(24) ‖ ciphertext+tag(16)`.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::kdf::random_bytes;
use crate::{Error, Result};

const VERSION: u8 = 1;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

pub fn seal(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let nonce: [u8; NONCE_LEN] = random_bytes();
    let ct = XChaCha20Poly1305::new(key.into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .expect("XChaCha20-Poly1305 encryption of in-memory data cannot fail");
    let mut blob = Vec::with_capacity(1 + NONCE_LEN + ct.len());
    blob.push(VERSION);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct);
    blob
}

pub fn open(key: &[u8; 32], blob: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if blob.len() < 1 + NONCE_LEN + TAG_LEN || blob[0] != VERSION {
        return Err(Error::Format("unknown or truncated blob"));
    }
    let (nonce, ct) = blob[1..].split_at(NONCE_LEN);
    XChaCha20Poly1305::new(key.into())
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| Error::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    const K: [u8; 32] = [1; 32];

    #[test]
    fn roundtrip() {
        let blob = seal(&K, b"secret", b"aad");
        assert_eq!(&open(&K, &blob, b"aad").unwrap()[..], b"secret");
    }

    #[test]
    fn wrong_key_or_aad_fails() {
        let blob = seal(&K, b"secret", b"aad");
        assert!(matches!(open(&[2; 32], &blob, b"aad"), Err(Error::Decrypt)));
        assert!(matches!(open(&K, &blob, b"other"), Err(Error::Decrypt)));
    }

    #[test]
    fn tampered_blob_fails() {
        let mut blob = seal(&K, b"secret", b"aad");
        let last = blob.len() - 1;
        blob[last] ^= 1;
        assert!(matches!(open(&K, &blob, b"aad"), Err(Error::Decrypt)));
    }

    #[test]
    fn truncated_or_unknown_version_is_format_error() {
        let blob = seal(&K, b"secret", b"aad");
        assert!(matches!(open(&K, &blob[..10], b"aad"), Err(Error::Format(_))));
        assert!(matches!(open(&K, &[], b"aad"), Err(Error::Format(_))));
        let mut v2 = blob.clone();
        v2[0] = 2;
        assert!(matches!(open(&K, &v2, b"aad"), Err(Error::Format(_))));
    }

    #[test]
    fn same_input_gives_different_blobs() {
        assert_ne!(seal(&K, b"x", b""), seal(&K, b"x", b""));
    }
}
