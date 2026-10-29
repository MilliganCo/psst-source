//! Self-signed certificate: generated once, pinned by clients via its SHA-256 fingerprint.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;

use axum_server::tls_rustls::RustlsConfig;
use data_encoding::BASE32_NOPAD;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};

fn other(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

/// Bytes produced by rcgen; the factory seam lets file-lifecycle tests use opaque data.
struct IdentityMaterial {
    key_der: Vec<u8>,
    cert_der: Vec<u8>,
    cert_pem: String,
}

fn regular_file_present(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() => Ok(true),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("non-regular TLS identity file: {}", path.display()),
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// Exclusive creation on every platform; Unix modes are set before the first byte is written.
/// Windows confidentiality depends on the directory's ACL; readonly is not an ACL substitute.
fn write_new_file(path: &Path, contents: &[u8], unix_mode: u32) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(unix_mode);
    }
    #[cfg(not(unix))]
    let _ = unix_mode;
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

fn ensure_cert_with(
    dir: &Path,
    generate: impl FnOnce() -> io::Result<IdentityMaterial>,
) -> io::Result<()> {
    if !fs::metadata(dir)?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TLS data path is not a directory",
        ));
    }
    let cert = regular_file_present(&dir.join("cert.der"))?;
    let key = regular_file_present(&dir.join("key.der"))?;
    match (cert, key) {
        (true, true) => {
            // Reuse via the existing loader; never silently replace corrupt/pinned identity.
            let _ = rustls_config(dir)?;
            return Ok(());
        }
        (true, false) | (false, true) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "incomplete TLS identity; restore the missing member instead of regenerating",
            ));
        }
        (false, false) => {}
    }
    if regular_file_present(&dir.join("cert.pem"))? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "orphan cert.pem; inspect the identity before generating a replacement",
        ));
    }
    let material = generate()?;
    // DER is the last written member. On error, leave state for explicit repair, not rotation.
    write_new_file(&dir.join("key.der"), &material.key_der, 0o600)?;
    write_new_file(&dir.join("cert.pem"), material.cert_pem.as_bytes(), 0o644)?;
    write_new_file(&dir.join("cert.der"), &material.cert_der, 0o644)?;
    Ok(())
}

/// Creates an identity only in an empty data directory. SANs are unchanged.
/// Existing DER/key pairs are loaded and preserved; partial/non-regular state fails closed.
/// PEM is ancillary and is not rewritten when an existing pair is reused.
pub fn ensure_cert(dir: &Path, host: &str) -> io::Result<()> {
    ensure_cert_with(dir, || {
        let mut names = vec![host.to_string(), "localhost".into(), "127.0.0.1".into()];
        names.dedup();
        let ck = rcgen::generate_simple_self_signed(names).map_err(other)?;
        Ok(IdentityMaterial {
            key_der: ck.signing_key.serialize_der(),
            cert_der: ck.cert.der().as_ref().to_vec(),
            cert_pem: ck.cert.pem(),
        })
    })
}

/// SHA-256 of the certificate, base32 without padding (52 chars). Goes into invite links.
pub fn fingerprint(dir: &Path) -> io::Result<String> {
    Ok(BASE32_NOPAD.encode(&Sha256::digest(std::fs::read(dir.join("cert.der"))?)))
}

pub fn rustls_config(dir: &Path) -> io::Result<RustlsConfig> {
    let cert = CertificateDer::from(std::fs::read(dir.join("cert.der"))?);
    let key = PrivatePkcs8KeyDer::from(std::fs::read(dir.join("key.der"))?);
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(other)?
    .with_no_client_auth()
    .with_single_cert(vec![cert], key.into())
    .map_err(other)?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(cfg)))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Deliberately not a real certificate/key. These tests cover file contracts, not TLS crypto.
    fn opaque() -> io::Result<IdentityMaterial> {
        Ok(IdentityMaterial {
            key_der: b"opaque test key".to_vec(),
            cert_der: b"opaque test certificate".to_vec(),
            cert_pem: "opaque test PEM".into(),
        })
    }

    #[test]
    fn writes_new_files_exclusively() {
        let dir = tempfile::tempdir().unwrap();
        ensure_cert_with(dir.path(), opaque).unwrap();
        assert_eq!(
            fs::read(dir.path().join("key.der")).unwrap(),
            b"opaque test key"
        );
        assert_eq!(
            fs::read(dir.path().join("cert.der")).unwrap(),
            b"opaque test certificate"
        );
        assert_eq!(
            fs::read(dir.path().join("cert.pem")).unwrap(),
            b"opaque test PEM"
        );
        assert_eq!(
            write_new_file(&dir.path().join("key.der"), b"replacement", 0o600)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(
            fs::read(dir.path().join("key.der")).unwrap(),
            b"opaque test key"
        );
    }

    #[test]
    fn partial_pair_is_not_regenerated() {
        for existing in ["cert.der", "key.der"] {
            let dir = tempfile::tempdir().unwrap();
            fs::write(dir.path().join(existing), b"existing sentinel").unwrap();
            let error = ensure_cert_with(dir.path(), || {
                panic!("generation must not run for partial state")
            })
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(
                fs::read(dir.path().join(existing)).unwrap(),
                b"existing sentinel"
            );
            let other = if existing == "cert.der" {
                "key.der"
            } else {
                "cert.der"
            };
            assert!(!dir.path().join(other).exists());
            assert!(!dir.path().join("cert.pem").exists());
        }
    }

    #[test]
    fn orphan_pem_is_not_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("cert.pem"), b"existing PEM").unwrap();
        assert_eq!(
            ensure_cert_with(dir.path(), || panic!(
                "generation must not run for orphan PEM"
            ))
            .unwrap_err()
            .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            fs::read(dir.path().join("cert.pem")).unwrap(),
            b"existing PEM"
        );
        assert!(!dir.path().join("key.der").exists());
        assert!(!dir.path().join("cert.der").exists());
    }

    #[test]
    fn corrupt_existing_pair_is_not_rotated() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("cert.der"), b"invalid cert").unwrap();
        fs::write(dir.path().join("key.der"), b"invalid key").unwrap();
        assert!(ensure_cert_with(dir.path(), || panic!(
            "existing identity must not be rotated"
        ))
        .is_err());
        assert_eq!(
            fs::read(dir.path().join("cert.der")).unwrap(),
            b"invalid cert"
        );
        assert_eq!(
            fs::read(dir.path().join("key.der")).unwrap(),
            b"invalid key"
        );
    }

    #[test]
    fn a_racing_key_is_never_clobbered() {
        let dir = tempfile::tempdir().unwrap();
        let error = ensure_cert_with(dir.path(), || {
            fs::write(dir.path().join("key.der"), b"other initializer").unwrap();
            opaque()
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            fs::read(dir.path().join("key.der")).unwrap(),
            b"other initializer"
        );
        assert!(!dir.path().join("cert.pem").exists());
        assert!(!dir.path().join("cert.der").exists());
    }

    #[test]
    fn failed_factory_has_no_file_writes() {
        let dir = tempfile::tempdir().unwrap();
        assert!(ensure_cert_with(dir.path(), || Err(io::Error::other(
            "synthetic factory failure"
        )))
        .is_err());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn new_key_is_owner_only_and_public_files_are_not_world_writable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        ensure_cert_with(dir.path(), opaque).unwrap();
        let key_mode = fs::metadata(dir.path().join("key.der"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            key_mode & 0o077,
            0,
            "no group/other access, even before any chmod"
        );
        for name in ["cert.der", "cert.pem"] {
            let mode = fs::metadata(dir.path().join(name))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o022,
                0,
                "public certificate must not be writable by group/others"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlink_identity_member_is_not_followed() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        fs::write(&target, b"do not touch").unwrap();
        symlink(&target, dir.path().join("key.der")).unwrap();
        assert_eq!(
            ensure_cert_with(dir.path(), || panic!("symlink must fail before generation"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(fs::read(&target).unwrap(), b"do not touch");
        assert!(fs::symlink_metadata(dir.path().join("key.der"))
            .unwrap()
            .file_type()
            .is_symlink());
    }
}
