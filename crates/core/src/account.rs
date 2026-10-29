//! Account keys: master password → Argon2id → auth/wrap keys; random account key;
//! recovery code; X25519 key pair for receiving shared collection keys.

use crypto_box::SecretKey;
use data_encoding::BASE32_NOPAD;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::aead;
use crate::kdf::{argon2id, hkdf, random_bytes, KdfParams, Key};
use crate::{Error, Result};

const AAD_ACCOUNT: &[u8] = b"pwd/account";
const AAD_PRIVATE: &[u8] = b"pwd/private";
/// 120 bits → exactly 24 base32 characters.
const RECOVERY_BYTES: usize = 15;

/// Everything about an account that is persisted (locally and on the server). No plaintext secrets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountBlobs {
    #[serde(with = "crate::proto::b64")]
    pub kdf_salt: [u8; 16],
    pub kdf_params: KdfParams,
    #[serde(with = "crate::proto::b64")]
    pub enc_account_key: Vec<u8>,
    #[serde(with = "crate::proto::b64")]
    pub enc_account_key_recovery: Vec<u8>,
    #[serde(with = "crate::proto::b64")]
    pub public_key: [u8; 32],
    #[serde(with = "crate::proto::b64")]
    pub enc_private_key: Vec<u8>,
}

/// Decrypted account. Keys are wiped on drop.
pub struct UnlockedAccount {
    account_key: Key,
    secret_key: SecretKey,
}

impl UnlockedAccount {
    pub fn public_key(&self) -> [u8; 32] {
        *self.secret_key.public_key().as_bytes()
    }

    pub(crate) fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }

    /// Encrypts small local secrets (e.g. `recovery_auth`) under the account key.
    pub fn seal_private(&self, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        crate::aead::seal(&self.account_key, plaintext, &[b"pwd/private-data/".as_slice(), aad].concat())
    }

    pub fn open_private(&self, blob: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        crate::aead::open(&self.account_key, blob, &[b"pwd/private-data/".as_slice(), aad].concat())
    }
}

/// Result of creating an account or resetting it with the recovery code.
pub struct NewCredentials {
    pub blobs: AccountBlobs,
    /// Sent to the server; the server stores only SHA-256(auth_key).
    pub auth_key: Key,
    /// Shown to the user once.
    pub recovery_code: String,
    /// Sent to the server at registration; the server stores only its hash.
    pub recovery_auth: Key,
    pub account: UnlockedAccount,
}

/// Lowest Argon2id cost accepted for account keys. Login params come from the server,
/// so without a floor a hostile server could make the password cheap to brute-force.
#[cfg(not(test))]
const KDF_FLOOR: KdfParams = KdfParams::DEFAULT;
#[cfg(test)]
const KDF_FLOOR: KdfParams = KdfParams::FAST;

/// Keys derived from the master password: `auth_key` goes to the server, the wrap key stays here.
pub struct LoginKeys {
    pub auth_key: Key,
    wrap_key: Key,
}

/// Derives login keys from the salt and params returned by prelogin (or stored locally).
pub fn derive_login(password: &str, salt: &[u8; 16], params: KdfParams) -> Result<LoginKeys> {
    if params.m_kib < KDF_FLOOR.m_kib || params.t < KDF_FLOOR.t {
        return Err(Error::KdfParams);
    }
    let master = argon2id(password.as_bytes(), salt, params)?;
    Ok(LoginKeys { auth_key: hkdf(&master[..], "pwd/auth"), wrap_key: hkdf(&master[..], "pwd/wrap") })
}

/// Opens the account blobs with keys from `derive_login`. Wrong password -> `Error::Decrypt`.
pub fn unlock_with(keys: &LoginKeys, blobs: &AccountBlobs) -> Result<UnlockedAccount> {
    open_account(&keys.wrap_key, &blobs.enc_account_key, blobs)
}

fn group(text: &str, size: usize) -> String {
    text.as_bytes()
        .chunks(size)
        .map(|c| std::str::from_utf8(c).expect("base32 is ASCII"))
        .collect::<Vec<_>>()
        .join("-")
}

fn parse_recovery_code(code: &str) -> Result<Zeroizing<Vec<u8>>> {
    let clean: String = code.chars().filter(char::is_ascii_alphanumeric).collect::<String>().to_ascii_uppercase();
    let raw = Zeroizing::new(BASE32_NOPAD.decode(clean.as_bytes()).map_err(|_| Error::RecoveryCode)?);
    if raw.len() != RECOVERY_BYTES {
        return Err(Error::RecoveryCode);
    }
    Ok(raw)
}

fn to_key(bytes: &[u8]) -> Result<Key> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| Error::Format("key must be 32 bytes"))?;
    Ok(Zeroizing::new(arr))
}

/// Wraps the keys under a fresh password salt and a fresh recovery code.
fn build(account_key: Key, secret_key: SecretKey, password: &str, params: KdfParams) -> Result<NewCredentials> {
    let kdf_salt = random_bytes::<16>();
    let keys = derive_login(password, &kdf_salt, params)?;
    let recovery_raw = Zeroizing::new(random_bytes::<RECOVERY_BYTES>());
    let private = Zeroizing::new(secret_key.to_bytes());
    let blobs = AccountBlobs {
        kdf_salt,
        kdf_params: params,
        enc_account_key: aead::seal(&keys.wrap_key, &account_key[..], AAD_ACCOUNT),
        enc_account_key_recovery: aead::seal(
            &hkdf(&recovery_raw[..], "pwd/recovery-wrap"),
            &account_key[..],
            AAD_ACCOUNT,
        ),
        public_key: *secret_key.public_key().as_bytes(),
        enc_private_key: aead::seal(&account_key, &private[..], AAD_PRIVATE),
    };
    Ok(NewCredentials {
        blobs,
        auth_key: keys.auth_key,
        recovery_code: group(&BASE32_NOPAD.encode(&recovery_raw[..]), 4),
        recovery_auth: hkdf(&recovery_raw[..], "pwd/recovery-auth"),
        account: UnlockedAccount { account_key, secret_key },
    })
}

fn open_account(wrap: &[u8; 32], enc_account_key: &[u8], blobs: &AccountBlobs) -> Result<UnlockedAccount> {
    let account_key = to_key(&aead::open(wrap, enc_account_key, AAD_ACCOUNT)?)?;
    let private = to_key(&aead::open(&account_key, &blobs.enc_private_key, AAD_PRIVATE)?)?;
    let secret_key = SecretKey::from(*private);
    if secret_key.public_key().as_bytes() != &blobs.public_key {
        return Err(Error::Format("public key does not match private key"));
    }
    Ok(UnlockedAccount { account_key, secret_key })
}

pub fn create_account(password: &str, params: KdfParams) -> Result<NewCredentials> {
    build(Zeroizing::new(random_bytes()), SecretKey::generate(&mut OsRng), password, params)
}

/// Wrong password → `Error::Decrypt`.
pub fn unlock(password: &str, blobs: &AccountBlobs) -> Result<UnlockedAccount> {
    unlock_with(&derive_login(password, &blobs.kdf_salt, blobs.kdf_params)?, blobs)
}

/// Re-wraps the account key under a new password. Recovery code and X25519 keys stay the same.
/// Returns the new blobs and the new auth key for the server.
pub fn change_password(
    account: &UnlockedAccount,
    blobs: &AccountBlobs,
    new_password: &str,
    params: KdfParams,
) -> Result<(AccountBlobs, Key)> {
    let kdf_salt = random_bytes::<16>();
    let keys = derive_login(new_password, &kdf_salt, params)?;
    let new_blobs = AccountBlobs {
        kdf_salt,
        kdf_params: params,
        enc_account_key: aead::seal(&keys.wrap_key, &account.account_key[..], AAD_ACCOUNT),
        ..blobs.clone()
    };
    Ok((new_blobs, keys.auth_key))
}

/// Opens the account with the recovery code, sets a new password and issues a new recovery code.
pub fn recover(code: &str, blobs: &AccountBlobs, new_password: &str, params: KdfParams) -> Result<NewCredentials> {
    let raw = parse_recovery_code(code)?;
    let old = open_account(&hkdf(&raw, "pwd/recovery-wrap"), &blobs.enc_account_key_recovery, blobs)?;
    build(old.account_key, old.secret_key, new_password, params)
}

/// Proof of knowing the recovery code, sent to the server on `/api/recover`.
pub fn recovery_auth(code: &str) -> Result<Key> {
    Ok(hkdf(&parse_recovery_code(code)?, "pwd/recovery-auth"))
}

/// Public-key fingerprint for voice verification: 125 bits of SHA-256 as 5 groups of 5 base32 chars.
pub fn fingerprint(public_key: &[u8; 32]) -> String {
    let text = BASE32_NOPAD.encode(&Sha256::digest(public_key)[..16]);
    group(&text[..25], 5)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    const PW: &str = "пароль-тест 42";
    const FAST: KdfParams = KdfParams::FAST;

    #[test]
    fn create_then_unlock() {
        let c = create_account(PW, FAST).unwrap();
        let u = unlock(PW, &c.blobs).unwrap();
        assert_eq!(*u.account_key, *c.account.account_key);
        assert_eq!(u.public_key(), c.blobs.public_key);
        assert_eq!(c.blobs.kdf_params, FAST);
    }

    #[test]
    fn wrong_password_is_decrypt_error() {
        let c = create_account(PW, FAST).unwrap();
        assert!(matches!(unlock("пароль-тест 43", &c.blobs), Err(Error::Decrypt)));
    }

    #[test]
    fn recovery_code_shape() {
        let c = create_account(PW, FAST).unwrap();
        let groups: Vec<&str> = c.recovery_code.split('-').collect();
        assert_eq!(groups.len(), 6);
        assert!(groups.iter().all(|g| g.len() == 4));
        assert_eq!(*recovery_auth(&c.recovery_code).unwrap(), *c.recovery_auth);
    }

    #[test]
    fn change_password_keeps_keys_and_recovery_code() {
        let c = create_account(PW, FAST).unwrap();
        let (blobs, auth) = change_password(&c.account, &c.blobs, "новый", FAST).unwrap();
        assert_ne!(*auth, *c.auth_key);
        assert!(matches!(unlock(PW, &blobs), Err(Error::Decrypt)));
        let u = unlock("новый", &blobs).unwrap();
        assert_eq!(*u.account_key, *c.account.account_key);
        assert_eq!(blobs.enc_account_key_recovery, c.blobs.enc_account_key_recovery);
        assert!(recover(&c.recovery_code, &blobs, "третий", FAST).is_ok());
    }

    #[test]
    fn recover_accepts_messy_code() {
        let c = create_account(PW, FAST).unwrap();
        let messy = format!(" {}\n", c.recovery_code.to_lowercase().replace('-', " "));
        let r = recover(&messy, &c.blobs, "после-сброса", FAST).unwrap();
        assert_eq!(*r.account.account_key, *c.account.account_key);
        assert_eq!(r.blobs.public_key, c.blobs.public_key);
        assert_ne!(r.recovery_code, c.recovery_code, "recovery must issue a new code");
        assert!(matches!(unlock(PW, &r.blobs), Err(Error::Decrypt)));
        assert!(unlock("после-сброса", &r.blobs).is_ok());
        assert!(recover(&c.recovery_code, &r.blobs, "x", FAST).is_err(), "old code must stop working");
    }

    #[test]
    fn invalid_recovery_code() {
        let c = create_account(PW, FAST).unwrap();
        assert!(matches!(recovery_auth("abc"), Err(Error::RecoveryCode)));
        assert!(matches!(recover("", &c.blobs, "x", FAST), Err(Error::RecoveryCode)));
        assert!(matches!(recover("ЖЖЖЖ-1111", &c.blobs, "x", FAST), Err(Error::RecoveryCode)));
        let other = create_account(PW, FAST).unwrap();
        assert!(matches!(recover(&other.recovery_code, &c.blobs, "x", FAST), Err(Error::Decrypt)));
    }

    #[test]
    fn unlock_detects_swapped_public_key() {
        let c = create_account(PW, FAST).unwrap();
        let other = create_account(PW, FAST).unwrap();
        let mut blobs = c.blobs.clone();
        blobs.public_key = other.blobs.public_key;
        assert!(matches!(unlock(PW, &blobs), Err(Error::Format(_))));
    }

    #[test]
    fn derive_login_rejects_weak_params_from_server() {
        let weak = KdfParams { m_kib: 8, t: 1, p: 1 };
        assert!(matches!(derive_login(PW, &[0; 16], weak), Err(Error::KdfParams)));
        assert!(matches!(create_account(PW, weak), Err(Error::KdfParams)));
    }

    #[test]
    fn derive_login_then_unlock_with() {
        let c = create_account(PW, FAST).unwrap();
        let keys = derive_login(PW, &c.blobs.kdf_salt, c.blobs.kdf_params).unwrap();
        assert_eq!(*keys.auth_key, *c.auth_key);
        let u = unlock_with(&keys, &c.blobs).unwrap();
        assert_eq!(u.public_key(), c.blobs.public_key);
    }

    #[test]
    fn private_data_roundtrip_and_blobs_json() {
        let c = create_account(PW, FAST).unwrap();
        let blob = c.account.seal_private(b"secret", b"recovery_auth");
        assert_eq!(&c.account.open_private(&blob, b"recovery_auth").unwrap()[..], b"secret");
        assert!(c.account.open_private(&blob, b"other").is_err());
        let json = serde_json::to_value(&c.blobs).unwrap();
        assert!(json["enc_account_key"].is_string());
        assert_eq!(serde_json::from_value::<AccountBlobs>(json).unwrap(), c.blobs);
    }

    #[test]
    fn fingerprint_shape() {
        let fp = fingerprint(&[9; 32]);
        assert_eq!(fp, fingerprint(&[9; 32]));
        assert_ne!(fp, fingerprint(&[8; 32]));
        let groups: Vec<&str> = fp.split('-').collect();
        assert_eq!(groups.len(), 5);
        assert!(groups.iter().all(|g| g.len() == 5));
    }
}
