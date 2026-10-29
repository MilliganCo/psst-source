//! Collection keys, sharing via sealed boxes, and per-record encryption bound to ids.

use crypto_box::aead::{Aead, AeadCore};
use crypto_box::{Nonce, PublicKey, SalsaBox, SecretKey};
use rand_core::OsRng;
use serde::{de::DeserializeOwned, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::account::UnlockedAccount;
use crate::aead;
use crate::kdf::{random_bytes, Key};
use crate::{Error, Result};

const NONCE_LEN: usize = 24;
/// Granted payload: collection_id(16) | key_version(4, BE) | key(32).
const GRANT_LEN: usize = 52;

/// Symmetric key of a collection plus its rotation counter.
pub struct CollectionKey {
    pub key: Key,
    pub version: u32,
}

/// Authenticated box between `own` and `peer`; refuses low-order peer keys,
/// whose shared secret would be known to everyone.
fn grant_box(peer: &[u8; 32], own: &SecretKey) -> Result<SalsaBox> {
    let own_dh = x25519_dalek::StaticSecret::from(own.to_bytes());
    if !own_dh.diffie_hellman(&x25519_dalek::PublicKey::from(*peer)).was_contributory() {
        return Err(Error::Format("weak public key"));
    }
    Ok(SalsaBox::new(&PublicKey::from(*peer), own))
}

impl CollectionKey {
    pub fn generate() -> Self {
        Self { key: Zeroizing::new(random_bytes()), version: 1 }
    }

    /// Fresh random key with the next version; used after removing a member.
    pub fn rotate(&self) -> Result<Self> {
        let version = self.version.checked_add(1).ok_or(Error::Format("key version overflow"))?;
        Ok(Self { key: Zeroizing::new(random_bytes()), version })
    }

    /// Gives this key to `member`, authenticated by `granter`'s key pair and bound to the collection.
    /// The personal collection is granted by the owner to themselves.
    pub fn seal_for(&self, collection_id: Uuid, member: &[u8; 32], granter: &UnlockedAccount) -> Result<Vec<u8>> {
        let nonce = SalsaBox::generate_nonce(&mut OsRng);
        let mut msg = Zeroizing::new(Vec::with_capacity(GRANT_LEN));
        msg.extend_from_slice(collection_id.as_bytes());
        msg.extend_from_slice(&self.version.to_be_bytes());
        msg.extend_from_slice(&self.key[..]);
        let ct = grant_box(member, granter.secret_key())?
            .encrypt(&nonce, msg.as_slice())
            .map_err(|_| Error::Format("grant encryption failed"))?;
        Ok([nonce.as_slice(), &ct].concat())
    }

    /// Opens a key granted to `account` by the holder of the `granter` public key.
    pub fn open_sealed(
        sealed: &[u8],
        collection_id: Uuid,
        version: u32,
        granter: &[u8; 32],
        account: &UnlockedAccount,
    ) -> Result<Self> {
        if sealed.len() < NONCE_LEN {
            return Err(Error::Format("truncated key grant"));
        }
        let (nonce, ct) = sealed.split_at(NONCE_LEN);
        let msg = Zeroizing::new(
            grant_box(granter, account.secret_key())?
                .decrypt(Nonce::from_slice(nonce), ct)
                .map_err(|_| Error::Decrypt)?,
        );
        if msg.len() != GRANT_LEN
            || msg[..16] != collection_id.as_bytes()[..]
            || msg[16..20] != version.to_be_bytes()
        {
            return Err(Error::Decrypt);
        }
        let key: [u8; 32] = msg[20..].try_into().expect("length checked");
        Ok(Self { key: Zeroizing::new(key), version })
    }
}

/// AAD = item_id ‖ collection_id ‖ key_version (big-endian).
fn aad(collection_id: Uuid, item_id: Uuid, version: u32) -> [u8; 36] {
    let mut a = [0u8; 36];
    a[..16].copy_from_slice(item_id.as_bytes());
    a[16..32].copy_from_slice(collection_id.as_bytes());
    a[32..].copy_from_slice(&version.to_be_bytes());
    a
}

pub fn encrypt_record<T: Serialize>(ck: &CollectionKey, collection_id: Uuid, item_id: Uuid, record: &T) -> Result<Vec<u8>> {
    let json = Zeroizing::new(serde_json::to_vec(record)?);
    Ok(aead::seal(&ck.key, &json, &aad(collection_id, item_id, ck.version)))
}

pub fn decrypt_record<T: DeserializeOwned>(ck: &CollectionKey, collection_id: Uuid, item_id: Uuid, blob: &[u8]) -> Result<T> {
    let json = aead::open(&ck.key, blob, &aad(collection_id, item_id, ck.version))?;
    Ok(serde_json::from_slice(&json)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::create_account;
    use crate::kdf::KdfParams;
    use crate::model::{Item, ItemKind, Label, LabelColor, Meta};
    use crate::Error;
    use chrono::Utc;

    fn item() -> Item {
        let mut i = Item::new(ItemKind::Login, "Банк", Utc::now());
        i.password = "s3cr3t".into();
        i
    }

    #[test]
    fn member_opens_shared_key_and_reads_items() {
        let alice = create_account("a", KdfParams::FAST).unwrap();
        let bob = create_account("b", KdfParams::FAST).unwrap();
        let carol = create_account("c", KdfParams::FAST).unwrap();
        let ck = CollectionKey::generate();
        assert_eq!(ck.version, 1);
        let (col, id) = (Uuid::new_v4(), Uuid::new_v4());
        let original = item();
        let blob = encrypt_record(&ck, col, id, &original).unwrap();

        let granted = ck.seal_for(col, &bob.blobs.public_key, &alice.account).unwrap();
        let bob_ck = CollectionKey::open_sealed(&granted, col, 1, &alice.blobs.public_key, &bob.account).unwrap();
        assert_eq!(*bob_ck.key, *ck.key);
        let read: Item = decrypt_record(&bob_ck, col, id, &blob).unwrap();
        assert_eq!(read, original);

        let to_self = ck.seal_for(col, &alice.blobs.public_key, &alice.account).unwrap();
        let own = CollectionKey::open_sealed(&to_self, col, 1, &alice.blobs.public_key, &alice.account).unwrap();
        assert_eq!(*own.key, *ck.key);

        assert!(matches!(
            CollectionKey::open_sealed(&granted, col, 1, &alice.blobs.public_key, &carol.account),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn server_cannot_substitute_granted_key() {
        let alice = create_account("a", KdfParams::FAST).unwrap();
        let bob = create_account("b", KdfParams::FAST).unwrap();
        let mallory = create_account("m", KdfParams::FAST).unwrap();
        let col = Uuid::new_v4();
        let forged = CollectionKey::generate().seal_for(col, &bob.blobs.public_key, &mallory.account).unwrap();
        assert!(matches!(
            CollectionKey::open_sealed(&forged, col, 1, &alice.blobs.public_key, &bob.account),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn granted_key_is_bound_to_collection_and_version() {
        let alice = create_account("a", KdfParams::FAST).unwrap();
        let col = Uuid::new_v4();
        let granted = CollectionKey::generate().seal_for(col, &alice.blobs.public_key, &alice.account).unwrap();
        let me = &alice.blobs.public_key;
        assert!(CollectionKey::open_sealed(&granted, Uuid::new_v4(), 1, me, &alice.account).is_err());
        assert!(CollectionKey::open_sealed(&granted, col, 2, me, &alice.account).is_err());
        assert!(CollectionKey::open_sealed(&granted[..10], col, 1, me, &alice.account).is_err());
    }

    #[test]
    fn rejects_low_order_member_key() {
        let alice = create_account("a", KdfParams::FAST).unwrap();
        let ck = CollectionKey::generate();
        assert!(matches!(ck.seal_for(Uuid::new_v4(), &[0; 32], &alice.account), Err(Error::Format(_))));
    }

    #[test]
    fn rotate_at_max_version_is_error() {
        let ck = CollectionKey { key: CollectionKey::generate().key, version: u32::MAX };
        assert!(ck.rotate().is_err());
    }

    #[test]
    fn blob_is_bound_to_ids() {
        let ck = CollectionKey::generate();
        let (col, id) = (Uuid::new_v4(), Uuid::new_v4());
        let blob = encrypt_record(&ck, col, id, &item()).unwrap();
        assert!(matches!(decrypt_record::<Item>(&ck, col, Uuid::new_v4(), &blob), Err(Error::Decrypt)));
        assert!(matches!(decrypt_record::<Item>(&ck, Uuid::new_v4(), id, &blob), Err(Error::Decrypt)));
    }

    #[test]
    fn rotation_locks_out_old_key() {
        let old = CollectionKey::generate();
        let new = old.rotate().unwrap();
        assert_eq!(new.version, 2);
        assert_ne!(*new.key, *old.key);
        let (col, id) = (Uuid::new_v4(), Uuid::new_v4());
        let blob = encrypt_record(&new, col, id, &item()).unwrap();
        assert!(matches!(decrypt_record::<Item>(&old, col, id, &blob), Err(Error::Decrypt)));
        let old_key_new_version = CollectionKey { key: old.key.clone(), version: 2 };
        assert!(matches!(decrypt_record::<Item>(&old_key_new_version, col, id, &blob), Err(Error::Decrypt)));
        let same_key_wrong_version = CollectionKey { key: new.key.clone(), version: 1 };
        assert!(matches!(decrypt_record::<Item>(&same_key_wrong_version, col, id, &blob), Err(Error::Decrypt)));
    }

    #[test]
    fn meta_roundtrip() {
        let ck = CollectionKey::generate();
        let col = Uuid::new_v4();
        let meta = Meta {
            name: "Семья".into(),
            labels: vec![Label { id: Uuid::new_v4(), name: "банк".into(), color: LabelColor::Green }],
        };
        let blob = encrypt_record(&ck, col, col, &meta).unwrap();
        assert_eq!(decrypt_record::<Meta>(&ck, col, col, &blob).unwrap(), meta);
    }
}
