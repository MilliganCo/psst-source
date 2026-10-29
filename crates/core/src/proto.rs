//! Wire types shared by `pwd-server` and the app. Bytes travel as base64 strings.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::account::AccountBlobs;
use crate::kdf::KdfParams;

/// `#[serde(with = "b64")]` for `Vec<u8>` and fixed-size arrays.
pub mod b64 {
    use data_encoding::BASE64;
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer, T: AsRef<[u8]>>(v: &T, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&BASE64.encode(v.as_ref()))
    }

    /// Base64 text; also accepts a JSON array of numbers (local vaults written before base64).
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        Text(String),
        Bytes(Vec<u8>),
    }

    pub fn deserialize<'de, D: Deserializer<'de>, T: TryFrom<Vec<u8>>>(d: D) -> Result<T, D::Error> {
        let bytes = match Repr::deserialize(d)? {
            Repr::Text(s) => BASE64.decode(s.as_bytes()).map_err(D::Error::custom)?,
            Repr::Bytes(b) => b,
        };
        T::try_from(bytes).map_err(|_| D::Error::custom("wrong byte length"))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PreloginReq {
    pub username: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PreloginResp {
    #[serde(with = "b64")]
    pub kdf_salt: [u8; 16],
    pub kdf_params: KdfParams,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RegisterReq {
    pub invite: String,
    pub username: String,
    #[serde(with = "b64")]
    pub auth_key: [u8; 32],
    #[serde(with = "b64")]
    pub recovery_auth: [u8; 32],
    pub account: AccountBlobs,
    /// Device name shown in the session list ("Windows · DESKTOP-1").
    #[serde(default)]
    pub device: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LoginReq {
    pub username: String,
    #[serde(with = "b64")]
    pub auth_key: [u8; 32],
    #[serde(default)]
    pub device: String,
}

/// One logged-in device. `id` is a short hash prefix, not the token.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SessionInfo {
    pub id: String,
    pub device: String,
    pub created_at: i64,
    pub last_seen: i64,
    pub current: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SessionResp {
    pub token: String,
    pub user_id: Uuid,
    pub username: String,
    pub is_admin: bool,
    pub account: AccountBlobs,
}

/// Password change: new auth key and re-wrapped blobs.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccountUpdateReq {
    #[serde(with = "b64")]
    pub auth_key: [u8; 32],
    pub account: AccountBlobs,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct CollectionWire {
    pub id: Uuid,
    pub kind: String,
    pub role: String,
    pub key_version: u32,
    #[serde(with = "b64")]
    pub sealed_ck: Vec<u8>,
    #[serde(with = "b64")]
    pub granted_by: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ItemWire {
    pub id: Uuid,
    pub collection_id: Uuid,
    pub key_version: u32,
    #[serde(with = "b64")]
    pub blob: Vec<u8>,
    pub deleted: bool,
    pub rev: i64,
    pub updated_at: String,
    /// Username of the last writer, as the server saw it (empty from servers before 0.7).
    #[serde(default)]
    pub author: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SyncResp {
    pub rev: i64,
    pub collections: Vec<CollectionWire>,
    pub items: Vec<ItemWire>,
    /// Collections this user lost access to (or that were deleted).
    pub removed: Vec<Uuid>,
}

/// `base_rev` is the rev the client last saw (0 for a new item); a mismatch returns 409 with the current item.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PutItemReq {
    pub collection_id: Uuid,
    pub key_version: u32,
    #[serde(with = "b64")]
    pub blob: Vec<u8>,
    pub deleted: bool,
    pub base_rev: i64,
    pub updated_at: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RevResp {
    pub rev: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreateCollectionReq {
    pub id: Uuid,
    pub kind: String,
    pub key_version: u32,
    #[serde(with = "b64")]
    pub sealed_ck: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct UserKey {
    pub user_id: Uuid,
    pub username: String,
    #[serde(with = "b64")]
    pub public_key: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Member {
    pub user_id: Uuid,
    pub username: String,
    pub role: String,
    #[serde(with = "b64")]
    pub public_key: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PutMemberReq {
    pub role: String,
    pub key_version: u32,
    #[serde(with = "b64")]
    pub sealed_ck: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Grant {
    pub user_id: Uuid,
    #[serde(with = "b64")]
    pub sealed_ck: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RotatedItem {
    pub id: Uuid,
    /// Rev the owner re-encrypted from; a newer server rev means someone edited meanwhile.
    pub rev: i64,
    #[serde(with = "b64")]
    pub blob: Vec<u8>,
}

/// New collection key in one transaction: members in `remove` lose access, every remaining member
/// gets a grant, every live item is re-encrypted.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RotateReq {
    pub key_version: u32,
    #[serde(default)]
    pub remove: Vec<Uuid>,
    pub grants: Vec<Grant>,
    pub items: Vec<RotatedItem>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InviteReq {
    pub is_admin: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InviteResp {
    pub code: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AdminUser {
    pub id: Uuid,
    pub username: String,
    pub is_admin: bool,
    pub disabled: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ErrorResp {
    pub error: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_travel_as_base64() {
        let k = UserKey { user_id: Uuid::nil(), username: "a".into(), public_key: [255; 32] };
        let json = serde_json::to_value(&k).unwrap();
        assert!(json["public_key"].as_str().unwrap().starts_with("////"));
        assert_eq!(serde_json::from_value::<UserKey>(json).unwrap(), k);
        let short = serde_json::json!({"user_id": Uuid::nil(), "username": "a", "public_key": "AAAA"});
        assert!(serde_json::from_value::<UserKey>(short).is_err());
    }

    #[test]
    fn accepts_legacy_number_arrays() {
        // Phase-2 vaults stored account bytes as JSON arrays.
        let old = serde_json::json!({"user_id": Uuid::nil(), "username": "a", "public_key": vec![7u8; 32]});
        assert_eq!(serde_json::from_value::<UserKey>(old).unwrap().public_key, [7; 32]);
    }
}
