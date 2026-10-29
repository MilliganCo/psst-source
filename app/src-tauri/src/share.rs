//! Shared folders: create, members (keys checked trust-on-first-use), roles,
//! removal followed by key rotation so a removed member cannot read new records.

use std::collections::HashMap;
use std::sync::Mutex;

use chrono::Utc;
use data_encoding::BASE64;
use pwd_core::account::fingerprint;
use pwd_core::collection::{encrypt_record, CollectionKey};
use pwd_core::model::Meta;
use pwd_core::proto::*;
use serde::Serialize;
use uuid::Uuid;

use crate::store::CollectionRow;
use crate::sync::{self, client_for, lock};
use crate::vault::{io, meta_writable, write_row, Col, VResult, Vault, VaultError};

#[derive(Serialize, Debug, Clone)]
pub struct MemberView {
    pub user_id: Uuid,
    pub username: String,
    pub role: String,
    /// 5 groups of 5 characters, to compare by voice.
    pub fingerprint: String,
    /// The key differs from the one this device saw before.
    pub key_changed: bool,
    pub me: bool,
}

/// Percent-encodes a path segment (usernames may contain spaces or Cyrillic).
fn segment(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

impl Vault {
    pub fn create_collection(&mut self, name: &str) -> VResult<Uuid> {
        let name = name.trim();
        if name.is_empty() {
            return Err(VaultError::Invalid("folder name is required".into()));
        }
        let Vault { store, session, .. } = self;
        let s = session.as_mut().ok_or(VaultError::Locked)?;
        let id = Uuid::new_v4();
        let key = CollectionKey::generate();
        let me = s.account.public_key();
        store.put_collection(&CollectionRow {
            id,
            kind: "shared".into(),
            role: "owner".into(),
            key_version: key.version,
            sealed_ck: key.seal_for(id, &me, &s.account)?,
            granted_by: me,
            rev: 0,
            dirty: true,
        })?;
        let meta = Meta { name: name.into(), labels: vec![] };
        write_row(store, &key, id, id, &meta, Utc::now())?;
        s.cols.insert(id, Col { key, meta, meta_ok: true, kind: "shared".into(), role: "owner".into() });
        Ok(id)
    }

    pub fn rename_collection(&mut self, id: Uuid, name: &str) -> VResult<()> {
        let name = name.trim();
        if name.is_empty() {
            return Err(VaultError::Invalid("folder name is required".into()));
        }
        let Vault { store, session, .. } = self;
        let s = session.as_mut().ok_or(VaultError::Locked)?;
        let col = s.cols.get_mut(&id).ok_or(VaultError::NotFound)?;
        meta_writable(col)?;
        col.meta.name = name.into();
        write_row(store, &col.key, id, id, &col.meta, Utc::now())
    }

    /// Trust on first use: remembers a user's key the first time; true if it changed since.
    fn key_changed(&self, username: &str, pk: &[u8; 32]) -> VResult<bool> {
        let mut known: HashMap<String, String> = match self.store.get_kv("known_keys")? {
            Some(json) => serde_json::from_str(&json).map_err(io)?,
            None => HashMap::new(),
        };
        let encoded = BASE64.encode(pk);
        match known.get(&username.to_lowercase()) {
            Some(old) => Ok(*old != encoded),
            None => {
                known.insert(username.to_lowercase(), encoded);
                self.store.set_kv("known_keys", &serde_json::to_string(&known).map_err(io)?)?;
                Ok(false)
            }
        }
    }

    fn owned_col(&self, id: Uuid) -> VResult<&Col> {
        let col = self.session()?.cols.get(&id).ok_or(VaultError::NotFound)?;
        if col.role != "owner" {
            return Err(VaultError::Invalid("only the folder owner can manage members".into()));
        }
        Ok(col)
    }

    fn grant(&self, collection: Uuid, member_pk: &[u8; 32]) -> VResult<(u32, Vec<u8>)> {
        let col = self.owned_col(collection)?;
        Ok((col.key.version, col.key.seal_for(collection, member_pk, &self.session()?.account)?))
    }

    /// New key for the folder: a grant for every remaining member (keys checked against the ones
    /// seen before, so the server cannot slip in its own) and every record re-encrypted.
    fn rotation(&self, collection: Uuid, members: &[Member], remove: Vec<Uuid>) -> VResult<RotateReq> {
        for m in members {
            if self.key_changed(&m.username, &m.public_key)? {
                return Err(VaultError::KeyChanged(m.username.clone()));
            }
        }
        let col = self.owned_col(collection)?;
        if !col.meta_ok {
            return Err(VaultError::Invalid("folder metadata is unreadable".into()));
        }
        let s = self.session()?;
        let key = col.key.rotate()?;
        let grants = members
            .iter()
            .map(|m| Ok(Grant { user_id: m.user_id, sealed_ck: key.seal_for(collection, &m.public_key, &s.account)? }))
            .collect::<VResult<_>>()?;
        let rev = |id: Uuid| -> VResult<i64> { Ok(self.store.item_row(id)?.map_or(0, |r| r.rev)) };
        let mut items = vec![RotatedItem {
            id: collection,
            rev: rev(collection)?,
            blob: encrypt_record(&key, collection, collection, &col.meta)?,
        }];
        for (id, (cid, item)) in &s.items {
            if *cid == collection {
                items.push(RotatedItem { id: *id, rev: rev(*id)?, blob: encrypt_record(&key, collection, *id, item)? });
            }
        }
        Ok(RotateReq { key_version: key.version, remove, grants, items })
    }
}

pub async fn members(v: &Mutex<Vault>, id: Uuid) -> VResult<Vec<MemberView>> {
    let unsynced = lock(v).store.collections()?.iter().any(|c| c.id == id && c.dirty);
    if unsynced {
        sync::run(v).await?; // a just-created folder must reach the server first
    }
    let (client, info) = client_for(v).await?;
    let list: Vec<Member> = client.get(&format!("/api/collections/{id}/members")).await?;
    let vault = lock(v);
    list.into_iter()
        .map(|m| {
            Ok(MemberView {
                key_changed: vault.key_changed(&m.username, &m.public_key)?,
                fingerprint: fingerprint(&m.public_key),
                me: m.user_id == info.user_id,
                user_id: m.user_id,
                username: m.username,
                role: m.role,
            })
        })
        .collect()
}

pub async fn add_member(v: &Mutex<Vault>, id: Uuid, username: &str, role: &str) -> VResult<()> {
    sync::run(v).await?; // the folder must exist on the server first
    let (client, _) = client_for(v).await?;
    let user: UserKey = client.get(&format!("/api/users/{}", segment(username.trim()))).await.map_err(|e| match e {
        VaultError::Server(m) if m == "no such user" => VaultError::Invalid("no such user".into()),
        e => e,
    })?;
    let (key_version, sealed_ck) = {
        let vault = lock(v);
        if vault.key_changed(&user.username, &user.public_key)? {
            return Err(VaultError::KeyChanged(user.username));
        }
        vault.grant(id, &user.public_key)?
    };
    let req = PutMemberReq { role: role.into(), key_version, sealed_ck };
    let _: RevResp = client.put(&format!("/api/collections/{id}/members/{}", user.user_id), &req).await?;
    Ok(())
}

pub async fn set_role(v: &Mutex<Vault>, id: Uuid, user_id: Uuid, role: &str) -> VResult<()> {
    let (client, _) = client_for(v).await?;
    let list: Vec<Member> = client.get(&format!("/api/collections/{id}/members")).await?;
    let m = list.iter().find(|m| m.user_id == user_id).ok_or(VaultError::NotFound)?;
    let (key_version, sealed_ck) = {
        let vault = lock(v);
        if vault.key_changed(&m.username, &m.public_key)? {
            return Err(VaultError::KeyChanged(m.username.clone()));
        }
        vault.grant(id, &m.public_key)?
    };
    let req = PutMemberReq { role: role.into(), key_version, sealed_ck };
    let _: RevResp = client.put(&format!("/api/collections/{id}/members/{user_id}"), &req).await?;
    Ok(())
}

/// Removes a member and rotates the folder key in one server transaction, so either both happen
/// (they cannot read anything written afterwards) or neither does and it can simply be retried.
pub async fn remove_member(v: &Mutex<Vault>, id: Uuid, user_id: Uuid) -> VResult<()> {
    sync::run(v).await?; // rotation must cover exactly what the server has
    let (client, _) = client_for(v).await?;
    let members: Vec<Member> = client.get(&format!("/api/collections/{id}/members")).await?;
    if !members.iter().any(|m| m.user_id == user_id) {
        return Err(VaultError::NotFound);
    }
    let remaining: Vec<Member> = members.into_iter().filter(|m| m.user_id != user_id).collect();
    let req = lock(v).rotation(id, &remaining, vec![user_id])?;
    let _: RevResp = client.post(&format!("/api/collections/{id}/rotate"), &req).await?;
    sync::run(v).await.map(|_| ())
}

/// Leave a folder someone else shared with you.
pub async fn leave(v: &Mutex<Vault>, id: Uuid) -> VResult<()> {
    let (client, info) = client_for(v).await?;
    let _: RevResp = client.delete(&format!("/api/collections/{id}/members/{}", info.user_id)).await?;
    sync::run(v).await.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_refuses_a_substituted_member_key() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = Vault::open(&dir.path().join("vault.db")).unwrap();
        v.create_local("alice", "пароль алисы").unwrap();
        let col = v.create_collection("Семья").unwrap();
        let bob = |pk: u8| Member { user_id: Uuid::nil(), username: "bob".into(), role: "editor".into(), public_key: [pk; 32] };
        assert!(!v.key_changed("bob", &[1; 32]).unwrap(), "first sight is trusted");
        assert!(v.rotation(col, &[bob(1)], vec![]).is_ok());
        assert_eq!(v.rotation(col, &[bob(2)], vec![]).unwrap_err(), VaultError::KeyChanged("bob".into()));
    }

    #[test]
    fn encodes_path_segments() {
        assert_eq!(super::segment("bob"), "bob");
        assert_eq!(super::segment("a b/?"), "a%20b%2F%3F");
        assert_eq!(super::segment("ж"), "%D0%B6");
    }
}
