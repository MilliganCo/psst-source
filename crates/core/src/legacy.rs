//! Read-only import of the v1 Python vault format (`BRNGVLT1`).
//!
//! Layout (big-endian): magic(8) version:u16 kdf_type:u8 memory_cost:u32 time_cost:u32
//! parallelism:u8 salt(32) dek_nonce(12) wrapped_dek_len:u16 wrapped_dek payload_len:u32,
//! then payload = nonce(12) ‖ AES-256-GCM ciphertext of JSON `{entries, metadata}`.
//! KEK = Argon2id(password), DEK = AES-256-GCM-unwrap(KEK).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use chrono::{DateTime, NaiveDateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::kdf::{argon2id, KdfParams};
use crate::model::{Item, ItemKind, Label, LabelColor};
use crate::{Error, Result};

const MAGIC: &[u8] = b"BRNGVLT1";

/// Items and labels recovered from a legacy vault, ready to go into one collection.
pub struct LegacyImport {
    pub labels: Vec<Label>,
    pub items: Vec<(Uuid, Item)>,
}

#[derive(Deserialize)]
struct Payload {
    #[serde(default)]
    entries: Vec<Entry>,
}

// Per-field defaults: a container-level `#[serde(default)]` would move fields out of a `Drop` type.
#[derive(Deserialize)]
struct Entry {
    #[serde(default)]
    title: String,
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    category: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    created_at: String,
    #[serde(default)]
    updated_at: String,
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&end| end <= self.data.len())
            .ok_or(Error::Format("legacy vault is truncated"))?;
        let bytes = &self.data[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("took 2 bytes")))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("took 4 bytes")))
    }
}

/// Decrypts a v1 vault file and converts it. Wrong password → `Error::Decrypt`.
pub fn import(file: &[u8], password: &str) -> Result<LegacyImport> {
    let mut r = Reader { data: file, pos: 0 };
    if r.take(MAGIC.len()).ok() != Some(MAGIC) {
        return Err(Error::Format("not a legacy vault file"));
    }
    if r.u16()? != 1 {
        return Err(Error::Format("unsupported legacy vault version"));
    }
    if r.u8()? != 1 {
        return Err(Error::Format("unsupported legacy KDF"));
    }
    let m_kib = r.u32()?;
    let t = r.u32()?;
    let p = u32::from(r.u8()?);
    let salt = r.take(32)?;
    let dek_nonce = r.take(12)?;
    let wrapped_len = usize::from(r.u16()?);
    let wrapped_dek = r.take(wrapped_len)?;
    let payload_len = r.u32()? as usize;
    let payload = r.take(payload_len)?;
    if payload.len() < 12 {
        return Err(Error::Format("legacy payload is truncated"));
    }

    let kek = argon2id(password.as_bytes(), salt, KdfParams { m_kib, t, p })?;
    let dek = Zeroizing::new(aes_open(&kek[..], dek_nonce, wrapped_dek)?);
    let json = Zeroizing::new(aes_open(&dek, &payload[..12], &payload[12..])?);
    let payload: Payload = serde_json::from_slice(&json)?;
    Ok(convert(payload.entries))
}

fn aes_open(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| Error::Format("legacy key must be 32 bytes"))?
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| Error::Decrypt)
}

/// `category` and `tags` become labels (deduplicated by trimmed name, empty names skipped).
fn convert(entries: Vec<Entry>) -> LegacyImport {
    let mut labels: Vec<Label> = Vec::new();
    let mut items = Vec::new();
    for mut e in entries {
        let mut item_labels = Vec::new();
        for name in std::iter::once(&e.category).chain(&e.tags) {
            let name = name.trim();
            if name.is_empty() {
                continue;
            }
            let id = match labels.iter().find(|l| l.name == name) {
                Some(l) => l.id,
                None => {
                    let color = LabelColor::ALL[labels.len() % LabelColor::ALL.len()];
                    let label = Label { id: Uuid::new_v4(), name: name.to_string(), color };
                    let id = label.id;
                    labels.push(label);
                    id
                }
            };
            if !item_labels.contains(&id) {
                item_labels.push(id);
            }
        }

        let created_at = parse_time(&e.created_at).unwrap_or_else(Utc::now);
        let mut item = Item::new(ItemKind::Login, std::mem::take(&mut e.title), created_at);
        item.username = std::mem::take(&mut e.username);
        item.password = std::mem::take(&mut e.password);
        if !e.url.trim().is_empty() {
            item.urls.push(std::mem::take(&mut e.url));
        }
        item.notes = std::mem::take(&mut e.notes);
        item.labels = item_labels;
        item.updated_at = parse_time(&e.updated_at).unwrap_or(created_at);

        // Fresh ids: re-importing the same file must never overwrite items edited since.
        items.push((Uuid::new_v4(), item));
    }
    LegacyImport { labels, items }
}

/// Python wrote `datetime.utcnow().isoformat()`: naive UTC with optional fraction.
fn parse_time(s: &str) -> Option<DateTime<Utc>> {
    s.parse::<DateTime<Utc>>()
        .ok()
        .or_else(|| s.parse::<NaiveDateTime>().ok().map(|n| n.and_utc()))
}
