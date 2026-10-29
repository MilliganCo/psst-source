//! Encrypted backup file (.pwbak): every live password and note with folder names and labels,
//! sealed with its own backup password, so it can be stored anywhere and restored without a server.
//!
//! Layout: `PWBAK1` ‖ salt (16) ‖ m_kib, t, p (u32 LE each) ‖ XChaCha20-Poly1305 blob of the JSON.
//! The whole header is the AEAD's associated data: changing salt or costs fails decryption.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::kdf::{self, KdfParams};
use crate::model::{Item, Label};
use crate::{aead, Error, Result};

pub const MAGIC: &[u8] = b"PWBAK1";
const HEADER: usize = 6 + 16 + 12;

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Backup {
    pub created_at: DateTime<Utc>,
    pub folders: Vec<BackupFolder>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct BackupFolder {
    pub name: String,
    #[serde(default)]
    pub labels: Vec<Label>,
    pub items: Vec<BackupItem>,
}

/// An item with its original id (files point at their entry by id). Backups made before
/// attachments existed have no ids.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct BackupItem {
    #[serde(default)]
    pub id: Option<uuid::Uuid>,
    #[serde(flatten)]
    pub item: Item,
}

pub fn seal(backup: &Backup, password: &str) -> Result<Vec<u8>> {
    seal_with(backup, password, KdfParams::DEFAULT)
}

pub(crate) fn seal_with(backup: &Backup, password: &str, params: KdfParams) -> Result<Vec<u8>> {
    let salt: [u8; 16] = kdf::random_bytes();
    let mut out = Vec::with_capacity(HEADER);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&salt);
    for v in [params.m_kib, params.t, params.p] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    let key = kdf::argon2id(password.as_bytes(), &salt, params)?;
    let json = zeroize::Zeroizing::new(serde_json::to_vec(backup)?);
    let blob = aead::seal(&key, &json, &out);
    out.extend_from_slice(&blob);
    Ok(out)
}

pub fn open(bytes: &[u8], password: &str) -> Result<Backup> {
    if bytes.len() <= HEADER || !bytes.starts_with(MAGIC) {
        return Err(Error::Format("not a Passwords backup"));
    }
    let (header, blob) = bytes.split_at(HEADER);
    let num = |at: usize| u32::from_le_bytes(header[at..at + 4].try_into().expect("4 bytes"));
    let params = KdfParams { m_kib: num(22), t: num(26), p: num(30) };
    let key = kdf::argon2id(password.as_bytes(), &header[6..22], params)?;
    let json = aead::open(&key, blob, header)?;
    Ok(serde_json::from_slice(&json)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ItemKind, Label, LabelColor};
    use chrono::TimeZone;
    use uuid::Uuid;

    fn sample() -> Backup {
        let t = Utc.with_ymd_and_hms(2026, 10, 5, 12, 0, 0).unwrap();
        let mut gh = Item::new(ItemKind::Login, "GitHub", t);
        gh.password = "gh-Секрет-42".into();
        gh.totp = Some("JBSWY3DPEHPK3PXP".into());
        let work = Label { id: Uuid::new_v4(), name: "работа".into(), color: LabelColor::Blue };
        gh.labels = vec![work.id];
        Backup {
            created_at: t,
            folders: vec![
                BackupFolder { name: "Личное".into(), labels: vec![work], items: vec![BackupItem { id: Some(Uuid::new_v4()), item: gh }] },
                BackupFolder { name: "Семья".into(), labels: vec![], items: vec![BackupItem { id: None, item: Item::new(ItemKind::Note, "Wi-Fi", t) }] },
            ],
        }
    }

    #[test]
    fn roundtrip() {
        let b = sample();
        let file = seal_with(&b, "пароль копии", KdfParams::FAST).unwrap();
        assert!(file.starts_with(MAGIC));
        assert_eq!(open(&file, "пароль копии").unwrap(), b);
    }

    #[test]
    fn backups_from_before_attachments_still_read() {
        let old = r#"{"name":"Личное","labels":[],"items":[{"kind":"login","title":"GitHub","password":"p","created_at":"2026-10-05T12:00:00Z","updated_at":"2026-10-05T12:00:00Z"}]}"#;
        let f: BackupFolder = serde_json::from_str(old).unwrap();
        assert_eq!((f.items[0].id, f.items[0].item.title.as_str()), (None, "GitHub"));
    }

    #[test]
    fn wrong_password_and_tampering_fail() {
        let file = seal_with(&sample(), "пароль копии", KdfParams::FAST).unwrap();
        assert!(matches!(open(&file, "не тот"), Err(Error::Decrypt)));
        let mut body = file.clone();
        *body.last_mut().unwrap() ^= 1;
        assert!(matches!(open(&body, "пароль копии"), Err(Error::Decrypt)));
        let mut header = file.clone();
        header[MAGIC.len()] ^= 1; // salt is authenticated too
        assert!(matches!(open(&header, "пароль копии"), Err(Error::Decrypt)));
    }

    #[test]
    fn rejects_other_files_and_absurd_params() {
        assert!(matches!(open(b"name,url,username,password", "x"), Err(Error::Format(_))));
        assert!(matches!(open(&MAGIC[..4], "x"), Err(Error::Format(_))));
        let mut file = seal_with(&sample(), "p", KdfParams::FAST).unwrap();
        let m = MAGIC.len() + 16;
        file[m..m + 4].copy_from_slice(&u32::MAX.to_le_bytes()); // 4 TiB of memory
        assert!(matches!(open(&file, "p"), Err(Error::KdfParams)));
    }
}
