//! Vault logic without Tauri: account, collections, items, labels on top of the local store.

use std::collections::HashMap;
use std::path::Path;

use chrono::{DateTime, Utc};
use pwd_core::account::{self, AccountBlobs, UnlockedAccount};
use pwd_core::backup::{self, Backup, BackupFolder, BackupItem};
use pwd_core::collection::{decrypt_record, encrypt_record, CollectionKey};
use pwd_core::kdf::KdfParams;
use pwd_core::legacy;
use pwd_core::model::{Item, ItemKind, Label, Meta};
use serde::{Deserialize, Serialize, Serializer};
use uuid::Uuid;

use crate::store::{CollectionRow, ItemRow, Store};

/// Days a deleted item stays in the trash before it is purged on unlock.
const TRASH_DAYS: i64 = 30;

#[derive(Debug, PartialEq, Eq)]
pub enum VaultError {
    Locked,
    WrongPassword,
    NotFound,
    Exists,
    ReadOnly,
    Invalid(String),
    Io(String),
    /// Server unreachable or TLS refused (message for logs).
    Offline(String),
    /// Server session expired or revoked: log in again.
    SessionExpired,
    /// Server rejected the request.
    Server(String),
    /// A member's public key differs from the one seen before.
    KeyChanged(String),
    /// Too many wrong master passwords in a row: seconds to wait.
    Throttled(u64),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::Locked => f.write_str("locked"),
            VaultError::WrongPassword => f.write_str("wrong_password"),
            VaultError::NotFound => f.write_str("not_found"),
            VaultError::Exists => f.write_str("exists"),
            VaultError::ReadOnly => f.write_str("read_only"),
            VaultError::Invalid(m) => write!(f, "invalid: {m}"),
            VaultError::Io(m) => write!(f, "io: {m}"),
            VaultError::Offline(m) => write!(f, "offline: {m}"),
            VaultError::SessionExpired => f.write_str("session_expired"),
            VaultError::Server(m) => write!(f, "server: {m}"),
            VaultError::KeyChanged(u) => write!(f, "key_changed: {u}"),
            VaultError::Throttled(s) => write!(f, "throttled: {s}"),
        }
    }
}

/// IPC errors travel as their code string.
impl Serialize for VaultError {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl From<rusqlite::Error> for VaultError {
    fn from(e: rusqlite::Error) -> Self {
        VaultError::Io(e.to_string())
    }
}

impl From<pwd_core::Error> for VaultError {
    fn from(e: pwd_core::Error) -> Self {
        match e {
            pwd_core::Error::Invalid(m) => VaultError::Invalid(m.into()),
            other => VaultError::Io(other.to_string()),
        }
    }
}

pub type VResult<T> = Result<T, VaultError>;

#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct Status {
    pub has_account: bool,
    pub unlocked: bool,
    pub username: Option<String>,
    /// Records (or folders) that could not be decrypted on unlock.
    pub corrupt: usize,
}

#[derive(Serialize, Debug, Clone)]
pub struct CollectionView {
    pub id: Uuid,
    pub name: String,
    pub kind: String,
    pub role: String,
    pub labels: Vec<Label>,
    pub count: usize,
}

#[derive(Serialize, Debug, Clone)]
pub struct ItemSummary {
    pub id: Uuid,
    pub collection_id: Uuid,
    pub kind: ItemKind,
    pub title: String,
    pub username: String,
    pub urls: Vec<String>,
    pub labels: Vec<Uuid>,
    pub favorite: bool,
    pub has_password: bool,
    pub has_totp: bool,
    pub deleted: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub history_len: usize,
    /// Password health: guessable, same as in another live item, unchanged for a year.
    pub weak: bool,
    pub reused: bool,
    pub old: bool,
    /// Found in known breaches by the last check in this session (Have I Been Pwned).
    pub pwned: bool,
}

#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct TotpCode {
    pub code: String,
    pub left: u64,
    pub period: u64,
}

#[derive(Serialize, Debug)]
pub struct ItemDetails {
    #[serde(flatten)]
    pub summary: ItemSummary,
    pub notes: String,
    pub history: Vec<DateTime<Utc>>,
    pub attachments: Vec<AttachmentView>,
}

/// Largest attached file.
pub const ATTACHMENT_MAX: usize = 8 * 1024 * 1024;

#[derive(Serialize, Debug, PartialEq, Eq, Clone)]
pub struct AttachmentView {
    pub id: Uuid,
    pub name: String,
    pub size: usize,
    pub added_at: DateTime<Utc>,
}

/// Decoded length of standard padded base64.
fn b64_len(s: &str) -> usize {
    (s.len() / 4 * 3).saturating_sub(s.bytes().rev().take_while(|&b| b == b'=').count())
}

/// A folder with its exportable items and their ids.
type FolderItems<'a> = (&'a Col, Vec<(Uuid, &'a Item)>);

/// Entries, as opposed to chat lines and attached files.
fn is_entry(i: &Item) -> bool {
    matches!(i.kind, ItemKind::Login | ItemKind::Note)
}

/// Editor payload. `password`/`totp`: `None` keeps the stored value, `Some("")` clears it.
#[derive(Deserialize, Debug, Clone)]
pub struct ItemInput {
    pub id: Option<Uuid>,
    pub collection_id: Uuid,
    pub kind: ItemKind,
    pub title: String,
    #[serde(default)]
    pub username: String,
    pub password: Option<String>,
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default)]
    pub notes: String,
    pub totp: Option<String>,
    #[serde(default)]
    pub labels: Vec<Uuid>,
    #[serde(default)]
    pub favorite: bool,
}

pub(crate) struct Col {
    pub(crate) key: CollectionKey,
    pub(crate) meta: Meta,
    /// False if the meta record could not be decrypted: never write it back.
    pub(crate) meta_ok: bool,
    pub(crate) kind: String,
    pub(crate) role: String,
}

pub(crate) struct Session {
    pub(crate) account: UnlockedAccount,
    pub(crate) cols: HashMap<Uuid, Col>,
    pub(crate) items: HashMap<Uuid, (Uuid, Item)>,
    pub(crate) corrupt: Vec<Uuid>,
}

pub struct Vault {
    pub(crate) store: Store,
    pub(crate) session: Option<Session>,
    /// item id -> (updated_at it was scored at, weak): zxcvbn costs ~0.15 ms per password.
    weak_cache: HashMap<Uuid, (DateTime<Utc>, bool)>,
    /// item id -> (updated_at it was checked at, times seen in breaches). Until lock.
    pwned: HashMap<Uuid, (DateTime<Utc>, u64)>,
}

pub(crate) fn io(e: impl std::fmt::Display) -> VaultError {
    VaultError::Io(e.to_string())
}

pub(crate) fn wrong_password(e: pwd_core::Error) -> VaultError {
    match e {
        pwd_core::Error::Decrypt => VaultError::WrongPassword,
        e => e.into(),
    }
}

pub(crate) fn writable(col: &Col) -> VResult<()> {
    if col.role == "viewer" {
        Err(VaultError::ReadOnly)
    } else {
        Ok(())
    }
}

/// Writable and its meta record was readable (so rewriting it loses nothing).
pub(crate) fn meta_writable(col: &Col) -> VResult<()> {
    writable(col)?;
    if col.meta_ok {
        Ok(())
    } else {
        Err(VaultError::Invalid("folder metadata is unreadable".into()))
    }
}

/// Encrypts a record and stores it as a dirty row (keeps the row's rev as the sync base).
pub(crate) fn write_row<T: Serialize>(
    store: &Store,
    key: &CollectionKey,
    collection_id: Uuid,
    id: Uuid,
    record: &T,
    updated_at: DateTime<Utc>,
) -> VResult<()> {
    store.put_item(&ItemRow {
        id,
        collection_id,
        key_version: key.version,
        blob: encrypt_record(key, collection_id, id, record)?,
        deleted: false,
        rev: store.item_rev(id)?,
        dirty: true,
        updated_at: updated_at.to_rfc3339(),
    })?;
    Ok(())
}

const OLD_AFTER_DAYS: i64 = 365;
const FAILURES_KEY: &str = "unlock_failures";

/// Wait after `n` wrong master passwords in a row: none for the first four, then 30 s doubling up to 15 min.
fn throttle_secs(n: u32) -> i64 {
    if n < 5 {
        0
    } else {
        (30i64 << (n - 5).min(5)).min(900)
    }
}

/// Only the first 32 characters are scored: zxcvbn gets slow on long input, and a strong
/// prefix makes the whole password strong.
fn estimate(password: &str, context: &[&str]) -> zxcvbn::Entropy {
    let end = password.char_indices().nth(32).map_or(password.len(), |(n, _)| n);
    zxcvbn::zxcvbn(&password[..end], context)
}

/// zxcvbn score below 3 = cracked within hours offline.
fn is_weak(i: &Item) -> bool {
    estimate(&i.password, &[&i.title, &i.username]).score() < zxcvbn::Score::Three
}

/// (item id, revision, password) to check against breaches.
pub type BreachCandidate = (Uuid, DateTime<Utc>, zeroize::Zeroizing<String>);

/// A breach result counts only for the revision it was checked at.
fn breached(results: &HashMap<Uuid, (DateTime<Utc>, u64)>, id: Uuid, i: &Item) -> bool {
    results.get(&id).is_some_and(|&(at, n)| at == i.updated_at && n > 0)
}

/// Label ids by lowercase name for `names`; missing labels are created in the folder's meta.
fn merge_labels<'a>(col: &mut Col, names: impl Iterator<Item = &'a str>) -> HashMap<String, Uuid> {
    let mut by_name: HashMap<String, Uuid> = col.meta.labels.iter().map(|l| (l.name.to_lowercase(), l.id)).collect();
    for name in names.filter(|n| !n.is_empty()) {
        by_name.entry(name.to_lowercase()).or_insert_with(|| {
            let color = pwd_core::model::LabelColor::ALL[col.meta.labels.len() % 9];
            let label = Label { id: Uuid::new_v4(), name: name.to_string(), color };
            let id = label.id;
            col.meta.labels.push(label);
            id
        });
    }
    by_name
}

/// Longest chat message, characters.
pub const MESSAGE_MAX: usize = 4000;

/// A folder chat line. `author` comes from the server (who uploaded it), so members cannot
/// write under someone else's name; a line not yet synced shows the name this app wrote.
#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct MessageView {
    pub id: Uuid,
    pub author: String,
    pub text: String,
    pub at: DateTime<Utc>,
    pub mine: bool,
}

#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct ChatSummary {
    pub collection_id: Uuid,
    pub count: usize,
    pub last_at: DateTime<Utc>,
    pub last_author: String,
    pub last_mine: bool,
}

/// Live feedback for the editor.
#[derive(Serialize, Debug)]
pub struct PasswordCheck {
    /// zxcvbn 0..=4; below 3 counts as weak.
    pub score: u8,
    /// Time to guess it offline against a slow hash (10 000 guesses per second).
    pub crack_secs: f64,
    /// Titles of other live items with the same password.
    pub reused_in: Vec<String>,
}

fn summary(id: Uuid, collection_id: Uuid, i: &Item, reused: bool, weak: bool, pwned: bool) -> ItemSummary {
    let live = i.deleted_at.is_none() && !i.password.is_empty();
    let changed = i.password_history.last().map_or(i.created_at, |h| h.changed_at);
    ItemSummary {
        id,
        collection_id,
        kind: i.kind,
        title: i.title.clone(),
        username: i.username.clone(),
        urls: i.urls.clone(),
        labels: i.labels.clone(),
        favorite: i.favorite,
        has_password: !i.password.is_empty(),
        has_totp: i.totp.is_some(),
        deleted: i.deleted_at.is_some(),
        created_at: i.created_at,
        updated_at: i.updated_at,
        history_len: i.password_history.len(),
        weak: live && weak,
        reused: live && reused,
        old: live && Utc::now() - changed > chrono::Duration::days(OLD_AFTER_DAYS),
        pwned: live && pwned,
    }
}

impl Vault {
    pub fn open(path: &Path) -> VResult<Vault> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(io)?;
        }
        Ok(Vault { store: Store::open(path)?, session: None, weak_cache: HashMap::new(), pwned: HashMap::new() })
    }

    pub(crate) fn blobs(&self) -> VResult<AccountBlobs> {
        let json = self.store.get_kv("account")?.ok_or(VaultError::NotFound)?;
        serde_json::from_str(&json).map_err(io)
    }

    pub(crate) fn session(&self) -> VResult<&Session> {
        self.session.as_ref().ok_or(VaultError::Locked)
    }

    pub fn status(&self) -> VResult<Status> {
        Ok(Status {
            has_account: self.store.get_kv("account")?.is_some(),
            unlocked: self.session.is_some(),
            username: self.store.get_kv("username")?,
            corrupt: self.session.as_ref().map_or(0, |s| s.corrupt.len()),
        })
    }

    /// Creates the local account and the personal collection; returns the recovery code.
    pub fn create_local(&mut self, username: &str, password: &str) -> VResult<String> {
        if self.store.get_kv("account")?.is_some() {
            return Err(VaultError::Exists);
        }
        let username = username.trim();
        if username.is_empty() || password.is_empty() {
            return Err(VaultError::Invalid("username and password are required".into()));
        }
        let creds = account::create_account(password, KdfParams::DEFAULT)?;
        let id = Uuid::new_v4();
        let key = CollectionKey::generate();
        let me = creds.blobs.public_key;
        self.store.put_collection(&CollectionRow {
            id,
            kind: "personal".into(),
            role: "owner".into(),
            key_version: key.version,
            sealed_ck: key.seal_for(id, &me, &creds.account)?,
            granted_by: me,
            rev: 0,
            dirty: true,
        })?;
        let meta = Meta { name: "Личное".into(), labels: vec![] };
        write_row(&self.store, &key, id, id, &meta, Utc::now())?;
        self.store.set_kv("account", &serde_json::to_string(&creds.blobs).map_err(io)?)?;
        self.store.set_kv("username", username)?;
        let sealed = creds.account.seal_private(&creds.recovery_auth[..], b"recovery_auth");
        self.store.set_kv("recovery_auth", &data_encoding::BASE64.encode(&sealed))?;
        let col = Col { key, meta, meta_ok: true, kind: "personal".into(), role: "owner".into() };
        self.session = Some(Session {
            account: creds.account,
            cols: HashMap::from([(id, col)]),
            items: HashMap::new(),
            corrupt: vec![],
        });
        Ok(creds.recovery_code)
    }

    pub fn unlock(&mut self, password: &str) -> VResult<()> {
        self.unlock_at(password, Utc::now())
    }

    /// Wrong passwords are counted on disk; from the 5th in a row each attempt waits (see `throttle_secs`).
    pub(crate) fn unlock_at(&mut self, password: &str, now: DateTime<Utc>) -> VResult<()> {
        let (fails, last) = self.unlock_failures()?;
        let limit = throttle_secs(fails);
        let wait = limit - (now - last).num_seconds().clamp(0, limit);
        if wait > 0 {
            return Err(VaultError::Throttled(wait as u64));
        }
        match account::unlock(password, &self.blobs()?) {
            Err(pwd_core::Error::Decrypt) => {
                self.store.set_kv(FAILURES_KEY, &format!("{} {}", fails + 1, now.to_rfc3339()))?;
                Err(VaultError::WrongPassword)
            }
            Err(e) => Err(e.into()),
            Ok(account) => {
                if fails > 0 {
                    self.store.del_kv(FAILURES_KEY)?;
                }
                self.session = Some(self.load(account)?);
                self.purge_expired()
            }
        }
    }

    fn unlock_failures(&self) -> VResult<(u32, DateTime<Utc>)> {
        let parsed = self.store.get_kv(FAILURES_KEY)?.and_then(|s| {
            let (n, at) = s.split_once(' ')?;
            Some((n.parse().ok()?, DateTime::parse_from_rfc3339(at).ok()?.with_timezone(&Utc)))
        });
        Ok(parsed.unwrap_or((0, DateTime::<Utc>::MIN_UTC)))
    }

    /// Decrypts every collection granted to this account and every live item in them.
    pub(crate) fn load(&self, account: UnlockedAccount) -> VResult<Session> {
        let rows = self.store.items()?;
        let mut cols = HashMap::new();
        let mut corrupt = Vec::new();
        let me = account.public_key();
        for c in self.store.collections()? {
            // Only we can grant our personal folder; anything else was planted.
            if c.kind == "personal" && c.granted_by != me {
                corrupt.push(c.id);
                continue;
            }
            let Ok(key) = CollectionKey::open_sealed(&c.sealed_ck, c.id, c.key_version, &c.granted_by, &account) else {
                corrupt.push(c.id);
                continue;
            };
            let meta = rows
                .iter()
                .find(|r| r.id == c.id && !r.deleted)
                .map(|r| decrypt_record::<Meta>(&key, c.id, c.id, &r.blob));
            let (meta, meta_ok) = match meta {
                Some(Ok(m)) => (m, true),
                // Not synced yet (shared folder just granted): fill in on next load.
                None => (Meta { name: "…".into(), labels: vec![] }, false),
                Some(Err(_)) => {
                    corrupt.push(c.id);
                    (Meta { name: "?".into(), labels: vec![] }, false)
                }
            };
            cols.insert(c.id, Col { key, meta, meta_ok, kind: c.kind, role: c.role });
        }
        let mut items = HashMap::new();
        for r in rows.iter().filter(|r| !r.deleted && !cols.contains_key(&r.id)) {
            let Some(col) = cols.get(&r.collection_id) else { continue };
            match decrypt_record::<Item>(&col.key, r.collection_id, r.id, &r.blob) {
                Ok(item) => {
                    items.insert(r.id, (r.collection_id, item));
                }
                Err(_) => corrupt.push(r.id),
            }
        }
        Ok(Session { account, cols, items, corrupt })
    }

    fn purge_expired(&mut self) -> VResult<()> {
        let cutoff = Utc::now() - chrono::Duration::days(TRASH_DAYS);
        let expired: Vec<Uuid> = self
            .session()?
            .items
            .iter()
            .filter(|(_, (_, i))| i.deleted_at.is_some_and(|d| d < cutoff))
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            match self.purge(id) {
                Ok(()) | Err(VaultError::ReadOnly) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    pub fn lock(&mut self) {
        self.session = None;
        self.weak_cache.clear();
        self.pwned.clear();
    }

    pub fn change_password(&mut self, old: &str, new: &str) -> VResult<()> {
        if new.is_empty() {
            return Err(VaultError::Invalid("new password is empty".into()));
        }
        let blobs = self.blobs()?;
        let account = account::unlock(old, &blobs).map_err(wrong_password)?;
        let (new_blobs, auth_key) = account::change_password(&account, &blobs, new, KdfParams::DEFAULT)?;
        self.store.set_kv("account", &serde_json::to_string(&new_blobs).map_err(io)?)?;
        if self.store.get_kv("server")?.is_some() {
            let update = pwd_core::proto::AccountUpdateReq { auth_key: *auth_key, account: new_blobs };
            let sealed = account.seal_private(serde_json::to_string(&update).map_err(io)?.as_bytes(), b"pending_account");
            self.store.set_kv("pending_account", &data_encoding::BASE64.encode(&sealed))?;
        }
        Ok(())
    }

    pub fn collections(&self) -> VResult<Vec<CollectionView>> {
        let s = self.session()?;
        let mut out: Vec<CollectionView> = s
            .cols
            .iter()
            .map(|(id, c)| CollectionView {
                id: *id,
                name: c.meta.name.clone(),
                kind: c.kind.clone(),
                role: c.role.clone(),
                labels: c.meta.labels.clone(),
                count: s.items.values().filter(|(cid, i)| cid == id && i.deleted_at.is_none() && is_entry(i)).count(),
            })
            .collect();
        out.sort_by_key(|c| (c.kind != "personal", c.name.to_lowercase()));
        Ok(out)
    }

    pub fn list(&mut self) -> VResult<Vec<ItemSummary>> {
        let items = &self.session.as_ref().ok_or(VaultError::Locked)?.items;
        let pwned = &self.pwned;
        let cache = &mut self.weak_cache;
        cache.retain(|id, _| items.contains_key(id));
        let mut uses: HashMap<&str, usize> = HashMap::new();
        for (_, i) in items.values().filter(|(_, i)| i.deleted_at.is_none() && !i.password.is_empty()) {
            *uses.entry(i.password.as_str()).or_default() += 1;
        }
        let mut out: Vec<ItemSummary> = items
            .iter()
            .filter(|(_, (_, i))| is_entry(i))
            .map(|(id, (col, i))| {
                let weak = match cache.get(id) {
                    Some(&(at, weak)) if at == i.updated_at => weak,
                    _ => {
                        let weak = is_weak(i);
                        cache.insert(*id, (i.updated_at, weak));
                        weak
                    }
                };
                summary(*id, *col, i, uses.get(i.password.as_str()).is_some_and(|&n| n > 1), weak, breached(pwned, *id, i))
            })
            .collect();
        out.sort_by_key(|i| i.title.to_lowercase());
        Ok(out)
    }

    /// A chat line in a folder: an encrypted item like any other, so it syncs, follows the
    /// folder's roles and is re-encrypted on key rotation.
    pub fn post_message(&mut self, collection_id: Uuid, text: &str) -> VResult<Uuid> {
        let text = text.trim();
        if text.is_empty() {
            return Err(VaultError::Invalid("message is empty".into()));
        }
        if text.chars().count() > MESSAGE_MAX {
            return Err(VaultError::Invalid("message is too long".into()));
        }
        let author = self.store.get_kv("username")?.unwrap_or_else(|| "?".into());
        self.save(ItemInput {
            id: None,
            collection_id,
            kind: ItemKind::Message,
            title: author,
            username: String::new(),
            password: None,
            urls: vec![],
            notes: text.to_string(),
            totp: None,
            labels: vec![],
            favorite: false,
        })
    }

    /// Oldest first.
    pub fn messages(&self, collection_id: Uuid) -> VResult<Vec<MessageView>> {
        let me = self.store.get_kv("username")?.unwrap_or_default();
        let authors = self.store.authors()?;
        let mut out: Vec<MessageView> = self
            .session()?
            .items
            .iter()
            .filter(|(_, (c, i))| *c == collection_id && i.kind == ItemKind::Message && i.deleted_at.is_none())
            .map(|(id, (_, i))| {
                let author = authors.get(id).cloned().unwrap_or_else(|| i.title.clone());
                MessageView { id: *id, mine: author == me, author, text: i.notes.clone(), at: i.created_at }
            })
            .collect();
        out.sort_by_key(|m| (m.at, m.id));
        Ok(out)
    }

    /// Folders that have messages: how many and when the last one came (for unread marks).
    pub fn chat_summary(&self) -> VResult<Vec<ChatSummary>> {
        let me = self.store.get_kv("username")?.unwrap_or_default();
        let authors = self.store.authors()?;
        let mut by_col: HashMap<Uuid, ChatSummary> = HashMap::new();
        for (id, (c, i)) in &self.session()?.items {
            if i.kind != ItemKind::Message || i.deleted_at.is_some() {
                continue;
            }
            let author = authors.get(id).cloned().unwrap_or_else(|| i.title.clone());
            let e = by_col.entry(*c).or_insert(ChatSummary {
                collection_id: *c,
                count: 0,
                last_at: i.created_at,
                last_mine: author == me,
                last_author: author.clone(),
            });
            e.count += 1;
            if i.created_at >= e.last_at {
                e.last_at = i.created_at;
                e.last_mine = author == me;
                e.last_author = author;
            }
        }
        let mut out: Vec<ChatSummary> = by_col.into_values().collect();
        out.sort_by_key(|s| s.collection_id);
        Ok(out)
    }

    /// Items to check against breaches: (id, revision, password).
    pub fn pwned_candidates(&self) -> VResult<Vec<BreachCandidate>> {
        Ok(self
            .session()?
            .items
            .iter()
            .filter(|(_, (_, i))| i.deleted_at.is_none() && i.kind != ItemKind::Message && !i.password.is_empty())
            .map(|(id, (_, i))| (*id, i.updated_at, zeroize::Zeroizing::new(i.password.clone())))
            .collect())
    }

    pub fn set_pwned(&mut self, results: Vec<(Uuid, DateTime<Utc>, u64)>) {
        for (id, at, n) in results {
            self.pwned.insert(id, (at, n));
        }
    }

    /// `id`: the item being edited, so it does not count as reuse of itself.
    pub fn check_password(&self, id: Option<Uuid>, password: &str, title: &str, username: &str) -> VResult<PasswordCheck> {
        let items = &self.session()?.items;
        let mut reused_in: Vec<String> = items
            .iter()
            .filter(|(o, (_, i))| Some(**o) != id && i.deleted_at.is_none() && !password.is_empty() && i.password == password)
            .map(|(_, (_, i))| i.title.clone())
            .collect();
        reused_in.sort();
        let e = estimate(password, &[title, username]);
        Ok(PasswordCheck { score: e.score().into(), crack_secs: e.guesses() as f64 / 1e4, reused_in })
    }

    pub fn get(&self, id: Uuid) -> VResult<ItemDetails> {
        let items = &self.session()?.items;
        let (col, i) = items.get(&id).ok_or(VaultError::NotFound)?;
        let reused = items.iter().any(|(o, (_, other))| *o != id && other.deleted_at.is_none() && other.password == i.password);
        Ok(ItemDetails {
            summary: summary(id, *col, i, reused, is_weak(i), breached(&self.pwned, id, i)),
            notes: i.notes.clone(),
            history: i.password_history.iter().map(|h| h.changed_at).collect(),
            attachments: self.attachments(id)?,
        })
    }

    /// Live files of an entry, oldest first.
    pub fn attachments(&self, item_id: Uuid) -> VResult<Vec<AttachmentView>> {
        let mut out: Vec<AttachmentView> = self
            .session()?
            .items
            .iter()
            .filter(|(_, (_, i))| i.kind == ItemKind::File && i.parent == Some(item_id) && i.deleted_at.is_none())
            .map(|(id, (_, i))| AttachmentView { id: *id, name: i.title.clone(), size: b64_len(&i.notes), added_at: i.created_at })
            .collect();
        out.sort_by_key(|a| (a.added_at, a.id));
        Ok(out)
    }

    /// Attaches a file (its name only, no path) to an entry in a writable folder.
    pub fn attach(&mut self, item_id: Uuid, name: &str, data: &[u8]) -> VResult<Uuid> {
        if data.len() > ATTACHMENT_MAX {
            return Err(VaultError::Invalid("file is larger than 8 MB".into()));
        }
        let name: String = name.rsplit(['/', '\\']).next().unwrap_or("").trim().chars().take(200).collect();
        let name = if name.is_empty() { "файл".to_string() } else { name };
        let now = Utc::now();
        let Vault { store, session, .. } = self;
        let s = session.as_mut().ok_or(VaultError::Locked)?;
        let (col_id, parent) = s.items.get(&item_id).ok_or(VaultError::NotFound)?;
        if !is_entry(parent) {
            return Err(VaultError::Invalid("files attach to entries only".into()));
        }
        let col_id = *col_id;
        let col = s.cols.get(&col_id).ok_or(VaultError::NotFound)?;
        writable(col)?;
        let mut file = Item::new(ItemKind::File, name, now);
        file.notes = data_encoding::BASE64.encode(data);
        file.parent = Some(item_id);
        let id = Uuid::new_v4();
        write_row(store, &col.key, col_id, id, &file, now)?;
        s.items.insert(id, (col_id, file));
        Ok(id)
    }

    pub fn attachment_data(&self, id: Uuid) -> VResult<(String, Vec<u8>)> {
        let (_, i) = self.session()?.items.get(&id).filter(|(_, i)| i.kind == ItemKind::File).ok_or(VaultError::NotFound)?;
        let data = data_encoding::BASE64.decode(i.notes.as_bytes()).map_err(|_| io("attachment is damaged"))?;
        Ok((i.title.clone(), data))
    }

    pub fn remove_attachment(&mut self, id: Uuid) -> VResult<()> {
        match self.session()?.items.get(&id) {
            Some((_, i)) if i.kind == ItemKind::File => self.purge(id),
            _ => Err(VaultError::NotFound),
        }
    }

    /// Files of an entry, including trashed ones.
    fn children(&self, item_id: Uuid) -> Vec<Uuid> {
        self.session.as_ref().map_or(vec![], |s| {
            s.items.iter().filter(|(_, (_, i))| i.kind == ItemKind::File && i.parent == Some(item_id)).map(|(id, _)| *id).collect()
        })
    }

    /// After an entry moved folders (and got a new id): its files follow.
    fn move_children(&mut self, old_id: Uuid, new_id: Uuid) -> VResult<()> {
        let now = Utc::now();
        let children = self.children(old_id);
        let Vault { store, session, .. } = self;
        let s = session.as_mut().ok_or(VaultError::Locked)?;
        let new_col = s.items.get(&new_id).map(|(c, _)| *c).ok_or(VaultError::NotFound)?;
        for child in children {
            let Some((old_col, mut file)) = s.items.remove(&child) else { continue };
            let old_key_version = s.cols.get(&old_col).map_or(0, |c| c.key.version);
            store.put_item(&ItemRow {
                id: child,
                collection_id: old_col,
                key_version: old_key_version,
                blob: vec![],
                deleted: true,
                rev: store.item_rev(child)?,
                dirty: true,
                updated_at: now.to_rfc3339(),
            })?;
            file.parent = Some(new_id);
            file.updated_at = now;
            let id = Uuid::new_v4();
            let col = s.cols.get(&new_col).ok_or(VaultError::NotFound)?;
            write_row(store, &col.key, new_col, id, &file, now)?;
            s.items.insert(id, (new_col, file));
        }
        Ok(())
    }

    /// `field`: `password`, `totp` or `history:N` (0 = oldest).
    pub fn reveal(&self, id: Uuid, field: &str) -> VResult<String> {
        let (_, i) = self.session()?.items.get(&id).ok_or(VaultError::NotFound)?;
        match field {
            "password" => Ok(i.password.clone()),
            "totp" => i.totp.clone().ok_or(VaultError::NotFound),
            f => {
                let n: usize = f
                    .strip_prefix("history:")
                    .and_then(|n| n.parse().ok())
                    .ok_or_else(|| VaultError::Invalid(format!("unknown field {f}")))?;
                i.password_history.get(n).map(|h| h.value.clone()).ok_or(VaultError::NotFound)
            }
        }
    }

    /// Current 2FA code and seconds until it changes.
    pub fn totp(&self, id: Uuid) -> VResult<TotpCode> {
        let spec = zeroize::Zeroizing::new(self.reveal(id, "totp")?);
        let (code, left, period) = pwd_core::totp::code(&spec, Utc::now().timestamp().max(0) as u64)?;
        Ok(TotpCode { code, left, period })
    }

    pub fn save(&mut self, input: ItemInput) -> VResult<Uuid> {
        let old_id = input.id;
        let id = self.save_inner(input)?;
        if let Some(old) = old_id.filter(|o| *o != id) {
            self.move_children(old, id)?;
        }
        Ok(id)
    }

    fn save_inner(&mut self, input: ItemInput) -> VResult<Uuid> {
        let title = input.title.trim().to_string();
        if title.is_empty() {
            return Err(VaultError::Invalid("title is required".into()));
        }
        let now = Utc::now();
        let Vault { store, session, .. } = self;
        let s = session.as_mut().ok_or(VaultError::Locked)?;
        let col = s.cols.get(&input.collection_id).ok_or(VaultError::NotFound)?;
        writable(col)?;
        let mut moved_from = None;
        let mut item = match input.id {
            Some(id) => {
                let (old_col, i) = s.items.get(&id).ok_or(VaultError::NotFound)?;
                let old = s.cols.get(old_col).ok_or(VaultError::NotFound)?;
                writable(old)?;
                if *old_col != input.collection_id {
                    moved_from = Some((id, *old_col, old.key.version));
                }
                i.clone()
            }
            None => Item::new(input.kind, title.clone(), now),
        };
        let id = match (input.id, moved_from) {
            (Some(id), None) => id,
            _ => Uuid::new_v4(),
        };
        item.kind = input.kind;
        item.title = title;
        item.username = input.username.trim().to_string();
        item.urls = input.urls.iter().map(|u| u.trim().to_string()).filter(|u| !u.is_empty()).collect();
        item.notes = input.notes;
        if let Some(p) = input.password {
            item.set_password(p, now);
        }
        if let Some(t) = input.totp {
            let t = t.trim().to_string();
            if !t.is_empty() {
                pwd_core::totp::code(&t, 0)?; // reject a secret that can never produce codes
            }
            item.totp = Some(t).filter(|t| !t.is_empty());
        }
        let mut labels: Vec<Uuid> = Vec::new();
        for l in input.labels {
            if col.meta.labels.iter().any(|x| x.id == l) && !labels.contains(&l) {
                labels.push(l);
            }
        }
        item.labels = labels;
        item.favorite = input.favorite;
        item.updated_at = now;
        write_row(store, &col.key, input.collection_id, id, &item, now)?;
        s.items.insert(id, (input.collection_id, item));
        if let Some((old_id, old_col, key_version)) = moved_from {
            store.put_item(&ItemRow {
                id: old_id,
                collection_id: old_col,
                key_version,
                blob: vec![],
                deleted: true,
                rev: store.item_rev(old_id)?,
                dirty: true,
                updated_at: now.to_rfc3339(),
            })?;
            s.items.remove(&old_id);
        }
        Ok(id)
    }

    fn update_item(&mut self, id: Uuid, f: impl FnOnce(&mut Item)) -> VResult<()> {
        let Vault { store, session, .. } = self;
        let s = session.as_mut().ok_or(VaultError::Locked)?;
        let (col_id, item) = s.items.get_mut(&id).ok_or(VaultError::NotFound)?;
        let col = s.cols.get(col_id).ok_or(VaultError::NotFound)?;
        writable(col)?;
        f(item);
        item.updated_at = Utc::now();
        write_row(store, &col.key, *col_id, id, &*item, item.updated_at)
    }

    pub fn delete(&mut self, id: Uuid) -> VResult<()> {
        self.update_item(id, |i| i.deleted_at = Some(Utc::now()))?;
        for child in self.children(id) {
            self.update_item(child, |i| i.deleted_at = Some(Utc::now()))?;
        }
        Ok(())
    }

    pub fn restore(&mut self, id: Uuid) -> VResult<()> {
        self.update_item(id, |i| i.deleted_at = None)?;
        for child in self.children(id) {
            self.update_item(child, |i| i.deleted_at = None)?;
        }
        Ok(())
    }

    pub fn purge(&mut self, id: Uuid) -> VResult<()> {
        for child in self.children(id) {
            self.purge_one(child)?;
        }
        self.purge_one(id)
    }

    fn purge_one(&mut self, id: Uuid) -> VResult<()> {
        let Vault { store, session, .. } = self;
        let s = session.as_mut().ok_or(VaultError::Locked)?;
        let (col_id, _) = s.items.get(&id).ok_or(VaultError::NotFound)?;
        let col = s.cols.get(col_id).ok_or(VaultError::NotFound)?;
        writable(col)?;
        store.put_item(&ItemRow {
            id,
            collection_id: *col_id,
            key_version: col.key.version,
            blob: vec![],
            deleted: true,
            rev: store.item_rev(id)?,
            dirty: true,
            updated_at: Utc::now().to_rfc3339(),
        })?;
        s.items.remove(&id);
        Ok(())
    }

    pub fn save_label(&mut self, collection_id: Uuid, mut label: Label) -> VResult<()> {
        label.name = label.name.trim().to_string();
        if label.name.is_empty() {
            return Err(VaultError::Invalid("label name is required".into()));
        }
        let Vault { store, session, .. } = self;
        let s = session.as_mut().ok_or(VaultError::Locked)?;
        let col = s.cols.get_mut(&collection_id).ok_or(VaultError::NotFound)?;
        meta_writable(col)?;
        match col.meta.labels.iter_mut().find(|l| l.id == label.id) {
            Some(existing) => *existing = label,
            None => col.meta.labels.push(label),
        }
        write_row(store, &col.key, collection_id, collection_id, &col.meta, Utc::now())
    }

    pub fn delete_label(&mut self, collection_id: Uuid, label_id: Uuid) -> VResult<()> {
        let now = Utc::now();
        let Vault { store, session, .. } = self;
        let s = session.as_mut().ok_or(VaultError::Locked)?;
        let col = s.cols.get_mut(&collection_id).ok_or(VaultError::NotFound)?;
        meta_writable(col)?;
        col.meta.labels.retain(|l| l.id != label_id);
        write_row(store, &col.key, collection_id, collection_id, &col.meta, now)?;
        for (id, (cid, item)) in s.items.iter_mut() {
            if *cid == collection_id && item.labels.contains(&label_id) {
                item.labels.retain(|l| *l != label_id);
                item.updated_at = now;
                write_row(store, &col.key, collection_id, *id, &*item, now)?;
            }
        }
        Ok(())
    }

    /// Live entries and files per folder (no chat lines, no trash), folders by name.
    fn exportable(&self) -> VResult<Vec<FolderItems<'_>>> {
        let s = self.session()?;
        let mut out: Vec<FolderItems<'_>> = s
            .cols
            .iter()
            .map(|(cid, col)| {
                let mut items: Vec<(Uuid, &Item)> = s
                    .items
                    .iter()
                    .filter(|(_, (c, i))| c == cid && i.deleted_at.is_none() && i.kind != ItemKind::Message)
                    .map(|(id, (_, i))| (*id, i))
                    .collect();
                items.sort_by_key(|(_, i)| i.title.to_lowercase());
                (col, items)
            })
            .collect();
        out.sort_by_key(|(c, _)| (c.kind != "personal", c.meta.name.to_lowercase()));
        Ok(out)
    }

    /// Encrypted backup of every folder with its own password; returns how many entries it holds.
    pub fn export_backup(&self, path: &Path, password: &str) -> VResult<usize> {
        if password.chars().count() < 8 {
            return Err(VaultError::Invalid("backup password must be at least 8 characters".into()));
        }
        let folders: Vec<BackupFolder> = self
            .exportable()?
            .into_iter()
            .map(|(col, items)| BackupFolder {
                name: col.meta.name.clone(),
                labels: col.meta.labels.clone(),
                items: items.into_iter().map(|(id, i)| BackupItem { id: Some(id), item: i.clone() }).collect(),
            })
            .collect();
        let count = folders.iter().flat_map(|f| &f.items).filter(|b| is_entry(&b.item)).count();
        let bytes = backup::seal(&Backup { created_at: Utc::now(), folders }, password)?;
        std::fs::write(path, bytes).map_err(io)?;
        Ok(count)
    }

    /// Restores a backup into one folder. Labels are matched by name; every source folder other
    /// than one named like the target becomes a label, so nothing gets mixed up silently.
    pub fn import_backup(&mut self, path: &Path, password: &str, collection_id: Uuid) -> VResult<usize> {
        let bytes = std::fs::read(path).map_err(io)?;
        let b = backup::open(&bytes, password).map_err(|e| match e {
            pwd_core::Error::Decrypt => VaultError::Invalid("wrong backup password or damaged file".into()),
            pwd_core::Error::Format(_) | pwd_core::Error::Json(_) => VaultError::Invalid("not a Passwords backup".into()),
            e => e.into(),
        })?;
        let now = Utc::now();
        let Vault { store, session, .. } = self;
        let s = session.as_mut().ok_or(VaultError::Locked)?;
        let col = s.cols.get_mut(&collection_id).ok_or(VaultError::NotFound)?;
        meta_writable(col)?;
        let target = col.meta.name.to_lowercase();
        // Per source item: a new id and the names of its labels (plus its folder's name).
        let mut named: Vec<(Uuid, Item, Vec<String>)> = Vec::new();
        let mut new_id: HashMap<Uuid, Uuid> = HashMap::new();
        for f in &b.folders {
            for BackupItem { id, item: i } in &f.items {
                let mut names: Vec<String> =
                    i.labels.iter().filter_map(|l| f.labels.iter().find(|x| x.id == *l)).map(|l| l.name.clone()).collect();
                if f.name.to_lowercase() != target && is_entry(i) {
                    names.push(f.name.clone());
                }
                let fresh = Uuid::new_v4();
                if let Some(old) = id {
                    new_id.insert(*old, fresh);
                }
                named.push((fresh, i.clone(), names));
            }
        }
        let label_for = merge_labels(col, named.iter().flat_map(|(_, _, n)| n.iter().map(String::as_str)));
        write_row(store, &col.key, collection_id, collection_id, &col.meta, now)?;
        let mut entries = 0;
        for (id, mut item, names) in named.iter().cloned() {
            if item.kind == ItemKind::File {
                // A file whose entry is not in the backup has nowhere to go.
                let Some(parent) = item.parent.and_then(|p| new_id.get(&p).copied()) else { continue };
                item.parent = Some(parent);
            } else {
                entries += 1;
            }
            item.labels = names.iter().filter_map(|n| label_for.get(&n.to_lowercase()).copied()).collect();
            item.labels.sort();
            item.labels.dedup();
            write_row(store, &col.key, collection_id, id, &item, now)?;
            s.items.insert(id, (collection_id, item));
        }
        Ok(entries)
    }

    /// Plain-text CSV (no encryption!). Shared folders become the "folder" column.
    pub fn export_csv(&self, path: &Path) -> VResult<usize> {
        let mut entries = Vec::new();
        for (col, items) in self.exportable()? {
            for (_, i) in items.into_iter().filter(|(_, i)| is_entry(i)) {
                let first_label = i.labels.first().and_then(|l| col.meta.labels.iter().find(|x| x.id == *l)).map(|l| l.name.clone());
                let extra_urls = i.urls.iter().skip(1).map(|u| format!("\n{u}")).collect::<String>();
                entries.push(pwd_core::csv_import::CsvEntry {
                    title: i.title.clone(),
                    username: i.username.clone(),
                    password: i.password.clone(),
                    url: i.urls.first().cloned().unwrap_or_default(),
                    notes: format!("{}{extra_urls}", i.notes),
                    totp: i.totp.clone().unwrap_or_default(),
                    group: if col.kind == "personal" { first_label.unwrap_or_default() } else { col.meta.name.clone() },
                    is_note: i.kind == ItemKind::Note,
                });
            }
        }
        let text = zeroize::Zeroizing::new(pwd_core::csv_import::write(&entries)?);
        std::fs::write(path, text.as_bytes()).map_err(io)?;
        Ok(entries.len())
    }

    /// Imports a password CSV export (Chrome, Edge, Firefox, Bitwarden, KeePass) into a collection.
    /// Source folders become labels (merged by name). Returns the item count.
    pub fn import_csv(&mut self, path: &Path, collection_id: Uuid) -> VResult<usize> {
        let text = std::fs::read_to_string(path).map_err(|e| match e.kind() {
            std::io::ErrorKind::InvalidData => VaultError::Invalid("file is not UTF-8".into()),
            _ => io(e),
        })?;
        let entries = pwd_core::csv_import::parse(&text)?;
        let now = Utc::now();
        let Vault { store, session, .. } = self;
        let s = session.as_mut().ok_or(VaultError::Locked)?;
        let col = s.cols.get_mut(&collection_id).ok_or(VaultError::NotFound)?;
        meta_writable(col)?;
        let label_for = merge_labels(col, entries.iter().map(|e| e.group.as_str()));
        write_row(store, &col.key, collection_id, collection_id, &col.meta, now)?;
        for e in &entries {
            let kind = if e.is_note { ItemKind::Note } else { ItemKind::Login };
            let mut item = Item::new(kind, e.title.clone(), now);
            item.username = e.username.clone();
            item.password = e.password.clone();
            item.urls = Some(e.url.clone()).filter(|u| !u.is_empty()).into_iter().collect();
            item.notes = e.notes.clone();
            // A secret that cannot produce codes is kept in the notes instead of failing the import.
            if !e.totp.is_empty() {
                if pwd_core::totp::code(&e.totp, 0).is_ok() {
                    item.totp = Some(e.totp.clone());
                } else {
                    item.notes = format!("{}\n2FA: {}", item.notes, e.totp).trim().to_string();
                }
            }
            item.labels = label_for.get(&e.group.to_lowercase()).copied().into_iter().collect();
            let id = Uuid::new_v4();
            write_row(store, &col.key, collection_id, id, &item, now)?;
            s.items.insert(id, (collection_id, item));
        }
        Ok(entries.len())
    }

    /// Imports a v1 `.vault` file into a collection; labels merge by name. Returns the item count.
    pub fn import_legacy(&mut self, path: &Path, password: &str, collection_id: Uuid) -> VResult<usize> {
        let bytes = std::fs::read(path).map_err(io)?;
        let imported = legacy::import(&bytes, password).map_err(|e| match e {
            pwd_core::Error::Decrypt => VaultError::WrongPassword,
            pwd_core::Error::Format(m) => VaultError::Invalid(m.into()),
            e => e.into(),
        })?;
        let now = Utc::now();
        let Vault { store, session, .. } = self;
        let s = session.as_mut().ok_or(VaultError::Locked)?;
        let col = s.cols.get_mut(&collection_id).ok_or(VaultError::NotFound)?;
        meta_writable(col)?;
        let mut label_map = HashMap::new();
        for l in imported.labels {
            match col.meta.labels.iter().find(|x| x.name.to_lowercase() == l.name.to_lowercase()) {
                Some(x) => {
                    label_map.insert(l.id, x.id);
                }
                None => {
                    label_map.insert(l.id, l.id);
                    col.meta.labels.push(l);
                }
            }
        }
        write_row(store, &col.key, collection_id, collection_id, &col.meta, now)?;
        let count = imported.items.len();
        for (id, mut item) in imported.items {
            item.labels = item.labels.iter().filter_map(|l| label_map.get(l).copied()).collect();
            write_row(store, &col.key, collection_id, id, &item, item.updated_at)?;
            s.items.insert(id, (collection_id, item));
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pwd_core::model::LabelColor;

    const PW: &str = "мастер пароль";

    fn new_vault(dir: &tempfile::TempDir) -> Vault {
        let mut v = Vault::open(&dir.path().join("vault.db")).unwrap();
        let code = v.create_local("cody", PW).unwrap();
        assert_eq!(code.len(), 29);
        v
    }

    fn personal(v: &Vault) -> Uuid {
        v.collections().unwrap()[0].id
    }

    fn login(v: &Vault, title: &str, password: &str) -> ItemInput {
        ItemInput {
            id: None,
            collection_id: personal(v),
            kind: ItemKind::Login,
            title: title.into(),
            username: "cody@example.com".into(),
            password: Some(password.into()),
            urls: vec!["https://example.com".into()],
            notes: "заметка".into(),
            totp: None,
            labels: vec![],
            favorite: false,
        }
    }

    #[test]
    fn create_lock_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = new_vault(&dir);
        assert_eq!(v.status().unwrap(), Status { has_account: true, unlocked: true, username: Some("cody".into()), corrupt: 0 });
        let cols = v.collections().unwrap();
        assert_eq!(cols.len(), 1);
        assert_eq!((cols[0].name.as_str(), cols[0].kind.as_str()), ("Личное", "personal"));
        assert_eq!(v.create_local("x", "y"), Err(VaultError::Exists));

        v.lock();
        assert!(!v.status().unwrap().unlocked);
        assert!(matches!(v.list(), Err(VaultError::Locked)));
        assert_eq!(v.unlock("не тот"), Err(VaultError::WrongPassword));
        v.unlock(PW).unwrap();
        assert!(v.list().unwrap().is_empty());
    }

    #[test]
    fn save_list_get_reveal() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = new_vault(&dir);
        let id = v.save(login(&v, "GitHub", "gh-secret")).unwrap();
        let list = v.list().unwrap();
        assert_eq!(list.len(), 1);
        assert!(list[0].has_password && !list[0].has_totp);
        assert_eq!(list[0].title, "GitHub");
        assert_eq!(v.get(id).unwrap().notes, "заметка");
        assert_eq!(v.reveal(id, "password").unwrap(), "gh-secret");
        assert_eq!(v.collections().unwrap()[0].count, 1);

        let mut empty = login(&v, "  ", "x");
        empty.title = "  ".into();
        assert!(matches!(v.save(empty), Err(VaultError::Invalid(_))));
        assert_eq!(v.reveal(Uuid::new_v4(), "password"), Err(VaultError::NotFound));
    }

    #[test]
    fn editing_password_keeps_history() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = new_vault(&dir);
        let id = v.save(login(&v, "Bank", "old-1")).unwrap();
        let mut edit = login(&v, "Bank", "new-2");
        edit.id = Some(id);
        v.save(edit.clone()).unwrap();
        assert_eq!(v.get(id).unwrap().summary.history_len, 1);
        assert_eq!(v.reveal(id, "history:0").unwrap(), "old-1");

        edit.password = None;
        edit.title = "Bank 2".into();
        edit.totp = Some("JBSWY3DPEHPK3PXP".into());
        v.save(edit.clone()).unwrap();
        assert_eq!(v.reveal(id, "password").unwrap(), "new-2");
        assert_eq!(v.reveal(id, "totp").unwrap(), "JBSWY3DPEHPK3PXP");
        let code = v.totp(id).unwrap();
        assert_eq!(code.code.len(), 6);
        assert!((1..=30).contains(&code.left));
        let mut bad = edit.clone();
        bad.totp = Some("not base32!".into());
        assert!(matches!(v.save(bad), Err(VaultError::Invalid(_))));
        edit.totp = Some(String::new());
        v.save(edit).unwrap();
        assert!(!v.list().unwrap()[0].has_totp);
    }

    #[test]
    fn chat_post_list_summary_delete() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = new_vault(&dir);
        let col = personal(&v);
        assert!(v.chat_summary().unwrap().is_empty());
        let first = v.post_message(col, "  привет 󰇵 ").unwrap();
        v.post_message(col, "второе
в две строки").unwrap();
        let msgs = v.messages(col).unwrap();
        assert_eq!(
            msgs.iter().map(|m| (m.author.as_str(), m.text.as_str(), m.mine)).collect::<Vec<_>>(),
            [("cody", "привет 󰇵", true), ("cody", "второе
в две строки", true)]
        );
        let sum = v.chat_summary().unwrap();
        assert_eq!((sum.len(), sum[0].collection_id, sum[0].count), (1, col, 2));
        assert_eq!(sum[0].last_at, msgs[1].at);
        assert_eq!((sum[0].last_author.as_str(), sum[0].last_mine), ("cody", true));

        assert!(matches!(v.post_message(col, "   "), Err(VaultError::Invalid(_))));
        assert!(matches!(v.post_message(col, &"я".repeat(MESSAGE_MAX + 1)), Err(VaultError::Invalid(_))));

        v.purge(first).unwrap();
        assert_eq!(v.messages(col).unwrap().len(), 1);
        assert!(v.list().unwrap().is_empty(), "messages are not passwords");
    }

    #[test]
    fn chat_messages_stay_out_of_the_password_list() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = new_vault(&dir);
        v.save(login(&v, "GitHub", "gh-1")).unwrap();
        let mut msg = login(&v, "alice", "");
        msg.kind = ItemKind::Message;
        msg.notes = "привет".into();
        v.save(msg).unwrap();
        assert_eq!(v.list().unwrap().iter().map(|i| i.title.as_str()).collect::<Vec<_>>(), ["GitHub"]);
        assert_eq!(v.collections().unwrap()[0].count, 1);
    }

    #[test]
    fn check_password_scores_and_finds_reuse() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = new_vault(&dir);
        let gh = v.save(login(&v, "GitHub", "Ksl9#vQ2-mPz7!rW")).unwrap();
        v.save(login(&v, "GitLab", "Ksl9#vQ2-mPz7!rW")).unwrap();
        let trashed = v.save(login(&v, "Старое", "Ksl9#vQ2-mPz7!rW")).unwrap();
        v.delete(trashed).unwrap();

        let weak = v.check_password(None, "qwerty123", "Почта", "cody").unwrap();
        assert!(weak.score < 3 && weak.crack_secs < 3600.0, "{weak:?}");
        assert!(weak.reused_in.is_empty());

        let strong = v.check_password(None, "Ksl9#vQ2-mPz7!rW", "Новая", "cody").unwrap();
        assert!(strong.score >= 3, "{strong:?}");
        assert_eq!(strong.reused_in, ["GitHub", "GitLab"], "live items only, sorted");
        assert_eq!(v.check_password(Some(gh), "Ksl9#vQ2-mPz7!rW", "GitHub", "cody").unwrap().reused_in, ["GitLab"], "not itself");
        assert!(v.check_password(None, "", "x", "y").unwrap().reused_in.is_empty());
    }

    #[test]
    fn repeated_wrong_passwords_throttle_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = new_vault(&dir);
        v.lock();
        let t0 = Utc::now();
        for _ in 0..5 {
            assert_eq!(v.unlock_at("не тот", t0), Err(VaultError::WrongPassword));
        }
        assert_eq!(v.unlock_at(PW, t0), Err(VaultError::Throttled(30)), "even the right password waits");
        assert_eq!(v.unlock_at(PW, t0 + chrono::Duration::seconds(10)), Err(VaultError::Throttled(20)));
        drop(v);

        let mut v = Vault::open(&dir.path().join("vault.db")).unwrap();
        assert_eq!(v.unlock_at(PW, t0 + chrono::Duration::seconds(10)), Err(VaultError::Throttled(20)), "restart does not reset");
        let t1 = t0 + chrono::Duration::seconds(31);
        assert_eq!(v.unlock_at("не тот", t1), Err(VaultError::WrongPassword));
        assert_eq!(v.unlock_at(PW, t1), Err(VaultError::Throttled(60)), "the wait doubles");
        let t2 = t1 + chrono::Duration::seconds(61);
        v.unlock_at(PW, t2).unwrap();
        v.lock();
        assert_eq!(v.unlock_at("не тот", t2), Err(VaultError::WrongPassword));
        v.unlock_at(PW, t2).unwrap();
    }

    #[test]
    fn health_flags_weak_reused_old() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = new_vault(&dir);
        let weak = v.save(login(&v, "Почта", "qwerty123")).unwrap();
        let a = v.save(login(&v, "GitHub", "Ksl9#vQ2-mPz7!rW")).unwrap();
        let b = v.save(login(&v, "GitLab", "Ksl9#vQ2-mPz7!rW")).unwrap();
        let flags = |v: &mut Vault, id: Uuid| {
            let s = v.list().unwrap().into_iter().find(|s| s.id == id).unwrap();
            (s.weak, s.reused, s.old)
        };
        assert_eq!(flags(&mut v, weak), (true, false, false));
        assert_eq!(flags(&mut v, a), (false, true, false));
        assert!(v.get(b).unwrap().summary.reused);

        v.delete(b).unwrap();
        assert_eq!(flags(&mut v, a), (false, false, false), "items in the trash do not count as reuse");
        assert!(!v.get(b).unwrap().summary.reused);

        let two_years_ago = Utc::now() - chrono::Duration::days(730);
        v.session.as_mut().unwrap().items.get_mut(&a).unwrap().1.created_at = two_years_ago;
        assert_eq!(flags(&mut v, a), (false, false, true));
        let mut edit = login(&v, "GitHub", "Zt4$wq-Lm8!pXv2#");
        edit.id = Some(a);
        v.save(edit).unwrap();
        assert_eq!(flags(&mut v, a), (false, false, false), "a new password is not old");
    }

    #[test]
    fn delete_restore_purge_persist() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = new_vault(&dir);
        let id = v.save(login(&v, "Temp", "p")).unwrap();
        v.delete(id).unwrap();
        assert!(v.list().unwrap()[0].deleted);
        assert_eq!(v.collections().unwrap()[0].count, 0);
        v.restore(id).unwrap();
        assert!(!v.list().unwrap()[0].deleted);
        v.purge(id).unwrap();
        assert!(v.list().unwrap().is_empty());
        drop(v);

        let mut v = Vault::open(&dir.path().join("vault.db")).unwrap();
        v.unlock(PW).unwrap();
        assert!(v.list().unwrap().is_empty());
    }

    #[test]
    fn data_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = new_vault(&dir);
        let id = v.save(login(&v, "Persist", "pp")).unwrap();
        drop(v);
        let mut v = Vault::open(&dir.path().join("vault.db")).unwrap();
        assert_eq!(v.status().unwrap(), Status { has_account: true, unlocked: false, username: Some("cody".into()), corrupt: 0 });
        v.unlock(PW).unwrap();
        assert_eq!(v.reveal(id, "password").unwrap(), "pp");
    }

    #[test]
    fn labels_and_label_removal() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = new_vault(&dir);
        let col = personal(&v);
        let label = Label { id: Uuid::new_v4(), name: "банк".into(), color: LabelColor::Green };
        v.save_label(col, label.clone()).unwrap();
        assert_eq!(v.collections().unwrap()[0].labels, std::slice::from_ref(&label));
        let mut input = login(&v, "Bank", "p");
        input.labels = vec![label.id, Uuid::new_v4()];
        let id = v.save(input).unwrap();
        assert_eq!(v.get(id).unwrap().summary.labels, [label.id], "unknown label ids are dropped");
        v.delete_label(col, label.id).unwrap();
        assert!(v.collections().unwrap()[0].labels.is_empty());
        assert!(v.get(id).unwrap().summary.labels.is_empty());
    }

    #[test]
    fn database_holds_no_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = new_vault(&dir);
        v.save(login(&v, "SUPERSECRETTITLE", "hunter2-ZZZ")).unwrap();
        drop(v);
        let bytes = std::fs::read(dir.path().join("vault.db")).unwrap();
        let hay = String::from_utf8_lossy(&bytes);
        for needle in ["SUPERSECRETTITLE", "hunter2-ZZZ", "cody@example.com", "Личное"] {
            assert!(!hay.contains(needle), "{needle} leaked");
        }
    }

    #[test]
    fn change_password() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = new_vault(&dir);
        assert_eq!(v.change_password("wrong", "new"), Err(VaultError::WrongPassword));
        v.change_password(PW, "новый пароль").unwrap();
        v.lock();
        assert_eq!(v.unlock(PW), Err(VaultError::WrongPassword));
        v.unlock("новый пароль").unwrap();
    }

    fn raw_db(dir: &tempfile::TempDir) -> rusqlite::Connection {
        rusqlite::Connection::open(dir.path().join("vault.db")).unwrap()
    }

    #[test]
    fn corrupt_rows_are_skipped_and_reported() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = new_vault(&dir);
        let good = v.save(login(&v, "Good", "p")).unwrap();
        let bad = v.save(login(&v, "Bad", "p")).unwrap();
        drop(v);
        let db = raw_db(&dir);
        db.execute("UPDATE items SET blob = x'0102' WHERE id = ?1", [bad.to_string()]).unwrap();
        db.execute("INSERT INTO items (id, collection_id, key_version, blob, updated_at) VALUES ('nope', 'nope', 1, x'00', '')", []).unwrap();
        drop(db);

        let mut v = Vault::open(&dir.path().join("vault.db")).unwrap();
        v.unlock(PW).unwrap();
        let ids: Vec<Uuid> = v.list().unwrap().iter().map(|i| i.id).collect();
        assert_eq!(ids, [good]);
        assert_eq!(v.status().unwrap().corrupt, 1);
    }

    #[test]
    fn unreadable_folder_metadata_is_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let v = new_vault(&dir);
        let col = personal(&v);
        drop(v);
        raw_db(&dir).execute("UPDATE items SET blob = x'0102' WHERE id = ?1", [col.to_string()]).unwrap();
        let mut v = Vault::open(&dir.path().join("vault.db")).unwrap();
        v.unlock(PW).unwrap();
        let label = Label { id: Uuid::new_v4(), name: "x".into(), color: LabelColor::Red };
        assert!(matches!(v.save_label(col, label), Err(VaultError::Invalid(_))));
        assert_eq!(v.status().unwrap().corrupt, 1);
    }

    /// A vault with a labelled 2FA login in the personal folder and a note in "Семья".
    fn filled(dir: &tempfile::TempDir) -> Vault {
        let mut v = new_vault(dir);
        let col = personal(&v);
        let work = Label { id: Uuid::new_v4(), name: "работа".into(), color: pwd_core::model::LabelColor::Blue };
        v.save_label(col, work.clone()).unwrap();
        let mut gh = login(&v, "GitHub", "gh-Секрет-42");
        gh.labels = vec![work.id];
        gh.totp = Some("JBSWY3DPEHPK3PXP".into());
        gh.favorite = true;
        let id = v.save(gh).unwrap();
        let mut edit = login(&v, "GitHub", "gh-new-43");
        (edit.id, edit.labels, edit.totp, edit.favorite) = (Some(id), vec![work.id], None, true);
        v.save(edit).unwrap();
        let fam = v.create_collection("Семья").unwrap();
        let mut wifi = login(&v, "Wi-Fi", "");
        (wifi.collection_id, wifi.kind, wifi.notes) = (fam, ItemKind::Note, "SSID home".into());
        v.save(wifi).unwrap();
        v.post_message(fam, "не в копию").unwrap();
        let gone = v.save(login(&v, "Удалённое", "x")).unwrap();
        v.delete(gone).unwrap();
        v
    }

    #[test]
    fn attachments_follow_their_item() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = new_vault(&dir);
        let id = v.save(login(&v, "Сервер", "pw-1")).unwrap();
        let key = b"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n".to_vec();
        let f = v.attach(id, "C:\\keys\\id_ed25519", &key).unwrap();
        assert_eq!(v.list().unwrap().len(), 1, "a file is not a password");
        assert_eq!(v.collections().unwrap()[0].count, 1);
        let a = v.get(id).unwrap().attachments;
        assert_eq!((a.len(), a[0].id, a[0].name.as_str(), a[0].size), (1, f, "id_ed25519", key.len()));
        assert_eq!(v.attachment_data(f).unwrap(), ("id_ed25519".to_string(), key.clone()));
        assert!(matches!(v.attach(id, "big.bin", &vec![0; ATTACHMENT_MAX + 1]), Err(VaultError::Invalid(_))));
        assert!(matches!(v.attach(f, "nested.txt", b"x"), Err(VaultError::Invalid(_))), "files attach to entries only");

        v.delete(id).unwrap();
        assert!(v.get(id).unwrap().attachments.is_empty(), "trashed along with the entry");
        v.restore(id).unwrap();
        assert_eq!(v.get(id).unwrap().attachments.len(), 1);

        let fam = v.create_collection("Семья").unwrap();
        let mut moved = login(&v, "Сервер", "");
        (moved.id, moved.collection_id, moved.password) = (Some(id), fam, None);
        let new_id = v.save(moved).unwrap();
        let a = v.get(new_id).unwrap().attachments;
        assert_eq!(a.len(), 1, "moves with the entry");
        assert_eq!(v.attachment_data(a[0].id).unwrap().1, key);
        assert_eq!(v.attachment_data(f), Err(VaultError::NotFound), "the old copy is gone");

        let second = v.attach(new_id, "readme.txt", b"hello").unwrap();
        v.remove_attachment(second).unwrap();
        assert_eq!(v.get(new_id).unwrap().attachments.len(), 1);

        let file = dir.path().join("with-files.pwbak");
        v.export_backup(&file, "пароль копии").unwrap();
        v.purge(new_id).unwrap();
        assert_eq!(v.attachment_data(a[0].id), Err(VaultError::NotFound), "purged with the entry");

        let col = personal(&v);
        v.import_backup(&file, "пароль копии", col).unwrap();
        let back = v.list().unwrap().into_iter().find(|i| i.title == "Сервер").unwrap();
        let a = v.get(back.id).unwrap().attachments;
        assert_eq!(v.attachment_data(a[0].id).unwrap(), ("id_ed25519".to_string(), key), "backups carry files");
    }

    #[test]
    fn breach_results_mark_items_until_the_password_changes() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = new_vault(&dir);
        let leaked = v.save(login(&v, "Форум", "password")).unwrap();
        let fine = v.save(login(&v, "Банк", "Zt4$wq-Lm8!pXv2#")).unwrap();
        v.post_message(personal(&v), "чат не проверяем").unwrap();
        let cands = v.pwned_candidates().unwrap();
        assert_eq!(cands.len(), 2, "only items with a password");
        let results = cands.iter().map(|(id, at, _)| (*id, *at, if *id == leaked { 42 } else { 0 })).collect();
        v.set_pwned(results);
        let flag = |v: &mut Vault, id| v.list().unwrap().into_iter().find(|i| i.id == id).unwrap().pwned;
        assert!(flag(&mut v, leaked) && !flag(&mut v, fine));
        assert!(v.get(leaked).unwrap().summary.pwned);

        let mut edit = login(&v, "Форум", "Kq9!mZ2-vR7#pL4x");
        edit.id = Some(leaked);
        v.save(edit).unwrap();
        assert!(!flag(&mut v, leaked), "a changed password needs a new check");
        v.set_pwned(vec![(fine, Utc::now(), 1)]);
        v.lock();
        v.unlock(PW).unwrap();
        assert!(!flag(&mut v, fine), "results live only until lock");
    }

    #[test]
    fn backup_roundtrip_into_another_vault() {
        let (d1, d2) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let v = filled(&d1);
        let file = d1.path().join("passwords.pwbak");
        assert_eq!(v.export_backup(&file, "пароль копии").unwrap(), 2, "live passwords and notes, no chat, no trash");

        let mut w = new_vault(&d2);
        let col = personal(&w);
        assert!(matches!(w.import_backup(&file, "не тот", col), Err(VaultError::Invalid(_))));
        assert_eq!(w.import_backup(&file, "пароль копии", col).unwrap(), 2);
        let list = w.list().unwrap();
        let gh = list.iter().find(|i| i.title == "GitHub").unwrap();
        assert_eq!(w.reveal(gh.id, "password").unwrap(), "gh-new-43");
        assert_eq!(w.reveal(gh.id, "history:0").unwrap(), "gh-Секрет-42", "history comes along");
        assert!(gh.has_totp && gh.favorite);
        let names: Vec<String> = gh.labels.iter().map(|l| w.collections().unwrap()[0].labels.iter().find(|x| x.id == *l).unwrap().name.clone()).collect();
        assert_eq!(names, ["работа"]);
        let wifi = list.iter().find(|i| i.title == "Wi-Fi").unwrap();
        assert_eq!((wifi.kind, wifi.collection_id), (ItemKind::Note, col));
        let folder: Vec<String> = wifi.labels.iter().map(|l| w.collections().unwrap()[0].labels.iter().find(|x| x.id == *l).unwrap().name.clone()).collect();
        assert_eq!(folder, ["Семья"], "the source folder becomes a label");

        std::fs::write(&file, "not a backup").unwrap();
        assert!(matches!(w.import_backup(&file, "пароль копии", col), Err(VaultError::Invalid(_))));
    }

    #[test]
    fn csv_export_imports_back() {
        let (d1, d2) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let v = filled(&d1);
        let csv = d1.path().join("passwords.csv");
        assert_eq!(v.export_csv(&csv).unwrap(), 2);
        let mut w = new_vault(&d2);
        let col = personal(&w);
        assert_eq!(w.import_csv(&csv, col).unwrap(), 2);
        let list = w.list().unwrap();
        let gh = list.iter().find(|i| i.title == "GitHub").unwrap();
        assert_eq!(w.reveal(gh.id, "password").unwrap(), "gh-new-43");
        assert!(gh.has_totp);
        assert_eq!(list.iter().find(|i| i.title == "Wi-Fi").unwrap().kind, ItemKind::Note);
    }

    #[test]
    fn import_csv_with_folders_and_2fa() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = new_vault(&dir);
        let col = personal(&v);
        let csv = dir.path().join("bitwarden.csv");
        std::fs::write(
            &csv,
            "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
             Работа,,login,GitLab,,,0,https://gitlab.com,cody,gl-1,JBSWY3DPEHPK3PXP\n\
             Работа,,login,Jira,,,0,https://jira.local,cody,j-1,not-a-secret!\n\
             ,,note,Wi-Fi,SSID home,,0,,,,\n",
        )
        .unwrap();
        assert_eq!(v.import_csv(&csv, col).unwrap(), 3);
        let labels = v.collections().unwrap()[0].labels.clone();
        assert_eq!(labels.iter().map(|l| l.name.as_str()).collect::<Vec<_>>(), ["Работа"]);
        let list = v.list().unwrap();
        let gl = list.iter().find(|i| i.title == "GitLab").unwrap();
        assert_eq!(gl.labels, [labels[0].id]);
        assert_eq!(v.reveal(gl.id, "password").unwrap(), "gl-1");
        assert_eq!(v.totp(gl.id).unwrap().code.len(), 6);
        let jira = list.iter().find(|i| i.title == "Jira").unwrap();
        assert!(!jira.has_totp, "a broken 2FA secret must not block the import");
        assert!(v.get(jira.id).unwrap().notes.contains("not-a-secret!"), "it is kept in the notes");
        assert_eq!(list.iter().find(|i| i.title == "Wi-Fi").unwrap().kind, ItemKind::Note);

        std::fs::write(&csv, "a,b\n1,2\n").unwrap();
        assert!(matches!(v.import_csv(&csv, col), Err(VaultError::Invalid(_))));
    }

}
