//! Server sync: pinned-TLS client, connect / login, push + pull with conflict resolution.
//! Network calls never hold the vault lock: gather under lock, talk to the server, apply under lock.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use chrono::Utc;
use data_encoding::{BASE32_NOPAD, BASE64};
use pwd_core::account::{self, UnlockedAccount};
use pwd_core::collection::{decrypt_record, encrypt_record, CollectionKey};
use pwd_core::model::{HistoryEntry, Item, Meta, HISTORY_LIMIT};
use pwd_core::proto::*;
use reqwest::StatusCode;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::store::{CollectionRow, ItemRow};
use crate::vault::{io, write_row, wrong_password, VResult, Vault, VaultError};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ServerInfo {
    pub url: String,
    pub fp: String,
    #[serde(default)]
    pub token: String,
    pub user_id: Uuid,
    pub username: String,
    pub is_admin: bool,
    #[serde(default)]
    pub last_sync: Option<String>,
}

#[derive(Serialize, Debug, Clone)]
pub struct ServerStatus {
    pub url: String,
    pub username: String,
    pub is_admin: bool,
    pub last_sync: Option<String>,
    /// `pwd://host:port?fp=…` for logging in on another device.
    pub link: String,
    /// This account's key fingerprint, to read out to people you share with.
    pub fingerprint: String,
}

#[derive(Serialize, Debug, Default, Clone)]
pub struct SyncReport {
    pub pushed: usize,
    pub pulled: usize,
    pub conflicts: usize,
}

// ---------- links ----------

pub struct Link {
    pub url: String,
    pub fp: String,
    pub invite: Option<String>,
}

/// `pwd://host:port/invite/CODE?fp=FP` or `pwd://host:port?fp=FP`.
pub fn parse_link(s: &str) -> VResult<Link> {
    let bad = || VaultError::Invalid("invite link is malformed".into());
    let s = s.trim();
    let rest = s.strip_prefix("pwd://").or_else(|| s.strip_prefix("https://")).ok_or_else(bad)?;
    let (main, query) = rest.split_once('?').ok_or_else(bad)?;
    let fp = query.split('&').find_map(|kv| kv.strip_prefix("fp=")).ok_or_else(bad)?;
    let (hostport, path) = main.split_once('/').unwrap_or((main, ""));
    if hostport.is_empty() {
        return Err(bad());
    }
    let invite = path
        .strip_prefix("invite/")
        .map(|c| c.trim_end_matches('/').to_string())
        .filter(|c| !c.is_empty());
    Ok(Link { url: format!("https://{hostport}"), fp: fp.to_uppercase(), invite })
}

fn server_link(info: &ServerInfo) -> String {
    format!("pwd://{}?fp={}", info.url.trim_start_matches("https://"), info.fp)
}

// ---------- pinned TLS client ----------

/// Accepts exactly one certificate: the one whose SHA-256 is in the invite link.
#[derive(Debug)]
struct Pinned {
    fp: Vec<u8>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if Sha256::digest(end_entity.as_ref()).as_slice() == self.fp.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("server certificate fingerprint mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

pub(crate) enum PushOutcome {
    Accepted(i64),
    Conflict(Option<ItemWire>),
    Forbidden,
    KeyRotated,
}

pub(crate) struct Client {
    http: reqwest::Client,
    url: String,
    token: Option<String>,
}

fn net(e: reqwest::Error) -> VaultError {
    let mut msg = e.to_string();
    let mut src = std::error::Error::source(&e);
    while let Some(s) = src {
        msg.push_str(": ");
        msg.push_str(&s.to_string());
        src = s.source();
    }
    VaultError::Offline(msg)
}

impl Client {
    pub(crate) fn new(url: &str, fp: &str, token: Option<String>) -> VResult<Client> {
        let fp = BASE32_NOPAD
            .decode(fp.as_bytes())
            .map_err(|_| VaultError::Invalid("invite link is malformed".into()))?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(io)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Pinned { fp, provider }))
            .with_no_client_auth();
        let http = reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(net)?;
        Ok(Client { http, url: url.trim_end_matches('/').to_string(), token })
    }

    async fn send<T: DeserializeOwned>(&self, req: reqwest::RequestBuilder) -> VResult<T> {
        let req = match &self.token {
            Some(t) => req.bearer_auth(t),
            None => req,
        };
        let res = req.send().await.map_err(net)?;
        let status = res.status();
        if status.is_success() {
            return res.json().await.map_err(net);
        }
        let msg = res.json::<ErrorResp>().await.map(|e| e.error).unwrap_or_else(|_| status.to_string());
        Err(match status {
            StatusCode::UNAUTHORIZED => VaultError::SessionExpired,
            StatusCode::TOO_MANY_REQUESTS => VaultError::Server("too_many_attempts".into()),
            _ => VaultError::Server(msg),
        })
    }

    pub(crate) async fn get<T: DeserializeOwned>(&self, path: &str) -> VResult<T> {
        self.send(self.http.get(format!("{}{path}", self.url))).await
    }

    pub(crate) async fn post<B: Serialize, T: DeserializeOwned>(&self, path: &str, body: &B) -> VResult<T> {
        self.send(self.http.post(format!("{}{path}", self.url)).json(body)).await
    }

    pub(crate) async fn put<B: Serialize, T: DeserializeOwned>(&self, path: &str, body: &B) -> VResult<T> {
        self.send(self.http.put(format!("{}{path}", self.url)).json(body)).await
    }

    pub(crate) async fn delete<T: DeserializeOwned>(&self, path: &str) -> VResult<T> {
        self.send(self.http.delete(format!("{}{path}", self.url))).await
    }

    /// A raw file (installers are large: a longer timeout than API calls).
    pub(crate) async fn bytes(&self, path: &str) -> VResult<Vec<u8>> {
        let res = self.http.get(format!("{}{path}", self.url)).timeout(Duration::from_secs(900)).send().await.map_err(net)?;
        if !res.status().is_success() {
            return Err(VaultError::Server(res.status().to_string()));
        }
        Ok(res.bytes().await.map_err(net)?.to_vec())
    }

    async fn put_item(&self, id: Uuid, req: &PutItemReq) -> VResult<PushOutcome> {
        let mut r = self.http.put(format!("{}/api/items/{id}", self.url)).json(req);
        if let Some(t) = &self.token {
            r = r.bearer_auth(t);
        }
        let res = r.send().await.map_err(net)?;
        match res.status() {
            s if s.is_success() => Ok(PushOutcome::Accepted(res.json::<RevResp>().await.map_err(net)?.rev)),
            StatusCode::CONFLICT => Ok(PushOutcome::Conflict(res.json().await.map_err(net)?)),
            StatusCode::FORBIDDEN => Ok(PushOutcome::Forbidden),
            StatusCode::PRECONDITION_FAILED => Ok(PushOutcome::KeyRotated),
            StatusCode::UNAUTHORIZED => Err(VaultError::SessionExpired),
            s => Err(VaultError::Server(s.to_string())),
        }
    }
}

pub(crate) fn lock(v: &Mutex<Vault>) -> MutexGuard<'_, Vault> {
    v.lock().unwrap_or_else(|e| e.into_inner())
}

// ---------- vault side (runs under the lock) ----------

pub(crate) struct Outbox {
    pub(crate) server: ServerInfo,
    since: i64,
    collections: Vec<CreateCollectionReq>,
    items: Vec<(Uuid, PutItemReq)>,
    account: Option<AccountUpdateReq>,
}

/// Item and meta records both travel as opaque JSON when re-encrypting.
type Record = serde_json::Value;

fn same_except_password(a: &Item, b: &Item) -> bool {
    let mut a = a.clone();
    a.password.clone_from(&b.password);
    a.password_history.clone_from(&b.password_history);
    a.updated_at = b.updated_at;
    a == *b
}

impl Vault {
    /// Server settings; the session token is filled in only while unlocked (it is stored sealed).
    pub(crate) fn server_info(&self) -> VResult<Option<ServerInfo>> {
        let Some(json) = self.store.get_kv("server")? else { return Ok(None) };
        let mut info: ServerInfo = serde_json::from_str(&json).map_err(io)?;
        if let (Some(sealed), Some(s)) = (self.store.get_kv("token")?, self.session.as_ref()) {
            let raw = s.account.open_private(&BASE64.decode(sealed.as_bytes()).map_err(io)?, b"session_token")?;
            info.token = String::from_utf8(raw.to_vec()).map_err(io)?;
        }
        Ok(Some(info))
    }

    /// The token authorizes writes on the server, so it never sits in the file in clear.
    fn set_server_info(&self, info: &ServerInfo) -> VResult<()> {
        let s = self.session()?;
        let sealed = s.account.seal_private(info.token.as_bytes(), b"session_token");
        self.store.set_kv("token", &BASE64.encode(&sealed))?;
        let public = ServerInfo { token: String::new(), ..info.clone() };
        self.store.set_kv("server", &serde_json::to_string(&public).map_err(io)?)?;
        Ok(())
    }

    pub fn server_status(&self) -> VResult<Option<ServerStatus>> {
        let fingerprint = pwd_core::account::fingerprint(&self.blobs()?.public_key);
        Ok(self.server_info()?.map(|i| ServerStatus {
            fingerprint,
            link: server_link(&i),
            url: i.url,
            username: i.username,
            is_admin: i.is_admin,
            last_sync: i.last_sync,
        }))
    }

    /// Verifies the master password and builds the registration for an existing local account.
    fn register_request(
        &self,
        password: &str,
        recovery_code: Option<&str>,
        invite: String,
        username: Option<&str>,
    ) -> VResult<RegisterReq> {
        if self.server_info()?.is_some() {
            return Err(VaultError::Exists);
        }
        let blobs = self.blobs()?;
        let keys = account::derive_login(password, &blobs.kdf_salt, blobs.kdf_params)?;
        let account = account::unlock_with(&keys, &blobs).map_err(wrong_password)?;
        let recovery_auth = match (self.store.get_kv("recovery_auth")?, recovery_code) {
            (_, Some(code)) => *account::recovery_auth(code)?,
            (Some(sealed), None) => {
                let blob = BASE64.decode(sealed.as_bytes()).map_err(io)?;
                let raw = account.open_private(&blob, b"recovery_auth")?;
                raw.as_slice().try_into().map_err(|_| io("bad recovery_auth"))?
            }
            (None, None) => return Err(VaultError::Invalid("recovery code required".into())),
        };
        let username = match username.map(str::trim).filter(|u| !u.is_empty()) {
            Some(u) => u.to_string(),
            None => self.store.get_kv("username")?.ok_or(VaultError::NotFound)?,
        };
        Ok(RegisterReq { invite, username, auth_key: *keys.auth_key, recovery_auth, account: blobs, device: device_name() })
    }

    /// New device: keep the account the server returned, start with an empty local cache.
    fn adopt_account(&mut self, resp: &SessionResp, account: UnlockedAccount, link: &Link) -> VResult<()> {
        self.store.set_kv("account", &serde_json::to_string(&resp.account).map_err(io)?)?;
        self.store.set_kv("username", &resp.username)?;
        self.session = Some(self.load(account)?);
        self.set_server_info(&ServerInfo {
            url: link.url.clone(),
            fp: link.fp.clone(),
            token: resp.token.clone(),
            user_id: resp.user_id,
            username: resp.username.clone(),
            is_admin: resp.is_admin,
            last_sync: None,
        })?;
        Ok(())
    }

    /// Copies our not-yet-uploaded records of a folder we can no longer write into the personal folder.
    fn rescue(&self, old: &crate::vault::Session, rows: &[ItemRow]) -> VResult<()> {
        let Some((pid, personal)) = old.cols.iter().find(|(_, c)| c.kind == "personal") else { return Ok(()) };
        let now = Utc::now();
        for row in rows.iter().filter(|r| r.dirty && !r.deleted && r.id != r.collection_id) {
            if let Some((_, item)) = old.items.get(&row.id) {
                let mut copy = item.clone();
                copy.title = format!("{} (нет доступа)", copy.title);
                copy.labels.clear();
                copy.updated_at = now;
                write_row(&self.store, &personal.key, *pid, Uuid::new_v4(), &copy, now)?;
            }
        }
        Ok(())
    }

    pub(crate) fn outbox(&self) -> VResult<Outbox> {
        let s = self.session()?;
        let server = self.server_info()?.ok_or_else(|| VaultError::Invalid("not connected to a server".into()))?;
        let since = self.store.get_kv("last_rev")?.and_then(|r| r.parse().ok()).unwrap_or(0);
        let collections = self
            .store
            .collections()?
            .into_iter()
            .filter(|c| c.dirty)
            .map(|c| CreateCollectionReq { id: c.id, kind: c.kind, key_version: c.key_version, sealed_ck: c.sealed_ck })
            .collect();
        let items = self
            .store
            .items()?
            .into_iter()
            .filter(|r| r.dirty)
            .map(|r| {
                let req = PutItemReq {
                    collection_id: r.collection_id,
                    key_version: r.key_version,
                    blob: r.blob,
                    deleted: r.deleted,
                    base_rev: r.rev,
                    updated_at: r.updated_at,
                };
                (r.id, req)
            })
            .collect();
        let account = match self.store.get_kv("pending_account")? {
            Some(sealed) => {
                let raw = s.account.open_private(&BASE64.decode(sealed.as_bytes()).map_err(io)?, b"pending_account")?;
                Some(serde_json::from_slice(&raw).map_err(io)?)
            }
            None => None,
        };
        Ok(Outbox { server, since, collections, items, account })
    }

    /// Server returned a newer version of an item we changed. Nothing is lost:
    /// the later edit wins, a losing password goes to history, other losing edits become a copy.
    fn resolve(&mut self, id: Uuid, current: Option<ItemWire>, report: &mut SyncReport) -> VResult<()> {
        report.conflicts += 1;
        let Some(cur) = current else {
            // Purged on the server meanwhile: re-create ours.
            if let Some(mut row) = self.store.item_row(id)? {
                row.rev = 0;
                self.store.put_item(&row)?;
            }
            return Ok(());
        };
        let now = Utc::now();
        let Vault { store, session, .. } = self;
        let s = session.as_mut().ok_or(VaultError::Locked)?;
        let remote_row = |dirty: bool| ItemRow {
            id,
            collection_id: cur.collection_id,
            key_version: cur.key_version,
            blob: cur.blob.clone(),
            deleted: cur.deleted,
            rev: cur.rev,
            dirty,
            updated_at: cur.updated_at.clone(),
        };
        let Some(col) = s.cols.get(&cur.collection_id) else {
            store.put_item(&remote_row(false))?;
            return Ok(());
        };
        // Folder meta: merge labels.
        if id == cur.collection_id {
            if let Ok(remote) = decrypt_record::<Meta>(&col.key, id, id, &cur.blob) {
                let mut meta = col.meta.clone();
                for l in remote.labels {
                    if !meta.labels.iter().any(|x| x.id == l.id) {
                        meta.labels.push(l);
                    }
                }
                store.put_item(&ItemRow { blob: encrypt_record(&col.key, id, id, &meta)?, ..remote_row(true) })?;
            }
            return Ok(());
        }
        let local = s.items.get(&id).map(|(_, i)| i.clone());
        let remote = if cur.deleted { None } else { decrypt_record::<Item>(&col.key, cur.collection_id, id, &cur.blob).ok() };
        match (local, remote) {
            // We purged it, they edited it: keep their version.
            (None, Some(_)) => store.put_item(&remote_row(false))?,
            // They purged it: keep ours on top of their rev.
            (Some(_), None) if cur.deleted => {
                if let Some(mut row) = store.item_row(id)? {
                    row.rev = cur.rev;
                    store.put_item(&row)?;
                }
            }
            // Unreadable (e.g. new key not loaded yet): leave ours, it conflicts again next round.
            (Some(_), None) | (None, None) => {}
            (Some(local), Some(remote)) => {
                let (mut winner, loser) = if local.updated_at >= remote.updated_at { (local, remote) } else { (remote, local) };
                if same_except_password(&winner, &loser) {
                    if loser.password != winner.password
                        && !loser.password.is_empty()
                        && !winner.password_history.iter().any(|h| h.value == loser.password)
                    {
                        winner.password_history.push(HistoryEntry { value: loser.password.clone(), changed_at: now });
                        let excess = winner.password_history.len().saturating_sub(HISTORY_LIMIT);
                        winner.password_history.drain(..excess);
                    }
                } else if winner != loser {
                    let mut copy = loser.clone();
                    copy.title = format!("{} (конфликт)", copy.title);
                    copy.updated_at = now;
                    write_row(store, &col.key, cur.collection_id, Uuid::new_v4(), &copy, now)?;
                }
                let blob = encrypt_record(&col.key, cur.collection_id, id, &winner)?;
                store.put_item(&ItemRow { blob, updated_at: winner.updated_at.to_rfc3339(), ..remote_row(true) })?;
            }
        }
        Ok(())
    }

    /// Applies upload results and the pulled changes, then reloads the session.
    /// Returns true if something is still waiting to be uploaded.
    pub(crate) fn apply(
        &mut self,
        created: &[Uuid],
        account_done: bool,
        pushed: Vec<(Uuid, Vec<u8>, PushOutcome)>,
        pull: SyncResp,
        report: &mut SyncReport,
    ) -> VResult<bool> {
        self.session()?;
        for id in created {
            self.store.collection_clean(*id)?;
        }
        if account_done {
            self.store.del_kv("pending_account")?;
        }
        let mut full_resync = false;
        for (id, sent, outcome) in pushed {
            match outcome {
                PushOutcome::Accepted(rev) => {
                    report.pushed += 1;
                    self.store.ack_item(id, rev, &sent)?;
                }
                PushOutcome::Conflict(cur) => self.resolve(id, cur, report)?,
                // Lost write access: keep a copy in the personal folder, fetch the folder again.
                PushOutcome::Forbidden => {
                    if let (Some(row), Some(s)) = (self.store.item_row(id)?, self.session.as_ref()) {
                        self.rescue(s, std::slice::from_ref(&row))?;
                    }
                    self.store.delete_item(id)?;
                    full_resync = true;
                }
                // Re-encrypted below once the new key arrives.
                PushOutcome::KeyRotated => {}
            }
        }

        let old = self.session.take().ok_or(VaultError::Locked)?;
        let result = self.apply_pull(&old, pull, report, full_resync);
        self.session = Some(self.load(old.account)?);
        result?;
        Ok(self.store.items()?.iter().any(|r| r.dirty) || self.store.collections()?.iter().any(|c| c.dirty))
    }

    fn apply_pull(
        &self,
        old: &crate::vault::Session,
        pull: SyncResp,
        report: &mut SyncReport,
        full_resync: bool,
    ) -> VResult<()> {
        let me = old.account.public_key();
        let local: std::collections::HashMap<Uuid, CollectionRow> =
            self.store.collections()?.into_iter().map(|c| (c.id, c)).collect();
        for id in &pull.removed {
            if local.get(id).is_some_and(|c| c.kind == "personal") {
                continue; // the server cannot take our personal folder away
            }
            let rows: Vec<ItemRow> = self.store.items()?.into_iter().filter(|r| r.collection_id == *id).collect();
            self.rescue(old, &rows)?;
            self.store.delete_collection(*id)?;
        }
        for c in &pull.collections {
            // Grants are pinned: our personal folder only from ourselves, a shared folder only from
            // the key that granted it first (its owner). Anything else is a planted key.
            let pinned = match local.get(&c.id) {
                Some(l) => l.granted_by,
                None if c.kind == "personal" => me,
                None => c.granted_by,
            };
            if c.granted_by != pinned || (c.kind == "personal" && c.granted_by != me) {
                continue;
            }
            // Key rotated: re-encrypt our not-yet-uploaded rows of that folder with the new key.
            if let Some(prev) = old.cols.get(&c.id).filter(|p| p.key.version != c.key_version) {
                if let Ok(new) = CollectionKey::open_sealed(&c.sealed_ck, c.id, c.key_version, &c.granted_by, &old.account) {
                    let prev_key = CollectionKey { key: prev.key.key.clone(), version: prev.key.version };
                    for mut row in self.store.items()? {
                        if row.collection_id != c.id || !row.dirty || row.key_version != prev_key.version {
                            continue;
                        }
                        if row.deleted {
                            // Tombstones carry no blob; they only need the new version to be accepted.
                            row.key_version = new.version;
                            self.store.put_item(&row)?;
                        } else if let Ok(rec) = decrypt_record::<Record>(&prev_key, c.id, row.id, &row.blob) {
                            row.blob = encrypt_record(&new, c.id, row.id, &rec)?;
                            row.key_version = new.version;
                            self.store.put_item(&row)?;
                        }
                    }
                }
            }
            self.store.put_collection(&CollectionRow {
                id: c.id,
                kind: c.kind.clone(),
                role: c.role.clone(),
                key_version: c.key_version,
                sealed_ck: c.sealed_ck.clone(),
                granted_by: c.granted_by,
                rev: 0,
                dirty: false,
            })?;
        }
        for it in pull.items {
            if self.store.item_row(it.id)?.is_some_and(|r| r.dirty) {
                continue; // ours wins the race to the server; a conflict will resolve it
            }
            report.pulled += 1;
            if !it.author.is_empty() {
                self.store.set_author(it.id, &it.author)?;
            }
            self.store.put_item(&ItemRow {
                id: it.id,
                collection_id: it.collection_id,
                key_version: it.key_version,
                blob: it.blob,
                deleted: it.deleted,
                rev: it.rev,
                dirty: false,
                updated_at: it.updated_at,
            })?;
        }
        let rev = if full_resync { 0 } else { pull.rev };
        self.store.set_kv("last_rev", &rev.to_string())?;
        Ok(())
    }

    fn mark_synced(&self) -> VResult<()> {
        if let Some(mut info) = self.server_info()? {
            info.last_sync = Some(Utc::now().to_rfc3339());
            self.set_server_info(&info)?;
        }
        Ok(())
    }
}

// ---------- network flows (no lock held across awaits) ----------

/// Uploads the existing local account with an invite, then syncs.
pub async fn connect(
    v: &Mutex<Vault>,
    link: &str,
    password: &str,
    recovery_code: Option<&str>,
    username: Option<&str>,
) -> VResult<()> {
    let link = parse_link(link)?;
    let invite = link.invite.clone().ok_or_else(|| VaultError::Invalid("this link has no invite code".into()))?;
    let req = lock(v).register_request(password, recovery_code, invite, username)?;
    let client = Client::new(&link.url, &link.fp, None)?;
    let resp: SessionResp = client.post("/api/register", &req).await?;
    {
        let vault = lock(v);
        vault.store.set_kv("username", &resp.username)?;
        vault.set_server_info(&ServerInfo {
            url: link.url,
            fp: link.fp,
            token: resp.token,
            user_id: resp.user_id,
            username: resp.username,
            is_admin: resp.is_admin,
            last_sync: None,
        })?;
    }
    // Registered: a failed first upload is retried by the next sync, not a failed connect.
    let _ = run(v).await;
    Ok(())
}

async fn session_for(client: &Client, username: &str, password: &str) -> VResult<(SessionResp, UnlockedAccount)> {
    let pre: PreloginResp = client.post("/api/prelogin", &PreloginReq { username: username.into() }).await?;
    let keys = account::derive_login(password, &pre.kdf_salt, pre.kdf_params)?;
    let resp: SessionResp = match client.post("/api/login", &LoginReq { username: username.into(), auth_key: *keys.auth_key, device: device_name() }).await {
        Err(VaultError::SessionExpired) => return Err(VaultError::WrongPassword),
        r => r?,
    };
    let account = account::unlock_with(&keys, &resp.account).map_err(wrong_password)?;
    Ok((resp, account))
}

/// New device: log in with a server link, download everything.
pub async fn login(v: &Mutex<Vault>, link: &str, username: &str, password: &str) -> VResult<()> {
    let link = parse_link(link)?;
    if lock(v).status()?.has_account {
        return Err(VaultError::Exists);
    }
    let client = Client::new(&link.url, &link.fp, None)?;
    let (resp, account) = session_for(&client, username.trim(), password).await?;
    lock(v).adopt_account(&resp, account, &link)?;
    let _ = run(v).await; // logged in; the download is retried by the next sync
    Ok(())
}

/// Session expired: log in again with the master password; local data stays.
pub async fn relogin(v: &Mutex<Vault>, password: &str) -> VResult<()> {
    let info = lock(v).server_info()?.ok_or(VaultError::NotFound)?;
    let client = Client::new(&info.url, &info.fp, None)?;
    let (resp, _) = session_for(&client, &info.username, password).await?;
    {
        let vault = lock(v);
        if resp.account.public_key != vault.blobs()?.public_key {
            return Err(VaultError::Server("account key mismatch".into()));
        }
        vault.set_server_info(&ServerInfo { token: resp.token, is_admin: resp.is_admin, ..info })?;
        vault.store.set_kv("account", &serde_json::to_string(&resp.account).map_err(io)?)?;
    }
    run(v).await.map(|_| ())
}

/// One sync round trip, repeated while uploads keep producing work (conflicts, edits made meanwhile).
pub async fn run(v: &Mutex<Vault>) -> VResult<SyncReport> {
    let mut report = SyncReport::default();
    for _ in 0..4 {
        let ob = lock(v).outbox()?;
        let client = Client::new(&ob.server.url, &ob.server.fp, Some(ob.server.token.clone()))?;
        let mut account_done = false;
        if let Some(update) = &ob.account {
            let _: RevResp = client.post("/api/account", update).await?;
            account_done = true;
        }
        let mut created = Vec::new();
        for c in &ob.collections {
            let _: RevResp = client.post("/api/collections", c).await?;
            created.push(c.id);
        }
        let mut pushed = Vec::new();
        for (id, req) in ob.items {
            let outcome = client.put_item(id, &req).await?;
            pushed.push((id, req.blob, outcome));
        }
        let pull: SyncResp = client.get(&format!("/api/sync?since={}", ob.since)).await?;
        if !lock(v).apply(&created, account_done, pushed, pull, &mut report)? {
            break;
        }
    }
    lock(v).mark_synced()?;
    Ok(report)
}

/// The server moved (new IP or name): accept a new link only for the same certificate.
pub async fn update_link(v: &Mutex<Vault>, link: &str) -> VResult<()> {
    let link = parse_link(link)?;
    {
        let vault = lock(v);
        let info = vault.server_info()?.ok_or_else(|| VaultError::Invalid("not connected to a server".into()))?;
        if link.fp != info.fp {
            return Err(VaultError::Invalid("server certificate differs".into()));
        }
        vault.set_server_info(&ServerInfo { url: link.url, ..info })?;
    }
    run(v).await.map(|_| ())
}

/// "Windows · DESKTOP-1": how this computer appears in the device list.
pub fn device_name() -> String {
    let os = if cfg!(windows) { "Windows" } else if cfg!(target_os = "macos") { "macOS" } else { "Linux" };
    let host = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "компьютер".into());
    format!("{os} · {host}")
}

/// Devices logged in to this account, the current one marked.
pub async fn sessions(v: &Mutex<Vault>) -> VResult<Vec<pwd_core::proto::SessionInfo>> {
    let (client, _) = client_for(v).await?;
    client.get("/api/sessions").await
}

pub async fn revoke_session(v: &Mutex<Vault>, id: &str) -> VResult<()> {
    let (client, _) = client_for(v).await?;
    let _: RevResp = client.delete(&format!("/api/sessions/{id}")).await?;
    Ok(())
}

pub async fn revoke_other_sessions(v: &Mutex<Vault>) -> VResult<()> {
    let (client, _) = client_for(v).await?;
    let _: RevResp = client.post("/api/sessions/revoke_others", &serde_json::json!({})).await?;
    Ok(())
}

pub(crate) async fn client_for(v: &Mutex<Vault>) -> VResult<(Client, ServerInfo)> {
    let info = lock(v).server_info()?.ok_or_else(|| VaultError::Invalid("not connected to a server".into()))?;
    Ok((Client::new(&info.url, &info.fp, Some(info.token.clone()))?, info))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::ItemInput;
    use pwd_core::kdf::KdfParams;
    use pwd_core::model::ItemKind;

    fn vault(dir: &tempfile::TempDir) -> Vault {
        let mut v = Vault::open(&dir.path().join("vault.db")).unwrap();
        v.create_local("alice", "пароль алисы").unwrap();
        v
    }

    fn item(col: Uuid, title: &str) -> ItemInput {
        ItemInput {
            id: None,
            collection_id: col,
            kind: ItemKind::Login,
            title: title.into(),
            username: String::new(),
            password: Some("p".into()),
            urls: vec![],
            notes: String::new(),
            totp: None,
            labels: vec![],
            favorite: false,
        }
    }

    fn pull(v: &mut Vault, resp: SyncResp) {
        v.apply(&[], false, vec![], resp, &mut SyncReport::default()).unwrap();
    }

    fn titles(v: &mut Vault) -> Vec<String> {
        v.list().unwrap().into_iter().map(|i| i.title).collect()
    }

    #[test]
    fn planted_personal_grant_and_removal_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = vault(&dir);
        let personal = v.collections().unwrap()[0].id;
        let id = v.save(item(personal, "GitHub")).unwrap();
        let me = v.session().unwrap().account.public_key();
        let attacker = account::create_account("x", KdfParams::DEFAULT).unwrap();
        let fake = CollectionKey::generate().rotate().unwrap();
        let wire = CollectionWire {
            id: personal,
            kind: "personal".into(),
            role: "owner".into(),
            key_version: fake.version,
            sealed_ck: fake.seal_for(personal, &me, &attacker.account).unwrap(),
            granted_by: attacker.blobs.public_key,
        };
        pull(&mut v, SyncResp { rev: 5, collections: vec![wire], items: vec![], removed: vec![personal] });
        assert_eq!(v.collections().unwrap().len(), 1, "personal folder survives a server 'removed'");
        assert_eq!(v.reveal(id, "password").unwrap(), "p", "still on our own key");
    }

    #[test]
    fn losing_a_folder_keeps_unsynced_records() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = vault(&dir);
        let fam = v.create_collection("Семья").unwrap();
        v.save(item(fam, "Wi-Fi")).unwrap();
        pull(&mut v, SyncResp { rev: 5, removed: vec![fam], ..Default::default() });
        assert_eq!(v.collections().unwrap().len(), 1);
        assert_eq!(titles(&mut v), ["Wi-Fi (нет доступа)"]);
    }

    #[test]
    fn pending_tombstone_follows_key_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = vault(&dir);
        let fam = v.create_collection("Семья").unwrap();
        let id = v.save(item(fam, "Old")).unwrap();
        v.purge(id).unwrap();
        let wire = {
            let s = v.session().unwrap();
            let me = s.account.public_key();
            let new = s.cols[&fam].key.rotate().unwrap();
            CollectionWire {
                id: fam,
                kind: "shared".into(),
                role: "owner".into(),
                key_version: new.version,
                sealed_ck: new.seal_for(fam, &me, &s.account).unwrap(),
                granted_by: me,
            }
        };
        pull(&mut v, SyncResp { rev: 7, collections: vec![wire], ..Default::default() });
        assert_eq!(v.store.item_row(id).unwrap().unwrap().key_version, 2);
    }

    #[test]
    fn parses_links() {
        let l = parse_link(" pwd://10.0.0.5:8443/invite/abc123?fp=zz ").unwrap();
        assert_eq!((l.url.as_str(), l.fp.as_str(), l.invite.as_deref()), ("https://10.0.0.5:8443", "ZZ", Some("abc123")));
        let l = parse_link("pwd://host:8443?fp=QQ").unwrap();
        assert_eq!((l.url.as_str(), l.invite), ("https://host:8443", None));
        for bad in ["", "http://x?fp=1", "pwd://host:1", "pwd://?fp=1"] {
            assert!(parse_link(bad).is_err(), "{bad}");
        }
    }
}
