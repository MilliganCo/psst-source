//! pwd-server: stores only encrypted blobs, account wrappers and key grants. Never sees plaintext.

pub mod tls;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, FromRequestParts, Path as UrlPath, Query, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use data_encoding::{BASE32_NOPAD, HEXLOWER};
use pwd_core::account::AccountBlobs;
use pwd_core::kdf::KdfParams;
use pwd_core::proto::*;
use rand_core::{OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

const SESSION_DAYS: i64 = 30;
const INVITE_DAYS: i64 = 7;
const LOGIN_FAILURES: u32 = 5;
const LOGIN_WINDOW: Duration = Duration::from_secs(15 * 60);

pub struct AppState {
    db: Mutex<Connection>,
    secret: [u8; 32],
    failures: Mutex<HashMap<String, (u32, Instant)>>,
    /// Directory with installers and `latest.json`, served under /updates and /download.
    pub releases: Option<std::path::PathBuf>,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE, auth_hash BLOB NOT NULL,
    recovery_hash BLOB NOT NULL, account TEXT NOT NULL, public_key BLOB NOT NULL,
    is_admin INTEGER NOT NULL, disabled INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (token_hash BLOB PRIMARY KEY, user_id TEXT NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS invites (code_hash BLOB PRIMARY KEY, is_admin INTEGER NOT NULL, expires_at INTEGER NOT NULL, used_by TEXT);
CREATE TABLE IF NOT EXISTS collections (id TEXT PRIMARY KEY, kind TEXT NOT NULL, owner_id TEXT NOT NULL, key_version INTEGER NOT NULL, rev INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS memberships (
    collection_id TEXT NOT NULL, user_id TEXT NOT NULL, role TEXT NOT NULL, sealed_ck BLOB NOT NULL,
    granted_by BLOB NOT NULL, key_version INTEGER NOT NULL, removed INTEGER NOT NULL DEFAULT 0, rev INTEGER NOT NULL,
    PRIMARY KEY (collection_id, user_id));
CREATE TABLE IF NOT EXISTS items (
    id TEXT PRIMARY KEY, collection_id TEXT NOT NULL, key_version INTEGER NOT NULL, blob BLOB NOT NULL,
    deleted INTEGER NOT NULL, rev INTEGER NOT NULL, updated_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS items_by_collection ON items (collection_id, rev);
INSERT OR IGNORE INTO meta (key, value) VALUES ('rev', '0');
";

fn sha(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

impl AppState {
    pub fn open(path: &Path) -> rusqlite::Result<AppState> {
        Self::init(Connection::open(path)?)
    }

    pub fn open_in_memory() -> rusqlite::Result<AppState> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> rusqlite::Result<AppState> {
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;")?;
        conn.execute_batch(SCHEMA)?;
        // 0.7: sessions remember the device and when they were last used.
        let has_device: bool = conn.query_row("SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name = 'device'", [], |r| r.get(0))?;
        if !has_device {
            conn.execute_batch(
                "ALTER TABLE sessions ADD COLUMN device TEXT NOT NULL DEFAULT '';
                 ALTER TABLE sessions ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0;
                 ALTER TABLE sessions ADD COLUMN last_seen INTEGER NOT NULL DEFAULT 0;",
            )?;
        }
        // 0.7: items remember who wrote them last.
        let has_author: bool = conn.query_row("SELECT COUNT(*) FROM pragma_table_info('items') WHERE name = 'author'", [], |r| r.get(0))?;
        if !has_author {
            conn.execute_batch("ALTER TABLE items ADD COLUMN author TEXT NOT NULL DEFAULT '';")?;
        }
        let secret = match conn.query_row("SELECT value FROM meta WHERE key = 'secret'", [], |r| r.get::<_, String>(0)).optional()? {
            Some(hex) => HEXLOWER.decode(hex.as_bytes()).ok().and_then(|v| v.try_into().ok()).unwrap_or([0; 32]),
            None => {
                let s: [u8; 32] = random();
                conn.execute("INSERT INTO meta (key, value) VALUES ('secret', ?1)", [HEXLOWER.encode(&s)])?;
                s
            }
        };
        Ok(AppState { db: Mutex::new(conn), secret, failures: Mutex::new(HashMap::new()), releases: None })
    }

    fn db(&self) -> MutexGuard<'_, Connection> {
        self.db.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Consistent copy of the database (`VACUUM INTO`).
    pub fn backup(&self, to: &Path) -> rusqlite::Result<()> {
        self.db().execute("VACUUM INTO ?1", [to.to_string_lossy()])?;
        Ok(())
    }

    pub fn users(&self) -> rusqlite::Result<Vec<AdminUser>> {
        let db = self.db();
        let mut st = db.prepare("SELECT id, username, is_admin, disabled FROM users ORDER BY username")?;
        let rows = st.query_map([], |r| {
            Ok(AdminUser { id: uuid(r.get(0)?)?, username: r.get(1)?, is_admin: r.get(2)?, disabled: r.get(3)? })
        })?;
        rows.collect()
    }

    pub fn set_disabled(&self, username: &str, disabled: bool) -> rusqlite::Result<bool> {
        let db = self.db();
        let n = db.execute("UPDATE users SET disabled = ?1 WHERE username = ?2", params![disabled, username])?;
        db.execute("DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE disabled = 1)", [])?;
        Ok(n > 0)
    }
}

fn uuid(s: String) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(&s).map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e)))
}

/// One-time invite code (base32, 26 chars). Valid for 7 days.
pub fn create_invite(state: &AppState, is_admin: bool) -> rusqlite::Result<String> {
    let code = BASE32_NOPAD.encode(&random::<16>()).to_lowercase();
    state.db().execute(
        "INSERT INTO invites (code_hash, is_admin, expires_at) VALUES (?1, ?2, ?3)",
        params![&sha(code.as_bytes())[..], is_admin, now() + INVITE_DAYS * 86400],
    )?;
    Ok(code)
}

fn next_rev(tx: &Transaction) -> rusqlite::Result<i64> {
    tx.query_row("UPDATE meta SET value = CAST(value AS INTEGER) + 1 WHERE key = 'rev' RETURNING CAST(value AS INTEGER)", [], |r| r.get(0))
}

// ---------- errors ----------

pub struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(ErrorResp { error: self.1 })).into_response()
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(e: rusqlite::Error) -> Self {
        ApiError(StatusCode::INTERNAL_SERVER_ERROR, format!("database: {e}"))
    }
}

fn err(code: StatusCode, msg: &str) -> ApiError {
    ApiError(code, msg.into())
}

type ApiResult<T> = Result<Json<T>, ApiError>;

// ---------- auth extractors ----------

struct User {
    id: Uuid,
    is_admin: bool,
    public_key: [u8; 32],
    username: String,
    /// Token hash of the session making the request.
    session: [u8; 32],
}

impl FromRequestParts<Arc<AppState>> for User {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &Arc<AppState>) -> Result<Self, ApiError> {
        let token = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "login required"))?;
        let db = state.db();
        let hash = sha(token.as_bytes());
        let user = db
            .query_row(
                "SELECT u.id, u.is_admin, u.public_key, u.username FROM sessions s JOIN users u ON u.id = s.user_id
                 WHERE s.token_hash = ?1 AND s.expires_at > ?2 AND u.disabled = 0",
                params![&hash[..], now()],
                |r| {
                    let pk: Vec<u8> = r.get(2)?;
                    Ok(User { id: uuid(r.get(0)?)?, is_admin: r.get(1)?, public_key: pk.try_into().unwrap_or([0; 32]), username: r.get(3)?, session: hash })
                },
            )
            .optional()?
            .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "session expired"))?;
        // At most one write a minute per session.
        db.execute("UPDATE sessions SET last_seen = ?1 WHERE token_hash = ?2 AND last_seen < ?1 - 60", params![now(), &hash[..]])?;
        Ok(user)
    }
}

/// Client address for login rate limiting ("local" when unknown, e.g. in tests).
struct ClientIp(String);

impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, ApiError> {
        let ip = parts.extensions.get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip().to_string());
        Ok(ClientIp(ip.unwrap_or_else(|| "local".into())))
    }
}

// ---------- router ----------

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/prelogin", post(prelogin))
        .route("/api/register", post(register))
        .route("/api/login", post(login))
        .route("/api/recover", post(recover))
        .route("/api/account", post(update_account))
        .route("/api/sessions", get(list_sessions))
        .route("/api/sessions/revoke_others", post(revoke_other_sessions))
        .route("/api/sessions/{id}", delete(revoke_session))
        .route("/api/sync", get(sync))
        .route("/api/items/{id}", put(put_item))
        .route("/api/collections", post(create_collection))
        .route("/api/collections/{id}/members", get(members))
        .route("/api/collections/{id}/members/{user}", put(put_member).delete(remove_member))
        .route("/api/collections/{id}/rotate", post(rotate))
        .route("/api/users/{name}", get(user_key))
        .route("/api/admin/invites", post(admin_invite))
        .route("/api/admin/users", get(admin_users))
        .route("/api/admin/users/{id}/disable", post(admin_disable))
        .route("/updates/{file}", get(update_file))
        .route("/download", get(download_page))
        .route("/", get(download_page))
        // Attachments travel inside item blobs (up to 8 MB files) and a key rotation re-sends a whole folder.
        .layer(axum::extract::DefaultBodyLimit::max(256 * 1024 * 1024))
        .with_state(state)
}

fn valid_username(name: &str) -> bool {
    let n = name.trim();
    !n.is_empty() && n.chars().count() <= 64 && !n.chars().any(char::is_control) && n == name
}

fn new_session(db: &Connection, user_id: Uuid, device: &str) -> rusqlite::Result<String> {
    let token = HEXLOWER.encode(&random::<32>());
    let device: String = device.chars().filter(|c| !c.is_control()).take(64).collect();
    db.execute(
        "INSERT INTO sessions (token_hash, user_id, expires_at, device, created_at, last_seen) VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
        params![&sha(token.as_bytes())[..], user_id.to_string(), now() + SESSION_DAYS * 86400, device.trim(), now()],
    )?;
    Ok(token)
}

/// Short public id of a session: the first 8 bytes of its token hash, hex.
fn session_id(hash: &[u8]) -> String {
    HEXLOWER.encode(&hash[..8])
}

async fn list_sessions(State(st): State<Arc<AppState>>, user: User) -> ApiResult<Vec<SessionInfo>> {
    let db = st.db();
    let mut q = db.prepare(
        "SELECT token_hash, device, created_at, last_seen FROM sessions WHERE user_id = ?1 AND expires_at > ?2 ORDER BY last_seen DESC",
    )?;
    let rows = q.query_map(params![user.id.to_string(), now()], |r| {
        let hash: Vec<u8> = r.get(0)?;
        Ok(SessionInfo { id: session_id(&hash), device: r.get(1)?, created_at: r.get(2)?, last_seen: r.get(3)?, current: hash == user.session })
    })?;
    Ok(Json(rows.collect::<rusqlite::Result<_>>()?))
}

async fn revoke_session(State(st): State<Arc<AppState>>, user: User, UrlPath(id): UrlPath<String>) -> ApiResult<RevResp> {
    let db = st.db();
    let hashes: Vec<Vec<u8>> = db
        .prepare("SELECT token_hash FROM sessions WHERE user_id = ?1")?
        .query_map([user.id.to_string()], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let hash = hashes.into_iter().find(|h| session_id(h) == id).ok_or_else(|| err(StatusCode::NOT_FOUND, "no such session"))?;
    db.execute("DELETE FROM sessions WHERE token_hash = ?1", [&hash])?;
    Ok(Json(RevResp { rev: 0 }))
}

async fn revoke_other_sessions(State(st): State<Arc<AppState>>, user: User) -> ApiResult<RevResp> {
    st.db().execute("DELETE FROM sessions WHERE user_id = ?1 AND token_hash != ?2", params![user.id.to_string(), &user.session[..]])?;
    Ok(Json(RevResp { rev: 0 }))
}

fn account_json(a: &AccountBlobs) -> String {
    serde_json::to_string(a).expect("account blobs serialize")
}

async fn prelogin(State(st): State<Arc<AppState>>, Json(req): Json<PreloginReq>) -> ApiResult<PreloginResp> {
    let db = st.db();
    let account: Option<String> =
        db.query_row("SELECT account FROM users WHERE username = ?1", [&req.username], |r| r.get(0)).optional()?;
    match account.and_then(|a| serde_json::from_str::<AccountBlobs>(&a).ok()) {
        Some(a) => Ok(Json(PreloginResp { kdf_salt: a.kdf_salt, kdf_params: a.kdf_params })),
        // Unknown users get a stable fake salt so usernames cannot be probed.
        None => {
            let h = sha(&[&st.secret[..], req.username.to_lowercase().as_bytes()].concat());
            Ok(Json(PreloginResp { kdf_salt: h[..16].try_into().expect("16 bytes"), kdf_params: KdfParams::DEFAULT }))
        }
    }
}

async fn register(State(st): State<Arc<AppState>>, Json(req): Json<RegisterReq>) -> ApiResult<SessionResp> {
    if !valid_username(&req.username) {
        return Err(err(StatusCode::BAD_REQUEST, "invalid username"));
    }
    let mut db = st.db();
    let tx = db.transaction()?;
    let invite: Option<bool> = tx
        .query_row(
            "SELECT is_admin FROM invites WHERE code_hash = ?1 AND used_by IS NULL AND expires_at > ?2",
            params![&sha(req.invite.trim().to_lowercase().as_bytes())[..], now()],
            |r| r.get(0),
        )
        .optional()?;
    let is_admin = invite.ok_or_else(|| err(StatusCode::FORBIDDEN, "invite is invalid or used"))?;
    let taken: bool = tx.query_row("SELECT COUNT(*) > 0 FROM users WHERE username = ?1", [&req.username], |r| r.get(0))?;
    if taken {
        return Err(err(StatusCode::CONFLICT, "username taken"));
    }
    let id = Uuid::new_v4();
    tx.execute(
        "INSERT INTO users (id, username, auth_hash, recovery_hash, account, public_key, is_admin, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            id.to_string(),
            req.username,
            &sha(&req.auth_key)[..],
            &sha(&req.recovery_auth)[..],
            account_json(&req.account),
            &req.account.public_key[..],
            is_admin,
            chrono::Utc::now().to_rfc3339()
        ],
    )?;
    tx.execute(
        "UPDATE invites SET used_by = ?1 WHERE code_hash = ?2",
        params![id.to_string(), &sha(req.invite.trim().to_lowercase().as_bytes())[..]],
    )?;
    let token = new_session(&tx, id, &req.device)?;
    tx.commit()?;
    Ok(Json(SessionResp { token, user_id: id, username: req.username, is_admin, account: req.account }))
}

/// Records a failed attempt; `Err` once the key is over the limit.
fn check_limit(st: &AppState, key: &str, failed: bool) -> Result<(), ApiError> {
    let mut f = st.failures.lock().unwrap_or_else(|e| e.into_inner());
    f.retain(|_, (_, at)| at.elapsed() < LOGIN_WINDOW);
    let entry = f.entry(key.to_string()).or_insert((0, Instant::now()));
    if failed {
        entry.0 += 1;
    }
    if entry.0 >= LOGIN_FAILURES && !failed {
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many attempts, try again in 15 minutes"));
    }
    Ok(())
}

async fn login(State(st): State<Arc<AppState>>, ClientIp(ip): ClientIp, Json(req): Json<LoginReq>) -> ApiResult<SessionResp> {
    let key = format!("{}|{ip}", req.username.to_lowercase());
    check_limit(&st, &key, false)?;
    let db = st.db();
    let row = db
        .query_row(
            "SELECT id, username, auth_hash, account, is_admin FROM users WHERE username = ?1 AND disabled = 0",
            [&req.username],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Vec<u8>>(2)?, r.get::<_, String>(3)?, r.get::<_, bool>(4)?)),
        )
        .optional()?;
    let Some((id, username, hash, account, is_admin)) = row.filter(|r| ct_eq(&r.2, &sha(&req.auth_key))) else {
        drop(db);
        check_limit(&st, &key, true)?;
        return Err(err(StatusCode::UNAUTHORIZED, "invalid username or password"));
    };
    let _ = hash;
    let id = uuid(id)?;
    let token = new_session(&db, id, &req.device)?;
    let account = serde_json::from_str(&account).map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "corrupt account"))?;
    Ok(Json(SessionResp { token, user_id: id, username, is_admin, account }))
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Deserialize)]
struct RecoverReq {
    username: String,
    #[serde(with = "pwd_core::proto::b64")]
    recovery_auth: [u8; 32],
    #[serde(with = "pwd_core::proto::b64")]
    new_auth_key: [u8; 32],
    #[serde(with = "pwd_core::proto::b64")]
    new_recovery_auth: [u8; 32],
    account: AccountBlobs,
    #[serde(default)]
    device: String,
}

/// Password reset with the recovery code: the client proves `recovery_auth` and uploads new blobs.
async fn recover(State(st): State<Arc<AppState>>, ClientIp(ip): ClientIp, Json(req): Json<RecoverReq>) -> ApiResult<SessionResp> {
    let key = format!("recover|{}|{ip}", req.username.to_lowercase());
    check_limit(&st, &key, false)?;
    let db = st.db();
    let row = db
        .query_row("SELECT id, username, recovery_hash, is_admin FROM users WHERE username = ?1 AND disabled = 0", [&req.username], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, Vec<u8>>(2)?, r.get::<_, bool>(3)?))
        })
        .optional()?;
    let Some((id, username, _, is_admin)) = row.filter(|r| ct_eq(&r.2, &sha(&req.recovery_auth))) else {
        drop(db);
        check_limit(&st, &key, true)?;
        return Err(err(StatusCode::UNAUTHORIZED, "invalid recovery code"));
    };
    db.execute(
        "UPDATE users SET auth_hash = ?1, recovery_hash = ?2, account = ?3 WHERE id = ?4",
        params![&sha(&req.new_auth_key)[..], &sha(&req.new_recovery_auth)[..], account_json(&req.account), id],
    )?;
    db.execute("DELETE FROM sessions WHERE user_id = ?1", [&id])?;
    let id = uuid(id)?;
    let token = new_session(&db, id, &req.device)?;
    Ok(Json(SessionResp { token, user_id: id, username, is_admin, account: req.account }))
}

async fn update_account(State(st): State<Arc<AppState>>, user: User, Json(req): Json<AccountUpdateReq>) -> ApiResult<RevResp> {
    if req.account.public_key != user.public_key {
        return Err(err(StatusCode::BAD_REQUEST, "public key cannot change"));
    }
    st.db().execute(
        "UPDATE users SET auth_hash = ?1, account = ?2 WHERE id = ?3",
        params![&sha(&req.auth_key)[..], account_json(&req.account), user.id.to_string()],
    )?;
    // A new master password should not leave a stolen or forgotten device logged in.
    st.db().execute("DELETE FROM sessions WHERE user_id = ?1 AND token_hash != ?2", params![user.id.to_string(), &user.session[..]])?;
    Ok(Json(RevResp { rev: 0 }))
}

#[derive(Deserialize)]
struct Since {
    #[serde(default)]
    since: i64,
}

async fn sync(State(st): State<Arc<AppState>>, user: User, Query(q): Query<Since>) -> ApiResult<SyncResp> {
    let db = st.db();
    let rev: i64 = db.query_row("SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'rev'", [], |r| r.get(0))?;
    let mut out = SyncResp { rev, ..Default::default() };
    let mut st_m = db.prepare(
        "SELECT m.collection_id, c.kind, m.role, m.key_version, m.sealed_ck, m.granted_by, m.removed, m.rev
         FROM memberships m JOIN collections c ON c.id = m.collection_id WHERE m.user_id = ?1",
    )?;
    let rows = st_m.query_map([user.id.to_string()], |r| {
        Ok((
            CollectionWire {
                id: uuid(r.get(0)?)?,
                kind: r.get(1)?,
                role: r.get(2)?,
                key_version: r.get(3)?,
                sealed_ck: r.get(4)?,
                granted_by: r.get::<_, Vec<u8>>(5)?.try_into().unwrap_or([0; 32]),
            },
            r.get::<_, bool>(6)?,
            r.get::<_, i64>(7)?,
        ))
    })?;
    let mut st_i = db.prepare(
        "SELECT id, collection_id, key_version, blob, deleted, rev, updated_at, author FROM items WHERE collection_id = ?1 AND rev > ?2",
    )?;
    for row in rows {
        let (col, removed, m_rev) = row?;
        if removed {
            if m_rev > q.since {
                out.removed.push(col.id);
            }
            continue;
        }
        // A new or changed membership (grant, rotation) sends the whole collection.
        let since = if m_rev > q.since { 0 } else { q.since };
        let items = st_i.query_map(params![col.id.to_string(), since], |r| {
            Ok(ItemWire {
                id: uuid(r.get(0)?)?,
                collection_id: uuid(r.get(1)?)?,
                key_version: r.get(2)?,
                blob: r.get(3)?,
                deleted: r.get(4)?,
                rev: r.get(5)?,
                updated_at: r.get(6)?,
                author: r.get(7)?,
            })
        })?;
        for it in items {
            out.items.push(it?);
        }
        if m_rev > q.since {
            out.collections.push(col);
        }
    }
    Ok(Json(out))
}

/// Active membership role of `user` in `collection`, if any.
fn role(db: &Connection, collection: &str, user: Uuid) -> rusqlite::Result<Option<String>> {
    db.query_row(
        "SELECT role FROM memberships WHERE collection_id = ?1 AND user_id = ?2 AND removed = 0",
        params![collection, user.to_string()],
        |r| r.get(0),
    )
    .optional()
}

fn can_write(role: &Option<String>) -> bool {
    matches!(role.as_deref(), Some("owner" | "editor"))
}

fn item_wire(db: &Connection, id: &str) -> rusqlite::Result<Option<ItemWire>> {
    db.query_row(
        "SELECT id, collection_id, key_version, blob, deleted, rev, updated_at, author FROM items WHERE id = ?1",
        [id],
        |r| {
            Ok(ItemWire {
                id: uuid(r.get(0)?)?,
                collection_id: uuid(r.get(1)?)?,
                key_version: r.get(2)?,
                blob: r.get(3)?,
                deleted: r.get(4)?,
                rev: r.get(5)?,
                updated_at: r.get(6)?,
                author: r.get(7)?,
            })
        },
    )
    .optional()
}

async fn put_item(
    State(st): State<Arc<AppState>>,
    user: User,
    UrlPath(id): UrlPath<Uuid>,
    Json(req): Json<PutItemReq>,
) -> Result<Response, ApiError> {
    let mut db = st.db();
    let tx = db.transaction()?;
    let col = req.collection_id.to_string();
    if !can_write(&role(&tx, &col, user.id)?) {
        return Err(err(StatusCode::FORBIDDEN, "no write access to this folder"));
    }
    let current = item_wire(&tx, &id.to_string())?;
    if current.as_ref().is_some_and(|cur| cur.collection_id != req.collection_id) {
        return Err(err(StatusCode::BAD_REQUEST, "items cannot change folder"));
    }
    if current.as_ref().map_or(0, |c| c.rev) != req.base_rev {
        return Ok((StatusCode::CONFLICT, Json(current)).into_response());
    }
    let kv: u32 = tx.query_row("SELECT key_version FROM collections WHERE id = ?1", [&col], |r| r.get(0))?;
    if kv != req.key_version {
        return Err(err(StatusCode::PRECONDITION_FAILED, "key_rotated"));
    }
    let rev = next_rev(&tx)?;
    tx.execute(
        "INSERT OR REPLACE INTO items (id, collection_id, key_version, blob, deleted, rev, updated_at, author) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![id.to_string(), col, req.key_version, req.blob, req.deleted, rev, req.updated_at, user.username],
    )?;
    tx.commit()?;
    Ok(Json(RevResp { rev }).into_response())
}

async fn create_collection(State(st): State<Arc<AppState>>, user: User, Json(req): Json<CreateCollectionReq>) -> ApiResult<RevResp> {
    if !matches!(req.kind.as_str(), "personal" | "shared") {
        return Err(err(StatusCode::BAD_REQUEST, "unknown folder kind"));
    }
    let mut db = st.db();
    let tx = db.transaction()?;
    let owner: Option<String> =
        tx.query_row("SELECT owner_id FROM collections WHERE id = ?1", [req.id.to_string()], |r| r.get(0)).optional()?;
    if let Some(owner) = owner {
        if owner != user.id.to_string() {
            return Err(err(StatusCode::CONFLICT, "folder id taken"));
        }
        let rev: i64 = tx.query_row("SELECT rev FROM collections WHERE id = ?1", [req.id.to_string()], |r| r.get(0))?;
        return Ok(Json(RevResp { rev }));
    }
    if req.kind == "personal" {
        let has: bool = tx.query_row(
            "SELECT COUNT(*) > 0 FROM collections WHERE owner_id = ?1 AND kind = 'personal'",
            [user.id.to_string()],
            |r| r.get(0),
        )?;
        if has {
            return Err(err(StatusCode::CONFLICT, "personal folder already exists"));
        }
    }
    let rev = next_rev(&tx)?;
    tx.execute(
        "INSERT INTO collections (id, kind, owner_id, key_version, rev) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![req.id.to_string(), req.kind, user.id.to_string(), req.key_version, rev],
    )?;
    tx.execute(
        "INSERT INTO memberships (collection_id, user_id, role, sealed_ck, granted_by, key_version, rev)
         VALUES (?1, ?2, 'owner', ?3, ?4, ?5, ?6)",
        params![req.id.to_string(), user.id.to_string(), req.sealed_ck, &user.public_key[..], req.key_version, rev],
    )?;
    tx.commit()?;
    Ok(Json(RevResp { rev }))
}

async fn user_key(State(st): State<Arc<AppState>>, _user: User, UrlPath(name): UrlPath<String>) -> ApiResult<UserKey> {
    st.db()
        .query_row("SELECT id, username, public_key FROM users WHERE username = ?1 AND disabled = 0", [&name], |r| {
            Ok(UserKey {
                user_id: uuid(r.get(0)?)?,
                username: r.get(1)?,
                public_key: r.get::<_, Vec<u8>>(2)?.try_into().unwrap_or([0; 32]),
            })
        })
        .optional()?
        .map(Json)
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "no such user"))
}

async fn members(State(st): State<Arc<AppState>>, user: User, UrlPath(id): UrlPath<Uuid>) -> ApiResult<Vec<Member>> {
    let db = st.db();
    if role(&db, &id.to_string(), user.id)?.is_none() {
        return Err(err(StatusCode::FORBIDDEN, "not a member"));
    }
    let mut stmt = db.prepare(
        "SELECT u.id, u.username, m.role, u.public_key FROM memberships m JOIN users u ON u.id = m.user_id
         WHERE m.collection_id = ?1 AND m.removed = 0 ORDER BY m.role != 'owner', u.username",
    )?;
    let rows = stmt.query_map([id.to_string()], |r| {
        Ok(Member {
            user_id: uuid(r.get(0)?)?,
            username: r.get(1)?,
            role: r.get(2)?,
            public_key: r.get::<_, Vec<u8>>(3)?.try_into().unwrap_or([0; 32]),
        })
    })?;
    Ok(Json(rows.collect::<rusqlite::Result<_>>()?))
}

fn require_owner(db: &Connection, collection: &str, user: Uuid) -> Result<(), ApiError> {
    match role(db, collection, user)?.as_deref() {
        Some("owner") => Ok(()),
        _ => Err(err(StatusCode::FORBIDDEN, "only the folder owner can do this")),
    }
}

async fn put_member(
    State(st): State<Arc<AppState>>,
    user: User,
    UrlPath((id, member)): UrlPath<(Uuid, Uuid)>,
    Json(req): Json<PutMemberReq>,
) -> ApiResult<RevResp> {
    if !matches!(req.role.as_str(), "editor" | "viewer") {
        return Err(err(StatusCode::BAD_REQUEST, "role must be editor or viewer"));
    }
    let mut db = st.db();
    let tx = db.transaction()?;
    let col = id.to_string();
    require_owner(&tx, &col, user.id)?;
    if member == user.id {
        return Err(err(StatusCode::BAD_REQUEST, "owner role cannot change"));
    }
    let (kv, kind): (u32, String) =
        tx.query_row("SELECT key_version, kind FROM collections WHERE id = ?1", [&col], |r| Ok((r.get(0)?, r.get(1)?)))?;
    if kind == "personal" {
        return Err(err(StatusCode::BAD_REQUEST, "personal folders cannot be shared"));
    }
    if kv != req.key_version {
        return Err(err(StatusCode::PRECONDITION_FAILED, "key_rotated"));
    }
    let exists: bool = tx.query_row("SELECT COUNT(*) > 0 FROM users WHERE id = ?1 AND disabled = 0", [member.to_string()], |r| r.get(0))?;
    if !exists {
        return Err(err(StatusCode::NOT_FOUND, "no such user"));
    }
    let rev = next_rev(&tx)?;
    tx.execute(
        "INSERT OR REPLACE INTO memberships (collection_id, user_id, role, sealed_ck, granted_by, key_version, removed, rev)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7)",
        params![col, member.to_string(), req.role, req.sealed_ck, &user.public_key[..], req.key_version, rev],
    )?;
    tx.commit()?;
    Ok(Json(RevResp { rev }))
}

/// The owner removes someone, or a member leaves. The owner should rotate the key afterwards.
async fn remove_member(State(st): State<Arc<AppState>>, user: User, UrlPath((id, member)): UrlPath<(Uuid, Uuid)>) -> ApiResult<RevResp> {
    let mut db = st.db();
    let tx = db.transaction()?;
    let col = id.to_string();
    let my_role = role(&tx, &col, user.id)?;
    if member == user.id {
        if my_role.as_deref() == Some("owner") {
            return Err(err(StatusCode::BAD_REQUEST, "the owner cannot leave their folder"));
        }
    } else {
        require_owner(&tx, &col, user.id)?;
    }
    let rev = next_rev(&tx)?;
    let n = tx.execute(
        "UPDATE memberships SET removed = 1, sealed_ck = x'', rev = ?1 WHERE collection_id = ?2 AND user_id = ?3 AND removed = 0",
        params![rev, col, member.to_string()],
    )?;
    if n == 0 {
        return Err(err(StatusCode::NOT_FOUND, "not a member"));
    }
    tx.commit()?;
    Ok(Json(RevResp { rev }))
}

async fn rotate(State(st): State<Arc<AppState>>, user: User, UrlPath(id): UrlPath<Uuid>, Json(req): Json<RotateReq>) -> ApiResult<RevResp> {
    let mut db = st.db();
    let tx = db.transaction()?;
    let col = id.to_string();
    require_owner(&tx, &col, user.id)?;
    let kv: u32 = tx.query_row("SELECT key_version FROM collections WHERE id = ?1", [&col], |r| r.get(0))?;
    if req.key_version != kv + 1 {
        return Err(err(StatusCode::CONFLICT, "key version must increase by one"));
    }
    let active: Vec<String> = tx
        .prepare("SELECT user_id FROM memberships WHERE collection_id = ?1 AND removed = 0")?
        .query_map([&col], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let remove: Vec<String> = req.remove.iter().map(|u| u.to_string()).collect();
    if remove.contains(&user.id.to_string()) {
        return Err(err(StatusCode::BAD_REQUEST, "the owner cannot leave their folder"));
    }
    let mut remaining: Vec<String> = active.iter().filter(|m| !remove.contains(m)).cloned().collect();
    let mut granted: Vec<String> = req.grants.iter().map(|g| g.user_id.to_string()).collect();
    remaining.sort();
    granted.sort();
    let mut live: Vec<(String, i64)> = tx
        .prepare("SELECT id, rev FROM items WHERE collection_id = ?1 AND deleted = 0")?
        .query_map([&col], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let mut sent: Vec<(String, i64)> = req.items.iter().map(|i| (i.id.to_string(), i.rev)).collect();
    live.sort();
    sent.sort();
    if remove.iter().any(|m| !active.contains(m)) || remaining != granted || live != sent {
        return Err(err(StatusCode::CONFLICT, "folder changed, sync and retry"));
    }
    let rev = next_rev(&tx)?;
    for m in &remove {
        tx.execute(
            "UPDATE memberships SET removed = 1, sealed_ck = x'', rev = ?1 WHERE collection_id = ?2 AND user_id = ?3",
            params![rev, col, m],
        )?;
    }
    tx.execute("UPDATE collections SET key_version = ?1, rev = ?2 WHERE id = ?3", params![req.key_version, rev, col])?;
    for g in &req.grants {
        tx.execute(
            "UPDATE memberships SET sealed_ck = ?1, granted_by = ?2, key_version = ?3, rev = ?4 WHERE collection_id = ?5 AND user_id = ?6",
            params![g.sealed_ck, &user.public_key[..], req.key_version, rev, col, g.user_id.to_string()],
        )?;
    }
    for it in &req.items {
        tx.execute(
            "UPDATE items SET blob = ?1, key_version = ?2, rev = ?3 WHERE id = ?4 AND collection_id = ?5",
            params![it.blob, req.key_version, rev, it.id.to_string(), col],
        )?;
    }
    tx.commit()?;
    Ok(Json(RevResp { rev }))
}

fn require_admin(user: &User) -> Result<(), ApiError> {
    if user.is_admin {
        Ok(())
    } else {
        Err(err(StatusCode::FORBIDDEN, "admin only"))
    }
}

async fn admin_invite(State(st): State<Arc<AppState>>, user: User, Json(req): Json<InviteReq>) -> ApiResult<InviteResp> {
    require_admin(&user)?;
    Ok(Json(InviteResp { code: create_invite(&st, req.is_admin)? }))
}

async fn admin_users(State(st): State<Arc<AppState>>, user: User) -> ApiResult<Vec<AdminUser>> {
    require_admin(&user)?;
    Ok(Json(st.users()?))
}

#[derive(Deserialize)]
struct DisableReq {
    disabled: bool,
}

async fn admin_disable(State(st): State<Arc<AppState>>, user: User, UrlPath(id): UrlPath<Uuid>, Json(req): Json<DisableReq>) -> ApiResult<RevResp> {
    require_admin(&user)?;
    if id == user.id {
        return Err(err(StatusCode::BAD_REQUEST, "cannot disable yourself"));
    }
    let db = st.db();
    db.execute("UPDATE users SET disabled = ?1 WHERE id = ?2", params![req.disabled, id.to_string()])?;
    db.execute("DELETE FROM sessions WHERE user_id = ?1", [id.to_string()])?;
    Ok(Json(RevResp { rev: 0 }))
}

// ---------- releases ----------

fn release_files(st: &AppState) -> Vec<String> {
    let Some(dir) = &st.releases else { return vec![] };
    let mut files: Vec<String> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| !n.starts_with('.'))
        .collect();
    files.sort();
    files
}

async fn update_file(State(st): State<Arc<AppState>>, UrlPath(file): UrlPath<String>) -> Result<Response, ApiError> {
    if !release_files(&st).contains(&file) {
        return Err(err(StatusCode::NOT_FOUND, "no such file"));
    }
    let path = st.releases.as_ref().expect("listed files imply a releases dir").join(&file);
    let bytes = tokio::fs::read(path).await.map_err(|_| err(StatusCode::NOT_FOUND, "no such file"))?;
    let ct = if file.ends_with(".json") { "application/json" } else { "application/octet-stream" };
    Ok(([("content-type", ct), ("content-disposition", "attachment")], bytes).into_response())
}

async fn download_page(State(st): State<Arc<AppState>>) -> Html<String> {
    let links: String = release_files(&st)
        .iter()
        .filter(|f| !f.ends_with(".sig") && !f.ends_with(".json"))
        .map(|f| format!("<li><a href=\"/updates/{f}\">{f}</a></li>"))
        .collect();
    let body = if links.is_empty() { "<p>Установщики ещё не опубликованы.</p>".to_string() } else { format!("<ul>{links}</ul>") };
    Html(format!(
        "<!doctype html><html lang=ru><meta charset=utf-8><title>Passwords</title>\
         <body style=\"background:#040a06;color:#b9f6c6;font:15px/1.6 ui-monospace,monospace;padding:40px\">\
         <h1 style=\"color:#3cff8f\">▌PASSWORDS</h1><p>Скачайте приложение и откройте ссылку-приглашение от администратора.</p>{body}</body></html>"
    ))
}

// ---------- data directory, links, serving ----------

#[derive(serde::Serialize, Deserialize, Clone, Debug)]
pub struct Config {
    pub host: String,
    pub port: u16,
}

impl Config {
    pub fn load(data: &Path) -> std::io::Result<Config> {
        let text = std::fs::read_to_string(data.join("config.json"))
            .map_err(|e| std::io::Error::new(e.kind(), format!("{}: {e} (run `pwd-server init` first)", data.display())))?;
        serde_json::from_str(&text).map_err(std::io::Error::other)
    }
}

/// Creates the data directory: config, certificate, database. Safe to run again.
pub fn init_data(data: &Path, host: &str, port: u16) -> std::io::Result<Config> {
    std::fs::create_dir_all(data.join("releases"))?;
    let cfg = Config { host: host.to_string(), port };
    std::fs::write(data.join("config.json"), serde_json::to_string_pretty(&cfg).map_err(std::io::Error::other)?)?;
    tls::ensure_cert(data, host)?;
    AppState::open(&data.join("server.db")).map_err(std::io::Error::other)?;
    Ok(cfg)
}

/// Makes the files in `dir` the published release (installers, .sig files, latest.json):
/// the previous release is removed so /download lists only the current one.
pub fn publish_release(data: &Path, dir: &Path) -> std::io::Result<Vec<String>> {
    let to = data.join("releases");
    std::fs::create_dir_all(&to)?;
    let mut files = vec![];
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        if e.file_type()?.is_file() {
            files.push(e.file_name().into_string().map_err(|_| std::io::Error::other("file name is not UTF-8"))?);
        }
    }
    files.sort();
    for e in std::fs::read_dir(&to)? {
        let e = e?;
        if e.file_type()?.is_file() {
            std::fs::remove_file(e.path())?;
        }
    }
    for f in &files {
        std::fs::copy(dir.join(f), to.join(f))?;
    }
    Ok(files)
}

pub fn open_state(data: &Path) -> std::io::Result<AppState> {
    let mut st = AppState::open(&data.join("server.db")).map_err(std::io::Error::other)?;
    st.releases = Some(data.join("releases"));
    Ok(st)
}

/// `pwd://host:port/invite/CODE?fp=FP` — or a plain server link without a code.
pub fn link(cfg: &Config, fingerprint: &str, invite: Option<&str>) -> String {
    match invite {
        Some(code) => format!("pwd://{}:{}/invite/{code}?fp={fingerprint}", cfg.host, cfg.port),
        None => format!("pwd://{}:{}?fp={fingerprint}", cfg.host, cfg.port),
    }
}

/// Serves HTTPS until the handle shuts down. `handle.listening()` resolves to the bound address.
pub async fn serve(state: Arc<AppState>, data: &Path, addr: SocketAddr, handle: axum_server::Handle) -> std::io::Result<()> {
    let tls = tls::rustls_config(data)?;
    axum_server::bind_rustls(addr, tls)
        .handle(handle)
        .serve(router(state).into_make_service_with_connect_info::<SocketAddr>())
        .await
}
