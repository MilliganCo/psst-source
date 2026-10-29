use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use pwd_core::account::AccountBlobs;
use pwd_core::kdf::KdfParams;
use pwd_core::proto::*;
use pwd_server::{create_invite, AppState};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

struct T {
    app: axum::Router,
    state: Arc<AppState>,
}

fn blobs(pk: u8) -> AccountBlobs {
    AccountBlobs {
        kdf_salt: [pk; 16],
        kdf_params: KdfParams::DEFAULT,
        enc_account_key: vec![1, 2, 3],
        enc_account_key_recovery: vec![4, 5],
        public_key: [pk; 32],
        enc_private_key: vec![6],
    }
}

impl T {
    fn new() -> T {
        let state = Arc::new(AppState::open_in_memory().unwrap());
        T { app: pwd_server::router(state.clone()), state }
    }

    async fn call(&self, method: &str, uri: &str, token: Option<&str>, body: Value) -> (StatusCode, Value) {
        let mut req = Request::builder().method(method).uri(uri).header("content-type", "application/json");
        if let Some(t) = token {
            req = req.header("authorization", format!("Bearer {t}"));
        }
        let body = if body.is_null() { Body::empty() } else { Body::from(body.to_string()) };
        let res = self.app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    async fn ok<R: DeserializeOwned>(&self, method: &str, uri: &str, token: Option<&str>, body: Value) -> R {
        let (s, v) = self.call(method, uri, token, body).await;
        assert!(s.is_success(), "{method} {uri} -> {s} {v}");
        serde_json::from_value(v).unwrap()
    }

    /// Registers `name` with auth key [n; 32] and public key [n; 32].
    async fn register(&self, name: &str, n: u8, admin: bool) -> SessionResp {
        let invite = create_invite(&self.state, admin).unwrap();
        let req = RegisterReq {
            invite,
            username: name.into(),
            auth_key: [n; 32],
            recovery_auth: [n + 100; 32],
            account: blobs(n),
            device: String::new(),
        };
        self.ok("POST", "/api/register", None, serde_json::to_value(req).unwrap()).await
    }

    async fn sync(&self, token: &str, since: i64) -> SyncResp {
        self.ok("GET", &format!("/api/sync?since={since}"), Some(token), Value::Null).await
    }

    async fn collection(&self, token: &str, kind: &str) -> Uuid {
        let id = Uuid::new_v4();
        let req = CreateCollectionReq { id, kind: kind.into(), key_version: 1, sealed_ck: vec![9; 80] };
        let _: RevResp = self.ok("POST", "/api/collections", Some(token), serde_json::to_value(req).unwrap()).await;
        id
    }

    async fn put(&self, token: &str, col: Uuid, id: Uuid, base_rev: i64, kv: u32) -> (StatusCode, Value) {
        let req = PutItemReq { collection_id: col, key_version: kv, blob: vec![7; 40], deleted: false, base_rev, updated_at: "2026-01-01T00:00:00Z".into() };
        self.call("PUT", &format!("/api/items/{id}"), Some(token), serde_json::to_value(req).unwrap()).await
    }
}

#[tokio::test]
async fn register_login_prelogin() {
    let t = T::new();
    let s = t.register("alice", 1, true).await;
    assert!(s.is_admin);
    assert_eq!(s.account, blobs(1));

    let (st, _) = t.call("POST", "/api/register", None, json!({"invite": "nope", "username": "x", "auth_key": "AA==", "recovery_auth": "AA==", "account": blobs(2)})).await;
    assert!(st.is_client_error());

    let pre: PreloginResp = t.ok("POST", "/api/prelogin", None, json!({"username": "ALICE"})).await;
    assert_eq!(pre.kdf_salt, [1; 16]);
    let fake1: PreloginResp = t.ok("POST", "/api/prelogin", None, json!({"username": "ghost"})).await;
    let fake2: PreloginResp = t.ok("POST", "/api/prelogin", None, json!({"username": "ghost"})).await;
    assert_eq!(fake1.kdf_salt, fake2.kdf_salt, "unknown users get a stable fake salt");

    let login: SessionResp = t.ok("POST", "/api/login", None, serde_json::to_value(LoginReq { username: "alice".into(), auth_key: [1; 32], device: String::new() }).unwrap()).await;
    assert_eq!(login.user_id, s.user_id);
    let (st, _) = t.call("POST", "/api/login", None, serde_json::to_value(LoginReq { username: "alice".into(), auth_key: [2; 32], device: String::new() }).unwrap()).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    // Invite is single-use; duplicate usernames are refused.
    let invite = create_invite(&t.state, false).unwrap();
    let req = |name: &str| {
        serde_json::to_value(RegisterReq { invite: invite.clone(), username: name.into(), auth_key: [3; 32], recovery_auth: [3; 32], account: blobs(3), device: String::new() }).unwrap()
    };
    let (st, _) = t.call("POST", "/api/register", None, req("Alice")).await;
    assert_eq!(st, StatusCode::CONFLICT);
    let (st, _) = t.call("POST", "/api/register", None, req("bob")).await;
    assert!(st.is_success());
    let (st, _) = t.call("POST", "/api/register", None, req("carol")).await;
    assert!(st.is_client_error(), "invite reused");
}

#[tokio::test]
async fn login_rate_limit() {
    let t = T::new();
    t.register("alice", 1, false).await;
    for _ in 0..5 {
        let (st, _) = t.call("POST", "/api/login", None, serde_json::to_value(LoginReq { username: "alice".into(), auth_key: [9; 32], device: String::new() }).unwrap()).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
    }
    let (st, _) = t.call("POST", "/api/login", None, serde_json::to_value(LoginReq { username: "alice".into(), auth_key: [1; 32], device: String::new() }).unwrap()).await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn auth_required_and_password_change() {
    let t = T::new();
    let s = t.register("alice", 1, false).await;
    let (st, _) = t.call("GET", "/api/sync?since=0", None, Value::Null).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let (st, _) = t.call("GET", "/api/sync?since=0", Some("bogus"), Value::Null).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);

    let new_blobs = AccountBlobs { kdf_salt: [11; 16], enc_account_key: vec![11], ..blobs(1) };
    let bad = AccountUpdateReq { auth_key: [11; 32], account: blobs(11) };
    let (st, _) = t.call("POST", "/api/account", Some(&s.token), serde_json::to_value(bad).unwrap()).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "public key cannot change");
    let upd = AccountUpdateReq { auth_key: [11; 32], account: new_blobs.clone() };
    let (st, _) = t.call("POST", "/api/account", Some(&s.token), serde_json::to_value(upd).unwrap()).await;
    assert!(st.is_success());
    let (st, _) = t.call("POST", "/api/login", None, serde_json::to_value(LoginReq { username: "alice".into(), auth_key: [1; 32], device: String::new() }).unwrap()).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    let l: SessionResp = t.ok("POST", "/api/login", None, serde_json::to_value(LoginReq { username: "alice".into(), auth_key: [11; 32], device: String::new() }).unwrap()).await;
    assert_eq!(l.account, new_blobs);
}

#[tokio::test]
async fn items_sync_conflict_and_isolation() {
    let t = T::new();
    let a = t.register("alice", 1, false).await;
    let b = t.register("bob", 2, false).await;
    let col = t.collection(&a.token, "personal").await;
    let item = Uuid::new_v4();
    let (st, v) = t.put(&a.token, col, item, 0, 1).await;
    assert!(st.is_success(), "{v}");
    let rev = v["rev"].as_i64().unwrap();

    let (st, cur) = t.put(&a.token, col, item, 0, 1).await;
    assert_eq!(st, StatusCode::CONFLICT, "stale base_rev");
    assert_eq!(cur["rev"].as_i64().unwrap(), rev);
    let (st, _) = t.put(&a.token, col, item, rev, 1).await;
    assert!(st.is_success());
    let (st, _) = t.put(&a.token, col, Uuid::new_v4(), 0, 2).await;
    assert_eq!(st, StatusCode::PRECONDITION_FAILED, "wrong key_version");

    let sa = t.sync(&a.token, 0).await;
    assert_eq!(sa.collections.len(), 1);
    assert_eq!(sa.collections[0].role, "owner");
    assert_eq!(sa.collections[0].granted_by, [1; 32]);
    assert_eq!(sa.items.len(), 1);
    assert!(t.sync(&a.token, sa.rev).await.items.is_empty());

    let sb = t.sync(&b.token, 0).await;
    assert!(sb.collections.is_empty() && sb.items.is_empty(), "bob sees nothing of alice");
    let (st, _) = t.put(&b.token, col, Uuid::new_v4(), 0, 1).await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // Personal folders: one per user, never shared; items never change folder.
    let req = CreateCollectionReq { id: Uuid::new_v4(), kind: "personal".into(), key_version: 1, sealed_ck: vec![1] };
    let (st, _) = t.call("POST", "/api/collections", Some(&a.token), serde_json::to_value(req).unwrap()).await;
    assert_eq!(st, StatusCode::CONFLICT);
    let add = PutMemberReq { role: "viewer".into(), key_version: 1, sealed_ck: vec![5; 80] };
    let (st, _) = t.call("PUT", &format!("/api/collections/{col}/members/{}", b.user_id), Some(&a.token), serde_json::to_value(add).unwrap()).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let other = t.collection(&a.token, "shared").await;
    let rev = t.sync(&a.token, 0).await.items.iter().find(|i| i.id == item).unwrap().rev;
    let (st, _) = t.put(&a.token, other, item, rev, 1).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "items cannot change folder");
}

#[tokio::test]
async fn sharing_roles_removal_and_rotation() {
    let t = T::new();
    let a = t.register("alice", 1, false).await;
    let b = t.register("bob", 2, false).await;
    let col = t.collection(&a.token, "shared").await;
    let item = Uuid::new_v4();
    t.put(&a.token, col, item, 0, 1).await;

    let key: UserKey = t.ok("GET", "/api/users/BOB", Some(&a.token), Value::Null).await;
    assert_eq!(key.public_key, [2; 32]);
    let add = PutMemberReq { role: "viewer".into(), key_version: 1, sealed_ck: vec![5; 80] };
    let uri = format!("/api/collections/{col}/members/{}", key.user_id);
    let _: RevResp = t.ok("PUT", &uri, Some(&a.token), serde_json::to_value(&add).unwrap()).await;
    let (st, _) = t.call("PUT", &uri, Some(&b.token), serde_json::to_value(&add).unwrap()).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "only the owner manages members");

    let sb = t.sync(&b.token, 0).await;
    assert_eq!(sb.collections.len(), 1);
    assert_eq!((sb.collections[0].role.as_str(), sb.collections[0].granted_by), ("viewer", [1; 32]));
    assert_eq!(sb.items.len(), 1, "new member gets existing items");
    let (st, _) = t.put(&b.token, col, Uuid::new_v4(), 0, 1).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "viewer cannot write");

    let members: Vec<Member> = t.ok("GET", &format!("/api/collections/{col}/members"), Some(&b.token), Value::Null).await;
    assert_eq!(members.len(), 2);

    // Remove bob and rotate in one request: bob loses access, old key_version is refused.
    let item_rev = t.sync(&a.token, 0).await.items.iter().find(|i| i.id == item).unwrap().rev;
    let rotate = |grants: Vec<Grant>, rev: i64| RotateReq {
        key_version: 2,
        remove: vec![b.user_id],
        grants,
        items: vec![RotatedItem { id: item, rev, blob: vec![8; 40] }],
    };
    let rot_uri = format!("/api/collections/{col}/rotate");
    let (st, _) = t.call("POST", &rot_uri, Some(&a.token), serde_json::to_value(rotate(vec![], item_rev)).unwrap()).await;
    assert_eq!(st, StatusCode::CONFLICT, "rotation must grant every remaining member");
    let alice_only = || vec![Grant { user_id: a.user_id, sealed_ck: vec![6; 80] }];
    let (st, _) = t.call("POST", &rot_uri, Some(&a.token), serde_json::to_value(rotate(alice_only(), item_rev - 1)).unwrap()).await;
    assert_eq!(st, StatusCode::CONFLICT, "an item edited since the owner read it blocks rotation");
    assert_eq!(t.sync(&b.token, sb.rev).await.removed, Vec::<Uuid>::new(), "failed rotation removes nobody");
    let _: RevResp = t.ok("POST", &rot_uri, Some(&a.token), serde_json::to_value(rotate(alice_only(), item_rev)).unwrap()).await;
    assert_eq!(t.sync(&b.token, sb.rev).await.removed, [col]);
    let (st, _) = t.put(&a.token, col, Uuid::new_v4(), 0, 1).await;
    assert_eq!(st, StatusCode::PRECONDITION_FAILED);
    let sa = t.sync(&a.token, 0).await;
    assert_eq!(sa.collections[0].key_version, 2);
    assert_eq!(sa.items[0].blob, vec![8; 40]);
    assert!(t.sync(&b.token, 0).await.collections.is_empty());
}

#[tokio::test]
async fn admin_only_endpoints() {
    let t = T::new();
    let admin = t.register("root", 1, true).await;
    let user = t.register("user", 2, false).await;
    let (st, _) = t.call("POST", "/api/admin/invites", Some(&user.token), json!({"is_admin": false})).await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    let inv: InviteResp = t.ok("POST", "/api/admin/invites", Some(&admin.token), json!({"is_admin": false})).await;
    assert!(inv.code.len() >= 20);
    let users: Vec<AdminUser> = t.ok("GET", "/api/admin/users", Some(&admin.token), Value::Null).await;
    assert_eq!(users.len(), 2);
    let (st, _) = t.call("POST", &format!("/api/admin/users/{}/disable", user.user_id), Some(&admin.token), json!({"disabled": true})).await;
    assert!(st.is_success());
    let (st, _) = t.call("GET", "/api/sync?since=0", Some(&user.token), Value::Null).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED, "disabled user is logged out");
}

#[test]
fn publish_release_replaces_the_previous_one() {
    let data = tempfile::tempdir().unwrap();
    pwd_server::init_data(data.path(), "127.0.0.1", 8443).unwrap();
    std::fs::write(data.path().join("releases/Passwords_0.1.0_x64-setup.exe"), b"old").unwrap();
    let new = tempfile::tempdir().unwrap();
    std::fs::write(new.path().join("Passwords_0.2.0_x64-setup.exe"), b"new").unwrap();
    std::fs::write(new.path().join("latest.json"), br#"{"version":"0.2.0","files":{}}"#).unwrap();
    std::fs::create_dir(new.path().join("subdir")).unwrap();

    let published = pwd_server::publish_release(data.path(), new.path()).unwrap();
    assert_eq!(published, ["Passwords_0.2.0_x64-setup.exe", "latest.json"]);
    let mut left: Vec<String> = std::fs::read_dir(data.path().join("releases"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    left.sort();
    assert_eq!(left, ["Passwords_0.2.0_x64-setup.exe", "latest.json"]);
}

#[tokio::test]
async fn sessions_list_revoke_and_password_change_logs_out_others() {
    let t = T::new();
    let a1 = t.register("alice", 1, false).await;
    let login = |device: &str| serde_json::to_value(LoginReq { username: "alice".into(), auth_key: [1; 32], device: device.into() }).unwrap();
    let a2: SessionResp = t.ok("POST", "/api/login", None, login("Ноутбук")).await;
    let a3: SessionResp = t.ok("POST", "/api/login", None, login("Телефон")).await;
    let bob = t.register("bob", 2, false).await;

    let list: Vec<SessionInfo> = t.ok("GET", "/api/sessions", Some(&a2.token), Value::Null).await;
    assert_eq!(list.len(), 3, "only alice's sessions");
    assert_eq!(list.iter().filter(|s| s.current).map(|s| s.device.as_str()).collect::<Vec<_>>(), ["Ноутбук"]);
    assert!(list.iter().all(|s| s.created_at > 0 && s.last_seen >= s.created_at));

    let phone = list.iter().find(|s| s.device == "Телефон").unwrap().id.clone();
    let (st, _) = t.call("DELETE", &format!("/api/sessions/{phone}"), Some(&bob.token), Value::Null).await;
    assert_eq!(st, StatusCode::NOT_FOUND, "not bob's session");
    let _: RevResp = t.ok("DELETE", &format!("/api/sessions/{phone}"), Some(&a2.token), Value::Null).await;
    assert_eq!(t.call("GET", "/api/sync?since=0", Some(&a3.token), Value::Null).await.0, StatusCode::UNAUTHORIZED);

    let _: RevResp = t.ok("POST", "/api/sessions/revoke_others", Some(&a2.token), Value::Null).await;
    assert_eq!(t.call("GET", "/api/sync?since=0", Some(&a1.token), Value::Null).await.0, StatusCode::UNAUTHORIZED);
    t.sync(&a2.token, 0).await;
    t.sync(&bob.token, 0).await;

    let a4: SessionResp = t.ok("POST", "/api/login", None, login("Планшет")).await;
    let upd = AccountUpdateReq { auth_key: [1; 32], account: blobs(1) };
    let _: RevResp = t.ok("POST", "/api/account", Some(&a4.token), serde_json::to_value(upd).unwrap()).await;
    assert_eq!(t.call("GET", "/api/sync?since=0", Some(&a2.token), Value::Null).await.0, StatusCode::UNAUTHORIZED, "password change logs out other devices");
    t.sync(&a4.token, 0).await;
}

#[tokio::test]
async fn items_carry_their_last_writer() {
    let t = T::new();
    let a = t.register("alice", 1, false).await;
    let b = t.register("bob", 2, false).await;
    let col = t.collection(&a.token, "shared").await;
    let add = PutMemberReq { role: "editor".into(), key_version: 1, sealed_ck: vec![5; 80] };
    let _: RevResp = t.ok("PUT", &format!("/api/collections/{col}/members/{}", b.user_id), Some(&a.token), serde_json::to_value(add).unwrap()).await;

    let item = Uuid::new_v4();
    let (_, v) = t.put(&a.token, col, item, 0, 1).await;
    let author = |s: &SyncResp| s.items.iter().find(|i| i.id == item).unwrap().author.clone();
    assert_eq!(author(&t.sync(&b.token, 0).await), "alice");
    let (st, _) = t.put(&b.token, col, item, v["rev"].as_i64().unwrap(), 1).await;
    assert!(st.is_success());
    assert_eq!(author(&t.sync(&a.token, 0).await), "bob", "the server, not the client, names the writer");
}
