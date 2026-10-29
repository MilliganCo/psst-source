//! Real pwd-server over TLS on 127.0.0.1:0, real vaults, real crypto.

use std::sync::{Arc, Mutex};

use pwd_app_lib::{sync, updates};
use pwd_app_lib::vault::{ItemInput, Vault, VaultError};
use pwd_core::model::ItemKind;
use pwd_server::{create_invite, AppState, Config};
use tempfile::TempDir;
use uuid::Uuid;

const PW: &str = "пароль для теста";

struct Server {
    _dir: TempDir,
    state: Arc<AppState>,
    cfg: Config,
    fp: String,
}

impl Server {
    async fn start() -> Server {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = pwd_server::init_data(dir.path(), "127.0.0.1", 0).unwrap();
        let state = Arc::new(pwd_server::open_state(dir.path()).unwrap());
        let handle = axum_server::Handle::new();
        let (st, path, h) = (state.clone(), dir.path().to_path_buf(), handle.clone());
        tokio::spawn(async move { pwd_server::serve(st, &path, "127.0.0.1:0".parse().unwrap(), h).await });
        cfg.port = handle.listening().await.unwrap().port();
        let fp = pwd_server::tls::fingerprint(dir.path()).unwrap();
        Server { _dir: dir, state, cfg, fp }
    }

    fn invite(&self, admin: bool) -> String {
        pwd_server::link(&self.cfg, &self.fp, Some(&create_invite(&self.state, admin).unwrap()))
    }

    fn data(&self) -> &std::path::Path {
        self._dir.path()
    }

    fn link(&self) -> String {
        pwd_server::link(&self.cfg, &self.fp, None)
    }
}

fn device(dir: &TempDir) -> Mutex<Vault> {
    Mutex::new(Vault::open(&dir.path().join("vault.db")).unwrap())
}

fn personal(v: &Mutex<Vault>) -> Uuid {
    v.lock().unwrap().collections().unwrap().into_iter().find(|c| c.kind == "personal").unwrap().id
}

fn login_item(col: Uuid, title: &str, password: &str) -> ItemInput {
    ItemInput {
        id: None,
        collection_id: col,
        kind: ItemKind::Login,
        title: title.into(),
        username: "cody".into(),
        password: Some(password.into()),
        urls: vec![],
        notes: String::new(),
        totp: None,
        labels: vec![],
        favorite: false,
    }
}

fn titles(v: &Mutex<Vault>) -> Vec<String> {
    let mut t: Vec<String> = v.lock().unwrap().list().unwrap().into_iter().map(|i| i.title).collect();
    t.sort();
    t
}

/// alice: local vault with one item, connected to the server; returns her device.
async fn alice(server: &Server, dir: &TempDir) -> (Mutex<Vault>, Uuid) {
    let a = device(dir);
    a.lock().unwrap().create_local("alice", PW).unwrap();
    let col = personal(&a);
    let id = a.lock().unwrap().save(login_item(col, "GitHub", "gh-1")).unwrap();
    sync::connect(&a, &server.invite(true), PW, None, None).await.unwrap();
    (a, id)
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_then_login_on_second_device() {
    let server = Server::start().await;
    let (d1, d2) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a, id) = alice(&server, &d1).await;
    assert!(a.lock().unwrap().server_status().unwrap().unwrap().is_admin);

    let b = device(&d2);
    assert_eq!(
        sync::login(&b, &server.link(), "alice", "не тот пароль").await.unwrap_err(),
        VaultError::WrongPassword
    );
    sync::login(&b, &server.link(), "alice", PW).await.unwrap();
    assert_eq!(titles(&b), ["GitHub"]);
    assert_eq!(b.lock().unwrap().reveal(id, "password").unwrap(), "gh-1");
    assert_eq!(b.lock().unwrap().collections().unwrap()[0].name, "Личное");
}

#[tokio::test(flavor = "multi_thread")]
async fn edits_flow_both_ways_and_conflicts_lose_nothing() {
    let server = Server::start().await;
    let (d1, d2) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a, id) = alice(&server, &d1).await;
    let b = device(&d2);
    sync::login(&b, &server.link(), "alice", PW).await.unwrap();
    let col = personal(&a);

    // Plain edit on A reaches B.
    let mut edit = login_item(col, "GitHub", "gh-2");
    edit.id = Some(id);
    a.lock().unwrap().save(edit.clone()).unwrap();
    let new_id = a.lock().unwrap().save(login_item(col, "Bank", "b-1")).unwrap();
    sync::run(&a).await.unwrap();
    sync::run(&b).await.unwrap();
    assert_eq!(titles(&b), ["Bank", "GitHub"]);
    assert_eq!(b.lock().unwrap().reveal(id, "password").unwrap(), "gh-2");

    // Both change the same item before syncing: A the password, B (later) the title.
    edit.password = Some("gh-3-from-A".into());
    a.lock().unwrap().save(edit.clone()).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(20));
    let mut b_edit = login_item(col, "GitHub (work)", "gh-2");
    b_edit.id = Some(id);
    b_edit.password = None;
    b.lock().unwrap().save(b_edit).unwrap();
    sync::run(&a).await.unwrap();
    sync::run(&b).await.unwrap();
    sync::run(&a).await.unwrap();
    assert_eq!(titles(&a), titles(&b), "devices converge");
    assert_eq!(titles(&b), ["Bank", "GitHub (work)", "GitHub (конфликт)"]);
    let copy = b.lock().unwrap().list().unwrap().into_iter().find(|i| i.title.contains("конфликт")).unwrap();
    assert_eq!(b.lock().unwrap().reveal(copy.id, "password").unwrap(), "gh-3-from-A");

    // Delete on B, purge on B: gone on A too.
    b.lock().unwrap().purge(new_id).unwrap();
    sync::run(&b).await.unwrap();
    sync::run(&a).await.unwrap();
    assert!(!titles(&a).contains(&"Bank".to_string()));
}

#[tokio::test(flavor = "multi_thread")]
async fn password_only_conflict_goes_to_history() {
    let server = Server::start().await;
    let (d1, d2) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a, id) = alice(&server, &d1).await;
    let b = device(&d2);
    sync::login(&b, &server.link(), "alice", PW).await.unwrap();
    let col = personal(&a);
    let mut e = login_item(col, "GitHub", "from-A");
    e.id = Some(id);
    a.lock().unwrap().save(e.clone()).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(20));
    e.password = Some("from-B".into());
    b.lock().unwrap().save(e).unwrap();
    sync::run(&a).await.unwrap();
    sync::run(&b).await.unwrap();
    let mut vb = b.lock().unwrap();
    assert_eq!(vb.list().unwrap().len(), 1);
    assert_eq!(vb.reveal(id, "password").unwrap(), "from-B");
    let history: Vec<String> = (0..vb.get(id).unwrap().history.len()).map(|i| vb.reveal(id, &format!("history:{i}")).unwrap()).collect();
    assert!(history.contains(&"from-A".to_string()), "{history:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_fingerprint_is_refused() {
    let server = Server::start().await;
    let d = tempfile::tempdir().unwrap();
    let a = device(&d);
    a.lock().unwrap().create_local("alice", PW).unwrap();
    let bad = server.invite(false).replace(&server.fp, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    let err = sync::connect(&a, &bad, PW, None, None).await.unwrap_err();
    assert!(matches!(err, VaultError::Offline(ref m) if m.contains("fingerprint")), "{err:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn shared_folder_roles_removal_and_key_rotation() {
    use pwd_app_lib::share;
    let server = Server::start().await;
    let (d1, d2) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a, _) = alice(&server, &d1).await;
    let b = device(&d2);
    b.lock().unwrap().create_local("bob", "пароль боба").unwrap();
    sync::connect(&b, &server.invite(false), "пароль боба", None, None).await.unwrap();

    let fam = a.lock().unwrap().create_collection("Семья").unwrap();
    let tv = a.lock().unwrap().save(login_item(fam, "Netflix", "nf-1")).unwrap();
    share::add_member(&a, fam, "bob", "viewer").await.unwrap();

    let members = share::members(&a, fam).await.unwrap();
    assert_eq!(members.iter().map(|m| (m.username.as_str(), m.role.as_str())).collect::<Vec<_>>(), [("alice", "owner"), ("bob", "viewer")]);
    assert!(members.iter().all(|m| m.fingerprint.len() == 29));

    sync::run(&b).await.unwrap();
    let cols = b.lock().unwrap().collections().unwrap();
    let shared = cols.iter().find(|c| c.id == fam).expect("bob sees the folder");
    assert_eq!((shared.name.as_str(), shared.role.as_str()), ("Семья", "viewer"));
    assert_eq!(b.lock().unwrap().reveal(tv, "password").unwrap(), "nf-1");
    assert_eq!(b.lock().unwrap().save(login_item(fam, "Hack", "x")), Err(VaultError::ReadOnly));

    // Promote to editor: bob writes, alice reads.
    let bob_id = members[1].user_id;
    share::set_role(&a, fam, bob_id, "editor").await.unwrap();
    sync::run(&b).await.unwrap();
    let by_bob = b.lock().unwrap().save(login_item(fam, "Spotify", "sp-1")).unwrap();
    sync::run(&b).await.unwrap();
    sync::run(&a).await.unwrap();
    assert_eq!(a.lock().unwrap().reveal(by_bob, "password").unwrap(), "sp-1");

    // Remove bob: key rotates, alice still reads everything, bob loses the folder.
    share::remove_member(&a, fam, bob_id).await.unwrap();
    assert_eq!(a.lock().unwrap().reveal(tv, "password").unwrap(), "nf-1");
    assert_eq!(a.lock().unwrap().reveal(by_bob, "password").unwrap(), "sp-1");
    let after = a.lock().unwrap().save(login_item(fam, "After", "secret-after")).unwrap();
    sync::run(&a).await.unwrap();
    sync::run(&b).await.unwrap();
    assert!(b.lock().unwrap().collections().unwrap().iter().all(|c| c.id != fam));
    assert_eq!(b.lock().unwrap().reveal(after, "password"), Err(VaultError::NotFound));

    // Unknown user.
    assert!(share::add_member(&a, fam, "nobody", "viewer").await.is_err());
}

#[tokio::test]
async fn update_is_found_downloaded_and_verified() {
    let srv = Server::start().await;
    let dir = tempfile::tempdir().unwrap();
    let (v, _) = alice(&srv, &dir).await;
    assert_eq!(updates::check(&v, "0.0.1", "windows").await.unwrap(), None, "nothing published yet");

    let fx = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/update");
    let apps = tempfile::tempdir().unwrap();
    for f in ["Passwords_9.9.9_x64-setup.exe", "Passwords_9.9.9_x64-setup.exe.sig"] {
        std::fs::copy(fx.join(f), apps.path().join(f)).unwrap();
    }
    std::fs::write(
        apps.path().join("latest.json"),
        r#"{"version":"9.9.9","notes":"тест","files":{"windows":"Passwords_9.9.9_x64-setup.exe"}}"#,
    )
    .unwrap();
    pwd_server::publish_release(srv.data(), apps.path()).unwrap();

    let up = updates::check(&v, "0.0.1", "windows").await.unwrap().expect("newer version announced");
    assert_eq!((up.version.as_str(), up.notes.as_str()), ("9.9.9", "тест"));
    assert_eq!(updates::check(&v, "9.9.9", "windows").await.unwrap(), None);
    assert_eq!(updates::check(&v, "0.0.1", "deb").await.unwrap(), None);

    let out = tempfile::tempdir().unwrap();
    let test_key = std::fs::read_to_string(fx.join("test.key.pub")).unwrap();
    let path = updates::download(&v, &up, &test_key, out.path()).await.unwrap();
    assert_eq!(std::fs::read(path).unwrap(), std::fs::read(fx.join("Passwords_9.9.9_x64-setup.exe")).unwrap());
    assert!(updates::download(&v, &up, updates::PUBLIC_KEY, out.path()).await.is_err(), "not signed by the release key");
}

#[tokio::test]
async fn folder_chat_reaches_members_and_viewers_cannot_post() {
    use pwd_app_lib::share;
    let server = Server::start().await;
    let (d1, d2) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a, _) = alice(&server, &d1).await;
    let b = device(&d2);
    b.lock().unwrap().create_local("bob", "пароль боба").unwrap();
    sync::connect(&b, &server.invite(false), "пароль боба", None, None).await.unwrap();
    let fam = a.lock().unwrap().create_collection("Семья").unwrap();
    share::add_member(&a, fam, "bob", "viewer").await.unwrap();

    a.lock().unwrap().post_message(fam, "всем привет").unwrap();
    sync::run(&a).await.unwrap();
    sync::run(&b).await.unwrap();
    let seen = b.lock().unwrap().messages(fam).unwrap();
    assert_eq!(seen.iter().map(|m| (m.author.as_str(), m.text.as_str(), m.mine)).collect::<Vec<_>>(), [("alice", "всем привет", false)]);
    assert_eq!(b.lock().unwrap().post_message(fam, "можно?"), Err(VaultError::ReadOnly));

    let bob_id = share::members(&a, fam).await.unwrap()[1].user_id;
    share::set_role(&a, fam, bob_id, "editor").await.unwrap();
    sync::run(&b).await.unwrap();
    b.lock().unwrap().post_message(fam, "привет, алиса").unwrap();
    sync::run(&b).await.unwrap();
    sync::run(&a).await.unwrap();
    let texts: Vec<String> = a.lock().unwrap().messages(fam).unwrap().into_iter().map(|m| format!("{}: {}", m.author, m.text)).collect();
    assert_eq!(texts, ["alice: всем привет", "bob: привет, алиса"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn devices_are_listed_and_can_be_logged_out() {
    let server = Server::start().await;
    let (d1, d2) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a, _) = alice(&server, &d1).await;
    let b = device(&d2);
    sync::login(&b, &server.link(), "alice", PW).await.unwrap();

    let list = sync::sessions(&a).await.unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list.iter().filter(|s| s.current).count(), 1);
    assert!(list.iter().all(|s| s.device.contains(" · ")), "{list:?}");

    sync::revoke_other_sessions(&a).await.unwrap();
    assert_eq!(sync::run(&b).await.unwrap_err(), VaultError::SessionExpired);
    sync::run(&a).await.unwrap();
    assert_eq!(sync::sessions(&a).await.unwrap().len(), 1);

    sync::relogin(&b, PW).await.unwrap();
    let other = sync::sessions(&a).await.unwrap().into_iter().find(|s| !s.current).unwrap();
    sync::revoke_session(&a, &other.id).await.unwrap();
    assert_eq!(sync::run(&b).await.unwrap_err(), VaultError::SessionExpired);
}

#[tokio::test(flavor = "multi_thread")]
async fn chat_author_comes_from_the_server_not_the_sender() {
    use pwd_app_lib::share;
    let server = Server::start().await;
    let (d1, d2) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a, _) = alice(&server, &d1).await;
    let b = device(&d2);
    b.lock().unwrap().create_local("bob", "пароль боба").unwrap();
    sync::connect(&b, &server.invite(false), "пароль боба", None, None).await.unwrap();
    let fam = a.lock().unwrap().create_collection("Семья").unwrap();
    share::add_member(&a, fam, "bob", "editor").await.unwrap();
    sync::run(&b).await.unwrap();

    // Bob's app writes "alice" as the author of his message.
    let mut forged = login_item(fam, "alice", "");
    forged.kind = ItemKind::Message;
    forged.notes = "я алиса, честно".into();
    b.lock().unwrap().save(forged).unwrap();
    sync::run(&b).await.unwrap();
    sync::run(&a).await.unwrap();
    let m = a.lock().unwrap().messages(fam).unwrap();
    assert_eq!((m[0].author.as_str(), m[0].mine), ("bob", false));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_large_attachment_reaches_another_member() {
    use pwd_app_lib::share;
    let server = Server::start().await;
    let (d1, d2) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a, _) = alice(&server, &d1).await;
    let b = device(&d2);
    b.lock().unwrap().create_local("bob", "пароль боба").unwrap();
    sync::connect(&b, &server.invite(false), "пароль боба", None, None).await.unwrap();
    let fam = a.lock().unwrap().create_collection("Семья").unwrap();
    let entry = a.lock().unwrap().save(login_item(fam, "Документы", "")).unwrap();
    let scan: Vec<u8> = (0..6 * 1024 * 1024).map(|i| (i * 7 % 251) as u8).collect();
    a.lock().unwrap().attach(entry, "паспорт.pdf", &scan).unwrap();
    share::add_member(&a, fam, "bob", "viewer").await.unwrap();
    sync::run(&a).await.unwrap();
    sync::run(&b).await.unwrap();
    let files = b.lock().unwrap().get(entry).unwrap().attachments;
    assert_eq!((files.len(), files[0].size), (1, scan.len()));
    assert_eq!(b.lock().unwrap().attachment_data(files[0].id).unwrap(), ("паспорт.pdf".to_string(), scan));
}
