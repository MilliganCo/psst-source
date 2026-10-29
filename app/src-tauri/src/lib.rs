mod clipboard;
mod hibp;
mod qr;
pub mod share;
mod store;
pub mod updates;
pub mod sync;
pub mod vault;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};

use pwd_core::generator::{self, GeneratorOptions};
use pwd_core::model::Label;
use tauri::{AppHandle, Manager, State};
use uuid::Uuid;
use vault::{CollectionView, ItemDetails, ItemInput, ItemSummary, Status, VResult, Vault, VaultError};

struct AppState(Mutex<Vault>);

impl AppState {
    fn vault(&self) -> MutexGuard<'_, Vault> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

type St<'a> = State<'a, AppState>;

// Commands are async so Argon2 and disk work run off the UI thread.

#[tauri::command]
async fn status(st: St<'_>) -> VResult<Status> {
    st.vault().status()
}

#[tauri::command]
async fn create_local(st: St<'_>, username: String, password: String) -> VResult<String> {
    st.vault().create_local(&username, &password)
}

#[tauri::command]
async fn unlock(st: St<'_>, password: String) -> VResult<()> {
    st.vault().unlock(&password)
}

#[tauri::command]
async fn lock(st: St<'_>) -> VResult<()> {
    st.vault().lock();
    clipboard::clear_now();
    Ok(())
}

#[tauri::command]
async fn change_password(st: St<'_>, old: String, new: String) -> VResult<()> {
    st.vault().change_password(&old, &new)
}

#[tauri::command]
async fn collections(st: St<'_>) -> VResult<Vec<CollectionView>> {
    st.vault().collections()
}

#[tauri::command]
async fn list(st: St<'_>) -> VResult<Vec<ItemSummary>> {
    st.vault().list()
}

#[tauri::command]
async fn get(st: St<'_>, id: Uuid) -> VResult<ItemDetails> {
    st.vault().get(id)
}

#[tauri::command]
async fn reveal(st: St<'_>, id: Uuid, field: String) -> VResult<String> {
    st.vault().reveal(id, &field)
}

#[tauri::command]
async fn copy(st: St<'_>, id: Uuid, field: String, clear_after: u64) -> VResult<()> {
    let text = match field.as_str() {
        "username" => st.vault().get(id)?.summary.username,
        "totp" => st.vault().totp(id)?.code, // the current code, never the secret
        f => st.vault().reveal(id, f)?,
    };
    clipboard::copy_secret(text, clear_after).map_err(VaultError::Io)
}

#[tauri::command]
async fn totp(st: St<'_>, id: Uuid) -> VResult<vault::TotpCode> {
    st.vault().totp(id)
}

#[tauri::command]
async fn copy_text(text: String, clear_after: u64) -> VResult<()> {
    clipboard::copy_secret(text, clear_after).map_err(VaultError::Io)
}

#[tauri::command]
async fn save(st: St<'_>, input: ItemInput) -> VResult<Uuid> {
    st.vault().save(input)
}

#[tauri::command]
async fn delete(st: St<'_>, id: Uuid) -> VResult<()> {
    st.vault().delete(id)
}

#[tauri::command]
async fn restore(st: St<'_>, id: Uuid) -> VResult<()> {
    st.vault().restore(id)
}

#[tauri::command]
async fn purge(st: St<'_>, id: Uuid) -> VResult<()> {
    st.vault().purge(id)
}

#[tauri::command]
async fn save_label(st: St<'_>, collection_id: Uuid, label: Label) -> VResult<()> {
    st.vault().save_label(collection_id, label)
}

#[tauri::command]
async fn delete_label(st: St<'_>, collection_id: Uuid, label_id: Uuid) -> VResult<()> {
    st.vault().delete_label(collection_id, label_id)
}

#[tauri::command]
async fn import_legacy(st: St<'_>, path: String, password: String, collection_id: Uuid) -> VResult<usize> {
    st.vault().import_legacy(&PathBuf::from(path), &password, collection_id)
}

#[tauri::command]
async fn import_csv(st: St<'_>, path: String, collection_id: Uuid) -> VResult<usize> {
    st.vault().import_csv(&PathBuf::from(path), collection_id)
}

#[tauri::command]
fn generate(opts: GeneratorOptions) -> VResult<String> {
    Ok(generator::generate_password(&opts)?)
}

#[tauri::command]
fn generate_passphrase(words: usize, separator: String) -> VResult<String> {
    Ok(generator::generate_passphrase(words, &separator)?)
}

/// Path of the v1 vault if it exists, to offer an import on first run.
#[tauri::command]
fn legacy_vault_path() -> Option<String> {
    let p = dirs::home_dir()?.join(".password_manager").join("vault.vault");
    p.exists().then(|| p.to_string_lossy().into_owned())
}

// ---------- server ----------

#[tauri::command]
async fn server_status(st: St<'_>) -> VResult<Option<sync::ServerStatus>> {
    st.vault().server_status()
}

#[tauri::command]
async fn connect(
    st: St<'_>,
    link: String,
    password: String,
    recovery_code: Option<String>,
    username: Option<String>,
) -> VResult<()> {
    sync::connect(&st.0, &link, &password, recovery_code.as_deref(), username.as_deref()).await
}

#[tauri::command]
async fn update_server_link(st: St<'_>, link: String) -> VResult<()> {
    sync::update_link(&st.0, &link).await
}

#[tauri::command]
async fn login_server(st: St<'_>, link: String, username: String, password: String) -> VResult<()> {
    sync::login(&st.0, &link, &username, &password).await
}

#[tauri::command]
async fn relogin(st: St<'_>, password: String) -> VResult<()> {
    sync::relogin(&st.0, &password).await
}

#[tauri::command]
async fn sync_now(st: St<'_>) -> VResult<sync::SyncReport> {
    sync::run(&st.0).await
}

#[tauri::command]
async fn create_collection(st: St<'_>, name: String) -> VResult<Uuid> {
    st.vault().create_collection(&name)
}

#[tauri::command]
async fn rename_collection(st: St<'_>, id: Uuid, name: String) -> VResult<()> {
    st.vault().rename_collection(id, &name)
}

#[tauri::command]
async fn members(st: St<'_>, id: Uuid) -> VResult<Vec<share::MemberView>> {
    share::members(&st.0, id).await
}

#[tauri::command]
async fn add_member(st: St<'_>, id: Uuid, username: String, role: String) -> VResult<()> {
    share::add_member(&st.0, id, &username, &role).await
}

#[tauri::command]
async fn set_member_role(st: St<'_>, id: Uuid, user_id: Uuid, role: String) -> VResult<()> {
    share::set_role(&st.0, id, user_id, &role).await
}

#[tauri::command]
async fn remove_member(st: St<'_>, id: Uuid, user_id: Uuid) -> VResult<()> {
    share::remove_member(&st.0, id, user_id).await
}

#[tauri::command]
async fn leave_collection(st: St<'_>, id: Uuid) -> VResult<()> {
    share::leave(&st.0, id).await
}

/// One-time invite link for a new person (admin only).
#[tauri::command]
async fn admin_invite(st: St<'_>, is_admin: bool) -> VResult<String> {
    let (client, info) = sync::client_for(&st.0).await?;
    let r: pwd_core::proto::InviteResp = client.post("/api/admin/invites", &pwd_core::proto::InviteReq { is_admin }).await?;
    Ok(format!("pwd://{}/invite/{}?fp={}", info.url.trim_start_matches("https://"), r.code, info.fp))
}

#[tauri::command]
async fn admin_users(st: St<'_>) -> VResult<Vec<pwd_core::proto::AdminUser>> {
    let (client, _) = sync::client_for(&st.0).await?;
    client.get("/api/admin/users").await
}

#[tauri::command]
async fn admin_disable(st: St<'_>, user_id: Uuid, disabled: bool) -> VResult<()> {
    let (client, _) = sync::client_for(&st.0).await?;
    let _: pwd_core::proto::RevResp =
        client.post(&format!("/api/admin/users/{user_id}/disable"), &serde_json::json!({ "disabled": disabled })).await?;
    Ok(())
}

#[tauri::command]
async fn check_password(st: St<'_>, id: Option<Uuid>, password: String, title: String, username: String) -> VResult<vault::PasswordCheck> {
    st.vault().check_password(id, &password, &title, &username)
}

#[derive(serde::Serialize)]
struct HibpReport {
    checked: usize,
    pwned: usize,
}

/// Breach check: passwords are hashed here and only 5-character SHA-1 prefixes go out.
#[tauri::command]
async fn hibp_check(st: St<'_>) -> VResult<HibpReport> {
    let cands = st.vault().pwned_candidates()?;
    let mut unique: Vec<zeroize::Zeroizing<String>> = cands.iter().map(|c| c.2.clone()).collect();
    unique.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    unique.dedup_by(|a, b| a.as_str() == b.as_str());
    let counts = hibp::check(unique.iter().map(|p| p.to_string()).collect()).await?;
    let by_pw: std::collections::HashMap<&str, u64> = unique.iter().map(|p| p.as_str()).zip(counts).collect();
    let results: Vec<_> = cands.iter().map(|(id, at, pw)| (*id, *at, by_pw[pw.as_str()])).collect();
    let pwned = results.iter().filter(|r| r.2 > 0).count();
    st.vault().set_pwned(results);
    Ok(HibpReport { checked: cands.len(), pwned })
}

/// 2FA secret from a screenshot of the site's QR code in the clipboard.
#[tauri::command]
async fn totp_from_clipboard() -> VResult<String> {
    let (w, h, rgba) = clipboard::read_image().map_err(|_| VaultError::Invalid("no image in the clipboard".into()))?;
    let text = qr::decode(w, h, &rgba).ok_or_else(|| VaultError::Invalid("no QR code in the clipboard image".into()))?;
    pwd_core::totp::code(&text, 0)?; // must be a usable 2FA link or secret
    Ok(text)
}

#[tauri::command]
async fn export_backup(st: St<'_>, path: String, password: String) -> VResult<usize> {
    st.vault().export_backup(std::path::Path::new(&path), &password)
}

#[tauri::command]
async fn import_backup(st: St<'_>, path: String, password: String, collection_id: Uuid) -> VResult<usize> {
    st.vault().import_backup(std::path::Path::new(&path), &password, collection_id)
}

#[tauri::command]
async fn export_csv(st: St<'_>, path: String) -> VResult<usize> {
    st.vault().export_csv(std::path::Path::new(&path))
}

#[tauri::command]
async fn sessions(st: St<'_>) -> VResult<Vec<pwd_core::proto::SessionInfo>> {
    sync::sessions(&st.0).await
}

#[tauri::command]
async fn revoke_session(st: St<'_>, id: String) -> VResult<()> {
    sync::revoke_session(&st.0, &id).await
}

#[tauri::command]
async fn revoke_other_sessions(st: St<'_>) -> VResult<()> {
    sync::revoke_other_sessions(&st.0).await
}

#[tauri::command]
async fn attach_file(st: St<'_>, item_id: Uuid, path: String) -> VResult<Uuid> {
    let path = std::path::Path::new(&path);
    let size = std::fs::metadata(path).map_err(vault::io)?.len();
    if size > vault::ATTACHMENT_MAX as u64 {
        return Err(VaultError::Invalid("file is larger than 8 MB".into()));
    }
    let data = std::fs::read(path).map_err(vault::io)?;
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    st.vault().attach(item_id, &name, &data)
}

#[tauri::command]
async fn save_attachment(st: St<'_>, id: Uuid, path: String) -> VResult<()> {
    let (_, data) = st.vault().attachment_data(id)?;
    std::fs::write(path, data).map_err(vault::io)
}

#[tauri::command]
async fn remove_attachment(st: St<'_>, id: Uuid) -> VResult<()> {
    st.vault().remove_attachment(id)
}

#[tauri::command]
async fn post_message(st: St<'_>, collection_id: Uuid, text: String) -> VResult<Uuid> {
    st.vault().post_message(collection_id, &text)
}

#[tauri::command]
async fn messages(st: St<'_>, collection_id: Uuid) -> VResult<Vec<vault::MessageView>> {
    st.vault().messages(collection_id)
}

#[tauri::command]
async fn chat_summary(st: St<'_>) -> VResult<Vec<vault::ChatSummary>> {
    st.vault().chat_summary()
}

#[tauri::command]
async fn update_check(st: St<'_>) -> VResult<Option<updates::UpdateInfo>> {
    updates::check(&st.0, env!("CARGO_PKG_VERSION"), updates::platform()).await
}

/// Re-checks (the webview does not choose the file), downloads, verifies, starts the installer, exits.
#[tauri::command]
async fn update_install(app: tauri::AppHandle, st: St<'_>) -> VResult<()> {
    let up = updates::check(&st.0, env!("CARGO_PKG_VERSION"), updates::platform())
        .await?
        .ok_or_else(|| VaultError::Invalid("no update available".into()))?;
    let dir = std::env::temp_dir().join("passwords-update");
    let path = updates::download(&st.0, &up, updates::PUBLIC_KEY, &dir).await?;
    updates::launch(&path, updates::platform())?;
    app.exit(0);
    Ok(())
}

/// Closing the window hides it to the tray instead of quitting (Windows, when enabled).
static CLOSE_TO_TRAY: AtomicBool = AtomicBool::new(false);

#[tauri::command]
fn set_close_to_tray(on: bool) {
    CLOSE_TO_TRAY.store(on && cfg!(windows), Ordering::Relaxed);
}

fn show_window(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

#[cfg(windows)]
fn tray(app: &tauri::App) -> tauri::Result<()> {
    use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
    use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
    use tauri::Emitter;
    let open = MenuItem::with_id(app, "open", "Открыть", true, None::<&str>)?;
    let lock = MenuItem::with_id(app, "lock", "Заблокировать", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Выход", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &lock, &PredefinedMenuItem::separator(app)?, &quit])?;
    let mut tray = TrayIconBuilder::with_id("main").tooltip("Passwords").menu(&menu).show_menu_on_left_click(false);
    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.on_menu_event(|app, e| match e.id().as_ref() {
        "open" => show_window(app),
        "lock" => {
            if let Some(st) = app.try_state::<AppState>() {
                st.vault().lock();
            }
            clipboard::clear_now();
            let _ = app.emit("vault-locked", ());
        }
        "quit" => app.exit(0),
        _ => {}
    })
    .on_tray_icon_event(|tray, e| {
        if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = e {
            show_window(tray.app_handle());
        }
    })
    .build(app)?;
    Ok(())
}

pub fn run() {
    let mut builder = tauri::Builder::default();
    // A second copy on the same vault would keep its own in-memory state and overwrite this one's
    // writes. With PWD_DATA_DIR each copy has its own vault, so several may run (testing).
    if std::env::var_os("PWD_DATA_DIR").is_none() {
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| show_window(app)));
    }
    builder
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .setup(|app| {
            let dir = match std::env::var_os("PWD_DATA_DIR") {
                Some(d) => PathBuf::from(d),
                None => app.path().app_data_dir()?,
            };
            let vault = Vault::open(&dir.join("vault.db")).map_err(|e| e.to_string())?;
            app.manage(AppState(Mutex::new(vault)));
            #[cfg(windows)]
            tray(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if CLOSE_TO_TRAY.load(Ordering::Relaxed) {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            status,
            create_local,
            unlock,
            lock,
            change_password,
            collections,
            list,
            get,
            reveal,
            copy,
            copy_text,
            totp,
            save,
            delete,
            restore,
            purge,
            save_label,
            delete_label,
            import_legacy,
            import_csv,
            generate,
            generate_passphrase,
            legacy_vault_path,
            server_status,
            connect,
            update_server_link,
            login_server,
            relogin,
            sync_now,
            create_collection,
            rename_collection,
            members,
            add_member,
            set_member_role,
            remove_member,
            leave_collection,
            admin_invite,
            admin_users,
            admin_disable,
            update_check,
            update_install,
            check_password,
            post_message,
            messages,
            chat_summary,
            export_backup,
            import_backup,
            export_csv,
            hibp_check,
            totp_from_clipboard,
            sessions,
            revoke_session,
            revoke_other_sessions,
            set_close_to_tray,
            attach_file,
            save_attachment,
            remove_attachment
        ])
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|_, event| {
            if let tauri::RunEvent::Exit = event {
                clipboard::clear_now();
            }
        });
}
