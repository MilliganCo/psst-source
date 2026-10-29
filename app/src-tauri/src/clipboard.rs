//! Clipboard with auto-clear. One clipboard handle lives for the whole app: on Linux the
//! contents are served by this process and would vanish with the handle.

use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use arboard::Clipboard;
use zeroize::Zeroizing;

/// Last value we put on the clipboard, with a generation so an older timer never clears a newer copy.
static LAST: Mutex<Option<(u64, Zeroizing<String>)>> = Mutex::new(None);

fn clipboard() -> Result<&'static Mutex<Clipboard>, String> {
    static CB: OnceLock<Mutex<Clipboard>> = OnceLock::new();
    if let Some(cb) = CB.get() {
        return Ok(cb);
    }
    let cb = Clipboard::new().map_err(|e| format!("clipboard: {e}"))?;
    Ok(CB.get_or_init(|| Mutex::new(cb)))
}

/// Writes text, asking clipboard managers not to keep it in history.
fn set(cb: &mut Clipboard, text: &str) -> Result<(), arboard::Error> {
    #[cfg(windows)]
    {
        use arboard::SetExtWindows;
        cb.set().exclude_from_history().exclude_from_cloud().text(text)
    }
    #[cfg(target_os = "linux")]
    {
        use arboard::SetExtLinux;
        cb.set().exclude_from_history().text(text)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        cb.set_text(text)
    }
}

/// Clears the clipboard if it still holds our value (only for generation `only`, if given).
fn clear_ours(only: Option<u64>) {
    let mut last = LAST.lock().unwrap_or_else(|e| e.into_inner());
    let Some((generation, value)) = last.as_ref() else { return };
    if only.is_some_and(|g| g != *generation) {
        return;
    }
    if let Ok(cb) = clipboard() {
        let mut cb = cb.lock().unwrap_or_else(|e| e.into_inner());
        if cb.get_text().map(Zeroizing::new).is_ok_and(|now| now.as_str() == value.as_str()) {
            let _ = cb.clear();
        }
    }
    *last = None;
}

/// Copies `text`; after `clear_after_secs` clears the clipboard if it still holds `text`.
pub fn copy_secret(text: String, clear_after_secs: u64) -> Result<(), String> {
    let text = Zeroizing::new(text);
    let cb = clipboard()?;
    set(&mut cb.lock().unwrap_or_else(|e| e.into_inner()), &text).map_err(|e| format!("clipboard: {e}"))?;
    let generation = {
        let mut last = LAST.lock().unwrap_or_else(|e| e.into_inner());
        let g = last.as_ref().map_or(0, |(g, _)| g + 1);
        *last = Some((g, text));
        g
    };
    if clear_after_secs > 0 {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(clear_after_secs));
            clear_ours(Some(generation));
        });
    }
    Ok(())
}

/// The clipboard image as RGBA (e.g. a screenshot of a QR code).
pub fn read_image() -> Result<(usize, usize, Vec<u8>), String> {
    let cb = clipboard()?;
    let img = cb.lock().unwrap_or_else(|e| e.into_inner()).get_image().map_err(|e| format!("clipboard: {e}"))?;
    Ok((img.width, img.height, img.bytes.into_owned()))
}

/// Now, instead of waiting for the timer: on lock, and on exit (the timer thread dies with the process).
pub fn clear_now() {
    clear_ours(None);
}
