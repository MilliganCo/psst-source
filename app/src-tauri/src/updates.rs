//! Signed updates from the team's own server. The server only hosts files: an installer is
//! accepted when its minisign signature checks against the key built into the app, and the
//! signed (trusted) comment names that exact file, whose name carries the version. A server
//! admin can therefore neither push a modified build nor roll clients back to an older one.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use data_encoding::BASE64;
use minisign_verify::{PublicKey, Signature};
use serde::{Deserialize, Serialize};

use crate::sync;
use crate::vault::{io, VResult, Vault, VaultError};

/// `tauri signer` public key (base64 of the minisign key file). The private key stays on the
/// release machine (~/.passwords-release/update.key) and is used by scripts/package.sh.
pub const PUBLIC_KEY: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IEUzRUUxMzhCRkUyNDFBMEIKUldRTEdpVCtpeFB1NDJ4UzJXR1grUGhCWFBmZ2VDN2QwWVJVd2pMaDJwanE4WURpUStNbm5ndTcK";

/// `latest.json` written by scripts/package.sh and served under /updates.
#[derive(Deserialize, Clone, Debug)]
pub struct Latest {
    pub version: String,
    #[serde(default)]
    pub notes: String,
    /// `windows`, `deb` or `appimage` -> installer file name.
    pub files: HashMap<String, String>,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub struct UpdateInfo {
    pub version: String,
    pub notes: String,
    pub file: String,
}

fn parts(v: &str) -> Option<Vec<u64>> {
    v.split('.').map(|p| p.parse().ok()).collect()
}

/// Dotted numeric versions; anything unparsable is never newer.
pub fn newer(candidate: &str, current: &str) -> bool {
    matches!((parts(candidate), parts(current)), (Some(a), Some(b)) if a > b)
}

/// Which installer this copy of the app updates itself with.
pub fn platform() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if std::env::var_os("APPIMAGE").is_some() {
        "appimage"
    } else {
        "deb"
    }
}

pub fn pick(latest: &Latest, current: &str, platform: &str) -> Option<UpdateInfo> {
    let file = latest.files.get(platform)?;
    let named_right = file.contains(&format!("_{}_", latest.version)) && !file.contains(['/', '\\']);
    (newer(&latest.version, current) && named_right).then(|| UpdateInfo {
        version: latest.version.clone(),
        notes: latest.notes.clone(),
        file: file.clone(),
    })
}

/// `sig` is a `tauri signer` .sig file: base64 of a minisign signature.
pub fn verify(public_key: &str, file: &str, data: &[u8], sig: &str) -> VResult<()> {
    let bad = |what: &str| VaultError::Invalid(format!("update rejected: {what}"));
    let decode = |b64: &str| BASE64.decode(b64.trim().as_bytes()).ok().and_then(|b| String::from_utf8(b).ok());
    let pk = decode(public_key).and_then(|t| PublicKey::decode(&t).ok()).ok_or_else(|| bad("bad public key"))?;
    let sig = decode(sig).and_then(|t| Signature::decode(&t).ok()).ok_or_else(|| bad("malformed signature"))?;
    pk.verify(data, &sig, false).map_err(|_| bad("signature does not match"))?;
    let signed_name = sig.trusted_comment().split('\t').find_map(|f| f.strip_prefix("file:"));
    if signed_name != Some(file) {
        return Err(bad("signature is for another file"));
    }
    Ok(())
}

/// None when nothing newer is published for `platform`.
pub async fn check(v: &Mutex<Vault>, current: &str, platform: &str) -> VResult<Option<UpdateInfo>> {
    let (client, _) = sync::client_for(v).await?;
    match client.get::<Latest>("/updates/latest.json").await {
        Ok(latest) => Ok(pick(&latest, current, platform)),
        Err(VaultError::Server(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Downloads the installer and its signature, verifies them, writes the installer into `dir`.
pub async fn download(v: &Mutex<Vault>, up: &UpdateInfo, public_key: &str, dir: &Path) -> VResult<PathBuf> {
    let (client, _) = sync::client_for(v).await?;
    let data = client.bytes(&format!("/updates/{}", up.file)).await?;
    let sig = client.bytes(&format!("/updates/{}.sig", up.file)).await?;
    verify(public_key, &up.file, &data, &String::from_utf8_lossy(&sig))?;
    std::fs::create_dir_all(dir).map_err(io)?;
    let path = dir.join(&up.file);
    std::fs::write(&path, &data).map_err(io)?;
    Ok(path)
}

/// Starts installing a verified installer. The caller exits right after: the installer replaces
/// the app's files and starts it again (the delay lets this copy release the single-instance lock).
pub fn launch(path: &Path, platform: &str) -> VResult<()> {
    use std::process::Command;
    let started = match platform {
        // Tauri's NSIS installer: /P = passive (progress bar only), /R = start the app when done.
        "windows" => Command::new(path).args(["/P", "/R"]).spawn(),
        "appimage" => {
            let target = PathBuf::from(std::env::var_os("APPIMAGE").ok_or_else(|| io("APPIMAGE is not set"))?);
            let next = target.with_extension("new");
            std::fs::copy(path, &next).map_err(io)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&next, std::fs::Permissions::from_mode(0o755)).map_err(io)?;
            }
            std::fs::rename(&next, &target).map_err(io)?;
            Command::new("sh").args(["-c", "sleep 1; exec \"$0\""]).arg(&target).spawn()
        }
        // A .deb needs root: polkit asks for the password. If that fails, the system installer opens it.
        _ => Command::new("sh")
            .args(["-c", "sleep 1; if pkexec apt-get install -y \"$0\"; then exec pwd-app; else xdg-open \"$0\"; fi"])
            .arg(path)
            .spawn(),
    };
    started.map(drop).map_err(io)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/update/");
    const FILE: &str = "Passwords_9.9.9_x64-setup.exe";

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!("{FX}{name}")).unwrap()
    }
    fn text(name: &str) -> String {
        String::from_utf8(fixture(name)).unwrap()
    }

    #[test]
    fn compares_versions_numerically() {
        assert!(newer("0.3.0", "0.2.0"));
        assert!(newer("0.10.0", "0.9.9"));
        assert!(newer("1.0.0", "0.99.0"));
        assert!(!newer("0.2.0", "0.2.0"));
        assert!(!newer("0.1.9", "0.2.0"));
        assert!(!newer("garbage", "0.2.0"));
    }

    #[test]
    fn picks_the_installer_for_this_platform_only_when_newer() {
        let latest: Latest = serde_json::from_str(
            r#"{"version":"9.9.9","notes":"новое","files":{"windows":"Passwords_9.9.9_x64-setup.exe","deb":"Passwords_9.9.9_amd64.deb"}}"#,
        )
        .unwrap();
        let up = pick(&latest, "0.2.0", "windows").unwrap();
        assert_eq!((up.version.as_str(), up.file.as_str(), up.notes.as_str()), ("9.9.9", FILE, "новое"));
        assert_eq!(pick(&latest, "0.2.0", "deb").unwrap().file, "Passwords_9.9.9_amd64.deb");
        assert_eq!(pick(&latest, "0.2.0", "appimage"), None, "no file for this platform");
        assert_eq!(pick(&latest, "9.9.9", "windows"), None, "already up to date");

        let mut lying = latest.clone();
        lying.files.insert("windows".into(), "Passwords_0.0.1_x64-setup.exe".into());
        assert_eq!(pick(&lying, "0.2.0", "windows"), None, "file name must carry the announced version");
    }

    #[test]
    fn verifies_signature_and_signed_file_name() {
        let key = text("test.key.pub");
        let data = fixture(FILE);
        let sig = text(&format!("{FILE}.sig"));
        verify(&key, FILE, &data, &sig).unwrap();

        let mut tampered = data.clone();
        tampered[0] ^= 1;
        assert!(verify(&key, FILE, &tampered, &sig).is_err(), "modified installer");
        assert!(verify(&key, FILE, &data, &text("old-name.sig")).is_err(), "signature made for another (older) file");
        assert!(verify(PUBLIC_KEY, FILE, &data, &sig).is_err(), "signed by a different key");
        assert!(verify(&key, FILE, &data, "not a signature").is_err());
    }
}
