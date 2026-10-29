//! Password CSV exports: Chrome / Edge, Firefox, Bitwarden, KeePass(XC), and similar.
//! Columns are matched by header name, so column order does not matter.

use csv::ReaderBuilder;

use crate::{Error, Result};

const TITLE: &[&str] = &["name", "title", "account", "entry"];
const USER: &[&str] = &["username", "login_username", "user name", "user", "login", "email"];
const PASS: &[&str] = &["password", "login_password"];
const URL: &[&str] = &["url", "login_uri", "uri", "website", "web site"];
const NOTES: &[&str] = &["notes", "note", "extra", "comments", "comment"];
const TOTP: &[&str] = &["totp", "login_totp", "otp", "otpauth"];
const GROUP: &[&str] = &["folder", "group", "grouping", "category"];
const KIND: &[&str] = &["type"];

/// One row of an export, before it becomes an `Item`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CsvEntry {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub totp: String,
    /// Folder / group in the source app; becomes a label.
    pub group: String,
    pub is_note: bool,
}

/// `https://www.example.com:8443/x` → `example.com`.
fn host(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let host = rest.split(['/', ':', '?', '#']).next().unwrap_or("");
    host.strip_prefix("www.").unwrap_or(host).to_string()
}

pub fn parse(text: &str) -> Result<Vec<CsvEntry>> {
    let text = text.trim_start_matches('\u{feff}');
    let first = text.lines().next().unwrap_or("");
    let delimiter = if first.matches(';').count() > first.matches(',').count() { b';' } else { b',' };
    let mut rdr = ReaderBuilder::new().delimiter(delimiter).flexible(true).from_reader(text.as_bytes());
    let headers: Vec<String> = rdr
        .headers()
        .map_err(|_| Error::Invalid("broken CSV file"))?
        .iter()
        .map(|h| h.trim().to_lowercase())
        .collect();
    let col = |names: &[&str]| names.iter().find_map(|n| headers.iter().position(|h| h == n));
    let (title, user, pass, url, notes, totp, group, kind) =
        (col(TITLE), col(USER), col(PASS), col(URL), col(NOTES), col(TOTP), col(GROUP), col(KIND));
    if pass.is_none() || (title.is_none() && url.is_none()) {
        return Err(Error::Invalid("not a password export"));
    }
    let mut out = Vec::new();
    for rec in rdr.records() {
        let rec = rec.map_err(|_| Error::Invalid("broken CSV file"))?;
        let get = |i: Option<usize>| i.and_then(|i| rec.get(i)).unwrap_or("").trim().to_string();
        // KeePass groups are paths ("Root/Email"): keep the innermost name, drop the bare root.
        let group = get(group);
        let group = group.rsplit('/').next().unwrap_or("").trim();
        let mut e = CsvEntry {
            title: get(title),
            username: get(user),
            password: get(pass),
            url: get(url),
            notes: get(notes),
            totp: get(totp),
            group: if group.eq_ignore_ascii_case("root") { String::new() } else { group.to_string() },
            is_note: get(kind).eq_ignore_ascii_case("note"),
        };
        if e.title.is_empty() && e.username.is_empty() && e.password.is_empty() && e.notes.is_empty() && e.url.is_empty() {
            continue;
        }
        if e.title.is_empty() {
            e.title = host(&e.url);
        }
        if e.title.is_empty() {
            e.title = if e.username.is_empty() { "Без названия".into() } else { e.username.clone() };
        }
        out.push(e);
    }
    Ok(out)
}

/// Plain CSV in a layout `parse` (and Bitwarden) reads back: one row per entry.
pub fn write(entries: &[CsvEntry]) -> Result<String> {
    let mut w = csv::Writer::from_writer(Vec::new());
    let io = |_| Error::Invalid("broken CSV file");
    w.write_record(["name", "url", "username", "password", "totp", "notes", "folder", "type"]).map_err(io)?;
    for e in entries {
        let kind = if e.is_note { "note" } else { "login" };
        w.write_record([&e.title, &e.url, &e.username, &e.password, &e.totp, &e.notes, &e.group, kind]).map_err(io)?;
    }
    String::from_utf8(w.into_inner().map_err(|_| Error::Invalid("broken CSV file"))?).map_err(|_| Error::Invalid("broken CSV file"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    #[test]
    fn write_then_parse_roundtrip() {
        let entries = vec![
            CsvEntry {
                title: "GitHub, \"рабочий\"".into(),
                username: "cody".into(),
                password: "p,a\"ss".into(),
                url: "https://github.com".into(),
                notes: "две
строки".into(),
                totp: "JBSWY3DPEHPK3PXP".into(),
                group: "Работа".into(),
                is_note: false,
            },
            CsvEntry { title: "Wi-Fi".into(), notes: "SSID home".into(), is_note: true, ..Default::default() },
        ];
        assert_eq!(parse(&write(&entries).unwrap()).unwrap(), entries);
    }

    #[test]
    fn chrome_and_edge() {
        let csv = "name,url,username,password,note\n\
                   github.com,https://github.com/login,cody,gh-1,\n\
                   \"Банк, личный\",https://bank.ru,\"+7 900\",\"p,a\"\"s\",кодовое слово\n";
        let e = parse(csv).unwrap();
        assert_eq!(e.len(), 2);
        assert_eq!((e[0].title.as_str(), e[0].url.as_str(), e[0].username.as_str(), e[0].password.as_str()), ("github.com", "https://github.com/login", "cody", "gh-1"));
        assert_eq!((e[1].title.as_str(), e[1].password.as_str(), e[1].notes.as_str()), ("Банк, личный", "p,a\"s", "кодовое слово"));
    }

    #[test]
    fn firefox_has_no_title_column() {
        let csv = "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"\n\
                   \"https://www.example.com:8443\",\"me\",\"pw\",,\"https://www.example.com\",\"{x}\",\"1\",\"2\",\"3\"\n";
        let e = parse(csv).unwrap();
        assert_eq!(e[0].title, "example.com", "title derived from the host");
        assert_eq!(e[0].username, "me");
    }

    #[test]
    fn bitwarden_with_folders_notes_and_totp() {
        let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
                   Работа,1,login,GitLab,,,0,https://gitlab.com,cody,gl-1,JBSWY3DPEHPK3PXP\n\
                   ,,note,Wi-Fi,SSID home,,0,,,,\n";
        let e = parse(csv).unwrap();
        assert_eq!((e[0].group.as_str(), e[0].totp.as_str(), e[0].url.as_str()), ("Работа", "JBSWY3DPEHPK3PXP", "https://gitlab.com"));
        assert!(e[1].is_note);
        assert_eq!(e[1].notes, "SSID home");
    }

    #[test]
    fn keepass_with_bom_and_semicolons() {
        let csv = "\u{feff}\"Group\";\"Title\";\"Username\";\"Password\";\"URL\";\"Notes\"\n\"Root/Email\";\"Почта\";\"me@mail.ru\";\"m-1\";\"https://mail.ru\";\"\"\n";
        let e = parse(csv).unwrap();
        assert_eq!((e[0].group.as_str(), e[0].title.as_str(), e[0].password.as_str()), ("Email", "Почта", "m-1"));
    }

    #[test]
    fn skips_empty_rows_and_rejects_unknown_files() {
        let e = parse("name,url,username,password\n,,,\nx,,,p\n").unwrap();
        assert_eq!(e.len(), 1);
        assert!(matches!(parse("a,b,c\n1,2,3\n"), Err(Error::Invalid(_))));
        assert!(matches!(parse(""), Err(Error::Invalid(_))));
    }
}
