//! Decrypted data model. Each record is serialized to JSON and encrypted separately.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

/// Previous passwords kept per item.
pub const HISTORY_LIMIT: usize = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ItemKind {
    Login,
    Note,
    /// Folder chat line: `title` = author, `notes` = text, `created_at` = sent. Not a password.
    Message,
    /// File attached to an entry: `title` = file name, `notes` = base64 content, `parent` = entry.
    File,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub value: String,
    pub changed_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    pub kind: ItemKind,
    pub title: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default)]
    pub notes: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<String>,
    #[serde(default)]
    pub labels: Vec<Uuid>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub password_history: Vec<HistoryEntry>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default)]
    pub deleted_at: Option<DateTime<Utc>>,
    /// For files: the entry they belong to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<Uuid>,
}

impl Item {
    pub fn new(kind: ItemKind, title: impl Into<String>, now: DateTime<Utc>) -> Self {
        Self {
            kind,
            title: title.into(),
            username: String::new(),
            password: String::new(),
            urls: Vec::new(),
            notes: String::new(),
            totp: None,
            labels: Vec::new(),
            favorite: false,
            password_history: Vec::new(),
            created_at: now,
            updated_at: now,
            deleted_at: None,
            parent: None,
        }
    }

    /// Replaces the password; the previous non-empty value goes to history
    /// (oldest first, at most `HISTORY_LIMIT` entries).
    pub fn set_password(&mut self, new: String, now: DateTime<Utc>) {
        if new == self.password {
            return;
        }
        let old = std::mem::replace(&mut self.password, new);
        if !old.is_empty() {
            self.password_history.push(HistoryEntry { value: old, changed_at: now });
            let excess = self.password_history.len().saturating_sub(HISTORY_LIMIT);
            self.password_history.drain(..excess).for_each(|mut h| h.value.zeroize());
        }
        self.updated_at = now;
    }
}

impl Drop for Item {
    fn drop(&mut self) {
        self.password.zeroize();
        self.totp.zeroize();
        self.password_history.iter_mut().for_each(|h| h.value.zeroize());
    }
}

/// Label colour slot; every UI theme maps each slot to its own shade.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LabelColor {
    Red,
    Orange,
    Yellow,
    Green,
    Teal,
    Blue,
    Purple,
    Pink,
    Gray,
}

impl LabelColor {
    pub const ALL: [LabelColor; 9] = [
        Self::Red,
        Self::Orange,
        Self::Yellow,
        Self::Green,
        Self::Teal,
        Self::Blue,
        Self::Purple,
        Self::Pink,
        Self::Gray,
    ];
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Label {
    pub id: Uuid,
    pub name: String,
    pub color: LabelColor,
}

/// Collection name and labels. Stored as the record whose id equals the collection id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    pub name: String,
    #[serde(default)]
    pub labels: Vec<Label>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn t(sec: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_767_225_600 + sec, 0).unwrap()
    }

    #[test]
    fn set_password_moves_old_value_to_history() {
        let mut item = Item::new(ItemKind::Login, "GitHub", t(0));
        item.set_password("first".into(), t(1));
        assert!(item.password_history.is_empty(), "empty old password is not history");
        item.set_password("second".into(), t(2));
        assert_eq!(item.password, "second");
        assert_eq!(item.password_history, [HistoryEntry { value: "first".into(), changed_at: t(2) }]);
        assert_eq!(item.updated_at, t(2));
    }

    #[test]
    fn history_edge_cases() {
        let mut item = Item::new(ItemKind::Login, "x", t(0));
        item.set_password("same".into(), t(1));
        item.set_password("same".into(), t(2));
        assert!(item.password_history.is_empty());
        assert_eq!(item.updated_at, t(1), "no-op change must not touch updated_at");
        for i in 0..30 {
            item.set_password(format!("p{i}"), t(10 + i));
        }
        assert_eq!(item.password_history.len(), HISTORY_LIMIT);
        assert_eq!(item.password_history.last().unwrap().value, "p28");
        assert_eq!(item.password_history.first().unwrap().value, "p9");
    }

    #[test]
    fn json_shape() {
        let item = Item::new(ItemKind::Note, "x", t(0));
        let json = serde_json::to_value(&item).unwrap();
        assert_eq!(json["kind"], "note");
        assert!(json.get("totp").is_none());
        let minimal = r#"{"kind":"login","title":"y","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}"#;
        let parsed: Item = serde_json::from_str(minimal).unwrap();
        assert_eq!(parsed.username, "");
        assert!(parsed.labels.is_empty() && parsed.deleted_at.is_none());
        assert_eq!(serde_json::to_value(LabelColor::Teal).unwrap(), "teal");
    }
}
