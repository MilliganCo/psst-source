//! Local SQLite cache: the same encrypted blobs the server keeps, plus sync bookkeeping.

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

pub struct CollectionRow {
    pub id: Uuid,
    pub kind: String,
    pub role: String,
    pub key_version: u32,
    pub sealed_ck: Vec<u8>,
    pub granted_by: [u8; 32],
    pub rev: i64,
    pub dirty: bool,
}

pub struct ItemRow {
    pub id: Uuid,
    pub collection_id: Uuid,
    pub key_version: u32,
    pub blob: Vec<u8>,
    /// Tombstone: purged for good, blob is empty.
    pub deleted: bool,
    pub rev: i64,
    pub dirty: bool,
    pub updated_at: String,
}

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: &Path) -> rusqlite::Result<Store> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS collections (
                 id TEXT PRIMARY KEY, kind TEXT NOT NULL, role TEXT NOT NULL, key_version INTEGER NOT NULL,
                 sealed_ck BLOB NOT NULL, granted_by BLOB NOT NULL, rev INTEGER NOT NULL DEFAULT 0,
                 dirty INTEGER NOT NULL DEFAULT 1);
             CREATE TABLE IF NOT EXISTS items (
                 id TEXT PRIMARY KEY, collection_id TEXT NOT NULL, key_version INTEGER NOT NULL,
                 blob BLOB NOT NULL, deleted INTEGER NOT NULL DEFAULT 0, rev INTEGER NOT NULL DEFAULT 0,
                 dirty INTEGER NOT NULL DEFAULT 1, updated_at TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS authors (id TEXT PRIMARY KEY, author TEXT NOT NULL);",
        )?;
        Ok(Store { conn })
    }

    pub fn get_kv(&self, key: &str) -> rusqlite::Result<Option<String>> {
        self.conn.query_row("SELECT value FROM kv WHERE key = ?1", [key], |r| r.get(0)).optional()
    }

    pub fn set_kv(&self, key: &str, value: &str) -> rusqlite::Result<()> {
        self.conn.execute("INSERT OR REPLACE INTO kv (key, value) VALUES (?1, ?2)", [key, value])?;
        Ok(())
    }

    pub fn del_kv(&self, key: &str) -> rusqlite::Result<()> {
        self.conn.execute("DELETE FROM kv WHERE key = ?1", [key])?;
        Ok(())
    }

    pub fn collections(&self) -> rusqlite::Result<Vec<CollectionRow>> {
        let mut st = self.conn.prepare(
            "SELECT id, kind, role, key_version, sealed_ck, granted_by, rev, dirty FROM collections",
        )?;
        let rows = st.query_map([], |r| {
            let granted: Vec<u8> = r.get(5)?;
            Ok(CollectionRow {
                id: parse_uuid(r.get::<_, String>(0)?)?,
                kind: r.get(1)?,
                role: r.get(2)?,
                key_version: r.get(3)?,
                sealed_ck: r.get(4)?,
                granted_by: granted.try_into().unwrap_or([0; 32]),
                rev: r.get(6)?,
                dirty: r.get(7)?,
            })
        })?;
        // A row that cannot be parsed is skipped instead of failing the whole vault.
        Ok(rows.filter_map(Result::ok).collect())
    }

    pub fn put_collection(&self, c: &CollectionRow) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO collections (id, kind, role, key_version, sealed_ck, granted_by, rev, dirty)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![c.id.to_string(), c.kind, c.role, c.key_version, c.sealed_ck, &c.granted_by[..], c.rev, c.dirty],
        )?;
        Ok(())
    }

    pub fn items(&self) -> rusqlite::Result<Vec<ItemRow>> {
        let mut st = self.conn.prepare(
            "SELECT id, collection_id, key_version, blob, deleted, rev, dirty, updated_at FROM items",
        )?;
        let rows = st.query_map([], |r| {
            Ok(ItemRow {
                id: parse_uuid(r.get::<_, String>(0)?)?,
                collection_id: parse_uuid(r.get::<_, String>(1)?)?,
                key_version: r.get(2)?,
                blob: r.get(3)?,
                deleted: r.get(4)?,
                rev: r.get(5)?,
                dirty: r.get(6)?,
                updated_at: r.get(7)?,
            })
        })?;
        // A row that cannot be parsed is skipped instead of failing the whole vault.
        Ok(rows.filter_map(Result::ok).collect())
    }

    /// Last writer of an item as the server reported it.
    pub fn set_author(&self, id: Uuid, author: &str) -> rusqlite::Result<()> {
        self.conn.execute("INSERT OR REPLACE INTO authors (id, author) VALUES (?1, ?2)", params![id.to_string(), author])?;
        Ok(())
    }

    pub fn authors(&self) -> rusqlite::Result<std::collections::HashMap<Uuid, String>> {
        let mut st = self.conn.prepare("SELECT id, author FROM authors")?;
        let rows = st.query_map([], |r| Ok((parse_uuid(r.get::<_, String>(0)?)?, r.get::<_, String>(1)?)))?;
        Ok(rows.filter_map(Result::ok).collect())
    }

    pub fn item_rev(&self, id: Uuid) -> rusqlite::Result<i64> {
        Ok(self
            .conn
            .query_row("SELECT rev FROM items WHERE id = ?1", [id.to_string()], |r| r.get(0))
            .optional()?
            .unwrap_or(0))
    }

    pub fn put_item(&self, i: &ItemRow) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO items (id, collection_id, key_version, blob, deleted, rev, dirty, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                i.id.to_string(),
                i.collection_id.to_string(),
                i.key_version,
                i.blob,
                i.deleted,
                i.rev,
                i.dirty,
                i.updated_at
            ],
        )?;
        Ok(())
    }
}

impl Store {
    pub fn item_row(&self, id: Uuid) -> rusqlite::Result<Option<ItemRow>> {
        self.conn
            .query_row(
                "SELECT id, collection_id, key_version, blob, deleted, rev, dirty, updated_at FROM items WHERE id = ?1",
                [id.to_string()],
                |r| {
                    Ok(ItemRow {
                        id: parse_uuid(r.get::<_, String>(0)?)?,
                        collection_id: parse_uuid(r.get::<_, String>(1)?)?,
                        key_version: r.get(2)?,
                        blob: r.get(3)?,
                        deleted: r.get(4)?,
                        rev: r.get(5)?,
                        dirty: r.get(6)?,
                        updated_at: r.get(7)?,
                    })
                },
            )
            .optional()
    }

    /// Server accepted our upload at `rev`. Stays dirty if the row changed while uploading.
    pub fn ack_item(&self, id: Uuid, rev: i64, sent_blob: &[u8]) -> rusqlite::Result<()> {
        self.conn.execute(
            "UPDATE items SET rev = ?1, dirty = CASE WHEN blob = ?2 THEN 0 ELSE dirty END WHERE id = ?3",
            params![rev, sent_blob, id.to_string()],
        )?;
        Ok(())
    }

    pub fn delete_item(&self, id: Uuid) -> rusqlite::Result<()> {
        self.conn.execute("DELETE FROM items WHERE id = ?1", [id.to_string()])?;
        Ok(())
    }

    pub fn collection_clean(&self, id: Uuid) -> rusqlite::Result<()> {
        self.conn.execute("UPDATE collections SET dirty = 0 WHERE id = ?1", [id.to_string()])?;
        Ok(())
    }

    /// Access lost: forget the folder and everything in it.
    pub fn delete_collection(&self, id: Uuid) -> rusqlite::Result<()> {
        self.conn.execute("DELETE FROM items WHERE collection_id = ?1", [id.to_string()])?;
        self.conn.execute("DELETE FROM collections WHERE id = ?1", [id.to_string()])?;
        Ok(())
    }
}

fn parse_uuid(s: String) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(&s).map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e)))
}
