export type LabelColor = 'red' | 'orange' | 'yellow' | 'green' | 'teal' | 'blue' | 'purple' | 'pink' | 'gray';
export const LABEL_COLORS: LabelColor[] = ['red', 'orange', 'yellow', 'green', 'teal', 'blue', 'purple', 'pink', 'gray'];

export interface Label {
  id: string;
  name: string;
  color: LabelColor;
}

export interface Collection {
  id: string;
  name: string;
  kind: string;
  role: string;
  labels: Label[];
  count: number;
}

export interface ItemSummary {
  id: string;
  collection_id: string;
  kind: 'login' | 'note';
  title: string;
  username: string;
  urls: string[];
  labels: string[];
  favorite: boolean;
  has_password: boolean;
  has_totp: boolean;
  deleted: boolean;
  created_at: string;
  updated_at: string;
  history_len: number;
  /** Password health, computed in Rust: guessable, shared with another item, unchanged for a year. */
  weak: boolean;
  reused: boolean;
  old: boolean;
  /** Found in known breaches by this session's check. */
  pwned: boolean;
}

export interface AttachmentView {
  id: string;
  name: string;
  size: number;
  added_at: string;
}

export interface ItemDetails extends ItemSummary {
  notes: string;
  history: string[];
  attachments: AttachmentView[];
}

/** `password`/`totp`: null keeps the stored value, "" clears it. */
export interface ItemInput {
  id: string | null;
  collection_id: string;
  kind: 'login' | 'note';
  title: string;
  username: string;
  password: string | null;
  urls: string[];
  notes: string;
  totp: string | null;
  labels: string[];
  favorite: boolean;
}

export interface Status {
  has_account: boolean;
  unlocked: boolean;
  username: string | null;
  corrupt: number;
}

export interface GeneratorOptions {
  length: number;
  upper: boolean;
  lower: boolean;
  digits: boolean;
  symbols: boolean;
  exclude_similar: boolean;
}

export interface ServerStatus {
  url: string;
  username: string;
  is_admin: boolean;
  last_sync: string | null;
  link: string;
  fingerprint: string;
}

export interface SessionInfo {
  id: string;
  device: string;
  /** Unix seconds. */
  created_at: number;
  last_seen: number;
  current: boolean;
}

export interface MessageView {
  id: string;
  author: string;
  text: string;
  at: string;
  mine: boolean;
}

export interface ChatSummary {
  collection_id: string;
  count: number;
  last_at: string;
  last_author: string;
  last_mine: boolean;
}

export interface PasswordCheck {
  /** zxcvbn 0..4; below 3 is weak. */
  score: number;
  crack_secs: number;
  reused_in: string[];
}

export interface UpdateInfo {
  version: string;
  notes: string;
  file: string;
}

export interface SyncReport {
  pushed: number;
  pulled: number;
  conflicts: number;
}

export interface MemberView {
  user_id: string;
  username: string;
  role: 'owner' | 'editor' | 'viewer';
  fingerprint: string;
  key_changed: boolean;
  me: boolean;
}

export interface AdminUser {
  id: string;
  username: string;
  is_admin: boolean;
  disabled: boolean;
}
