import { invoke } from '@tauri-apps/api/core';
import { getCurrentWebview } from '@tauri-apps/api/webview';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { api, errorText, inTauri } from './api';
import { parseSettings, type Settings } from './settings';
import type { MenuItem } from './menus';
import { toNotify } from './chat';
import { isPermissionGranted, requestPermission, sendNotification } from '@tauri-apps/plugin-notification';
import type { ChatSummary, Collection, ItemDetails, ItemInput, ItemSummary, Label, ServerStatus, Status, UpdateInfo } from './types';

function loadSeen(): Record<string, string> {
  try {
    return JSON.parse(localStorage.getItem('chatSeen') ?? '{}');
  } catch {
    return {};
  }
}

export const THEMES = [
  { id: 'phosphor', name: 'Phosphor' },
  { id: 'amber', name: 'Amber' },
  { id: 'nord', name: 'Nord' },
  { id: 'dracula', name: 'Dracula' },
  { id: 'gruvbox', name: 'Gruvbox' },
  { id: 'catppuccin', name: 'Catppuccin' },
  { id: 'tokyo', name: 'Tokyo Night' },
  { id: 'paper', name: 'Paper' },
] as const;

function loadSettings(): Settings {
  let saved: string | null = null;
  try {
    saved = localStorage.getItem('settings');
  } catch {
    /* storage unavailable */
  }
  return parseSettings(saved, matchMedia('(prefers-reduced-motion: reduce)').matches);
}

export type Modal =
  | { kind: 'editor'; id: string | null }
  | { kind: 'labels' }
  | { kind: 'settings' }
  | { kind: 'import' }
  | { kind: 'share'; id: string }
  | { kind: 'folder' }
  | { kind: 'relogin' }
  | null;

class AppState {
  status = $state<Status | null>(null);
  collections = $state<Collection[]>([]);
  items = $state<ItemSummary[]>([]);
  /** Collection tab: an id or 'all'. */
  tab = $state('all');
  query = $state('');
  selectedId = $state<string | null>(null);
  modal = $state<Modal>(null);
  toasts = $state<{ id: number; text: string; err: boolean }[]>([]);
  settings = $state<Settings>(loadSettings());
  server = $state<ServerStatus | null>(null);
  sync = $state<'idle' | 'syncing' | 'offline' | 'expired'>('idle');
  private syncTimer: ReturnType<typeof setTimeout> | undefined;
  /** A newer signed release published on the server. */
  update = $state<UpdateInfo | null>(null);
  /** Folder whose chat is open in the right pane. */
  chat = $state<string | null>(null);
  chats = $state<ChatSummary[]>([]);
  private chatsLoaded = false;
  /** Per folder: time of the newest message seen (per device). */
  chatSeen = $state<Record<string, string>>(loadSeen());
  unread = $derived(new Set(this.chats.filter((c) => c.last_at > (this.chatSeen[c.collection_id] ?? '')).map((c) => c.collection_id)));
  /** The breach check ran since unlock (its results are kept in Rust until lock). */
  breachChecked = $state(false);
  /** Open right-click menu. */
  menu = $state<{ x: number; y: number; items: MenuItem[] } | null>(null);
  private updateCheckedAt = 0;

  labels = $derived(new Map<string, Label>(this.collections.flatMap((c) => c.labels.map((l) => [l.id, l] as const))));
  cols = $derived(new Map(this.collections.map((c) => [c.id, c] as const)));
  /** Collection new items go to: the open tab, else the personal one. */
  targetCol = $derived(
    this.collections.find((c) => c.id === this.tab && c.role !== 'viewer') ??
      this.collections.find((c) => c.kind === 'personal') ??
      this.collections[0],
  );

  applySettings() {
    const s = this.settings;
    try {
      localStorage.setItem('settings', JSON.stringify(s));
    } catch {
      /* not saved, still applied */
    }
    const root = document.documentElement;
    root.dataset.theme = s.theme;
    root.dataset.density = s.density;
    for (const fx of ['glow', 'vhs', 'pixels', 'blink'] as const) root.classList.toggle(`fx-${fx}`, s[fx]);
    if (inTauri) {
      getCurrentWebview().setZoom(s.scale / 100).catch(() => {});
      getCurrentWindow().setContentProtected(s.screenProtect).catch(() => {});
      invoke('set_close_to_tray', { on: s.closeToTray }).catch(() => {});
    } else {
      root.style.zoom = String(s.scale / 100);
    }
  }

  async refreshStatus() {
    this.status = await api.status();
    if (this.status.unlocked) {
      await this.refresh(true);
      this.server = await api.serverStatus();
      if (this.server) this.syncNow();
    }
    if (this.status.corrupt) this.toast(`Не удалось расшифровать записей: ${this.status.corrupt}. Они скрыты.`, true);
  }

  /** Reloads lists; after a local change (not from sync) schedules an upload in 2 s. */
  async refresh(fromSync = false) {
    if (!fromSync) this.scheduleSync();
    const [collections, items, chats] = await Promise.all([api.collections(), api.list(), api.chatSummary()]);
    const fresh = toNotify(this.chatsLoaded ? this.chats : null, chats, this.chatSeen, this.chat, document.hasFocus());
    this.collections = collections;
    this.items = items;
    this.chats = chats;
    this.chatsLoaded = true;
    if (fresh.length && this.settings.chatNotify) this.notify(fresh);
    if (this.chat && !collections.some((c) => c.id === this.chat)) this.chat = null;
    if (this.tab !== 'all' && !collections.some((c) => c.id === this.tab)) this.tab = 'all';
  }

  scheduleSync(ms = 2000) {
    if (!this.server || !this.status?.unlocked) return;
    clearTimeout(this.syncTimer);
    this.syncTimer = setTimeout(() => this.syncNow(), ms);
  }

  async syncNow(loud = false) {
    if (!this.server || this.sync === 'syncing' || this.sync === 'expired') return;
    this.sync = 'syncing';
    try {
      const r = await api.syncNow();
      if (!this.status?.unlocked) return;
      this.sync = 'idle';
      this.server = await api.serverStatus();
      await this.refresh(true);
      if (r.conflicts) this.toast(`Правки с двух устройств объединены (${r.conflicts}). Ничего не потеряно.`);
      else if (loud) this.toast('Синхронизировано');
      if (Date.now() - this.updateCheckedAt > 6 * 3600_000) this.checkUpdate();
    } catch (e) {
      if (!this.status?.unlocked) return;
      const code = String(e);
      this.sync = code === 'session_expired' ? 'expired' : code.startsWith('offline') ? 'offline' : 'idle';
      if (this.sync === 'expired') this.modal = { kind: 'relogin' };
      // A different certificate may mean someone is impersonating the server: always say so.
      else if (loud || this.sync === 'idle' || code.includes('fingerprint')) this.toast(errorText(e), true);
    }
    // An open chat polls fast; otherwise once a minute.
    this.scheduleSync(this.chat ? 4000 : 60_000);
  }

  /** Folder and author only: a notification can show up on a locked screen. */
  private async notify(list: ChatSummary[]) {
    if (!inTauri) return;
    try {
      if (!(await isPermissionGranted()) && (await requestPermission()) !== 'granted') return;
      for (const c of list) {
        const folder = this.cols.get(c.collection_id)?.name ?? 'папка';
        sendNotification({ title: `Passwords · ${folder}`, body: `Новое сообщение от ${c.last_author}` });
      }
    } catch {
      /* notifications unavailable */
    }
  }

  markChatSeen(collectionId: string, at: string | undefined) {
    if (!at || (this.chatSeen[collectionId] ?? '') >= at) return;
    this.chatSeen = { ...this.chatSeen, [collectionId]: at };
    try {
      localStorage.setItem('chatSeen', JSON.stringify(this.chatSeen));
    } catch {
      /* per-session only */
    }
  }

  openChat(collectionId: string) {
    this.chat = collectionId;
    this.scheduleSync(300);
  }

  async checkUpdate(loud = false) {
    this.updateCheckedAt = Date.now();
    try {
      this.update = await api.updateCheck();
      if (loud && !this.update) this.toast(`Установлена последняя версия ${__APP_VERSION__}`);
    } catch (e) {
      if (loud) this.toast(errorText(e), true);
    }
  }

  async installUpdate() {
    const u = this.update;
    if (!u || !confirm(`Установить Passwords ${u.version}?

${u.notes}

Приложение закроется и откроется снова.`)) return;
    this.toast('Загружаю обновление…');
    await this.run(() => api.updateInstall());
  }

  async lock() {
    clearTimeout(this.syncTimer);
    this.server = null;
    this.sync = 'idle';
    await api.lock();
    this.items = [];
    this.collections = [];
    this.selectedId = null;
    this.modal = null;
    this.chat = null;
    this.chats = [];
    this.chatsLoaded = false;
    this.breachChecked = false;
    await this.refreshStatus();
  }

  toast(text: string, err = false) {
    const id = Date.now() + Math.random();
    this.toasts.push({ id, text, err });
    setTimeout(() => (this.toasts = this.toasts.filter((t) => t.id !== id)), err ? 5000 : 2200);
  }

  /** Runs an action, turning backend errors into a toast. */
  async run<T>(action: () => Promise<T>, ok?: string): Promise<T | undefined> {
    try {
      const r = await action();
      if (ok) this.toast(ok);
      return r;
    } catch (e) {
      this.toast(errorText(e), true);
      return undefined;
    }
  }

  openMenu(e: MouseEvent | { clientX: number; clientY: number }, items: MenuItem[]) {
    if (e instanceof MouseEvent) {
      e.preventDefault();
      e.stopPropagation();
    }
    if (items.length) this.menu = { x: e.clientX, y: e.clientY, items };
  }

  /** Saves an item with a few fields changed; secrets stay as stored. */
  async patchItem(id: string, change: (d: ItemDetails) => Partial<ItemInput>, ok: string) {
    const d = await this.run(() => api.get(id));
    if (!d) return;
    const input: ItemInput = {
      id, collection_id: d.collection_id, kind: d.kind, title: d.title, username: d.username, password: null,
      urls: d.urls, notes: d.notes, totp: null, labels: d.labels, favorite: d.favorite, ...change(d),
    };
    if ((await this.run(() => api.save(input), ok)) !== undefined) await this.refresh();
  }

  async checkBreaches() {
    if (
      !confirm(
        'Проверить пароли по базе утечек Have I Been Pwned?\n\nНаружу уйдут только первые 5 символов SHA-1 хеша каждого пароля — по ним нельзя восстановить пароль. Сами пароли остаются на этом компьютере.',
      )
    )
      return;
    this.toast('Проверяю пароли по базе утечек…');
    const r = await this.run(() => api.hibpCheck());
    if (!r) return;
    this.breachChecked = true;
    await this.refresh(true);
    this.toast(r.pwned ? `Найдено в утечках: ${r.pwned} из ${r.checked}. Смените эти пароли.` : `Проверено ${r.checked}: в утечках не найдено`, r.pwned > 0);
    if (r.pwned) this.query = 'is:pwned';
  }

  async itemAction(id: string, title: string, action: 'delete' | 'restore' | 'purge') {
    if (action === 'purge' && !confirm(`Удалить «${title}» навсегда? Это нельзя отменить.`)) return;
    const msg = { delete: 'Перемещено в корзину', restore: 'Восстановлено', purge: 'Удалено навсегда' }[action];
    await this.run(() => api[action](id), msg);
    await this.refresh();
  }

  async copy(id: string, field: 'password' | 'username' | 'totp', what: string) {
    await this.run(() => api.copy(id, field, this.settings.clipboardSec), `${what} скопирован — очистится через ${this.settings.clipboardSec} с`);
  }
}

export const app = new AppState();
