// In-memory backend for running the UI in a plain browser. Mirrors the Tauri commands loosely.
import type { Collection, ItemInput, ItemSummary, Label } from './types';

interface MockItem extends ItemSummary {
  notes: string;
  password: string;
  totp: string | null;
  history: { value: string; at: string }[];
}

export function createMock() {
  const now = new Date().toISOString();
  let unlocked = false;
  let server: { url: string; username: string; is_admin: boolean; last_sync: string | null; link: string; fingerprint: string } | null = null;
  let hasAccount = true;
  const labels: Label[] = [
    { id: 'l-work', name: 'работа', color: 'blue' },
    { id: 'l-bank', name: 'банк', color: 'green' },
    { id: 'l-2fa', name: 'сервер', color: 'orange' },
  ];
  const cols: Collection[] = [
    { id: 'c-me', name: 'Личное', kind: 'personal', role: 'owner', labels, count: 0 },
    { id: 'c-fam', name: 'Семья', kind: 'shared', role: 'editor', labels: [{ id: 'l-tv', name: 'кино', color: 'pink' }], count: 0 },
  ];
  const mk = (title: string, over: Partial<MockItem>): MockItem => ({
    id: crypto.randomUUID(), collection_id: 'c-me', kind: 'login', title, username: '', urls: [], labels: [],
    favorite: false, has_password: true, has_totp: false, deleted: false, created_at: now, updated_at: now,
    history_len: 0, weak: false, reused: false, old: false, pwned: false, notes: '', password: 'Hunter2-' + title.length, totp: null, history: [], ...over,
  });
  const items: MockItem[] = [
    mk('GitHub', { username: 'cody@example.com', urls: ['https://github.com'], labels: ['l-work'], favorite: true }),
    mk('GitLab', { username: 'cody', urls: ['https://gitlab.com'], labels: ['l-work'] }),
    mk('Gitea home', { username: 'admin', urls: ['https://git.home.lan'], labels: ['l-2fa'], has_totp: true, totp: 'JBSWY3DPEHPK3PXP' }),
    mk('Сбербанк', { username: '+7 900 000-00-00', labels: ['l-bank'], notes: 'кодовое слово: тюльпан' }),
    mk('Wi-Fi дома', { kind: 'note', has_password: false, password: '', notes: 'SSID: home-5G\nпароль на роутере' }),
    mk('Netflix', { collection_id: 'c-fam', username: 'family@example.com', labels: ['l-tv'] }),
    mk('Старый форум', { deleted: true }),
  ];
  const ago = (min: number) => new Date(Date.now() - min * 60_000).toISOString();
  const chat = [
    { id: 'm1', collection_id: 'c-fam', author: 'мама', text: 'Пароль от Netflix поменяла \u{f0238}', at: ago(90), mine: false },
    { id: 'm2', collection_id: 'c-fam', author: 'cody', text: 'Спасибо! \u{f0514}', at: ago(85), mine: true },
    { id: 'm3', collection_id: 'c-fam', author: 'папа', text: 'А от Wi-Fi на даче какой?', at: ago(3), mine: false },
  ];
  const summary = ({ notes: _n, password: p, totp: _t, history: _h, ...s }: MockItem): ItemSummary => {
    const live = !s.deleted && !!p;
    const reused = items.some((o) => o.id !== s.id && !o.deleted && o.password === p);
    return { ...s, weak: live && p.length < 12, reused: live && reused, old: false, pwned: false };
  };
  const find = (id: unknown) => {
    const it = items.find((i) => i.id === id);
    if (!it) throw 'not_found';
    return it;
  };
  const counted = () =>
    cols.map((c) => ({ ...c, count: items.filter((i) => i.collection_id === c.id && !i.deleted).length }));

  const handlers: Record<string, (a: any) => unknown> = {
    update_check: () => null,
    attach_file: () => crypto.randomUUID(),
    save_attachment: () => undefined,
    remove_attachment: () => undefined,
    sessions: () => [
      { id: 'a1', device: 'Windows · DESKTOP-CODY', created_at: Date.now() / 1000 - 86400 * 3, last_seen: Date.now() / 1000, current: true },
      { id: 'b2', device: 'Linux · ubuntu-laptop', created_at: Date.now() / 1000 - 86400 * 9, last_seen: Date.now() / 1000 - 7200, current: false },
    ],
    revoke_session: () => undefined,
    revoke_other_sessions: () => undefined,
    totp_from_clipboard: () => 'otpauth://totp/Demo:cody?secret=JBSWY3DPEHPK3PXP&issuer=Demo',
    hibp_check: () => ({ checked: items.filter((i) => i.password && !i.deleted).length, pwned: 0 }),
    post_message: (a) => {
      const id = crypto.randomUUID();
      chat.push({ id, collection_id: a.collectionId, author: 'cody', text: a.text.trim(), at: new Date().toISOString(), mine: true });
      return id;
    },
    messages: (a) => chat.filter((m) => m.collection_id === a.collectionId),
    chat_summary: () =>
      [...new Set(chat.map((m) => m.collection_id))].map((c) => {
        const ms = chat.filter((m) => m.collection_id === c);
        const last = ms[ms.length - 1];
        return { collection_id: c, count: ms.length, last_at: last.at, last_author: last.author, last_mine: last.mine };
      }),
    check_password: (a) => ({
      score: Math.min(4, Math.floor(a.password.length / 4)),
      crack_secs: 10 ** a.password.length,
      reused_in: items.filter((i) => i.id !== a.id && !i.deleted && i.password === a.password).map((i) => i.title),
    }),
    status: () => ({ has_account: hasAccount, unlocked, username: 'cody', corrupt: 0 }),
    create_local: () => ((hasAccount = true), (unlocked = true), 'ABCD-EFGH-IJKL-MNOP-QRST-UVWX'),
    unlock: (a) => {
      if (a.password !== 'demo') throw 'wrong_password';
      unlocked = true;
    },
    lock: () => void (unlocked = false),
    change_password: () => undefined,
    collections: () => counted(),
    list: () => items.map(summary),
    get: (a) => {
      const it = find(a.id);
      const attachments = it.title === 'Gitea home' ? [{ id: 'f1', name: 'id_ed25519', size: 411, added_at: now }] : [];
      return { ...summary(it), notes: it.notes, history: it.history.map((h) => h.at), attachments };
    },
    reveal: (a) => {
      const it = find(a.id);
      if (a.field === 'password') return it.password;
      if (a.field === 'totp') return it.totp ?? '';
      return it.history[Number(String(a.field).split(':')[1])]?.value ?? '';
    },
    copy: () => undefined,
    copy_text: () => undefined,
    totp: () => ({ code: String(Math.floor(Math.random() * 1e6)).padStart(6, '0'), left: 30 - (Math.floor(Date.now() / 1000) % 30), period: 30 }),
    update_server_link: () => undefined,
    save: ({ input }: { input: ItemInput }) => {
      if (!input.title.trim()) throw 'invalid: title is required';
      const it = input.id ? find(input.id) : mk(input.title, { password: '' });
      if (!input.id) items.push(it);
      if (input.password !== null && input.password !== it.password) {
        if (it.password) it.history.push({ value: it.password, at: new Date().toISOString() });
        it.password = input.password;
      }
      if (input.totp !== null) it.totp = input.totp.trim() || null;
      Object.assign(it, {
        collection_id: input.collection_id, kind: input.kind, title: input.title.trim(), username: input.username,
        urls: input.urls.filter(Boolean), notes: input.notes, labels: input.labels, favorite: input.favorite,
        has_password: !!it.password, has_totp: !!it.totp, history_len: it.history.length,
        updated_at: new Date().toISOString(),
      });
      return it.id;
    },
    delete: (a) => void (find(a.id).deleted = true),
    restore: (a) => void (find(a.id).deleted = false),
    purge: (a) => void items.splice(items.indexOf(find(a.id)), 1),
    save_label: (a) => {
      const col = cols.find((c) => c.id === a.collectionId)!;
      const i = col.labels.findIndex((l) => l.id === a.label.id);
      if (i >= 0) col.labels[i] = a.label;
      else col.labels.push(a.label);
    },
    delete_label: (a) => {
      const col = cols.find((c) => c.id === a.collectionId)!;
      col.labels = col.labels.filter((l) => l.id !== a.labelId);
      items.forEach((i) => (i.labels = i.labels.filter((l) => l !== a.labelId)));
    },
    import_legacy: () => 0,
    import_csv: () => 3,
    generate: (a) => {
      const set = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*';
      return Array.from({ length: a.opts.length }, () => set[Math.floor(Math.random() * set.length)]).join('');
    },
    generate_passphrase: (a) =>
      Array.from({ length: a.words }, () => ['кот', 'дом', 'река', 'gamma', 'delta', 'orbit'][Math.floor(Math.random() * 6)]).join(a.separator),
    legacy_vault_path: () => null,
    server_status: () => server,
    connect: (a) => {
      if (!String(a.link).startsWith('pwd://')) throw 'invalid: invite link is malformed';
      server = { url: 'https://home.lan:8443', username: 'cody', is_admin: true, last_sync: new Date().toISOString(), link: 'pwd://home.lan:8443?fp=DEMO', fingerprint: 'ABCDE-FGHIJ-KLMNO-PQRST-UVWXY' };
    },
    login_server: () => undefined,
    relogin: () => undefined,
    sync_now: () => {
      if (server) server.last_sync = new Date().toISOString();
      return { pushed: 0, pulled: 0, conflicts: 0 };
    },
    create_collection: (a) => {
      const id = crypto.randomUUID();
      cols.push({ id, name: a.name, kind: 'shared', role: 'owner', labels: [], count: 0 });
      return id;
    },
    rename_collection: (a) => void (cols.find((c) => c.id === a.id)!.name = a.name),
    members: () => [
      { user_id: 'u1', username: 'cody', role: 'owner', fingerprint: 'ABCDE-FGHIJ-KLMNO-PQRST-UVWXY', key_changed: false, me: true },
      { user_id: 'u2', username: 'anna', role: 'editor', fingerprint: 'QWERT-YUIOP-ASDFG-HJKLZ-XCVBN', key_changed: false, me: false },
    ],
    add_member: () => undefined,
    set_member_role: () => undefined,
    remove_member: () => undefined,
    leave_collection: () => undefined,
    admin_invite: () => 'pwd://home.lan:8443/invite/k3xq7mz2demo?fp=DEMO',
    admin_users: () => [
      { id: 'u1', username: 'cody', is_admin: true, disabled: false },
      { id: 'u2', username: 'anna', is_admin: false, disabled: false },
    ],
    admin_disable: () => undefined,
  };

  return async <R,>(cmd: string, args: Record<string, unknown> = {}): Promise<R> => {
    await new Promise((r) => setTimeout(r, 40));
    const h = handlers[cmd];
    if (!h) throw `io: mock has no ${cmd}`;
    return h(args) as R;
  };
}
