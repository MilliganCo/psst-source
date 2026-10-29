import { invoke } from '@tauri-apps/api/core';
import { createMock } from './mock';
import type {
  AdminUser,
  Collection,
  GeneratorOptions,
  ItemDetails,
  ItemInput,
  ItemSummary,
  Label,
  MemberView,
  ServerStatus,
  Status,
  SyncReport,
  UpdateInfo,
  PasswordCheck,
  MessageView,
  ChatSummary,
  SessionInfo,
} from './types';

type Call = <R>(cmd: string, args?: Record<string, unknown>) => Promise<R>;

/** Real backend inside Tauri; an in-memory mock in a plain browser (UI preview and tests). */
export const inTauri = typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
const call: Call = inTauri
  ? invoke
  : import.meta.env.DEV
    ? createMock()
    : () => Promise.reject('io: откройте приложение Passwords, а не страницу в браузере');

export const api = {
  status: () => call<Status>('status'),
  createLocal: (username: string, password: string) => call<string>('create_local', { username, password }),
  unlock: (password: string) => call<void>('unlock', { password }),
  lock: () => call<void>('lock'),
  changePassword: (old: string, next: string) => call<void>('change_password', { old, new: next }),
  collections: () => call<Collection[]>('collections'),
  list: () => call<ItemSummary[]>('list'),
  get: (id: string) => call<ItemDetails>('get', { id }),
  reveal: (id: string, field: string) => call<string>('reveal', { id, field }),
  copy: (id: string, field: string, clearAfter: number) => call<void>('copy', { id, field, clearAfter }),
  copyText: (text: string, clearAfter: number) => call<void>('copy_text', { text, clearAfter }),
  totp: (id: string) => call<{ code: string; left: number; period: number }>('totp', { id }),
  save: (input: ItemInput) => call<string>('save', { input }),
  delete: (id: string) => call<void>('delete', { id }),
  restore: (id: string) => call<void>('restore', { id }),
  purge: (id: string) => call<void>('purge', { id }),
  saveLabel: (collectionId: string, label: Label) => call<void>('save_label', { collectionId, label }),
  deleteLabel: (collectionId: string, labelId: string) => call<void>('delete_label', { collectionId, labelId }),
  importLegacy: (path: string, password: string, collectionId: string) =>
    call<number>('import_legacy', { path, password, collectionId }),
  importCsv: (path: string, collectionId: string) => call<number>('import_csv', { path, collectionId }),
  generate: (opts: GeneratorOptions) => call<string>('generate', { opts }),
  generatePassphrase: (words: number, separator: string) => call<string>('generate_passphrase', { words, separator }),
  legacyVaultPath: () => call<string | null>('legacy_vault_path'),
  serverStatus: () => call<ServerStatus | null>('server_status'),
  connect: (link: string, password: string, recoveryCode: string | null, username: string | null = null) =>
    call<void>('connect', { link, password, recoveryCode, username }),
  updateServerLink: (link: string) => call<void>('update_server_link', { link }),
  loginServer: (link: string, username: string, password: string) => call<void>('login_server', { link, username, password }),
  relogin: (password: string) => call<void>('relogin', { password }),
  syncNow: () => call<SyncReport>('sync_now'),
  createCollection: (name: string) => call<string>('create_collection', { name }),
  renameCollection: (id: string, name: string) => call<void>('rename_collection', { id, name }),
  members: (id: string) => call<MemberView[]>('members', { id }),
  addMember: (id: string, username: string, role: string) => call<void>('add_member', { id, username, role }),
  setMemberRole: (id: string, userId: string, role: string) => call<void>('set_member_role', { id, userId, role }),
  removeMember: (id: string, userId: string) => call<void>('remove_member', { id, userId }),
  leaveCollection: (id: string) => call<void>('leave_collection', { id }),
  adminInvite: (isAdmin: boolean) => call<string>('admin_invite', { isAdmin }),
  adminUsers: () => call<AdminUser[]>('admin_users'),
  adminDisable: (userId: string, disabled: boolean) => call<void>('admin_disable', { userId, disabled }),
  totpFromClipboard: () => call<string>('totp_from_clipboard'),
  hibpCheck: () => call<{ checked: number; pwned: number }>('hibp_check'),
  exportBackup: (path: string, password: string) => call<number>('export_backup', { path, password }),
  importBackup: (path: string, password: string, collectionId: string) => call<number>('import_backup', { path, password, collectionId }),
  exportCsv: (path: string) => call<number>('export_csv', { path }),
  attachFile: (itemId: string, path: string) => call<string>('attach_file', { itemId, path }),
  saveAttachment: (id: string, path: string) => call<void>('save_attachment', { id, path }),
  removeAttachment: (id: string) => call<void>('remove_attachment', { id }),
  sessions: () => call<SessionInfo[]>('sessions'),
  revokeSession: (id: string) => call<void>('revoke_session', { id }),
  revokeOtherSessions: () => call<void>('revoke_other_sessions'),
  postMessage: (collectionId: string, text: string) => call<string>('post_message', { collectionId, text }),
  messages: (collectionId: string) => call<MessageView[]>('messages', { collectionId }),
  chatSummary: () => call<ChatSummary[]>('chat_summary'),
  checkPassword: (id: string | null, password: string, title: string, username: string) =>
    call<PasswordCheck>('check_password', { id, password, title, username }),
  updateCheck: () => call<UpdateInfo | null>('update_check'),
  updateInstall: () => call<void>('update_install'),
};

const INVALID: Record<string, string> = {
  'title is required': 'Нужно название',
  'username and password are required': 'Нужны имя и пароль',
  'label name is required': 'Нужно имя ярлыка',
  'new password is empty': 'Новый пароль пустой',
  'password length must be 4..=128': 'Длина пароля — от 4 до 128',
  'select at least one character class': 'Выберите хотя бы один набор символов',
  'passphrase must have 3..=20 words': 'Фраза — от 3 до 20 слов',
  'not a legacy vault file': 'Это не файл хранилища старой версии',
  'legacy vault is truncated': 'Файл хранилища повреждён',
  'unsupported legacy vault version': 'Неизвестная версия файла хранилища',
  'legacy payload is truncated': 'Файл хранилища повреждён',
  'invite link is malformed': 'Ссылка не похожа на приглашение — скопируйте её целиком',
  'this link has no invite code': 'В ссылке нет кода приглашения. Попросите у администратора новую',
  'recovery code required': 'Нужен код восстановления этого хранилища',
  'no such user': 'На сервере нет такого пользователя',
  'folder name is required': 'Нужно название папки',
  'not connected to a server': 'Хранилище не подключено к серверу',
  'only the folder owner can manage members': 'Участниками управляет только владелец папки',
  'folder metadata is unreadable': 'Данные папки не удалось расшифровать — изменять её нельзя',
  'TOTP secret is not base32': '2FA-секрет должен быть в base32 (буквы A–Z и цифры 2–7) или ссылкой otpauth://',
  'TOTP link has no secret': 'В ссылке otpauth:// нет секрета',
  'only TOTP links are supported': 'Поддерживаются только ссылки otpauth://totp/…',
  'unsupported TOTP algorithm': 'Неизвестный алгоритм 2FA',
  'invalid TOTP parameters': 'Неверные параметры 2FA (цифр должно быть 6–8)',
  'not a password export': 'Это не похоже на экспорт паролей: нет колонки с паролем',
  'broken CSV file': 'CSV-файл повреждён',
  'file is not UTF-8': 'Файл не в UTF-8. Пересохраните его в кодировке UTF-8',
  'server certificate differs': 'У этой ссылки другой сертификат — это другой сервер. Адрес не изменён',
  'no update available': 'Обновлений нет',
  'message is empty': 'Пустое сообщение',
  'file is larger than 8 MB': 'Файл больше 8 МБ — такие не прикрепляются',
  'files attach to entries only': 'Файл прикрепляется к записи',
  'no image in the clipboard': 'В буфере нет картинки. Сделайте скриншот QR-кода (Win+Shift+S или PrtSc) и нажмите снова',
  'no QR code in the clipboard image': 'На картинке не нашлось QR-кода. Захватите его целиком, с белой рамкой',
  'backup password must be at least 8 characters': 'Пароль копии — минимум 8 символов',
  'wrong backup password or damaged file': 'Неверный пароль копии или файл повреждён',
  'not a Passwords backup': 'Это не резервная копия Passwords',
  'message is too long': 'Сообщение слишком длинное — до 4000 символов',
};

const SERVER: Record<string, string> = {
  'invite is invalid or used': 'Приглашение недействительно или уже использовано',
  'username taken': 'Это имя на сервере уже занято',
  too_many_attempts: 'Слишком много попыток. Подождите 15 минут',
  'only the folder owner can do this': 'Это может только владелец папки',
  'no write access to this folder': 'В этой папке у вас только чтение',
  'folder changed, sync and retry': 'Папка изменилась — синхронизируйте и повторите',
  'invalid username': 'Недопустимое имя',
  'admin only': 'Только для администратора',
  'not a member': 'Вы больше не участник этой папки',
  key_rotated: 'Ключ папки только что сменился — синхронизируйте и повторите',
  'key version must increase by one': 'Ключ папки только что сменился — синхронизируйте и повторите',
  'personal folders cannot be shared': 'Личной папкой поделиться нельзя — создайте общую',
  'account key mismatch': 'Сервер вернул чужой аккаунт — вход отклонён',
  'the owner cannot leave their folder': 'Владелец не может покинуть свою папку',
};

/** Backend error codes → messages for people. */
export function errorText(e: unknown): string {
  const s = String(e);
  if (s === 'wrong_password') return 'Неверный пароль';
  if (s === 'locked') return 'Хранилище заблокировано';
  if (s === 'not_found') return 'Запись не найдена';
  if (s === 'exists') return 'Хранилище уже создано';
  if (s === 'read_only') return 'В этой папке у вас только чтение';
  if (s.startsWith('throttled: ')) return `Слишком много неверных попыток. Подождите ${s.slice(11)} с`;
  if (s.includes('413')) return 'Сервер не принял такой большой файл. Обновите сервер до последней версии';
  if (s.startsWith('invalid: update rejected')) return 'Обновление отклонено: подпись не сходится. Установщик не запущен — сообщите администратору';
  if (s.startsWith('invalid: ')) return INVALID[s.slice(9)] ?? s.slice(9);
  if (s === 'session_expired') return 'Сессия на сервере истекла — войдите снова';
  if (s.startsWith('offline: '))
    return s.includes('fingerprint')
      ? 'Сертификат сервера не совпадает с приглашением — подключение отклонено'
      : 'Нет связи с сервером';
  if (s.startsWith('server: ')) return SERVER[s.slice(8)] ?? `Сервер: ${s.slice(8)}`;
  if (s.startsWith('key_changed: '))
    return `Ключ пользователя ${s.slice(13)} изменился. Сверьте отпечаток лично, прежде чем давать доступ`;
  if (s.includes('invalid KDF parameters')) return 'Сервер прислал ослабленные параметры защиты пароля — вход отклонён';
  return s.replace(/^io: /, 'Ошибка: ');
}
