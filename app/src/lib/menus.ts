// Right-click menus: what each thing offers. Pure, so it is testable; the UI wires the actions.
import type { Collection, ItemSummary } from './types';

export type MenuItem = { label: string; keys?: string; danger?: boolean; run?: () => void; sub?: MenuItem[] } | 'sep';

export interface RowActions {
  copy: (field: 'password' | 'username' | 'totp' | 'url') => void;
  edit: () => void;
  favorite: () => void;
  move: (collectionId: string) => void;
  trash: () => void;
  restore: () => void;
  purge: () => void;
}

export function rowMenu(it: ItemSummary, cols: Collection[], a: RowActions): MenuItem[] {
  if (it.deleted) {
    return [
      { label: 'Восстановить', run: a.restore },
      { label: 'Удалить навсегда', danger: true, run: a.purge },
    ];
  }
  const copy: MenuItem[] = [];
  if (it.has_password) copy.push({ label: 'Копировать пароль', keys: 'Ctrl+C', run: () => a.copy('password') });
  if (it.username) copy.push({ label: 'Копировать логин', keys: 'Ctrl+B', run: () => a.copy('username') });
  if (it.has_totp) copy.push({ label: 'Копировать код 2FA', keys: 'Ctrl+T', run: () => a.copy('totp') });
  if (it.urls.length) copy.push({ label: 'Копировать адрес', run: () => a.copy('url') });
  if (cols.find((c) => c.id === it.collection_id)?.role === 'viewer') return copy;

  const targets = cols.filter((c) => c.id !== it.collection_id && c.role !== 'viewer');
  return [
    ...copy,
    ...(copy.length ? (['sep'] as MenuItem[]) : []),
    { label: 'Изменить', keys: 'Ctrl+E', run: a.edit },
    { label: it.favorite ? 'Убрать из избранного' : 'В избранное', run: a.favorite },
    ...(targets.length ? [{ label: 'Переместить в папку', sub: targets.map((c) => ({ label: c.name, run: () => a.move(c.id) })) }] : []),
    'sep',
    { label: 'В корзину', danger: true, run: a.trash },
  ];
}
