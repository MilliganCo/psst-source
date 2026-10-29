import { describe, expect, it } from 'vitest';
import { rowMenu, type MenuItem, type RowActions } from './menus';
import type { Collection, ItemSummary } from './types';

const item = (over: Partial<ItemSummary> = {}): ItemSummary => ({
  id: 'i1', collection_id: 'c1', kind: 'login', title: 'GitHub', username: 'cody', urls: ['https://github.com'], labels: [],
  favorite: false, has_password: true, has_totp: true, deleted: false, created_at: '', updated_at: '', history_len: 0,
  weak: false, reused: false, old: false, pwned: false, ...over,
});
const col = (id: string, name: string, role = 'owner'): Collection => ({ id, name, kind: 'shared', role, labels: [], count: 0 });
const cols = [col('c1', 'Личное'), col('c2', 'Семья'), col('c3', 'Чужая', 'viewer')];
const noop = () => {};
const actions: RowActions = { copy: noop, edit: noop, favorite: noop, move: noop, trash: noop, restore: noop, purge: noop };
const labels = (m: MenuItem[]) => m.map((x) => (x === 'sep' ? '—' : x.label));

describe('rowMenu', () => {
  it('offers copying, editing, moving and the trash for a normal login', () => {
    const m = rowMenu(item(), cols, actions);
    expect(labels(m)).toEqual([
      'Копировать пароль', 'Копировать логин', 'Копировать код 2FA', 'Копировать адрес', '—',
      'Изменить', 'В избранное', 'Переместить в папку', '—', 'В корзину',
    ]);
    const move = m.find((x) => x !== 'sep' && x.label === 'Переместить в папку') as Exclude<MenuItem, 'sep'>;
    expect(labels(move.sub!)).toEqual(['Семья']); // not the current folder, not read-only ones
  });

  it('skips what the item does not have', () => {
    const m = labels(rowMenu(item({ has_totp: false, urls: [], username: '', favorite: true }), cols, actions));
    expect(m).not.toContain('Копировать код 2FA');
    expect(m).not.toContain('Копировать адрес');
    expect(m).not.toContain('Копировать логин');
    expect(m).toContain('Убрать из избранного');
  });

  it('only restores or purges an item in the trash', () => {
    expect(labels(rowMenu(item({ deleted: true }), cols, actions))).toEqual(['Восстановить', 'Удалить навсегда']);
  });

  it('only copies in a read-only folder', () => {
    expect(labels(rowMenu(item({ collection_id: 'c3' }), cols, actions))).toEqual([
      'Копировать пароль', 'Копировать логин', 'Копировать код 2FA', 'Копировать адрес',
    ]);
  });

  it('runs the matching action', () => {
    const calls: string[] = [];
    const spy: RowActions = { ...actions, copy: (f) => calls.push(`copy:${f}`), move: (c) => calls.push(`move:${c}`) };
    const m = rowMenu(item(), cols, spy).filter((x) => x !== 'sep') as Exclude<MenuItem, 'sep'>[];
    m[0].run!();
    m.find((x) => x.sub)!.sub!.forEach((x) => x !== 'sep' && x.run!());
    expect(calls).toEqual(['copy:password', 'move:c2']);
  });
});
