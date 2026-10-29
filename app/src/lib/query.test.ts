import { describe, expect, it } from 'vitest';
import { filterItems, fuzzyScore, parseQuery, toggleToken } from './query';
import type { Collection, ItemSummary, Label } from './types';

const work: Label = { id: 'l1', name: 'Работа', color: 'blue' };
const bank: Label = { id: 'l2', name: 'банк', color: 'green' };
const two: Label = { id: 'l3', name: 'два слова', color: 'pink' };
const personal: Collection = { id: 'c1', name: 'Личное', kind: 'personal', role: 'owner', labels: [work, bank, two], count: 3 };
const family: Collection = { id: 'c2', name: 'Семья', kind: 'shared', role: 'editor', labels: [], count: 1 };

function item(id: string, over: Partial<ItemSummary>): ItemSummary {
  return {
    id, collection_id: 'c1', kind: 'login', title: id, username: '', urls: [], labels: [], favorite: false,
    has_password: true, has_totp: false, deleted: false, created_at: '', updated_at: '', history_len: 0,
    weak: false, reused: false, old: false, pwned: false, ...over,
  };
}

const items = [
  item('GitHub', { username: 'cody', labels: ['l1'], favorite: true, urls: ['https://github.com'] }),
  item('Сбербанк', { labels: ['l2', 'l3'], has_totp: true, weak: true, reused: true }),
  item('Netflix', { collection_id: 'c2', reused: true, old: true, pwned: true }),
  item('Old', { deleted: true, labels: ['l1'] }),
];
const ctx = {
  labels: new Map([work, bank, two].map((l) => [l.id, l])),
  cols: new Map([personal, family].map((c) => [c.id, c])),
};
const titles = (q: string) => filterItems(items, parseQuery(q), ctx).map((i) => i.title);

describe('parseQuery', () => {
  it('splits text, labels, collections, flags and negations', () => {
    const q = parseQuery('git #работа -#банк in:Семья is:fav -is:trash');
    expect(q.text).toEqual(['git']);
    expect(q.labels).toEqual([{ value: 'работа', neg: false }, { value: 'банк', neg: true }]);
    expect(q.cols).toEqual([{ value: 'семья', neg: false }]);
    expect(q.flags).toEqual([{ value: 'fav', neg: false }, { value: 'trash', neg: true }]);
    expect(q.command).toBeNull();
  });

  it('keeps quoted label names together', () => {
    expect(parseQuery('#"два слова" foo').labels).toEqual([{ value: 'два слова', neg: false }]);
  });

  it('treats a leading > as a command', () => {
    expect(parseQuery('> theme nord').command).toBe('theme nord');
    expect(parseQuery('>').command).toBe('');
  });
});

describe('toggleToken', () => {
  it('adds a missing token and removes a present one', () => {
    expect(toggleToken('git', '#банк')).toBe('git #банк');
    expect(toggleToken('git #банк is:fav', '#банк')).toBe('git is:fav');
    expect(toggleToken('', '#"два слова"')).toBe('#"два слова"');
  });
});

describe('fuzzyScore', () => {
  it('matches subsequences and prefers substrings', () => {
    expect(fuzzyScore('gthb', 'GitHub')).toBeGreaterThan(0);
    expect(fuzzyScore('xyz', 'GitHub')).toBe(-1);
    expect(fuzzyScore('hub', 'GitHub')).toBeGreaterThan(fuzzyScore('gtb', 'GitHub'));
  });
});

describe('filterItems', () => {
  it('hides trash unless asked', () => {
    expect(titles('')).toEqual(['GitHub', 'Сбербанк', 'Netflix']);
    expect(titles('is:trash')).toEqual(['Old']);
  });

  it('filters by label name, case-insensitive, with negation and quotes', () => {
    expect(titles('#работа')).toEqual(['GitHub']);
    expect(titles('-#банк')).toEqual(['GitHub', 'Netflix']);
    expect(titles('#"два слова"')).toEqual(['Сбербанк']);
  });

  it('filters by collection prefix and flags', () => {
    expect(titles('in:сем')).toEqual(['Netflix']);
    expect(titles('is:fav')).toEqual(['GitHub']);
    expect(titles('is:2fa')).toEqual(['Сбербанк']);
    expect(titles('-is:fav')).toEqual(['Сбербанк', 'Netflix']);
  });

  it('fuzzy-matches text over title, username and url, best first', () => {
    expect(titles('cody')).toEqual(['GitHub']);
    expect(titles('github.com')).toEqual(['GitHub']);
    expect(titles('бнк')).toEqual(['Сбербанк']);
  });

  it('filters by password health', () => {
    expect(titles('is:weak')).toEqual(['Сбербанк']);
    expect(titles('is:reused')).toEqual(['Сбербанк', 'Netflix']);
    expect(titles('is:old -is:weak')).toEqual(['Netflix']);
    expect(titles('is:pwned')).toEqual(['Netflix']);
  });

  it('ignores unknown flags', () => {
    expect(titles('is:nonsense')).toEqual(['GitHub', 'Сбербанк', 'Netflix']);
  });
});
