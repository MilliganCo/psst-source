import { describe, expect, it } from 'vitest';
import { toNotify } from './chat';
import type { ChatSummary } from './types';

const s = (c: string, at: string, author = 'bob', mine = false): ChatSummary => ({ collection_id: c, count: 1, last_at: at, last_author: author, last_mine: mine });

describe('toNotify', () => {
  const prev = [s('fam', '2026-10-05T10:00:00Z')];

  it('announces a newer message from someone else', () => {
    expect(toNotify(prev, [s('fam', '2026-10-05T10:05:00Z')], {}, null, true).map((x) => x.collection_id)).toEqual(['fam']);
    expect(toNotify(prev, [s('fam', '2026-10-05T10:00:00Z'), s('work', '2026-10-05T09:00:00Z')], {}, null, true).map((x) => x.collection_id)).toEqual(['work']);
  });

  it('stays quiet for own, seen, unchanged and open-and-focused chats, and before the first load', () => {
    expect(toNotify(prev, [s('fam', '2026-10-05T10:05:00Z', 'cody', true)], {}, null, true)).toEqual([]);
    expect(toNotify(prev, [s('fam', '2026-10-05T10:00:00Z')], {}, null, false)).toEqual([]);
    expect(toNotify(prev, [s('fam', '2026-10-05T10:05:00Z')], { fam: '2026-10-05T10:05:00Z' }, null, false)).toEqual([]);
    expect(toNotify(prev, [s('fam', '2026-10-05T10:05:00Z')], {}, 'fam', true)).toEqual([]);
    expect(toNotify(null, [s('fam', '2026-10-05T10:05:00Z')], {}, null, false)).toEqual([]);
  });

  it('still announces into an open chat when the window is in the background', () => {
    expect(toNotify(prev, [s('fam', '2026-10-05T10:05:00Z')], {}, 'fam', false)).toHaveLength(1);
  });
});
