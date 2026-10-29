// Console line: `text #label in:collection is:flag`, `-` negates a token, `>` starts a command.
import type { Collection, ItemSummary, Label } from './types';

export interface Term {
  value: string;
  neg: boolean;
}

export interface Query {
  text: string[];
  labels: Term[];
  cols: Term[];
  flags: Term[];
  command: string | null;
}

/** Whitespace-separated tokens; double quotes keep spaces inside one token. */
export function tokenize(q: string): string[] {
  return q.match(/(?:[^\s"]+|"[^"]*")+/g) ?? [];
}

const unquote = (s: string) => s.replace(/"/g, '');

export function parseQuery(q: string): Query {
  const out: Query = { text: [], labels: [], cols: [], flags: [], command: null };
  const trimmed = q.trimStart();
  if (trimmed.startsWith('>')) {
    out.command = trimmed.slice(1).trim();
    return out;
  }
  for (const raw of tokenize(q)) {
    const neg = raw.length > 1 && raw.startsWith('-');
    const tok = neg ? raw.slice(1) : raw;
    const lower = tok.toLowerCase();
    if (tok.startsWith('#') && tok.length > 1) out.labels.push({ value: unquote(lower.slice(1)), neg });
    else if (lower.startsWith('in:') && tok.length > 3) out.cols.push({ value: unquote(lower.slice(3)), neg });
    else if (lower.startsWith('is:') && tok.length > 3) out.flags.push({ value: lower.slice(3), neg });
    else out.text.push(unquote(raw));
  }
  return out;
}

/** Adds `token` to the query, or removes it if already present. */
export function toggleToken(q: string, token: string): string {
  const toks = tokenize(q);
  const i = toks.findIndex((t) => t.toLowerCase() === token.toLowerCase());
  if (i >= 0) toks.splice(i, 1);
  else toks.push(token);
  return toks.join(' ');
}

/** Token form of a label name, quoted when it has spaces. */
export const labelToken = (name: string) => (/\s/.test(name) ? `#"${name}"` : `#${name}`);

/** -1 = no match. Substring beats subsequence; earlier and tighter matches score higher. */
export function fuzzyScore(needle: string, hay: string): number {
  const n = needle.toLowerCase();
  const h = hay.toLowerCase();
  if (!n) return 0;
  const at = h.indexOf(n);
  if (at >= 0) return 1000 - at;
  let score = 0;
  let pos = -1;
  for (const ch of n) {
    const next = h.indexOf(ch, pos + 1);
    if (next < 0) return -1;
    score += next === pos + 1 ? 10 : 1;
    pos = next;
  }
  return score;
}

const FLAGS: Record<string, (i: ItemSummary) => boolean> = {
  fav: (i) => i.favorite,
  '2fa': (i) => i.has_totp,
  trash: (i) => i.deleted,
  note: (i) => i.kind === 'note',
  login: (i) => i.kind === 'login',
  weak: (i) => i.weak,
  reused: (i) => i.reused,
  old: (i) => i.old,
  pwned: (i) => i.pwned,
};

/** Password problems in words, for the row tooltip and the details pane. */
export function healthIssues(i: ItemSummary): string[] {
  const out: string[] = [];
  if (i.pwned) out.push('пароль есть в базах утечек — смените его');
  if (i.weak) out.push('слабый пароль');
  if (i.reused) out.push('такой же пароль есть в другой записи');
  if (i.old) out.push('пароль не меняли больше года');
  return out;
}

export function filterItems(
  items: ItemSummary[],
  q: Query,
  ctx: { labels: Map<string, Label>; cols: Map<string, Collection> },
): ItemSummary[] {
  const wantsTrash = q.flags.some((f) => f.value === 'trash' && !f.neg);
  const scored: [ItemSummary, number][] = [];
  for (const it of items) {
    if (it.deleted !== wantsTrash) continue;
    const names = it.labels.map((id) => ctx.labels.get(id)?.name.toLowerCase());
    if (!q.labels.every((t) => names.includes(t.value) !== t.neg)) continue;
    const col = ctx.cols.get(it.collection_id)?.name.toLowerCase() ?? '';
    if (!q.cols.every((t) => col.startsWith(t.value) !== t.neg)) continue;
    if (!q.flags.every((t) => (FLAGS[t.value] ? FLAGS[t.value](it) !== t.neg : true))) continue;
    let score = 0;
    let ok = true;
    for (const word of q.text) {
      const best = Math.max(...[it.title, it.username, ...it.urls].map((h) => fuzzyScore(word, h)));
      if (best < 0) {
        ok = false;
        break;
      }
      score += best;
    }
    if (ok) scored.push([it, score]);
  }
  if (q.text.length) scored.sort((a, b) => b[1] - a[1]);
  return scored.map(([it]) => it);
}
