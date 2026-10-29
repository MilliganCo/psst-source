<script lang="ts">
  import { api } from '../lib/api';
  import { GLYPHS } from '../lib/glyphs';
  import { app } from '../lib/state.svelte';
  import { LABEL_COLORS, type MessageView } from '../lib/types';

  let { id }: { id: string } = $props();

  let msgs = $state<MessageView[]>([]);
  let text = $state('');
  let picker = $state(false);
  let sending = $state(false);
  let listEl: HTMLElement | undefined = $state();
  let input: HTMLTextAreaElement | undefined = $state();
  const col = $derived(app.cols.get(id));
  const readOnly = $derived(col?.role === 'viewer');

  // Reload whenever lists refresh (after a sync or a post); stick to the bottom if already there.
  $effect(() => {
    void app.chats;
    const cid = id;
    api.messages(cid).then((m) => {
      if (cid !== id) return;
      const el = listEl;
      const atBottom = !el || el.scrollHeight - el.scrollTop - el.clientHeight < 40;
      msgs = m;
      app.markChatSeen(cid, m.at(-1)?.at);
      if (atBottom) queueMicrotask(() => listEl?.scrollTo({ top: listEl.scrollHeight }));
    }, () => {});
  });

  $effect(() => {
    void id;
    input?.focus();
  });

  async function send() {
    const t = text.trim();
    if (!t || sending) return;
    sending = true;
    const r = await app.run(() => api.postMessage(id, t));
    sending = false;
    if (r === undefined) return;
    text = '';
    picker = false;
    await app.refresh();
    queueMicrotask(() => listEl?.scrollTo({ top: listEl.scrollHeight }));
  }

  function onKey(e: KeyboardEvent) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      send();
    } else if (e.key === 'Escape') {
      e.stopPropagation();
      if (picker) picker = false;
      else app.chat = null;
    }
  }

  function insert(ch: string) {
    const el = input;
    const at = el?.selectionStart ?? text.length;
    const end = el?.selectionEnd ?? at;
    text = text.slice(0, at) + ch + text.slice(end);
    queueMicrotask(() => {
      el?.focus();
      el?.setSelectionRange(at + ch.length, at + ch.length);
    });
  }

  function hue(name: string) {
    let h = 0;
    for (const c of name) h = (h * 31 + c.codePointAt(0)!) >>> 0;
    return `var(--l-${LABEL_COLORS[h % (LABEL_COLORS.length - 1)]})`; // not gray
  }

  const time = (iso: string) => new Date(iso).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
  const day = (iso: string) => new Date(iso).toLocaleDateString('ru-RU', { day: 'numeric', month: 'long' });
  /** Same author within 5 minutes: no repeated name line. */
  const continues = (i: number) =>
    i > 0 && msgs[i - 1].author === msgs[i].author && Date.parse(msgs[i].at) - Date.parse(msgs[i - 1].at) < 5 * 60_000 && day(msgs[i - 1].at) === day(msgs[i].at);

  function menu(e: MouseEvent, m: MessageView) {
    app.openMenu(e, [
      { label: 'Копировать текст', run: () => app.run(() => api.copyText(m.text, 0), 'Скопировано') },
      ...(m.mine && !readOnly
        ? [{ label: 'Удалить сообщение', danger: true, run: async () => (await app.run(() => api.purge(m.id))) !== undefined && app.refresh() }]
        : []),
    ]);
  }
</script>

<aside class="chat" aria-label="Чат папки">
  <header>
    <span class="glow">┤ чат · {col?.name} ├</span>
    <button class="icon" onclick={() => (app.chat = null)} aria-label="Закрыть чат" title="Закрыть (Esc)">✕</button>
  </header>

  <div class="msgs" bind:this={listEl} role="log" aria-live="polite">
    {#each msgs as m, i (m.id)}
      {#if i === 0 || day(msgs[i - 1].at) !== day(m.at)}<p class="day muted">— {day(m.at)} —</p>{/if}
      <div class="msg" class:mine={m.mine} oncontextmenu={(e) => menu(e, m)} role="article">
        {#if !continues(i)}
          <p class="who"><b style="color: {hue(m.author)}">{m.author}</b> <span class="muted">{time(m.at)}</span></p>
        {/if}
        <p class="text">{m.text}</p>
      </div>
    {:else}
      <p class="muted empty">Здесь пока тихо. Сообщения видят все участники папки, сервер — только шифр.</p>
    {/each}
  </div>

  {#if readOnly}
    <p class="muted ro">В этой папке у вас только чтение — писать в чат нельзя.</p>
  {:else}
    {#if picker}
      <div class="picker" role="listbox" aria-label="Символы">
        {#each GLYPHS as g (g.ch)}
          <button class="g" title={g.name} aria-label={g.name} onclick={() => insert(g.ch)}>{g.ch}</button>
        {/each}
      </div>
    {/if}
    <div class="compose">
      <button class="icon nf" class:on={picker} title="Символы" aria-label="Символы" onclick={() => (picker = !picker)}>{'\u{f01f5}'}</button>
      <textarea
        bind:this={input}
        bind:value={text}
        onkeydown={onKey}
        rows="2"
        maxlength="4000"
        placeholder="сообщение — Enter отправить, Shift+Enter новая строка"
      ></textarea>
      <button class="btn primary" disabled={!text.trim() || sending} onclick={send} title="Отправить (Enter)" aria-label="Отправить">→</button>
    </div>
  {/if}
</aside>

<style>
  .chat {
    border-left: 1px solid var(--line);
    background: var(--surface);
    display: grid;
    grid-template-rows: auto 1fr auto auto;
    min-height: 0;
  }
  header {
    display: flex;
    justify-content: space-between;
    padding: 10px 14px 6px;
    color: var(--accent);
  }
  .msgs {
    overflow: auto;
    padding: 4px 14px 10px;
    min-height: 0;
  }
  .msg {
    padding: 1px 6px;
    border-left: 2px solid transparent;
  }
  .msg:hover {
    background: var(--raised);
  }
  .msg.mine {
    border-left-color: var(--accent);
  }
  p {
    margin: 0;
  }
  .who {
    margin-top: 8px;
  }
  .text {
    white-space: pre-wrap;
    word-break: break-word;
  }
  .day {
    text-align: center;
    margin: 12px 0 2px;
    font-size: 12px;
  }
  .empty,
  .ro {
    padding: 14px;
  }
  .picker {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(30px, 1fr));
    gap: 2px;
    max-height: 150px;
    overflow: auto;
    padding: 6px 14px;
    border-top: 1px solid var(--line);
  }
  .g {
    background: none;
    border: 1px solid transparent;
    font-size: 17px;
    line-height: 1.5;
    cursor: pointer;
    padding: 0;
  }
  .g:hover,
  .g:focus-visible {
    border-color: var(--accent);
    color: var(--accent);
  }
  .compose {
    display: flex;
    gap: 6px;
    align-items: flex-end;
    padding: 8px 14px 12px;
    border-top: 1px solid var(--line);
  }
  .compose textarea {
    min-height: 0;
    resize: none;
  }
  .nf {
    font-size: 18px;
  }
  .nf.on {
    color: var(--accent);
  }
</style>
