<script lang="ts">
  import { app, THEMES } from '../lib/state.svelte';
  import { filterItems, fuzzyScore, healthIssues, labelToken, parseQuery, toggleToken, tokenize } from '../lib/query';
  import Details from './Details.svelte';
  import Chat from './Chat.svelte';
  import Editor from './Editor.svelte';
  import Import from './Import.svelte';
  import Labels from './Labels.svelte';
  import Settings from './Settings.svelte';
  import Share from './Share.svelte';
  import NewFolder from './NewFolder.svelte';
  import Relogin from './Relogin.svelte';
  import { api } from '../lib/api';
  import { rowMenu, type MenuItem } from '../lib/menus';
  import type { Collection, ItemSummary, Label } from '../lib/types';

  let consoleInput: HTMLInputElement | undefined = $state();
  let listEl: HTMLElement | undefined = $state();
  let paletteIndex = $state(0);

  const parsed = $derived(parseQuery(app.query));
  const scoped = $derived(app.tab === 'all' ? app.items : app.items.filter((i) => i.collection_id === app.tab));
  const visible = $derived(filterItems(scoped, parsed, { labels: app.labels, cols: app.cols }));
  const scopeLabels = $derived(
    app.tab === 'all' ? app.collections.flatMap((c) => c.labels) : (app.cols.get(app.tab)?.labels ?? []),
  );
  const trashCount = $derived(scoped.filter((i) => i.deleted).length);
  const HEALTH = [['pwned', 'утечки'], ['weak', 'слабые'], ['reused', 'повторы'], ['old', 'старые']] as const;
  const healthCount = $derived(
    Object.fromEntries(HEALTH.map(([f]) => [f, scoped.filter((i) => !i.deleted && i[f]).length])) as Record<(typeof HEALTH)[number][0], number>,
  );

  // Keep the selection on a visible row.
  $effect(() => {
    if (!visible.some((i) => i.id === app.selectedId)) app.selectedId = visible[0]?.id ?? null;
  });

  interface Command {
    id: string;
    title: string;
    keys?: string;
    run: () => void;
  }
  const commands: Command[] = [
    { id: 'new', title: 'Новая запись', keys: 'Ctrl+N', run: () => (app.modal = { kind: 'editor', id: null }) },
    { id: 'lock', title: 'Заблокировать', keys: 'Ctrl+L', run: () => app.lock() },
    { id: 'labels', title: 'Ярлыки папки', run: () => (app.modal = { kind: 'labels' }) },
    { id: 'settings', title: 'Настройки', run: () => (app.modal = { kind: 'settings' }) },
    { id: 'import', title: 'Импорт паролей (Chrome, Firefox, Bitwarden, KeePass, старая версия)', run: () => (app.modal = { kind: 'import' }) },
    { id: 'trash', title: 'Показать корзину', run: () => (app.query = 'is:trash') },
    { id: 'folder', title: 'Новая папка', run: () => (app.modal = { kind: 'folder' }) },
    { id: 'share', title: 'Доступ к открытой папке', run: () => openShare() },
    { id: 'chat', title: 'Чат общей папки', run: () => openChatHere() },
    { id: 'hibp', title: 'Проверить пароли по базе утечек', run: () => app.checkBreaches() },
    { id: 'backup', title: 'Резервная копия и экспорт', run: () => (app.modal = { kind: 'settings' }) },
    { id: 'sync', title: 'Синхронизировать', run: () => app.syncNow(true) },
    { id: 'vhs', title: 'Эффект VHS: вкл / выкл', run: () => setFx('vhs') },
    { id: 'pixels', title: 'Пиксель-эффект: вкл / выкл', run: () => setFx('pixels') },
    { id: 'glow', title: 'Свечение: вкл / выкл', run: () => setFx('glow') },
    ...THEMES.map((t) => ({ id: `theme ${t.id}`, title: `Тема: ${t.name}`, run: () => setTheme(t.id) })),
  ];
  const palette = $derived(
    parsed.command === null
      ? []
      : commands
          .map((c) => ({ c, s: Math.max(fuzzyScore(parsed.command!, c.id), fuzzyScore(parsed.command!, c.title)) }))
          .filter((x) => x.s >= 0)
          .sort((a, b) => b.s - a.s)
          .map((x) => x.c),
  );
  $effect(() => {
    void palette.length;
    paletteIndex = 0;
  });

  function openChatHere() {
    const id = app.cols.get(app.tab)?.kind === 'shared' ? app.tab : app.collections.find((c) => c.kind === 'shared')?.id;
    if (id) app.openChat(id);
    else app.toast('Чат есть в общих папках. Создайте папку и пригласите в неё людей.', true);
  }

  function openShare() {
    const id = app.tab !== 'all' ? app.tab : app.collections.find((c) => c.kind === 'shared')?.id;
    if (id) app.modal = { kind: 'share', id };
    else app.modal = { kind: 'folder' };
  }

  const syncLabel = $derived.by(() => {
    if (!app.server) return 'локально';
    if (app.sync === 'syncing') return '⟳ синхронизация…';
    if (app.sync === 'offline') return '○ нет связи';
    if (app.sync === 'expired') return '! нужен вход';
    const t = app.server.last_sync ? new Date(app.server.last_sync).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' }) : '—';
    return `◉ ${app.server.url.replace('https://', '')} · ${t}`;
  });

  function setTheme(id: string) {
    app.settings.theme = id;
    app.applySettings();
  }
  function setFx(fx: 'vhs' | 'pixels' | 'glow') {
    app.settings[fx] = !app.settings[fx];
    app.applySettings();
  }
  function runCommand(c: Command | undefined) {
    if (!c) return;
    app.query = '';
    c.run();
  }

  function move(delta: number) {
    if (!visible.length) return;
    const i = visible.findIndex((x) => x.id === app.selectedId);
    const next = visible[Math.min(visible.length - 1, Math.max(0, i + delta))];
    app.selectedId = next.id;
    queueMicrotask(() => listEl?.querySelector(`[data-id="${next.id}"]`)?.scrollIntoView({ block: 'nearest' }));
  }

  function onConsoleKey(e: KeyboardEvent) {
    if (parsed.command !== null) {
      if (e.key === 'ArrowDown') paletteIndex = Math.min(palette.length - 1, paletteIndex + 1);
      else if (e.key === 'ArrowUp') paletteIndex = Math.max(0, paletteIndex - 1);
      else if (e.key === 'Enter') runCommand(palette[paletteIndex]);
      else if (e.key === 'Escape') app.query = '';
      else return;
      e.preventDefault();
      return;
    }
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      move(e.key === 'ArrowDown' ? 1 : -1);
      e.preventDefault();
    } else if (e.key === 'Enter' && app.selectedId) {
      app.modal = { kind: 'editor', id: app.selectedId };
    } else if (e.key === 'Escape') {
      app.query = '';
    }
  }

  const typing = (t: EventTarget | null) =>
    t instanceof HTMLElement && (t.tagName === 'TEXTAREA' || (t.tagName === 'INPUT' && t !== consoleInput) || t.isContentEditable);

  function onKey(e: KeyboardEvent) {
    if (app.modal) return;
    const ctrl = e.ctrlKey || e.metaKey;
    // e.code, not e.key: with the Russian layout Ctrl+C arrives as key 'с'.
    const k = e.code.startsWith('Key') ? e.code.slice(3).toLowerCase() : '';
    const sel = app.selectedId;
    const hasTextSelection =
      !!window.getSelection()?.toString() ||
      (document.activeElement === consoleInput && consoleInput!.selectionStart !== consoleInput!.selectionEnd);
    const item = app.items.find((i) => i.id === sel);
    if (ctrl && k === 'k') {
      app.query = '> ';
      consoleInput?.focus();
    } else if (ctrl && k === 'n') app.modal = { kind: 'editor', id: null };
    else if (ctrl && k === 'l') app.lock();
    else if (ctrl && k === 'e' && sel) app.modal = { kind: 'editor', id: sel };
    else if (ctrl && k === 'c' && sel && item?.has_password && !hasTextSelection && !typing(e.target)) app.copy(sel, 'password', 'Пароль');
    else if (ctrl && k === 'b' && sel && !typing(e.target)) app.copy(sel, 'username', 'Логин');
    else if (ctrl && k === 't' && sel && item?.has_totp && !typing(e.target)) app.copy(sel, 'totp', 'Код 2FA');
    else if ((e.key === 'ContextMenu' || (e.shiftKey && e.key === 'F10')) && item && !typing(e.target)) {
      const r = listEl?.querySelector(`[data-id="${item.id}"]`)?.getBoundingClientRect();
      openRowMenu({ clientX: (r?.left ?? 0) + 40, clientY: r?.bottom ?? 0 }, item);
    }
    else if (!ctrl && e.key === '/' && !typing(e.target) && document.activeElement !== consoleInput) consoleInput?.focus();
    else if (!typing(e.target) && document.activeElement !== consoleInput && (e.key === 'ArrowDown' || e.key === 'ArrowUp'))
      move(e.key === 'ArrowDown' ? 1 : -1);
    else return;
    e.preventDefault();
  }

  const isOn = (token: string) => tokenize(app.query).some((t) => t.toLowerCase() === token.toLowerCase());
  const toggle = (token: string) => {
    app.query = toggleToken(app.query, token);
    consoleInput?.focus();
  };
  const colName = (id: string) => app.cols.get(id)?.name ?? '';

  const COPY_WHAT = { password: 'Пароль', username: 'Логин', totp: 'Код 2FA' } as const;
  function openRowMenu(e: MouseEvent | { clientX: number; clientY: number }, it: ItemSummary) {
    app.selectedId = it.id;
    app.openMenu(
      e,
      rowMenu(it, app.collections, {
        copy: (f) => (f === 'url' ? app.run(() => api.copyText(it.urls[0], 0), 'Адрес скопирован') : app.copy(it.id, f, COPY_WHAT[f])),
        edit: () => (app.modal = { kind: 'editor', id: it.id }),
        favorite: () => app.patchItem(it.id, (d) => ({ favorite: !d.favorite }), it.favorite ? 'Убрано из избранного' : 'Добавлено в избранное'),
        // Labels belong to a folder, so they stay behind.
        move: (c) => app.patchItem(it.id, () => ({ collection_id: c, labels: [] }), `Перемещено в «${colName(c)}»`),
        trash: () => app.itemAction(it.id, it.title, 'delete'),
        restore: () => app.itemAction(it.id, it.title, 'restore'),
        purge: () => app.itemAction(it.id, it.title, 'purge'),
      }),
    );
  }

  function tabMenu(e: MouseEvent, c: Collection | null) {
    if (!c) return app.openMenu(e, [{ label: 'Новая папка', run: () => (app.modal = { kind: 'folder' }) }]);
    const items: MenuItem[] = [];
    if (c.role !== 'viewer')
      items.push(
        { label: 'Новая запись здесь', run: () => ((app.tab = c.id), (app.modal = { kind: 'editor', id: null })) },
        { label: 'Ярлыки папки', run: () => ((app.tab = c.id), (app.modal = { kind: 'labels' })) },
      );
    if (c.role === 'owner') items.push({ label: 'Переименовать', run: () => renameFolder(c) });
    if (c.kind === 'shared')
      items.push({ label: 'Чат папки', run: () => app.openChat(c.id) }, { label: 'Доступ', run: () => (app.modal = { kind: 'share', id: c.id }) });
    app.openMenu(e, items);
  }

  async function renameFolder(c: Collection) {
    const name = prompt('Новое название папки', c.name)?.trim();
    if (name && name !== c.name && (await app.run(() => api.renameCollection(c.id, name), 'Папка переименована')) !== undefined)
      await app.refresh();
  }

  function chipMenu(e: MouseEvent, l: Label) {
    const tok = labelToken(l.name);
    app.openMenu(e, [
      { label: `Только «${l.name}»`, run: () => (app.query = tok) },
      { label: `Скрыть «${l.name}»`, run: () => (app.query = toggleToken(app.query, `-${tok}`)) },
      'sep',
      { label: 'Изменить ярлыки…', run: () => (app.modal = { kind: 'labels' }) },
    ]);
  }

  function listMenu(e: MouseEvent) {
    if ((e.target as HTMLElement).closest('.row')) return;
    app.openMenu(e, [
      { label: 'Новая запись', keys: 'Ctrl+N', run: () => (app.modal = { kind: 'editor', id: null }) },
      { label: 'Импорт паролей…', run: () => (app.modal = { kind: 'import' }) },
      { label: 'Показать корзину', run: () => (app.query = 'is:trash') },
    ]);
  }
</script>

<svelte:window onkeydown={onKey} onfocus={() => app.scheduleSync(300)} />

<div class="shell">
  <header class="top">
    <span class="brand glow">▌PASSWORDS<span class="cursor"></span></span>
    <button class="who" class:off={app.sync === 'offline' || app.sync === 'expired'} title="Синхронизировать сейчас"
      onclick={() => (app.sync === 'expired' ? (app.modal = { kind: 'relogin' }) : app.server ? app.syncNow(true) : (app.modal = { kind: 'settings' }))}>
      {syncLabel} · {app.status?.username}
    </button>
    <span class="spacer"></span>
    {#if app.update}
      <button class="icon upd glow" title={app.update.notes} onclick={() => app.installUpdate()}>обновить до {app.update.version}</button>
    {/if}
    <button class="icon" title="Настройки" onclick={() => (app.modal = { kind: 'settings' })}>настройки</button>
    <button class="icon" title="Заблокировать (Ctrl+L)" onclick={() => app.lock()}>замок</button>
  </header>

  <div class="console">
    <span class="prompt glow">&gt;</span>
    <input
      bind:this={consoleInput}
      bind:value={app.query}
      onkeydown={onConsoleKey}
      placeholder="поиск: текст  #ярлык  in:папка  is:fav is:weak is:trash   ·   > команда"
      spellcheck="false"
      aria-label="Поиск и команды"
    />
    <span class="count muted">{parsed.command === null ? `${visible.length}` : ''}</span>
    {#if parsed.command !== null}
      <ul class="palette" role="listbox">
        {#each palette as c, i (c.id)}
          <li role="option" aria-selected={i === paletteIndex} class:on={i === paletteIndex}>
            <button onmousedown={(e) => (e.preventDefault(), runCommand(c))} onmouseenter={() => (paletteIndex = i)}>
              <span>{c.title}</span><span class="muted">{c.keys ?? c.id}</span>
            </button>
          </li>
        {:else}
          <li class="muted pad">нет такой команды</li>
        {/each}
      </ul>
    {/if}
  </div>

  <nav class="tabs" aria-label="Папки">
    <button class="tab" class:on={app.tab === 'all'} onclick={() => (app.tab = 'all')} oncontextmenu={(e) => tabMenu(e, null)}>Все <i>{app.items.filter((i) => !i.deleted).length}</i></button>
    {#each app.collections as c (c.id)}
      <button class="tab" class:on={app.tab === c.id} onclick={() => (app.tab = c.id)} oncontextmenu={(e) => tabMenu(e, c)}>
        {c.kind === 'shared' ? '⇄ ' : ''}{c.name} <i>{c.count}</i>{#if c.role === 'viewer'}<span class="muted"> ro</span>{/if}{#if app.unread.has(c.id)}<span class="unread" title="Новые сообщения в чате"> ●</span>{/if}
      </button>
    {/each}
    <button class="tab add" title="Новая папка" onclick={() => (app.modal = { kind: 'folder' })}>+</button>
    {#if app.tab !== 'all' && app.cols.get(app.tab)?.kind === 'shared'}
      <button class="tab share" class:on={app.chat === app.tab} onclick={() => (app.chat === app.tab ? (app.chat = null) : app.openChat(app.tab))}>
        чат{#if app.unread.has(app.tab)}<span class="unread"> ●</span>{/if}
      </button>
      <button class="tab share2" onclick={openShare}>доступ</button>
    {/if}
  </nav>

  <div class="chips">
    {#each scopeLabels as l (l.id)}
      {@const tok = labelToken(l.name)}
      <button class="chip" class:on={isOn(tok)} style="--c: var(--l-{l.color})" onclick={() => toggle(tok)} oncontextmenu={(e) => chipMenu(e, l)}>
        <span class="dot"></span>{l.name}
      </button>
    {/each}
    <button class="chip" class:on={isOn('is:fav')} onclick={() => toggle('is:fav')}>★ избранное</button>
    <button class="chip" class:on={isOn('is:2fa')} onclick={() => toggle('is:2fa')}>с кодом 2FA</button>
    {#each HEALTH as [flag, name] (flag)}
      {#if healthCount[flag] || isOn(`is:${flag}`)}
        <button class="chip" class:on={isOn(`is:${flag}`)} style="--c: var(--danger)" onclick={() => toggle(`is:${flag}`)}>
          <span class="dot"></span>{name} {healthCount[flag]}
        </button>
      {/if}
    {/each}
    {#if !app.breachChecked}
      <button class="chip ghost" title="Сверить пароли с базой утечек Have I Been Pwned" onclick={() => app.checkBreaches()}>проверить утечки</button>
    {/if}
    <button class="chip" class:on={isOn('is:trash')} onclick={() => toggle('is:trash')}>корзина {trashCount || ''}</button>
    <button class="chip ghost" onclick={() => (app.modal = { kind: 'labels' })}>+ ярлык</button>
  </div>

  <main class="body">
    <section class="list" bind:this={listEl} aria-label="Записи" oncontextmenu={listMenu}>
      {#each visible as it (it.id)}
        <button
          class="row"
          class:on={it.id === app.selectedId}
          data-id={it.id}
          onclick={() => (app.selectedId = it.id)}
          ondblclick={() => (app.modal = { kind: 'editor', id: it.id })}
          oncontextmenu={(e) => openRowMenu(e, it)}
        >
          <span class="mark">{it.id === app.selectedId ? '▸' : ' '}</span>
          <span class="title">{it.favorite ? '★ ' : ''}{it.title}{#if healthIssues(it).length && !it.deleted}<span class="err" title={healthIssues(it).join(', ')}>!</span>{/if}</span>
          <span class="user muted">{it.kind === 'note' ? 'заметка' : it.username}</span>
          <span class="labs">
            {#each it.labels as lid (lid)}
              {@const l = app.labels.get(lid)}
              {#if l}<span class="dot" style="--c: var(--l-{l.color})" title={l.name}></span>{/if}
            {/each}
            {#if app.tab === 'all' && app.collections.length > 1}<span class="col muted">{colName(it.collection_id)}</span>{/if}
          </span>
        </button>
      {:else}
        <div class="empty">
          {#if app.query}
            <p>Ничего не нашлось по <b>{app.query}</b>.</p>
            <button class="btn" onclick={() => (app.query = '')}>Сбросить поиск</button>
          {:else}
            <p>Здесь пока пусто.</p>
            <button class="btn primary" onclick={() => (app.modal = { kind: 'editor', id: null })}>Добавить запись</button>
          {/if}
        </div>
      {/each}
    </section>
    {#if app.chat}<Chat id={app.chat} />{:else}<Details />{/if}
  </main>

  <footer class="status muted">
    <span><b>^K</b> команды</span><span><b>^N</b> новая</span><span><b>^C</b> пароль</span><span><b>^B</b> логин</span><span><b>^T</b> 2FA</span>
    <span><b>^E</b> изменить</span><span><b>^L</b> замок</span><span><b>/</b> поиск</span>
  </footer>
</div>

{#if app.modal?.kind === 'editor'}<Editor id={app.modal.id} />{/if}
{#if app.modal?.kind === 'labels'}<Labels />{/if}
{#if app.modal?.kind === 'settings'}<Settings />{/if}
{#if app.modal?.kind === 'import'}<Import />{/if}
{#if app.modal?.kind === 'share'}<Share id={app.modal.id} />{/if}
{#if app.modal?.kind === 'folder'}<NewFolder />{/if}
{#if app.modal?.kind === 'relogin'}<Relogin />{/if}

<style>
  .shell {
    height: 100%;
    display: grid;
    grid-template-rows: auto auto auto auto 1fr auto;
  }
  .top {
    display: flex;
    align-items: baseline;
    gap: 14px;
    padding: 8px 14px 4px;
  }
  .brand {
    color: var(--accent);
    font-weight: 700;
    letter-spacing: 0.04em;
  }
  .brand .cursor {
    width: 0.5em;
    margin-left: 2px;
  }
  .spacer {
    flex: 1;
  }
  .who {
    background: none;
    border: 0;
    color: var(--muted);
    cursor: pointer;
    padding: 0;
  }
  .who:hover {
    color: var(--accent);
  }
  .upd {
    color: var(--accent);
  }
  .who.off {
    color: var(--danger);
  }
  .tab.add {
    border-style: dashed;
  }
  .tab.share {
    margin-left: auto;
  }
  .tab.share,
  .tab.share2 {
    border-radius: 0;
    border-bottom-color: var(--line);
  }
  .unread {
    color: var(--accent);
  }
  .console {
    position: relative;
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 6px 14px;
    padding: 0 10px;
    border: 1px solid var(--line);
    background: var(--surface);
  }
  .console:focus-within {
    border-color: var(--accent);
    box-shadow: 0 0 12px var(--glow);
  }
  .prompt {
    color: var(--accent);
    font-weight: 700;
  }
  .console input {
    border: 0;
    background: none;
    padding: 8px 0;
    caret-color: var(--accent);
    caret-shape: block;
  }
  .palette {
    position: absolute;
    top: 100%;
    left: -1px;
    right: -1px;
    margin: 0;
    padding: 4px 0;
    list-style: none;
    background: var(--raised);
    border: 1px solid var(--accent);
    z-index: 50;
    max-height: 320px;
    overflow: auto;
  }
  .palette button {
    width: 100%;
    display: flex;
    justify-content: space-between;
    background: none;
    border: 0;
    padding: 4px 12px;
    cursor: pointer;
    text-align: left;
  }
  .palette li.on button {
    background: var(--accent);
    color: var(--on-accent);
  }
  .palette li.on .muted {
    color: inherit;
    opacity: 0.7;
  }
  .pad {
    padding: 4px 12px;
  }
  .tabs {
    display: flex;
    gap: 6px;
    padding: 2px 14px;
    overflow-x: auto;
  }
  .tab {
    background: none;
    border: 1px solid var(--line);
    border-radius: 7px 7px 0 0;
    border-bottom-color: transparent;
    padding: 3px 12px;
    cursor: pointer;
    color: var(--muted);
  }
  .tab i {
    font-style: normal;
    opacity: 0.7;
  }
  .tab.on {
    color: var(--accent);
    border-color: var(--accent);
    background: var(--surface);
  }
  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    padding: 8px 14px;
    border-top: 1px solid var(--line);
  }
  .body {
    min-height: 0;
    display: grid;
    grid-template-columns: minmax(0, 1fr) minmax(300px, 38%);
    border-top: 1px solid var(--line);
  }
  .list {
    overflow: auto;
    padding: 4px 0;
  }
  .row {
    display: grid;
    grid-template-columns: 1.2em minmax(0, 1.2fr) minmax(0, 1fr) 10em;
    gap: 10px;
    width: 100%;
    background: none;
    border: 0;
    padding: var(--row-pad) 14px var(--row-pad) 8px;
    text-align: left;
    cursor: pointer;
    align-items: center;
  }
  .row:hover {
    background: var(--surface);
  }
  .row.on {
    background: var(--raised);
    color: var(--accent);
  }
  .mark {
    color: var(--accent);
  }
  .title .err {
    margin-left: 4px;
  }
  .title,
  .user {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .labs {
    display: flex;
    gap: 4px;
    align-items: center;
    justify-content: flex-end;
    overflow: hidden;
    white-space: nowrap;
  }
  .col {
    margin-left: 6px;
    font-size: 12px;
  }
  .empty {
    padding: 40px 24px;
    display: grid;
    justify-items: start;
    gap: 10px;
  }
  .empty p {
    margin: 0;
  }
  .status {
    display: flex;
    flex-wrap: wrap;
    gap: 18px;
    padding: 5px 14px;
    border-top: 1px solid var(--line);
    font-size: 12px;
  }
  .status b {
    color: var(--fg);
    font-weight: 400;
  }
</style>
