<script lang="ts">
  import { open, save } from '@tauri-apps/plugin-dialog';
  import { getCurrentWebview } from '@tauri-apps/api/webview';
  import { api, inTauri } from '../lib/api';
  import { app } from '../lib/state.svelte';
  import type { AttachmentView, ItemDetails } from '../lib/types';
  import { healthIssues, labelToken, toggleToken } from '../lib/query';
  import type { MenuItem } from '../lib/menus';

  let item = $state<ItemDetails | null>(null);
  let shown = $state<Record<string, string>>({});
  let otp = $state<{ code: string; left: number; period: number } | null>(null);
  const totpId = $derived(item?.has_totp ? item.id : null);

  // 2FA code: fetch, count down locally each second, refetch when it rolls over.
  $effect(() => {
    const id = totpId;
    otp = null;
    if (!id) return;
    let stop = false;
    const fetch = () => api.totp(id).then((c) => !stop && (otp = c), () => !stop && (otp = null));
    fetch();
    const t = setInterval(() => {
      if (!otp) return;
      if (otp.left <= 1) fetch();
      else otp = { ...otp, left: otp.left - 1 };
    }, 1000);
    return () => {
      stop = true;
      clearInterval(t);
    };
  });

  // Reload when the selection or the item list changes; hide revealed secrets on switch.
  $effect(() => {
    const id = app.selectedId;
    void app.items;
    if (!id) {
      item = null;
      return;
    }
    api.get(id).then((d) => {
      if (app.selectedId === id) {
        if (item?.id !== id || item?.updated_at !== d.updated_at) shown = {};
        item = d;
      }
    }, () => (item = null));
  });

  async function toggle(field: string) {
    if (!item) return;
    if (field in shown) {
      const { [field]: _, ...rest } = shown;
      shown = rest;
    } else {
      const value = await app.run(() => api.reveal(item!.id, field));
      if (value === undefined) return;
      shown = { ...shown, [field]: value };
      const sec = app.settings.revealSec;
      // Hide again later, unless it was hidden or replaced meanwhile.
      if (sec > 0)
        setTimeout(() => {
          if (shown[field] === value) {
            const { [field]: _, ...rest } = shown;
            shown = rest;
          }
        }, sec * 1000);
    }
  }

  async function copyField(field: string, what: string) {
    if (!item) return;
    await app.run(() => api.copy(item!.id, field, app.settings.clipboardSec), `${what} скопирован — очистится через ${app.settings.clipboardSec} с`);
  }

  const size = (n: number) => (n < 1024 ? `${n} Б` : n < 1024 * 1024 ? `${Math.round(n / 1024)} КБ` : `${(n / 1024 / 1024).toFixed(1)} МБ`);

  async function attachPaths(paths: string[]) {
    if (!item || readOnly || item.deleted) return;
    for (const p of paths) {
      const r = await app.run(() => api.attachFile(item!.id, p), `Прикреплено: ${p.split(/[\\/]/).pop()}`);
      if (r === undefined) break;
    }
    await app.refresh();
  }

  async function pickFiles() {
    if (!inTauri) return;
    const p = await open({ multiple: true });
    if (p) await attachPaths(Array.isArray(p) ? p : [p]);
  }

  async function saveFile(a: AttachmentView) {
    const path = inTauri ? await save({ defaultPath: a.name }) : null;
    if (path) await app.run(() => api.saveAttachment(a.id, path), `Сохранено: ${a.name}`);
  }

  async function removeFile(a: AttachmentView) {
    if (!confirm(`Удалить файл «${a.name}»? Это нельзя отменить.`)) return;
    await app.run(() => api.removeAttachment(a.id), 'Файл удалён');
    await app.refresh();
  }

  function fileMenu(e: MouseEvent, a: AttachmentView) {
    const items: MenuItem[] = [{ label: 'Сохранить…', run: () => saveFile(a) }];
    if (!readOnly) items.push({ label: 'Удалить файл', danger: true, run: () => removeFile(a) });
    app.openMenu(e, items);
  }

  // Files dropped on the window go to the selected entry.
  let dropping = $state(false);
  $effect(() => {
    if (!inTauri) return;
    const off = getCurrentWebview().onDragDropEvent((e) => {
      const t = e.payload.type;
      dropping = t === 'over' || t === 'enter';
      if (t === 'drop') attachPaths(e.payload.paths);
    });
    return () => void off.then((f) => f());
  });

  async function act(action: 'delete' | 'restore' | 'purge') {
    if (item) await app.itemAction(item.id, item.title, action);
  }

  /** Right click on a field: copy it (and show / hide a secret). */
  function fieldMenu(e: MouseEvent, field: string, what: string, text?: string) {
    const items: MenuItem[] = [
      { label: `Копировать ${what}`, run: () => (text !== undefined ? app.run(() => api.copyText(text, 0), 'Скопировано') : copyField(field, what)) },
    ];
    if (field === 'password' || field.startsWith('history:'))
      items.push({ label: field in shown ? 'Скрыть' : 'Показать', run: () => toggle(field) });
    app.openMenu(e, items);
  }

  const fmt = (iso: string) =>
    new Date(iso).toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
  const readOnly = $derived(item ? app.cols.get(item.collection_id)?.role === 'viewer' : true);
</script>

<aside class="details" aria-label="Запись">
  {#if item}
    <h2 class="glow">{item.title}</h2>
    <p class="meta muted">
      {app.cols.get(item.collection_id)?.name}{item.deleted ? ' · в корзине' : ''}{readOnly ? ' · только чтение' : ''}
    </p>
    {#if !item.deleted && healthIssues(item).length}
      <p class="health err">
        ⚠ {healthIssues(item).join(' · ')}
        {#if !readOnly}<button class="icon" onclick={() => (app.modal = { kind: 'editor', id: item!.id })}>сменить</button>{/if}
      </p>
    {/if}
    {#if item.labels.length}
      <p class="labs">
        {#each item.labels as lid (lid)}
          {@const l = app.labels.get(lid)}
          {#if l}<button class="lab" style="--c: var(--l-{l.color})" title="Показать записи с этим ярлыком"
              onclick={() => (app.query = toggleToken(app.query, labelToken(l.name)))}><span class="dot"></span>{l.name}</button>{/if}
        {/each}
      </p>
    {/if}

    <dl>
      {#if item.username}
        <dt>user</dt>
        <dd oncontextmenu={(e) => fieldMenu(e, 'username', 'логин')}><span class="val">{item.username}</span><button class="icon" onclick={() => copyField('username', 'Логин')}>копировать</button></dd>
      {/if}
      {#if item.has_password}
        <dt>pass</dt>
        <dd oncontextmenu={(e) => fieldMenu(e, 'password', 'пароль')}>
          <span class="val secret">{shown.password ?? '••••••••••••'}</span>
          <button class="icon" onclick={() => toggle('password')}>{'password' in shown ? 'скрыть' : 'показать'}</button>
          <button class="icon" onclick={() => copyField('password', 'Пароль')}>копировать</button>
        </dd>
      {/if}
      {#each item.urls as url (url)}
        <dt>url</dt>
        <dd oncontextmenu={(e) => fieldMenu(e, 'url', 'адрес', url)}><span class="val">{url}</span><button class="icon" onclick={() => app.run(() => api.copyText(url, 0), 'Адрес скопирован')}>копировать</button></dd>
      {/each}
      {#if item.has_totp}
        <dt>2fa</dt>
        <dd class="otp" oncontextmenu={(e) => fieldMenu(e, 'totp', 'код 2FA')}>
          {#if otp}
            <span class="code glow">{otp.code.slice(0, 3)} {otp.code.slice(3)}</span>
            <span class="bar" style="--p: {otp.left / otp.period}" title="{otp.left} с"></span>
            <button class="icon" onclick={() => copyField('totp', 'Код 2FA')}>копировать</button>
          {:else}
            <span class="err">2FA-секрет не подходит</span>
          {/if}
        </dd>
      {/if}
      {#if item.notes}
        <dt>notes</dt>
        <dd class="notes">{item.notes}</dd>
      {/if}
    </dl>

    {#if item.attachments.length || (!readOnly && !item.deleted)}
      <div class="files" class:dropping>
        <p class="muted">файлы{item.attachments.length ? ` · ${item.attachments.length}` : ''}</p>
        {#each item.attachments as a (a.id)}
          <div class="file" role="listitem" oncontextmenu={(e) => fileMenu(e, a)}>
            <span class="val">{a.name}</span>
            <span class="muted">{size(a.size)}</span>
            <button class="icon" onclick={() => saveFile(a)}>сохранить</button>
            {#if !readOnly}<button class="icon" onclick={() => removeFile(a)}>удалить</button>{/if}
          </div>
        {/each}
        {#if !readOnly && !item.deleted}
          <button class="icon add" title="Или перетащите файл в окно. До 8 МБ." onclick={pickFiles}>+ прикрепить файл</button>
        {/if}
      </div>
    {/if}

    {#if item.history.length}
      <details class="history">
        <summary class="muted">старые пароли · {item.history.length}</summary>
        <ul>
          {#each item.history.map((at, i) => ({ at, i })).reverse() as h (h.i)}
            {@const f = `history:${h.i}`}
            <li>
              <span class="muted">до {fmt(h.at)}</span>
              <span class="val secret">{shown[f] ?? '••••••'}</span>
              <button class="icon" onclick={() => toggle(f)}>{f in shown ? 'скрыть' : 'показать'}</button>
            </li>
          {/each}
        </ul>
      </details>
    {/if}

    <p class="stamp muted">изменено {fmt(item.updated_at)} · создано {fmt(item.created_at)}</p>

    {#if !readOnly}
      <div class="actions">
        {#if item.deleted}
          <button class="btn" onclick={() => act('restore')}>Восстановить</button>
          <button class="btn danger" onclick={() => act('purge')}>Удалить навсегда</button>
        {:else}
          <button class="btn primary" onclick={() => (app.modal = { kind: 'editor', id: item!.id })}>Изменить</button>
          <button class="btn danger" onclick={() => act('delete')}>В корзину</button>
        {/if}
      </div>
    {/if}
  {:else}
    <p class="muted pad">Выберите запись слева или нажмите Ctrl+N, чтобы добавить новую.</p>
  {/if}
</aside>

<style>
  .details {
    border-left: 1px solid var(--line);
    padding: 14px 16px;
    overflow: auto;
    background: var(--surface);
  }
  h2 {
    margin: 0;
    font-size: 18px;
    color: var(--accent);
    word-break: break-word;
  }
  .meta {
    margin: 2px 0 10px;
  }
  .health {
    margin: 0 0 12px;
  }
  .files {
    margin: 14px 0 0;
    padding: 6px 8px;
    border: 1px dashed transparent;
  }
  .files.dropping {
    border-color: var(--accent);
    box-shadow: 0 0 12px var(--glow);
  }
  .files p {
    margin: 0 0 4px;
  }
  .file {
    display: flex;
    gap: 10px;
    align-items: baseline;
  }
  .file .val {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .add {
    padding: 2px 0;
    text-align: left;
  }
  .labs {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin: 0 0 12px;
  }
  .lab {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    border: 1px solid var(--c);
    border-radius: 999px;
    padding: 0 8px;
    background: none;
    cursor: pointer;
  }
  .lab:hover {
    background: color-mix(in srgb, var(--c) 16%, transparent);
  }
  dl {
    display: grid;
    grid-template-columns: 4.5em minmax(0, 1fr);
    gap: 8px 10px;
    margin: 0;
  }
  dt {
    color: var(--muted);
  }
  dd {
    margin: 0;
    display: flex;
    flex-wrap: wrap;
    align-items: baseline;
    gap: 2px 6px;
  }
  .val {
    word-break: break-all;
    margin-right: 4px;
  }
  .secret {
    color: var(--accent);
  }
  .otp {
    align-items: center;
  }
  .code {
    color: var(--accent);
    font-size: 18px;
    font-weight: 700;
    letter-spacing: 0.08em;
  }
  .bar {
    width: 60px;
    height: 4px;
    background: linear-gradient(to right, var(--accent) calc(var(--p) * 100%), var(--line) 0);
  }
  .notes {
    white-space: pre-wrap;
    word-break: break-word;
  }
  .history {
    margin-top: 14px;
  }
  .history summary {
    cursor: pointer;
  }
  .history ul {
    list-style: none;
    padding: 6px 0 0;
    margin: 0;
    display: grid;
    gap: 4px;
  }
  .history li {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
  }
  .stamp {
    font-size: 12px;
    margin: 16px 0 10px;
  }
  .actions {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
  }
  .pad {
    padding-top: 30px;
  }
</style>
