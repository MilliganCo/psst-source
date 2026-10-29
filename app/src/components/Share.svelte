<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import { app } from '../lib/state.svelte';
  import type { MemberView } from '../lib/types';
  import Modal from './Modal.svelte';

  let { id }: { id: string } = $props();

  const col = $derived(app.cols.get(id));
  const isOwner = $derived(col?.role === 'owner');
  let members = $state<MemberView[] | null>(null);
  let username = $state('');
  let role = $state<'editor' | 'viewer'>('editor');
  let name = $state('');
  let busy = $state(false);

  const ROLES: Record<string, string> = { owner: 'владелец', editor: 'редактор', viewer: 'читатель' };

  async function load() {
    members = (await app.run(() => api.members(id))) ?? [];
  }

  onMount(() => {
    name = col?.name ?? '';
    if (app.server) load();
  });

  async function act(fn: () => Promise<unknown>, ok: string) {
    busy = true;
    const done = await app.run(fn, ok);
    busy = false;
    if (done !== undefined) {
      await load();
      await app.refresh(true);
    }
  }

  async function add(e: SubmitEvent) {
    e.preventDefault();
    if (!username.trim()) return;
    await act(() => api.addMember(id, username.trim(), role), `${username.trim()} получил доступ`);
    username = '';
  }

  async function remove(m: MemberView) {
    if (!confirm(`Убрать ${m.username} из папки «${col?.name}»? Ключ папки сменится, новые записи ему будут недоступны.`)) return;
    await act(() => api.removeMember(id, m.user_id), `${m.username} больше не видит папку`);
  }

  async function leave() {
    if (!confirm(`Покинуть папку «${col?.name}»? Она исчезнет с этого устройства.`)) return;
    if ((await app.run(() => api.leaveCollection(id), 'Вы покинули папку')) !== undefined) {
      app.modal = null;
      await app.refresh(true);
    }
  }

  async function rename(e: SubmitEvent) {
    e.preventDefault();
    await app.run(() => api.renameCollection(id, name), 'Папка переименована');
    await app.refresh();
  }
</script>

<Modal title={`Доступ · ${col?.name ?? ''}`} wide>
  <div class="stack">
    {#if col && col.role !== 'viewer'}
      <form class="row" onsubmit={rename}>
        <label class="field grow"><span>название папки</span><input bind:value={name} /></label>
        <button class="btn" disabled={!name.trim() || name === col.name}>Переименовать</button>
      </form>
    {/if}

    {#if !app.server}
      <p class="muted">Чтобы делиться папкой, подключите хранилище к серверу: Настройки → Сервер.</p>
    {:else if members === null}
      <p class="muted">загружаю участников…</p>
    {:else}
      <table>
        <thead><tr><th>кто</th><th>роль</th><th>отпечаток ключа</th><th></th></tr></thead>
        <tbody>
          {#each members as m (m.user_id)}
            <tr>
              <td>{m.username}{m.me ? ' (вы)' : ''}</td>
              <td>
                {#if isOwner && m.role !== 'owner'}
                  <select value={m.role} disabled={busy} onchange={(e) => act(() => api.setMemberRole(id, m.user_id, e.currentTarget.value), 'Роль изменена')}>
                    <option value="editor">редактор</option>
                    <option value="viewer">читатель</option>
                  </select>
                {:else}
                  {ROLES[m.role]}
                {/if}
              </td>
              <td class="fp" class:warn={m.key_changed}>
                {m.fingerprint}{#if m.key_changed}<br /><span class="err">ключ изменился — сверьте лично</span>{/if}
              </td>
              <td>{#if isOwner && m.role !== 'owner'}<button class="icon" disabled={busy} onclick={() => remove(m)} aria-label={`Убрать ${m.username}`}>убрать</button>{/if}</td>
            </tr>
          {/each}
        </tbody>
      </table>
      <p class="muted small">Отпечаток — короткая проверка ключа. Сравните его с тем, что видит у себя этот человек (Настройки → Сервер), голосом или лично.</p>

      {#if isOwner}
        <form class="row" onsubmit={add}>
          <label class="field grow"><span>имя пользователя на сервере</span><input bind:value={username} autocomplete="off" /></label>
          <label class="field"><span>роль</span>
            <select bind:value={role}><option value="editor">редактор</option><option value="viewer">читатель</option></select>
          </label>
          <button class="btn primary" disabled={busy || !username.trim()}>{busy ? 'жду сервер…' : 'Дать доступ'}</button>
        </form>
      {:else}
        <div><button class="btn danger" onclick={leave}>Покинуть папку</button></div>
      {/if}
    {/if}
  </div>
</Modal>

<style>
  .stack {
    display: grid;
    gap: 16px;
  }
  .row {
    display: flex;
    gap: 10px;
    align-items: end;
  }
  .grow {
    flex: 1;
  }
  table {
    width: 100%;
    border-collapse: collapse;
  }
  th {
    text-align: left;
    color: var(--muted);
    font-weight: 400;
    border-bottom: 1px solid var(--line);
    padding: 4px 6px;
  }
  td {
    padding: 6px;
    border-bottom: 1px solid var(--line);
    vertical-align: top;
  }
  td select {
    width: auto;
    padding: 2px 6px;
  }
  .fp {
    color: var(--accent);
    letter-spacing: 0.04em;
  }
  .fp.warn {
    color: var(--danger);
  }
  .small {
    font-size: 12px;
    margin: 0;
  }
  p {
    margin: 0;
  }
</style>
