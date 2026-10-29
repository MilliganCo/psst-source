<script lang="ts">
  import { onMount } from 'svelte';
  import { open } from '@tauri-apps/plugin-dialog';
  import { api, errorText, inTauri } from '../lib/api';
  import { app } from '../lib/state.svelte';
  import Modal from './Modal.svelte';

  let path = $state('');
  let password = $state('');
  let colId = $state(app.collections.find((c) => c.kind === 'personal')?.id ?? '');
  let error = $state('');
  let busy = $state(false);

  const isLegacy = $derived(path.toLowerCase().endsWith('.vault'));
  const isBackup = $derived(path.toLowerCase().endsWith('.pwbak'));

  onMount(async () => {
    path = (await api.legacyVaultPath()) ?? '';
  });

  async function pick() {
    if (!inTauri) return;
    const p = await open({ multiple: false, filters: [{ name: 'Резервная копия, CSV или старое хранилище', extensions: ['pwbak', 'csv', 'vault'] }] });
    if (typeof p === 'string') path = p;
  }

  async function run(e: SubmitEvent) {
    e.preventDefault();
    error = '';
    busy = true;
    try {
      const n = isBackup
        ? await api.importBackup(path, password, colId)
        : isLegacy
          ? await api.importLegacy(path, password, colId)
          : await api.importCsv(path, colId);
      app.toast(isLegacy || isBackup ? `Импортировано записей: ${n}` : `Импортировано записей: ${n}. Удалите CSV-файл — пароли в нём не зашифрованы.`);
      await app.refresh();
      app.modal = null;
    } catch (err) {
      error = errorText(err);
    } finally {
      busy = false;
    }
  }
</script>

<Modal title="Импорт паролей" wide>
  <form class="stack" onsubmit={run}>
    <div class="help">
      <p>Перенесите пароли из браузера или другого менеджера: сначала экспортируйте их в CSV.</p>
      <ul class="muted">
        <li><b>Chrome / Edge:</b> Настройки → Автозаполнение → Менеджер паролей → Настройки → Экспорт паролей</li>
        <li><b>Firefox:</b> Пароли (about:logins) → ⋯ → Экспорт логинов</li>
        <li><b>Bitwarden:</b> Инструменты → Экспорт хранилища → формат .csv</li>
        <li><b>KeePass / KeePassXC:</b> Файл → Экспорт → CSV</li>
        <li><b>Резервная копия этой программы:</b> файл <code>.pwbak</code> из Настройки → «данные»</li>
        <li><b>Старая версия этой программы:</b> файл <code>vault.vault</code> из папки <code>.password_manager</code></li>
      </ul>
      <p class="muted">Папки и группы станут ярлыками. Исходный файл не изменится.</p>
    </div>
    <div class="field">
      <span>файл (.pwbak, .csv или .vault)</span>
      <div class="row"><input bind:value={path} spellcheck="false" /><button type="button" class="btn" onclick={pick}>Выбрать</button></div>
    </div>
    {#if isLegacy || isBackup}
      <label class="field"><span>{isBackup ? 'пароль копии' : 'мастер-пароль старой версии'}</span><input type="password" bind:value={password} /></label>
    {/if}
    <label class="field">
      <span>в папку</span>
      <select bind:value={colId}>
        {#each app.collections.filter((c) => c.role !== 'viewer') as c (c.id)}<option value={c.id}>{c.name}</option>{/each}
      </select>
    </label>
    {#if error}<p class="err">! {error}</p>{/if}
    <div class="row">
      <button class="btn primary" disabled={busy || !path || (isLegacy && !password)}>{busy ? 'импортирую…' : 'Импортировать'}</button>
      <button type="button" class="btn" onclick={() => (app.modal = null)}>Позже</button>
    </div>
  </form>
</Modal>

<style>
  .stack {
    display: grid;
    gap: 12px;
  }
  .row {
    display: flex;
    gap: 8px;
  }
  p {
    margin: 0;
  }
  ul {
    margin: 6px 0;
    padding-left: 18px;
    display: grid;
    gap: 2px;
    font-size: 12px;
  }
  .help {
    display: grid;
    gap: 4px;
  }
</style>
