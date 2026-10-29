<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errorText } from '../lib/api';
  import { app } from '../lib/state.svelte';

  const LOGO = 'PASSWORDS';
  let typed = $state('');
  let username = $state('');
  let password = $state('');
  let repeat = $state('');
  let error = $state('');
  let busy = $state(false);
  let recoveryCode = $state<string | null>(null);
  let saved = $state(false);
  let input: HTMLInputElement | undefined = $state();

  const creating = $derived(!app.status?.has_account);
  /** new = local vault; invite = new vault registered on a server; login = existing server account. */
  let mode = $state<'new' | 'invite' | 'login'>('new');
  let link = $state('');
  let serverNote = $state('');

  onMount(() => {
    // The one orchestrated moment: the logo types itself out.
    if (matchMedia('(prefers-reduced-motion: reduce)').matches || !app.settings.blink) {
      typed = LOGO;
    } else {
      let i = 0;
      const t = setInterval(() => {
        typed = LOGO.slice(0, ++i);
        if (i >= LOGO.length) clearInterval(t);
      }, 55);
    }
    input?.focus();
  });

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    error = '';
    if (creating && mode !== 'login') {
      if (!username.trim()) return (error = 'Введите имя');
      if (password.length < 8) return (error = 'Мастер-пароль — минимум 8 символов');
      if (password !== repeat) return (error = 'Пароли не совпадают');
    }
    if (creating && mode !== 'new' && !link.trim()) return (error = 'Вставьте ссылку от администратора');
    busy = true;
    try {
      if (creating && mode === 'login') {
        await api.loginServer(link.trim(), username, password);
        password = '';
        await app.refreshStatus();
      } else if (creating) {
        recoveryCode = await api.createLocal(username, password);
        if (mode === 'invite') {
          try {
            await api.connect(link.trim(), password, null);
            serverNote = 'Хранилище подключено к серверу.';
          } catch (err) {
            serverNote = `Не удалось подключиться к серверу: ${errorText(err)}. Хранилище создано на этом компьютере — подключите его в Настройки → Сервер (там можно указать другое имя).`;
          }
        }
      } else {
        await api.unlock(password);
        await app.refreshStatus();
      }
    } catch (err) {
      error = errorText(err);
      password = '';
      input?.focus();
    } finally {
      busy = false;
    }
  }

  async function finish() {
    password = repeat = '';
    await app.refreshStatus();
    if (await api.legacyVaultPath()) app.modal = { kind: 'import' };
  }
</script>

<div class="lock">
  <h1 class="logo glow"><span class="bar">▌</span>{typed}<span class="cursor"></span></h1>

  {#if recoveryCode}
    <div class="card">
      {#if serverNote}<p class:err={serverNote.startsWith('Не удалось')}>{serverNote}</p>{/if}
      <p>Хранилище создано. Это код восстановления — единственный способ вернуть доступ, если вы забудете мастер-пароль.</p>
      <div class="code glow">{recoveryCode}</div>
      <p class="muted">Запишите его на бумаге или сохраните в другом надёжном месте. Больше мы его не покажем.</p>
      <div class="row">
        <button class="btn" onclick={() => app.run(() => api.copyText(recoveryCode!, 120), 'Код скопирован')}>скопировать</button>
      </div>
      <label class="check"><input type="checkbox" bind:checked={saved} /> Я сохранил код</label>
      <button class="btn primary" disabled={!saved} onclick={finish}>Открыть хранилище</button>
    </div>
  {:else}
    <form class="card" onsubmit={submit}>
      {#if creating}
        <div class="modes" role="tablist">
          <button type="button" role="tab" class="chip" class:on={mode === 'new'} aria-selected={mode === 'new'} onclick={() => (mode = 'new')}>новое хранилище</button>
          <button type="button" role="tab" class="chip" class:on={mode === 'invite'} aria-selected={mode === 'invite'} onclick={() => (mode = 'invite')}>по приглашению</button>
          <button type="button" role="tab" class="chip" class:on={mode === 'login'} aria-selected={mode === 'login'} onclick={() => (mode = 'login')}>вход на сервер</button>
        </div>
        <p class="muted">
          {#if mode === 'new'}Хранилище только на этом компьютере. К серверу можно подключить позже.
          {:else if mode === 'invite'}Вставьте ссылку-приглашение от администратора и придумайте имя и мастер-пароль.
          {:else}У вас уже есть аккаунт на сервере: войдите, и записи загрузятся на это устройство.{/if}
        </p>
        {#if mode !== 'new'}
          <label class="field"><span>{mode === 'invite' ? 'ссылка-приглашение' : 'ссылка на сервер'} (pwd://…)</span><input bind:value={link} spellcheck="false" /></label>
        {/if}
        <label class="field"><span>имя</span><input bind:value={username} bind:this={input} autocomplete="username" /></label>
        <label class="field"><span>мастер-пароль</span><input type="password" bind:value={password} autocomplete={mode === 'login' ? 'current-password' : 'new-password'} /></label>
        {#if mode !== 'login'}
          <label class="field"><span>ещё раз</span><input type="password" bind:value={repeat} autocomplete="new-password" /></label>
        {/if}
      {:else}
        <p class="muted">Хранилище <b class="user">{app.status?.username}</b> заблокировано.</p>
        <label class="field">
          <span>мастер-пароль</span>
          <input type="password" bind:value={password} bind:this={input} autocomplete="current-password" />
        </label>
      {/if}
      {#if error}<p class="err">! {error}</p>{/if}
      <button class="btn primary" disabled={busy || !password}>
        {busy ? 'проверяю…' : !creating ? 'Разблокировать' : mode === 'login' ? 'Войти' : 'Создать хранилище'}
      </button>
    </form>
  {/if}
</div>

<style>
  .lock {
    height: 100%;
    display: grid;
    place-content: center;
    gap: 24px;
    padding: 24px;
  }
  .logo {
    margin: 0;
    font-size: 44px;
    font-weight: 700;
    letter-spacing: 0.04em;
    color: var(--accent);
    min-height: 1.3em;
  }
  .bar {
    margin-right: 0.1em;
  }
  .card {
    width: min(420px, calc(100vw - 48px));
    display: grid;
    gap: 12px;
    border-left: 2px solid var(--accent);
    padding: 4px 0 4px 16px;
  }
  .card p {
    margin: 0;
  }
  .user {
    color: var(--fg);
  }
  .code {
    font-size: 22px;
    font-weight: 700;
    color: var(--accent);
    letter-spacing: 0.06em;
    word-break: break-all;
  }
  .row {
    display: flex;
    gap: 8px;
  }
  .modes {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
  }
  .check {
    display: flex;
    gap: 8px;
    align-items: center;
  }
</style>
