<script lang="ts">
  import { save } from '@tauri-apps/plugin-dialog';
  import { api, errorText, inTauri } from '../lib/api';
  import { app, THEMES } from '../lib/state.svelte';
  import type { AdminUser, SessionInfo } from '../lib/types';
  import Modal from './Modal.svelte';

  let oldPw = $state('');
  let newPw = $state('');
  let repeat = $state('');
  let pwError = $state('');
  let busy = $state(false);

  // server
  let link = $state('');
  let connectPw = $state('');
  let recovery = $state('');
  let needRecovery = $state(false);
  let connectError = $state('');
  let connecting = $state(false);
  let inviteAdmin = $state(false);
  let inviteLink = $state('');
  let users = $state<AdminUser[] | null>(null);
  let serverName = $state(app.status?.username ?? '');
  let newLink = $state('');

  const TABS = [
    ['look', 'вид'],
    ['security', 'безопасность'],
    ['server', 'сервер'],
    ['account', 'аккаунт'],
    ['data', 'данные'],
    ['about', 'о программе'],
  ] as const;
  let tab = $state<(typeof TABS)[number][0]>(app.update ? 'about' : 'look');

  async function moveServer(e: SubmitEvent) {
    e.preventDefault();
    if ((await app.run(() => api.updateServerLink(newLink.trim()), 'Адрес сервера обновлён')) !== undefined) {
      newLink = '';
      app.server = await api.serverStatus();
    }
  }

  async function connect(e: SubmitEvent) {
    e.preventDefault();
    connectError = '';
    connecting = true;
    try {
      await api.connect(link.trim(), connectPw, needRecovery ? recovery : null, serverName.trim() || null);
      app.toast('Хранилище подключено к серверу');
      link = connectPw = recovery = '';
      await app.refreshStatus();
    } catch (err) {
      if (String(err) === 'invalid: recovery code required') needRecovery = true;
      connectError = errorText(err);
    } finally {
      connecting = false;
    }
  }

  let devices = $state<SessionInfo[] | null>(null);
  async function loadDevices() {
    devices = (await app.run(() => api.sessions())) ?? null;
  }
  async function logoutDevice(d: SessionInfo) {
    if ((await app.run(() => api.revokeSession(d.id), `${d.device || 'Устройство'}: выход выполнен`)) !== undefined) await loadDevices();
  }
  async function logoutOthers() {
    if (!confirm('Выйти на всех других устройствах? Там попросят войти заново, данные на них останутся зашифрованными.')) return;
    if ((await app.run(() => api.revokeOtherSessions(), 'Другие устройства отключены')) !== undefined) await loadDevices();
  }
  const ago = (unix: number) => {
    const min = Math.round((Date.now() / 1000 - unix) / 60);
    if (min < 2) return 'сейчас';
    if (min < 60) return `${min} мин назад`;
    if (min < 48 * 60) return `${Math.round(min / 60)} ч назад`;
    return new Date(unix * 1000).toLocaleDateString('ru-RU');
  };

  async function invite() {
    const l = await app.run(() => api.adminInvite(inviteAdmin));
    if (l) inviteLink = l;
  }

  async function loadUsers() {
    users = (await app.run(() => api.adminUsers())) ?? null;
  }

  async function toggleUser(u: AdminUser) {
    await app.run(() => api.adminDisable(u.id, !u.disabled), u.disabled ? `${u.username} разблокирован` : `${u.username} заблокирован`);
    await loadUsers();
  }

  const copy = (text: string, what: string) => app.run(() => api.copyText(text, 0), `${what} скопирована`);
  const when = (iso: string | null) => (iso ? new Date(iso).toLocaleString('ru-RU') : 'ещё не было');

  const set = <K extends keyof typeof app.settings>(k: K, v: (typeof app.settings)[K]) => {
    app.settings[k] = v;
    app.applySettings();
  };

  // data
  let bkPw = $state('');
  let bkRepeat = $state('');
  let bkError = $state('');
  const today = () => new Date().toISOString().slice(0, 10);

  async function exportBackup(e: SubmitEvent) {
    e.preventDefault();
    bkError = '';
    if (bkPw.length < 8) return (bkError = 'Пароль копии — минимум 8 символов');
    if (bkPw !== bkRepeat) return (bkError = 'Пароли не совпадают');
    const path = inTauri ? await save({ defaultPath: `passwords-${today()}.pwbak`, filters: [{ name: 'Резервная копия', extensions: ['pwbak'] }] }) : null;
    if (!path) return;
    busy = true;
    try {
      const n = await api.exportBackup(path, bkPw);
      app.toast(`Копия сохранена: ${n} записей`);
      bkPw = bkRepeat = '';
    } catch (err) {
      bkError = errorText(err);
    } finally {
      busy = false;
    }
  }

  async function exportCsv() {
    if (!confirm('В CSV пароли лежат открытым текстом: любой, кто получит файл, прочитает их. Используйте его только для переезда и сразу удалите. Продолжить?')) return;
    const path = inTauri ? await save({ defaultPath: `passwords-${today()}.csv`, filters: [{ name: 'CSV', extensions: ['csv'] }] }) : null;
    if (path) await app.run(() => api.exportCsv(path).then((n) => app.toast(`Сохранено в CSV: ${n} записей. Удалите файл, когда он станет не нужен.`)));
  }

  async function changePassword(e: SubmitEvent) {
    e.preventDefault();
    pwError = '';
    if (newPw.length < 8) return (pwError = 'Новый пароль — минимум 8 символов');
    if (newPw !== repeat) return (pwError = 'Пароли не совпадают');
    busy = true;
    try {
      await api.changePassword(oldPw, newPw);
      app.toast('Мастер-пароль изменён');
      oldPw = newPw = repeat = '';
    } catch (err) {
      pwError = errorText(err);
    } finally {
      busy = false;
    }
  }
</script>

<Modal title="Настройки" wide>
  <div class="tabs" role="tablist" aria-label="Разделы настроек">
    {#each TABS as [id, name] (id)}
      <button role="tab" aria-selected={tab === id} class:on={tab === id} onclick={() => (tab = id)}>{name}</button>
    {/each}
  </div>
  <div class="stack">
    {#if tab === 'look'}
    <section>
      <h3>тема</h3>
      <div class="themes">
        {#each THEMES as t (t.id)}
          <button class="theme" class:on={app.settings.theme === t.id} data-theme={t.id} onclick={() => set('theme', t.id)}>
            <span class="sample"><b>&gt;</b> {t.name}<span class="dots"><i style="background: var(--l-red)"></i><i style="background: var(--l-green)"></i><i style="background: var(--l-blue)"></i><i style="background: var(--l-yellow)"></i></span></span>
          </button>
        {/each}
      </div>
    </section>

    <section>
      <h3>эффекты</h3>
      <div class="cols">
        <label class="check"><input type="checkbox" checked={app.settings.glow} onchange={(e) => set('glow', e.currentTarget.checked)} /> свечение текста</label>
        <label class="check"><input type="checkbox" checked={app.settings.vhs} onchange={(e) => set('vhs', e.currentTarget.checked)} /> VHS: сканлайны, бегущая полоса, цветная кайма</label>
        <label class="check"><input type="checkbox" checked={app.settings.pixels} onchange={(e) => set('pixels', e.currentTarget.checked)} /> пиксели: сетка экрана и острые края</label>
        <label class="check"><input type="checkbox" checked={app.settings.blink} onchange={(e) => set('blink', e.currentTarget.checked)} /> мигающий курсор</label>
      </div>
    </section>

    <section class="cols">
      <label class="field">
        <span>масштаб интерфейса</span>
        <select value={app.settings.scale} onchange={(e) => set('scale', Number(e.currentTarget.value))}>
          {#each [80, 90, 100, 110, 125, 150] as z (z)}<option value={z}>{z}%</option>{/each}
        </select>
      </label>
      <label class="field">
        <span>плотность списка</span>
        <select value={app.settings.density} onchange={(e) => set('density', e.currentTarget.value as typeof app.settings.density)}>
          <option value="compact">плотно</option>
          <option value="normal">обычно</option>
          <option value="comfy">просторно</option>
        </select>
      </label>
    </section>
    {/if}

    {#if tab === 'security'}
    <section class="cols">
      <label class="field">
        <span>блокировать после бездействия</span>
        <select value={app.settings.autolockMin} onchange={(e) => set('autolockMin', Number(e.currentTarget.value))}>
          {#each [1, 5, 10, 15, 30, 60] as m (m)}<option value={m}>{m} мин</option>{/each}
          <option value={0}>никогда</option>
        </select>
      </label>
      <label class="field">
        <span>очищать буфер обмена через</span>
        <select value={app.settings.clipboardSec} onchange={(e) => set('clipboardSec', Number(e.currentTarget.value))}>
          {#each [10, 20, 30, 60, 120] as s (s)}<option value={s}>{s} с</option>{/each}
          <option value={0}>не очищать</option>
        </select>
      </label>
      <label class="field">
        <span>скрывать показанный пароль через</span>
        <select value={app.settings.revealSec} onchange={(e) => set('revealSec', Number(e.currentTarget.value))}>
          {#each [10, 20, 30, 60] as s (s)}<option value={s}>{s} с</option>{/each}
          <option value={0}>не скрывать</option>
        </select>
      </label>
    </section>

    <section>
      <label class="check"><input type="checkbox" checked={app.settings.lockOnMinimize} onchange={(e) => set('lockOnMinimize', e.currentTarget.checked)} /> блокировать при сворачивании окна</label>
      <label class="check"><input type="checkbox" checked={app.settings.chatNotify} onchange={(e) => set('chatNotify', e.currentTarget.checked)} /> уведомлять о новых сообщениях в чате (без текста сообщения)</label>
      <label class="check"><input type="checkbox" checked={app.settings.closeToTray} onchange={(e) => set('closeToTray', e.currentTarget.checked)} /> при закрытии окна оставаться в трее — «Выход» в меню значка (Windows)</label>
      <label class="check"><input type="checkbox" checked={app.settings.screenProtect} onchange={(e) => set('screenProtect', e.currentTarget.checked)} /> прятать окно от скриншотов и демонстрации экрана (Windows)</label>
      <p class="muted">При блокировке буфер обмена очищается, если в нём ещё лежит скопированный пароль. После пяти неверных мастер-паролей подряд вход ненадолго закрывается.</p>
    </section>
    {/if}

    {#if tab === 'server'}
    <section>
      <h3>сервер</h3>
      {#if app.server}
        <dl class="kv">
          <dt>адрес</dt><dd>{app.server.url}</dd>
          <dt>вы</dt><dd>{app.server.username}{app.server.is_admin ? ' · администратор' : ''}</dd>
          <dt>ваш отпечаток</dt><dd class="fp">{app.server.fingerprint}</dd>
          <dt>синхронизация</dt><dd>{when(app.server.last_sync)}</dd>
        </dl>
        <div class="row">
          <button class="btn" onclick={() => app.syncNow(true)}>Синхронизировать</button>
          <button class="btn" onclick={() => copy(app.server!.link, 'Ссылка для входа')}>Ссылка для другого устройства</button>
        </div>
        <form class="row" onsubmit={moveServer}>
          <input bind:value={newLink} placeholder="сервер переехал? вставьте новую ссылку (pwd://…)" spellcheck="false" />
          <button class="btn" disabled={!newLink.trim()}>Сменить адрес</button>
        </form>
        <h3 class="sub">устройства</h3>
        {#if devices}
          <ul class="users">
            {#each devices as d (d.id)}
              <li>
                <span>{d.device || 'неизвестное устройство'} <span class="muted">· {d.current ? 'это устройство' : ago(d.last_seen)}</span></span>
                {#if !d.current}<button class="icon" onclick={() => logoutDevice(d)}>выйти</button>{/if}
              </li>
            {/each}
          </ul>
          {#if devices.length > 1}<div class="row"><button class="btn danger" onclick={logoutOthers}>Выйти на всех других устройствах</button></div>{/if}
        {:else}
          <button class="btn" onclick={loadDevices}>Показать устройства</button>
        {/if}
        {#if app.server.is_admin}
          <h3 class="sub">приглашения и пользователи</h3>
          <div class="row">
            <button class="btn primary" onclick={invite}>Создать приглашение</button>
            <label class="check"><input type="checkbox" bind:checked={inviteAdmin} /> с правами администратора</label>
          </div>
          {#if inviteLink}
            <div class="row"><code class="link">{inviteLink}</code><button class="btn" onclick={() => copy(inviteLink, 'Ссылка-приглашение')}>копировать</button></div>
          {/if}
          <p class="muted">Приглашение одноразовое и действует 7 дней. Передайте ссылку человеку — он откроет её в приложении.</p>
          {#if users}
            <ul class="users">
              {#each users as u (u.id)}
                <li>
                  <span>{u.username}{u.is_admin ? ' · админ' : ''}{u.disabled ? ' · заблокирован' : ''}</span>
                  {#if u.username !== app.server.username}<button class="icon" onclick={() => toggleUser(u)}>{u.disabled ? 'разблокировать' : 'заблокировать'}</button>{/if}
                </li>
              {/each}
            </ul>
          {:else}
            <button class="btn" onclick={loadUsers}>Показать пользователей</button>
          {/if}
        {/if}
      {:else}
        <form class="cols" onsubmit={connect}>
          <label class="field wide"><span>ссылка-приглашение (pwd://…)</span><input bind:value={link} spellcheck="false" /></label>
          <label class="field"><span>ваше имя на сервере</span><input bind:value={serverName} autocomplete="username" /></label>
          <label class="field"><span>мастер-пароль этого хранилища</span><input type="password" bind:value={connectPw} autocomplete="current-password" /></label>
          {#if needRecovery}<label class="field"><span>код восстановления</span><input bind:value={recovery} spellcheck="false" /></label>{:else}<span></span>{/if}
          {#if connectError}<p class="err wide">! {connectError}</p>{/if}
          <div class="wide"><button class="btn primary" disabled={connecting || !link || !connectPw}>{connecting ? 'подключаю…' : 'Подключить к серверу'}</button></div>
        </form>
        <p class="muted">Записи уйдут на сервер только в зашифрованном виде. Сервер не знает ни паролей, ни названий.</p>
      {/if}
    </section>
    {/if}

    {#if tab === 'account'}
    <section>
      <h3>мастер-пароль</h3>
      <form class="cols" onsubmit={changePassword}>
        <label class="field"><span>текущий</span><input type="password" bind:value={oldPw} autocomplete="current-password" /></label>
        <span></span>
        <label class="field"><span>новый</span><input type="password" bind:value={newPw} autocomplete="new-password" /></label>
        <label class="field"><span>ещё раз</span><input type="password" bind:value={repeat} autocomplete="new-password" /></label>
        {#if pwError}<p class="err wide">! {pwError}</p>{/if}
        <div class="wide"><button class="btn" disabled={busy || !oldPw || !newPw}>{busy ? 'меняю…' : 'Сменить пароль'}</button></div>
      </form>
      <p class="muted">Код восстановления после смены пароля остаётся прежним. Другие устройства, подключённые к серверу, попросят войти заново.</p>
    </section>
    {/if}

    {#if tab === 'data'}
    <section>
      <h3>резервная копия</h3>
      <p class="muted">Все пароли и заметки из всех папок в одном файле, зашифрованном отдельным паролем. Храните его на флешке или в облаке; восстановить можно без сервера через «Импорт».</p>
      <form class="cols" onsubmit={exportBackup}>
        <label class="field"><span>пароль копии</span><input type="password" bind:value={bkPw} autocomplete="new-password" /></label>
        <label class="field"><span>ещё раз</span><input type="password" bind:value={bkRepeat} autocomplete="new-password" /></label>
        {#if bkError}<p class="err wide">! {bkError}</p>{/if}
        <div class="wide"><button class="btn primary" disabled={busy || !bkPw}>Сохранить копию…</button></div>
      </form>
    </section>
    <section>
      <h3>импорт и экспорт</h3>
      <div class="row">
        <button class="btn" onclick={() => (app.modal = { kind: 'import' })}>Импорт…</button>
        <button class="btn danger" onclick={exportCsv}>Экспорт в CSV (без шифрования)…</button>
      </div>
      <p class="muted">Импорт понимает резервную копию, CSV из Chrome, Edge, Firefox, Bitwarden, KeePass и файл старой версии.</p>
    </section>
    {/if}

    {#if tab === 'about'}
    <section>
      <h3>версия</h3>
      <p>Passwords {__APP_VERSION__}</p>
      {#if app.update}
        <p>Доступна версия {app.update.version}. {app.update.notes}</p>
        <div class="row"><button class="btn primary" onclick={() => app.installUpdate()}>Установить {app.update.version}</button></div>
      {:else if app.server}
        <div class="row"><button class="btn" onclick={() => app.checkUpdate(true)}>Проверить обновления</button></div>
      {/if}
      <p class="muted">
        {app.server
          ? 'Обновления приходят с вашего сервера. Приложение ставит только сборки, подписанные ключом разработчика.'
          : 'Обновления приходят с сервера. Без сервера ставьте новую версию вручную.'}
      </p>
    </section>
    <section>
      <h3>благодарности</h3>
      <p class="muted">Шрифт JetBrains Mono (OFL). Словарь фраз — EFF Large Wordlist (CC BY 3.0 US). Оценка паролей — zxcvbn. Символы чата — Nerd Fonts (MIT; Material Design Icons — Apache 2.0).</p>
    </section>
    {/if}
  </div>
</Modal>

<style>
  .tabs {
    display: flex;
    gap: 4px;
    margin: -4px 0 16px;
    border-bottom: 1px solid var(--line);
    flex-wrap: wrap;
  }
  .tabs button {
    background: none;
    border: 1px solid transparent;
    border-bottom: 0;
    padding: 3px 12px;
    color: var(--muted);
    cursor: pointer;
    margin-bottom: -1px;
  }
  .tabs button.on {
    color: var(--accent);
    border-color: var(--line);
    background: var(--surface);
  }
  .stack {
    display: grid;
    gap: 22px;
  }
  h3 {
    margin: 0 0 8px;
    font-size: 13px;
    color: var(--muted);
    font-weight: 400;
  }
  .themes {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
    gap: 8px;
    margin-bottom: 10px;
  }
  .theme {
    background: var(--bg);
    color: var(--fg);
    border: 1px solid var(--line);
    padding: 10px;
    cursor: pointer;
    text-align: left;
  }
  .theme.on {
    border-color: var(--accent);
    box-shadow: 0 0 0 1px var(--accent);
  }
  .sample b {
    color: var(--accent);
  }
  .dots {
    display: flex;
    gap: 4px;
    margin-top: 6px;
  }
  .dots i {
    width: 10px;
    height: 10px;
    border-radius: 50%;
  }
  .cols {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px 16px;
  }
  .wide {
    grid-column: span 2;
    margin: 0;
  }
  .check {
    display: flex;
    gap: 8px;
    align-items: center;
  }
  .row {
    display: flex;
    gap: 8px;
    align-items: center;
    flex-wrap: wrap;
    margin-top: 10px;
  }
  .kv {
    display: grid;
    grid-template-columns: 12em 1fr;
    gap: 4px 12px;
    margin: 0;
  }
  .kv dt {
    color: var(--muted);
  }
  .kv dd {
    margin: 0;
    word-break: break-all;
  }
  .fp {
    color: var(--accent);
    letter-spacing: 0.04em;
  }
  .sub {
    margin-top: 18px;
  }
  .link {
    flex: 1;
    word-break: break-all;
    color: var(--accent);
    background: var(--bg);
    padding: 4px 8px;
    border: 1px dashed var(--line);
  }
  .users {
    list-style: none;
    padding: 0;
    margin: 10px 0 0;
    display: grid;
    gap: 4px;
  }
  .users li {
    display: flex;
    justify-content: space-between;
  }
  p {
    margin: 8px 0 0;
  }
</style>
