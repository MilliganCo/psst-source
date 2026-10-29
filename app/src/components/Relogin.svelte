<script lang="ts">
  import { api, errorText } from '../lib/api';
  import { app } from '../lib/state.svelte';
  import Modal from './Modal.svelte';

  let password = $state('');
  let error = $state('');
  let busy = $state(false);

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    error = '';
    try {
      await api.relogin(password);
      app.sync = 'idle';
      app.modal = null;
      app.toast('Снова на связи с сервером');
      await app.syncNow();
    } catch (err) {
      error = errorText(err);
    } finally {
      busy = false;
      password = '';
    }
  }
</script>

<Modal title="Вход на сервер">
  <form class="stack" onsubmit={submit}>
    <p>Сессия на сервере истекла. Правки сохраняются на этом устройстве и уйдут на сервер после входа.</p>
    <label class="field"><span>мастер-пароль</span><input type="password" bind:value={password} autocomplete="current-password" /></label>
    {#if error}<p class="err">! {error}</p>{/if}
    <div><button class="btn primary" disabled={busy || !password}>{busy ? 'вхожу…' : 'Войти'}</button></div>
  </form>
</Modal>

<style>
  .stack {
    display: grid;
    gap: 12px;
  }
  p {
    margin: 0;
  }
</style>
