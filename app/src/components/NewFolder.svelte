<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import { app } from '../lib/state.svelte';
  import Modal from './Modal.svelte';

  let name = $state('');
  let input: HTMLInputElement | undefined = $state();
  onMount(() => input?.focus());

  async function create(e: SubmitEvent) {
    e.preventDefault();
    const id = await app.run(() => api.createCollection(name), `Папка «${name.trim()}» создана`);
    if (id) {
      await app.refresh();
      app.tab = id;
      app.modal = app.server ? { kind: 'share', id } : null;
    }
  }
</script>

<Modal title="Новая папка">
  <form class="stack" onsubmit={create}>
    <p class="muted">Общую папку можно открыть другим людям на сервере. Свои ярлыки у каждой папки отдельные.</p>
    <label class="field"><span>название</span><input bind:this={input} bind:value={name} placeholder="например, Семья" /></label>
    <div><button class="btn primary" disabled={!name.trim()}>Создать</button></div>
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
