<script lang="ts">
  import type { Snippet } from 'svelte';
  import { app } from '../lib/state.svelte';

  let {
    title,
    children,
    wide = false,
    canClose = () => true,
  }: { title: string; children: Snippet; wide?: boolean; canClose?: () => boolean } = $props();

  export function close() {
    if (canClose()) app.modal = null;
  }
</script>

<svelte:window onkeydown={(e) => e.key === 'Escape' && close()} />

<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
<div class="backdrop" onmousedown={(e) => e.target === e.currentTarget && close()}>
  <div class="panel" class:wide role="dialog" aria-modal="true" aria-label={title} tabindex="-1">
    <header>
      <span class="glow">┤ {title} ├</span>
      <button class="icon" onclick={close} aria-label="Закрыть">✕</button>
    </header>
    <div class="body">{@render children()}</div>
  </div>
</div>

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    background: color-mix(in srgb, var(--bg) 70%, transparent);
    display: grid;
    place-items: center;
    z-index: 500;
  }
  .panel {
    width: min(560px, calc(100vw - 32px));
    max-height: calc(100vh - 48px);
    display: flex;
    flex-direction: column;
    background: var(--surface);
    border: 1px solid var(--accent);
    box-shadow: 0 0 0 4px var(--bg), 0 0 30px var(--glow);
  }
  .panel.wide {
    width: min(760px, calc(100vw - 32px));
  }
  header {
    display: flex;
    justify-content: space-between;
    padding: 6px 10px;
    border-bottom: 1px solid var(--line);
    color: var(--accent);
  }
  .body {
    padding: 14px;
    overflow: auto;
  }
</style>
