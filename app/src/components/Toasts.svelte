<script lang="ts">
  import { app } from '../lib/state.svelte';
</script>

<div class="toasts" role="status" aria-live="polite">
  {#each app.toasts as t (t.id)}
    <div class="toast" class:err={t.err}>{t.err ? '!' : '✓'} {t.text}</div>
  {/each}
</div>

<style>
  .toasts {
    position: fixed;
    right: 14px;
    bottom: 34px;
    display: grid;
    gap: 6px;
    z-index: 900;
    max-width: 420px;
  }
  .toast {
    background: var(--raised);
    border: 1px solid var(--accent);
    color: var(--fg);
    padding: 6px 12px;
  }
  .toast.err {
    border-color: var(--danger);
    color: var(--danger);
  }
</style>
