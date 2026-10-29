<script lang="ts">
  import { onMount } from 'svelte';
  import { getCurrentWindow } from '@tauri-apps/api/window';
  import { listen } from '@tauri-apps/api/event';
  import './app.css';
  import { inTauri } from './lib/api';
  import { app } from './lib/state.svelte';
  import Lock from './components/Lock.svelte';
  import Main from './components/Main.svelte';
  import Toasts from './components/Toasts.svelte';
  import ContextMenu from './components/ContextMenu.svelte';

  // The browser's own menu (reload, print, inspect) is noise here; text fields keep it for paste.
  const editable = (t: EventTarget | null) =>
    t instanceof HTMLElement && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable);

  let ready = $state(false);

  onMount(() => {
    app.applySettings();
    app.refreshStatus().finally(() => (ready = true));
    if (!inTauri) return;
    // Lock on minimize (when enabled). Minimizing does not always hide the page, so ask the window.
    const win = getCurrentWindow();
    const off = win.onResized(async () => {
      if (app.settings.lockOnMinimize && app.status?.unlocked && (await win.isMinimized())) app.lock();
    });
    // "Заблокировать" in the tray menu already locked the vault in Rust; reset the screen.
    const offTray = listen('vault-locked', () => app.lock());
    return () => {
      void off.then((f) => f());
      void offTray.then((f) => f());
    };
  });

  function onVisibility() {
    if (document.hidden && app.settings.lockOnMinimize && app.status?.unlocked) app.lock();
    else checkIdle();
  }

  // Auto-lock after N idle minutes (0 = never). Checked by wall clock, so sleep counts as idle.
  let lastActive = Date.now();
  const bump = () => (lastActive = Date.now());
  function checkIdle() {
    const min = app.settings.autolockMin;
    if (app.status?.unlocked && min > 0 && Date.now() - lastActive > min * 60_000) app.lock();
  }
  $effect(() => {
    const t = setInterval(checkIdle, 15_000);
    return () => clearInterval(t);
  });
</script>

<svelte:window oncontextmenu={(e) => !editable(e.target) && e.preventDefault()} onmousemove={bump} onkeydown={bump} onmousedown={bump} onwheel={bump} onfocus={checkIdle} />
<svelte:document onvisibilitychange={onVisibility} />

{#if ready && app.status}
  {#if app.status.unlocked}
    <Main />
  {:else}
    <Lock />
  {/if}
{/if}
<Toasts />
<ContextMenu />
