<script lang="ts">
  import { app } from '../lib/state.svelte';
  import type { MenuItem } from '../lib/menus';

  type Entry = Exclude<MenuItem, 'sep'>;
  let el: HTMLElement | undefined = $state();
  let pos = $state({ x: 0, y: 0, flip: false });
  let active = $state(-1);
  let openSub = $state<number | null>(null);
  const items = $derived(app.menu?.items ?? []);
  const actionable = (i: number) => items[i] !== undefined && items[i] !== 'sep';

  // Keep the menu inside the window, focus it, start on the first entry.
  $effect(() => {
    const m = app.menu;
    if (!m || !el) return;
    const r = el.getBoundingClientRect();
    pos = {
      x: Math.max(4, Math.min(m.x, innerWidth - r.width - 4)),
      y: Math.max(4, Math.min(m.y, innerHeight - r.height - 4)),
      flip: m.x + r.width * 2 > innerWidth,
    };
    active = items.findIndex((_, i) => actionable(i));
    openSub = null;
    el.focus();
  });

  const close = () => (app.menu = null);
  function run(m: Entry) {
    close();
    m.run?.();
  }

  function step(delta: number) {
    if (!items.length) return;
    let i = active;
    do i = (i + delta + items.length) % items.length;
    while (!actionable(i));
    active = i;
    openSub = null;
  }

  function enterSub() {
    const m = items[active];
    if (m === 'sep' || !m?.sub) return false;
    openSub = active;
    queueMicrotask(() => el?.querySelector<HTMLElement>('.sub button')?.focus());
    return true;
  }

  function onKey(e: KeyboardEvent) {
    const inSub = (e.target as HTMLElement).closest('.sub');
    if (inSub) {
      const buttons = [...inSub.querySelectorAll<HTMLElement>('button')];
      const at = buttons.indexOf(e.target as HTMLElement);
      if (e.key === 'ArrowDown') buttons[(at + 1) % buttons.length]?.focus();
      else if (e.key === 'ArrowUp') buttons[(at - 1 + buttons.length) % buttons.length]?.focus();
      else if (e.key === 'ArrowLeft' || e.key === 'Escape') {
        openSub = null;
        el?.focus();
      } else return;
    } else if (e.key === 'ArrowDown') step(1);
    else if (e.key === 'ArrowUp') step(-1);
    else if (e.key === 'ArrowRight') enterSub();
    else if (e.key === 'Enter' || e.key === ' ') {
      const m = items[active];
      if (m && m !== 'sep' && !enterSub()) run(m);
    } else if (e.key === 'Escape' || e.key === 'Tab') close();
    else return;
    e.preventDefault();
    e.stopPropagation();
  }
</script>

<svelte:window
  onmousedown={(e) => app.menu && el && !el.contains(e.target as Node) && close()}
  onblur={close}
  onresize={close}
/>

{#if app.menu}
  <ul class="menu" role="menu" tabindex="-1" bind:this={el} style="left: {pos.x}px; top: {pos.y}px" onkeydown={onKey}>
    {#each items as m, i (i)}
      {#if m === 'sep'}
        <li class="sep" role="separator"></li>
      {:else}
        <li role="none" class="item" onmouseenter={() => ((active = i), (openSub = m.sub ? i : null))}>
          <button
            role="menuitem"
            tabindex="-1"
            class:on={active === i}
            class:danger={m.danger}
            aria-haspopup={m.sub ? 'menu' : undefined}
            aria-expanded={m.sub ? openSub === i : undefined}
            onclick={() => (m.sub ? (openSub = i) : run(m))}
          >
            <span>{m.label}</span><span class="keys">{m.sub ? '▸' : (m.keys ?? '')}</span>
          </button>
          {#if m.sub && openSub === i}
            <ul class="menu sub" class:flip={pos.flip} role="menu">
              {#each m.sub as s, j (j)}
                {#if s !== 'sep'}
                  <li role="none"><button role="menuitem" class:danger={s.danger} onclick={() => run(s)}><span>{s.label}</span></button></li>
                {/if}
              {/each}
            </ul>
          {/if}
        </li>
      {/if}
    {/each}
  </ul>
{/if}

<style>
  .menu {
    position: fixed;
    z-index: 900;
    min-width: 230px;
    margin: 0;
    padding: 4px 0;
    list-style: none;
    background: var(--raised);
    border: 1px solid var(--accent);
    box-shadow: 0 6px 24px color-mix(in srgb, var(--bg) 80%, transparent), 0 0 12px var(--glow);
    outline: none;
  }
  .item {
    position: relative;
  }
  button {
    width: 100%;
    display: flex;
    justify-content: space-between;
    gap: 24px;
    background: none;
    border: 0;
    padding: 3px 12px;
    text-align: left;
    cursor: pointer;
  }
  button.on,
  .sub button:hover,
  .sub button:focus-visible {
    background: var(--accent);
    color: var(--on-accent);
    outline: none;
  }
  button.danger {
    color: var(--danger);
  }
  button.on.danger {
    background: var(--danger);
    color: var(--on-accent);
  }
  .keys {
    color: var(--muted);
  }
  button.on .keys {
    color: inherit;
    opacity: 0.75;
  }
  .sep {
    height: 1px;
    margin: 4px 0;
    background: var(--line);
  }
  .sub {
    position: absolute;
    left: 100%;
    top: -5px;
  }
  .sub.flip {
    left: auto;
    right: 100%;
  }
</style>
