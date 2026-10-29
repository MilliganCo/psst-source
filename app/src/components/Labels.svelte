<script lang="ts">
  import { api } from '../lib/api';
  import { app } from '../lib/state.svelte';
  import { LABEL_COLORS, type Label, type LabelColor } from '../lib/types';
  import Modal from './Modal.svelte';

  let colId = $state(app.targetCol?.id ?? '');
  const col = $derived(app.cols.get(colId));
  const editable = $derived(col?.role !== 'viewer');
  const COLOR_NAMES: Record<LabelColor, string> = {
    red: 'красный', orange: 'оранжевый', yellow: 'жёлтый', green: 'зелёный', teal: 'бирюзовый',
    blue: 'синий', purple: 'фиолетовый', pink: 'розовый', gray: 'серый',
  };
  let name = $state('');
  let color = $state<LabelColor>('blue');

  async function save(label: Label) {
    if ((await app.run(() => api.saveLabel(colId, label))) !== undefined) await app.refresh();
  }

  async function add(e: SubmitEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    await save({ id: crypto.randomUUID(), name: name.trim(), color });
    name = '';
  }

  async function remove(l: Label) {
    if (!confirm(`Удалить ярлык «${l.name}»? Записи останутся, ярлык снимется с них.`)) return;
    await app.run(() => api.deleteLabel(colId, l.id), 'Ярлык удалён');
    await app.refresh();
  }
</script>

<Modal title="Ярлыки">
  <div class="stack">
    <label class="field">
      <span>папка</span>
      <select bind:value={colId}>
        {#each app.collections as c (c.id)}<option value={c.id}>{c.name}</option>{/each}
      </select>
    </label>

    <ul>
      {#each col?.labels ?? [] as l (l.id)}
        <li>
          <span class="dot" style="--c: var(--l-{l.color})"></span>
          <input value={l.name} disabled={!editable} onchange={(e) => save({ ...l, name: e.currentTarget.value })} aria-label="Имя ярлыка" />
          <span class="swatches" role="radiogroup" aria-label="Цвет">
            {#each LABEL_COLORS as c (c)}
              <button
                class="sw"
                class:on={c === l.color}
                style="--c: var(--l-{c})"
                disabled={!editable}
                aria-label={COLOR_NAMES[c]}
                onclick={() => save({ ...l, color: c })}
              ></button>
            {/each}
          </span>
          {#if editable}<button class="icon" onclick={() => remove(l)} aria-label="Удалить">✕</button>{/if}
        </li>
      {:else}
        <li class="muted">Ярлыков пока нет.</li>
      {/each}
    </ul>

    {#if editable}
      <form class="add" onsubmit={add}>
        <span class="dot" style="--c: var(--l-{color})"></span>
        <input bind:value={name} placeholder="новый ярлык" aria-label="Новый ярлык" />
        <span class="swatches">
          {#each LABEL_COLORS as c (c)}
            <button type="button" class="sw" class:on={c === color} style="--c: var(--l-{c})" aria-label={COLOR_NAMES[c]} onclick={() => (color = c)}></button>
          {/each}
        </span>
        <button class="btn primary">Добавить</button>
      </form>
    {:else}
      <p class="muted">В этой папке у вас только чтение.</p>
    {/if}
  </div>
</Modal>

<style>
  .stack {
    display: grid;
    gap: 14px;
  }
  ul {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: 6px;
  }
  li,
  .add {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  li input,
  .add input {
    flex: 1;
    min-width: 0;
  }
  .swatches {
    display: flex;
    gap: 3px;
  }
  .sw {
    width: 14px;
    height: 14px;
    border-radius: 50%;
    border: 2px solid transparent;
    background: var(--c);
    padding: 0;
    cursor: pointer;
  }
  .sw.on {
    border-color: var(--fg);
  }
</style>
