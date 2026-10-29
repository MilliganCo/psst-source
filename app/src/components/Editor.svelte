<script lang="ts">
  import { onMount } from 'svelte';
  import { api } from '../lib/api';
  import { app } from '../lib/state.svelte';
  import { crackTime, strengthLabel } from '../lib/strength';
  import { LABEL_COLORS, type GeneratorOptions, type ItemInput, type PasswordCheck } from '../lib/types';
  import Modal from './Modal.svelte';

  let { id }: { id: string | null } = $props();

  const writable = $derived(app.collections.filter((c) => c.role !== 'viewer'));
  let form = $state<ItemInput>({
    id: null,
    collection_id: app.targetCol?.id ?? '',
    kind: 'login',
    title: '',
    username: '',
    password: '',
    urls: [],
    notes: '',
    totp: null,
    labels: [],
    favorite: false,
  });
  let urlsText = $state('');
  let showPassword = $state(false);
  /** For an existing item the password stays untouched (null) until the user edits it. */
  // svelte-ignore state_referenced_locally
  let passwordTouched = $state(id === null);
  let hadPassword = $state(false);
  let hadTotp = $state(false);
  type Gen = GeneratorOptions & { mode: 'chars' | 'words'; words: number; separator: string };
  const GEN_DEFAULTS: Gen = {
    length: 20, upper: true, lower: true, digits: true, symbols: true, exclude_similar: true, mode: 'chars', words: 5, separator: '-',
  };
  /** The generator remembers its last settings (per device, not secret). */
  function loadGen(): Gen {
    try {
      return { ...GEN_DEFAULTS, ...JSON.parse(localStorage.getItem('generator') ?? '{}') };
    } catch {
      return { ...GEN_DEFAULTS };
    }
  }
  let gen = $state<Gen>(loadGen());
  let genOpen = $state(false);
  let saving = $state(false);
  let titleInput: HTMLInputElement | undefined = $state();
  let modal: { close: () => void } | undefined = $state();
  let pristine = '';
  const snapshot = () => JSON.stringify([form, urlsText]);
  const canClose = () => saving || snapshot() === pristine || confirm('Закрыть без сохранения? Изменения пропадут.');

  const colLabels = $derived(app.cols.get(form.collection_id)?.labels ?? []);

  onMount(async () => {
    if (id) {
      const d = await app.run(() => api.get(id));
      if (d) {
        form = { ...form, id, collection_id: d.collection_id, kind: d.kind, title: d.title, username: d.username, password: null, urls: d.urls, notes: d.notes, totp: null, labels: d.labels, favorite: d.favorite };
        urlsText = d.urls.join('\n');
        hadPassword = d.has_password;
        hadTotp = d.has_totp;
      }
    }
    pristine = snapshot();
    titleInput?.focus();
  });

  async function revealCurrent() {
    if (!id) return;
    const p = await app.run(() => api.reveal(id, 'password'));
    if (p !== undefined) {
      form.password = p;
      passwordTouched = true;
      showPassword = true;
    }
  }

  async function generate() {
    try {
      localStorage.setItem('generator', JSON.stringify(gen));
    } catch {
      /* storage unavailable: defaults next time */
    }
    const p = await app.run(() =>
      gen.mode === 'words' ? api.generatePassphrase(gen.words, gen.separator) : api.generate(gen),
    );
    if (p !== undefined) {
      form.password = p;
      passwordTouched = true;
      showPassword = true;
    }
  }

  // Strength and reuse of the password being typed, debounced.
  let check = $state<PasswordCheck | null>(null);
  $effect(() => {
    const pw = passwordTouched ? (form.password ?? '') : '';
    const ctx = [form.title, form.username] as const;
    if (!pw) {
      check = null;
      return;
    }
    const t = setTimeout(() => api.checkPassword(id, pw, ctx[0], ctx[1]).then((c) => (check = c), () => (check = null)), 200);
    return () => clearTimeout(t);
  });

  async function totpFromQr() {
    const t = await app.run(() => api.totpFromClipboard());
    if (t) {
      form.totp = t;
      app.toast('2FA-секрет взят из QR-кода');
    }
  }

  let newLabel = $state('');
  async function addLabel(e: KeyboardEvent) {
    if (e.key !== 'Enter') return;
    e.preventDefault();
    const name = newLabel.trim();
    if (!name) return;
    const label = { id: crypto.randomUUID(), name, color: LABEL_COLORS[colLabels.length % LABEL_COLORS.length] };
    if ((await app.run(() => api.saveLabel(form.collection_id, label))) !== undefined) {
      await app.refresh();
      form.labels = [...form.labels, label.id];
      newLabel = '';
    }
  }

  function toggleLabel(lid: string) {
    form.labels = form.labels.includes(lid) ? form.labels.filter((l) => l !== lid) : [...form.labels, lid];
  }

  async function save(e: SubmitEvent) {
    e.preventDefault();
    saving = true;
    const input: ItemInput = {
      ...form,
      urls: urlsText.split('\n').map((u) => u.trim()).filter(Boolean),
      password: passwordTouched ? (form.password ?? '') : null,
      labels: form.labels.filter((l) => colLabels.some((x) => x.id === l)),
    };
    const newId = await app.run(() => api.save(input), id ? 'Сохранено' : 'Запись добавлена');
    saving = false;
    if (newId) {
      await app.refresh();
      app.selectedId = newId;
      app.modal = null;
    }
  }
</script>

<Modal title={id ? 'Изменить запись' : 'Новая запись'} wide {canClose} bind:this={modal}>
  <form class="grid" onsubmit={save}>
    <div class="kind">
      <button type="button" class="chip" class:on={form.kind === 'login'} onclick={() => (form.kind = 'login')}>логин</button>
      <button type="button" class="chip" class:on={form.kind === 'note'} onclick={() => (form.kind = 'note')}>заметка</button>
      <label class="fav"><input type="checkbox" bind:checked={form.favorite} /> ★ избранное</label>
    </div>

    <label class="field"><span>название</span><input bind:this={titleInput} bind:value={form.title} required /></label>
    <label class="field">
      <span>папка</span>
      <select bind:value={form.collection_id}>
        {#each writable as c (c.id)}<option value={c.id}>{c.name}</option>{/each}
      </select>
    </label>

    {#if form.kind === 'login'}
      <label class="field"><span>логин</span><input bind:value={form.username} autocomplete="off" spellcheck="false" /></label>
      <div class="field">
        <span>пароль</span>
        <div class="pw">
          <input
            type={showPassword ? 'text' : 'password'}
            value={form.password ?? ''}
            oninput={(e) => ((form.password = e.currentTarget.value), (passwordTouched = true))}
            placeholder={id && hadPassword && !passwordTouched ? 'без изменений' : ''}
            autocomplete="new-password"
            spellcheck="false"
          />
          <button type="button" class="btn" onclick={() => (showPassword = !showPassword)}>{showPassword ? 'скрыть' : 'показать'}</button>
          {#if form.password}<button type="button" class="btn" onclick={() => app.run(() => api.copyText(form.password ?? '', app.settings.clipboardSec), 'Пароль скопирован')}>копировать</button>{/if}
          {#if id && hadPassword && !passwordTouched}<button type="button" class="btn" onclick={revealCurrent}>текущий</button>{/if}
          <button type="button" class="btn" class:primary={genOpen} onclick={() => (genOpen = !genOpen)}>генератор</button>
        </div>
        {#if check}
          <div class="meter" class:weak={check.score < 3} aria-live="polite">
            <span class="bars" aria-hidden="true">{#each [0, 1, 2, 3] as i (i)}<i class:on={check.score > i}></i>{/each}</span>
            <span>{strengthLabel(check.score)} · подбор: {crackTime(check.crack_secs)}</span>
          </div>
          {#if check.reused_in.length}
            <p class="err reuse">! такой же пароль уже есть в: {check.reused_in.join(', ')}</p>
          {/if}
        {/if}
      </div>
      {#if genOpen}
        <div class="gen">
          <div class="row">
            <button type="button" class="chip" class:on={gen.mode === 'chars'} onclick={() => (gen.mode = 'chars')}>символы</button>
            <button type="button" class="chip" class:on={gen.mode === 'words'} onclick={() => (gen.mode = 'words')}>слова</button>
          </div>
          {#if gen.mode === 'chars'}
            <label class="row">длина <input type="range" min="8" max="128" bind:value={gen.length} /> <b>{gen.length}</b></label>
            <div class="row wrap">
              <label><input type="checkbox" bind:checked={gen.upper} /> A-Z</label>
              <label><input type="checkbox" bind:checked={gen.lower} /> a-z</label>
              <label><input type="checkbox" bind:checked={gen.digits} /> 0-9</label>
              <label><input type="checkbox" bind:checked={gen.symbols} /> !@#</label>
              <label><input type="checkbox" bind:checked={gen.exclude_similar} /> без I l 1 O 0</label>
            </div>
          {:else}
            <label class="row">слов <input type="range" min="3" max="10" bind:value={gen.words} /> <b>{gen.words}</b></label>
            <label class="row">разделитель
              <select bind:value={gen.separator} class="sep">
                <option value="-">дефис  слово-слово</option>
                <option value=" ">пробел  слово слово</option>
                <option value=".">точка  слово.слово</option>
                <option value="_">подчёркивание  слово_слово</option>
              </select>
            </label>
          {/if}
          <button type="button" class="btn primary" onclick={generate}>Сгенерировать</button>
        </div>
      {/if}
      <label class="field"><span>адреса, по одному в строке</span><textarea bind:value={urlsText} rows="2" spellcheck="false"></textarea></label>
      <label class="field">
        <span>код 2FA: секрет из QR-кода сайта</span>
        <div class="totp">
          <input
            value={form.totp ?? ''}
            oninput={(e) => (form.totp = e.currentTarget.value)}
            placeholder={id && hadTotp && form.totp === null ? 'сохранён, без изменений' : 'например JBSWY3DPEHPK3PXP или otpauth://…'}
            spellcheck="false"
          />
          <button type="button" class="btn" title="Сначала сделайте скриншот QR-кода сайта" onclick={totpFromQr}>из QR в буфере</button>
        </div>
        <small class="muted">Сайт показывает секрет рядом с QR-кодом при включении двухфакторной защиты («не могу отсканировать»). Или сделайте скриншот QR-кода (Win+Shift+S) и нажмите «из QR в буфере». Приложение будет само выдавать 6-значные коды.</small>
      </label>
    {/if}

    <label class="field"><span>заметки</span><textarea bind:value={form.notes} rows={form.kind === 'note' ? 8 : 3}></textarea></label>

    <div class="field">
      <span>ярлыки</span>
      <div class="row wrap">
        {#each colLabels as l (l.id)}
          <button type="button" class="chip" class:on={form.labels.includes(l.id)} style="--c: var(--l-{l.color})" onclick={() => toggleLabel(l.id)}>
            <span class="dot"></span>{l.name}
          </button>
        {:else}
          <span class="muted">В этой папке ещё нет ярлыков.</span>
        {/each}
        <input class="newlab" bind:value={newLabel} placeholder="+ новый ярлык, Enter" onkeydown={addLabel} />
      </div>
    </div>

    <div class="actions">
      <button class="btn primary" disabled={saving}>{saving ? 'сохраняю…' : 'Сохранить'}</button>
      <button type="button" class="btn" onclick={() => modal?.close()}>Отмена</button>
    </div>
  </form>
</Modal>

<style>
  .grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px 16px;
  }
  .grid > :global(*) {
    grid-column: span 2;
  }
  .grid > label.field:nth-of-type(1),
  .grid > label.field:nth-of-type(2) {
    grid-column: span 1;
  }
  .kind,
  .row {
    display: flex;
    gap: 8px;
    align-items: center;
  }
  .wrap {
    flex-wrap: wrap;
  }
  .fav {
    margin-left: auto;
    display: flex;
    gap: 6px;
    align-items: center;
  }
  .pw,
  .totp {
    display: flex;
    gap: 6px;
  }
  .meter {
    display: flex;
    gap: 8px;
    align-items: center;
    font-size: 12px;
    color: var(--muted);
    --c: var(--accent);
  }
  .meter.weak {
    --c: var(--danger);
  }
  .bars {
    display: inline-flex;
    gap: 3px;
  }
  .bars i {
    width: 22px;
    height: 5px;
    background: var(--line);
  }
  .bars i.on {
    background: var(--c);
  }
  .reuse {
    margin: 0;
    font-size: 12px;
  }
  .gen {
    display: grid;
    gap: 8px;
    padding: 10px;
    border: 1px dashed var(--line);
    justify-items: start;
  }
  .gen input[type='range'] {
    accent-color: var(--accent);
  }
  .actions {
    display: flex;
    gap: 8px;
  }
  .sep {
    width: auto;
  }
  .newlab {
    width: 14em;
    padding: 1px 8px;
  }
</style>
