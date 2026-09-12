// Grimoire UI. No framework, no build step.
//
// It only offers what the server would allow anyway: /api/v1/me reports role
// and capabilities, and the buttons follow. Enforcement happens in the server;
// this is about not walking anyone into a 403.
'use strict';

let me = null;
let state = { view: 'library', q: '', tags: new Set(), visibility: '' };

// --- transport --------------------------------------------------------------

async function api(method, path, body) {
  const opts = { method, headers: {}, credentials: 'same-origin' };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  if (me && me.csrfToken && method !== 'GET') opts.headers['X-CSRF-Token'] = me.csrfToken;

  const res = await fetch(path, opts);
  if (res.status === 204) return null;
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) {
    const err = new Error((data && data.error && data.error.message) || `Error ${res.status}`);
    err.code = data && data.error && data.error.code;
    err.status = res.status;
    throw err;
  }
  return data;
}

function can(capability) {
  return !!me && me.capabilities.includes(capability);
}

// --- helpers ----------------------------------------------------------------

const $ = (id) => document.getElementById(id);

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') node.className = v;
    else if (k === 'text') node.textContent = v;
    else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else if (v === true) node.setAttribute(k, '');
    else if (v !== false && v != null) node.setAttribute(k, v);
  }
  for (const child of children.flat()) {
    if (child != null) node.append(child);
  }
  return node;
}

let toastTimer;
function toast(message) {
  const node = $('toast');
  node.textContent = message;
  node.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { node.hidden = true; }, 3200);
}

function formatDate(value) {
  if (!value) return '–';
  const d = new Date(value);
  if (Number.isNaN(d.getTime()) || d.getFullYear() < 2000) return '–';
  return d.toLocaleDateString('en-GB', { day: '2-digit', month: '2-digit', year: 'numeric' });
}

function relative(value) {
  if (!value) return 'never';
  const d = new Date(value);
  if (Number.isNaN(d.getTime()) || d.getFullYear() < 2000) return 'never';
  const minutes = Math.round((Date.now() - d.getTime()) / 60000);
  if (minutes < 2) return 'just now';
  if (minutes < 60) return `${minutes} min ago`;
  if (minutes < 1440) return `${Math.round(minutes / 60)} h ago`;
  return formatDate(value);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast('Copied.');
  } catch {
    // No clipboard API without a secure context (plain http).
    const area = el('textarea', { style: 'position:fixed;opacity:0' });
    area.value = text;
    document.body.append(area);
    area.select();
    document.execCommand('copy');
    area.remove();
    toast('Copied.');
  }
}

// --- library ----------------------------------------------------------------

async function loadLibrary() {
  const params = new URLSearchParams();
  if (state.q) params.set('q', state.q);
  if (state.visibility) params.set('visibility', state.visibility);
  for (const tag of state.tags) params.append('tag', tag);

  const [{ prompts }, { tags }] = await Promise.all([
    api('GET', '/api/v1/prompts?' + params),
    api('GET', '/api/v1/tags'),
  ]);
  renderTags(tags);
  renderPrompts(prompts);
}

function renderTags(tags) {
  const bar = $('tagbar');
  bar.replaceChildren(...tags.map((tag) =>
    el('button', {
      class: 'chip',
      'aria-pressed': state.tags.has(tag.name) ? 'true' : 'false',
      onclick: () => {
        state.tags.has(tag.name) ? state.tags.delete(tag.name) : state.tags.add(tag.name);
        loadLibrary().catch(showError);
      },
    }, `${tag.name} · ${tag.count}`)));
}

function renderPrompts(prompts) {
  const list = $('promptList');
  const empty = $('emptyLibrary');
  list.replaceChildren(...prompts.map(promptCard));

  if (prompts.length === 0) {
    empty.hidden = false;
    empty.textContent = state.q || state.tags.size || state.visibility
      ? 'Nothing found.'
      : can('prompts:write')
        ? 'No prompts yet. Create the first one.'
        : 'No prompts yet.';
  } else {
    empty.hidden = true;
  }
}

function promptCard(p) {
  const actions = [
    el('button', { onclick: () => copyText(p.body) }, 'Copy'),
  ];
  if (can('prompts:write')) {
    actions.push(el('button', { onclick: () => openPromptDialog(p) }, 'Edit'));
    actions.push(el('button', {
      class: 'ghost',
      onclick: async () => {
        if (!confirm(`Delete "${p.title}"? It stays restorable through the revision history.`)) return;
        try {
          await api('DELETE', `/api/v1/prompts/${p.id}`);
          toast('Deleted.');
          await loadLibrary();
        } catch (err) { showError(err); }
      },
    }, 'Delete'));
  }

  return el('article', { class: 'card' },
    el('header', {},
      el('h3', { text: p.title }),
      p.visibility === 'private' ? el('span', { class: 'badge', text: 'private' }) : null,
      el('span', { class: 'meta', text: `${p.owner.name} · ${formatDate(p.updatedAt)} · v${p.revision}` })),
    p.tags.length ? el('div', { class: 'meta', text: p.tags.join(' · ') }) : null,
    el('pre', { text: p.body }),
    el('div', { class: 'actions' }, actions));
}

// --- create and edit ---------------------------------------------------------

let editing = null;

function openPromptDialog(prompt) {
  editing = prompt || null;
  $('promptDialogTitle').textContent = prompt ? 'Edit prompt' : 'New prompt';
  $('pTitle').value = prompt ? prompt.title : '';
  $('pBody').value = prompt ? prompt.body : '';
  $('pTags').value = prompt ? prompt.tags.join(', ') : '';
  $('pPrivate').checked = prompt ? prompt.visibility === 'private' : false;
  $('promptError').hidden = true;

  // The visibility toggle tells the truth about this instance.
  const wrap = $('pPrivateWrap');
  wrap.hidden = !me.instance.privatePrompts;
  $('pPrivateNote').textContent = me.instance.privateVisibleToAdmins
    ? '— administrators of this instance can read private prompts.'
    : '';
  $('promptDialog').showModal();
}

async function savePrompt() {
  const payload = {
    title: $('pTitle').value.trim(),
    body: $('pBody').value,
    tags: $('pTags').value.split(',').map((t) => t.trim()).filter(Boolean),
    visibility: $('pPrivate').checked ? 'private' : 'shared',
  };
  if (editing) await api('PATCH', `/api/v1/prompts/${editing.id}`, payload);
  else await api('POST', '/api/v1/prompts', payload);
  toast(editing ? 'Saved.' : 'Created.');
  await loadLibrary();
}

// --- API keys ---------------------------------------------------------------

async function loadKeys() {
  const all = $('allKeys').checked ? '?all=1' : '';
  const { keys } = await api('GET', '/api/v1/api-keys' + all);
  const list = $('keyList');
  if (keys.length === 0) {
    list.replaceChildren(el('p', { class: 'empty', text: 'No keys yet.' }));
    return;
  }
  list.replaceChildren(...keys.map(keyCard));
}

function keyCard(k) {
  const roleLabel = k.role === 'editor' ? 'read and write' : 'read only';
  const actions = [];
  if (!k.revokedAt) {
    actions.push(el('button', {
      class: 'ghost',
      onclick: async () => {
        if (!confirm(`Revoke the key "${k.name}"? This is permanent.`)) return;
        try {
          await api('DELETE', `/api/v1/api-keys/${k.id}`);
          toast('Revoked.');
          await loadKeys();
        } catch (err) { showError(err); }
      },
    }, 'Revoke'));
  }
  return el('article', { class: 'card' },
    el('header', {},
      el('h3', { text: k.name }),
      el('span', { class: 'badge', text: roleLabel })),
    el('div', { class: 'meta' },
      `${k.id} · ${k.owner.name} · created ${formatDate(k.createdAt)} · ` +
      `last used ${relative(k.lastUsedAt)} · expires ${formatDate(k.expiresAt)}`),
    k.statusNote ? el('div', { class: k.status === 'active' ? 'meta' : 'warn', text: k.statusNote }) : null,
    actions.length ? el('div', { class: 'actions' }, actions) : null);
}

async function createKey() {
  const result = await api('POST', '/api/v1/api-keys', {
    name: $('kName').value.trim(),
    role: $('kRole').value,
    expiresInDays: Number($('kDays').value) || 0,
  });
  $('keyPlain').textContent = result.plaintext;
  $('keyRevealDialog').showModal();
  await loadKeys();
}

// --- administration ----------------------------------------------------------

async function loadAdmin() {
  const [{ users }, { entries }] = await Promise.all([
    api('GET', '/api/v1/admin/users'),
    api('GET', '/api/v1/admin/audit?limit=50'),
  ]);

  $('userList').replaceChildren(...users.map((u) => el('article', { class: 'card' },
    el('header', {},
      el('h3', { text: u.name }),
      el('span', { class: 'badge', text: u.lastSeenRole || 'no access' })),
    el('div', { class: 'meta', text: `${u.email || '–'} · last signed in ${relative(u.lastLoginAt)}` }),
    u.id === me.user.id ? null : el('div', { class: 'actions' },
      el('button', { class: 'ghost', onclick: () => openDeleteUser(u) }, 'Remove')))));

  $('auditList').replaceChildren(...(entries.length
    ? entries.map((e) => el('article', { class: 'card' },
        el('div', {}, el('strong', { text: e.action }),
          ' · ', e.actor.name || 'system', ' · ', formatDate(e.at)),
        e.reason ? el('div', { class: 'meta', text: 'Reason: ' + e.reason }) : null))
    : [el('p', { class: 'empty', text: 'Nothing recorded yet.' })]));
}

let deletingUser = null;

async function openDeleteUser(user) {
  deletingUser = user;
  const info = await api('GET', `/api/v1/admin/users/${user.id}/footprint`);
  const f = info.footprint;
  $('duSummary').textContent =
    `${user.name}: ${f.sharedPrompts} shared prompts (these stay), ` +
    `${f.privatePrompts} private, ${f.activeKeys} active keys, ${f.sessions} sessions.`;

  const choice = el('div', {});
  if (f.privatePrompts > 0 && info.transferAllowed) {
    choice.append(
      el('label', { class: 'checkbox' },
        el('input', { type: 'radio', name: 'priv', value: 'delete', checked: true }),
        ' Delete private prompts'),
      el('label', { class: 'checkbox' },
        el('input', { type: 'radio', name: 'priv', value: 'transfer' }),
        ' Take over private prompts (grants you read access, recorded in the audit log)'));
  }
  $('duPrivate').replaceChildren(choice);
  $('duReasonWrap').hidden = true;
  $('duReason').value = '';
  $('duError').hidden = true;
  choice.addEventListener('change', () => {
    $('duReasonWrap').hidden = selectedPrivateChoice() !== 'transfer';
  });
  $('deleteUserDialog').showModal();
}

function selectedPrivateChoice() {
  const checked = document.querySelector('input[name="priv"]:checked');
  return checked ? checked.value : 'delete';
}

async function deleteUser() {
  await api('DELETE', `/api/v1/admin/users/${deletingUser.id}`, {
    privatePrompts: selectedPrivateChoice(),
    reason: $('duReason').value.trim(),
  });
  toast('User removed.');
  await loadAdmin();
}

// --- views ------------------------------------------------------------------

const loaders = { library: loadLibrary, keys: loadKeys, admin: loadAdmin };

async function showView(name) {
  state.view = name;
  for (const tab of document.querySelectorAll('.tab')) {
    tab.setAttribute('aria-current', tab.dataset.view === name ? 'true' : 'false');
  }
  for (const view of document.querySelectorAll('.view')) {
    view.hidden = view.id !== 'view-' + name;
  }
  try { await loaders[name](); } catch (err) { showError(err); }
}

function showError(err) {
  if (err && err.status === 401) { location.href = '/auth/login'; return; }
  toast(err && err.message ? err.message : 'Unexpected error.');
}

// --- startup ----------------------------------------------------------------

function wire() {
  for (const tab of document.querySelectorAll('.tab')) {
    tab.addEventListener('click', () => showView(tab.dataset.view));
  }

  let searchTimer;
  $('search').addEventListener('input', (e) => {
    state.q = e.target.value.trim();
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => loadLibrary().catch(showError), 180);
  });
  $('filterVisibility').addEventListener('change', (e) => {
    state.visibility = e.target.value;
    loadLibrary().catch(showError);
  });

  $('newPrompt').addEventListener('click', () => openPromptDialog(null));
  $('promptForm').addEventListener('submit', (e) => {
    if (e.submitter && e.submitter.value !== 'save') return;
    e.preventDefault();
    savePrompt()
      .then(() => $('promptDialog').close())
      .catch((err) => { $('promptError').textContent = err.message; $('promptError').hidden = false; });
  });

  $('newKey').addEventListener('click', () => {
    $('kName').value = '';
    $('keyError').hidden = true;
    $('keyDialog').showModal();
  });
  $('keyForm').addEventListener('submit', (e) => {
    if (e.submitter && e.submitter.value !== 'save') return;
    e.preventDefault();
    createKey()
      .then(() => $('keyDialog').close())
      .catch((err) => { $('keyError').textContent = err.message; $('keyError').hidden = false; });
  });
  $('allKeys').addEventListener('change', () => loadKeys().catch(showError));
  $('copyKey').addEventListener('click', () => copyText($('keyPlain').textContent));
  $('closeReveal').addEventListener('click', () => {
    $('keyPlain').textContent = '';
    $('keyRevealDialog').close();
  });

  $('deleteUserForm').addEventListener('submit', (e) => {
    if (e.submitter && e.submitter.value !== 'delete') return;
    e.preventDefault();
    deleteUser()
      .then(() => $('deleteUserDialog').close())
      .catch((err) => { $('duError').textContent = err.message; $('duError').hidden = false; });
  });

  $('logout').addEventListener('click', async () => {
    try {
      const res = await api('POST', '/auth/logout');
      location.href = (res && res.providerLogoutUrl) || '/';
    } catch { location.href = '/'; }
  });
}

async function start() {
  try {
    me = await api('GET', '/api/v1/me');
  } catch (err) {
    if (err.status === 401) { location.href = '/auth/login'; return; }
    $('boot').textContent = 'The application is not reachable right now: ' + err.message;
    return;
  }

  document.title = me.instance.title;
  $('appTitle').textContent = me.instance.title;
  $('whoName').textContent = me.user.name || me.user.email || '';
  $('whoRole').textContent = me.roleLabel;

  $('newPrompt').hidden = !can('prompts:write');
  document.querySelector('.tab[data-view="keys"]').hidden = !can('keys:manage');
  document.querySelector('.tab[data-view="admin"]').hidden = !can('admin:read');
  $('allKeysWrap').hidden = !can('admin:read');
  $('kRole').querySelector('option[value="editor"]').disabled = !can('prompts:write');
  if (!me.instance.privatePrompts) $('filterVisibility').hidden = true;

  wire();
  $('boot').hidden = true;
  $('app').hidden = false;
  await showView('library');
}

start();
