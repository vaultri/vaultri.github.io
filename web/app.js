// La UI del vault. Todo lo que toca claves o secretos pasa por el WASM: aquí
// solo hay pintado, eventos y la copia local en `localStorage`.

import init, { Vault } from './pkg/totp_web.js';

/// El vault cifrado vive en `localStorage`. Son bytes ilegibles sin la
/// passphrase: quien inspeccione el almacenamiento no ve ni qué servicios hay.
const STORAGE_KEY = 'vaultrie/vault/v1';

/// Tras este rato sin tocar nada se suelta la MK y hay que volver a desbloquear.
const IDLE_LOCK_MS = 5 * 60 * 1000;

const RING_RADIUS = 10;
const RING_LENGTH = 2 * Math.PI * RING_RADIUS;

const $ = (id) => document.getElementById(id);
const now = () => Date.now() / 1000;

let vault = null;
let ticker = null;
let idleTimer = null;
/** Filas ya pintadas, por id de entrada, para no rehacer el DOM cada segundo. */
const rows = new Map();

// --- Arranque ---------------------------------------------------------------

await init();

$('loading').hidden = true;
$('app').removeAttribute('aria-busy');

const saved = localStorage.getItem(STORAGE_KEY);
if (saved) {
  try {
    vault = Vault.restore(fromBase64(saved));
    show('unlock');
    $('unlock-pass').focus();
  } catch (error) {
    // Si la copia local no se puede leer, lo honesto es decirlo y no ofrecer
    // un "crear vault" que la pisaría en silencio.
    show('unlock');
    fail('unlock-error', `No se pudo leer el vault guardado: ${error.message}`);
    $('unlock-form').hidden = true;
  }
} else {
  show('setup');
  $('setup-pass').focus();
}

// --- Crear vault ------------------------------------------------------------

$('setup-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  clearError('setup-error');

  const passphrase = $('setup-pass').value;
  if (passphrase !== $('setup-repeat').value) {
    fail('setup-error', 'Las dos passphrases no coinciden.');
    return;
  }

  const button = $('setup-form').querySelector('button[type="submit"]');
  await withBusy(button, 'Cifrando…', () => {
    vault = Vault.create(passphrase);
    persist();
  });

  $('recovery-key').textContent = vault.takeRecoveryKey();
  show('recovery');
});

$('recovery-copy').addEventListener('click', () => {
  copy($('recovery-key').textContent, 'Clave de recuperación copiada');
});

$('recovery-done').addEventListener('click', () => {
  // El texto se queda en el DOM si no se limpia, y esta clave abre el vault.
  $('recovery-key').textContent = '';
  openVault();
});

// --- Desbloquear ------------------------------------------------------------

$('unlock-toggle').addEventListener('click', () => {
  const usingRecovery = !$('unlock-recovery-label').hidden;
  $('unlock-recovery-label').hidden = usingRecovery;
  $('unlock-pass-label').hidden = !usingRecovery;
  $('unlock-toggle').textContent = usingRecovery
    ? 'Usar la clave de recuperación'
    : 'Usar la passphrase';
  clearError('unlock-error');
  (usingRecovery ? $('unlock-pass') : $('unlock-recovery')).focus();
});

$('unlock-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  clearError('unlock-error');

  const usingRecovery = !$('unlock-recovery-label').hidden;
  const secret = usingRecovery ? $('unlock-recovery').value : $('unlock-pass').value;
  const button = $('unlock-form').querySelector('button[type="submit"]');

  const opened = await withBusy(button, 'Descifrando…', () => {
    try {
      if (usingRecovery) {
        vault.unlockWithRecoveryKey(secret);
      } else {
        vault.unlock(secret);
      }
      return true;
    } catch {
      // El core no distingue "clave incorrecta" de "datos manipulados", y el
      // mensaje aquí tampoco debería inventarse esa diferencia.
      fail('unlock-error', usingRecovery
        ? 'Esa clave de recuperación no abre este vault.'
        : 'Esa passphrase no abre este vault.');
      return false;
    }
  });

  if (opened) {
    $('unlock-pass').value = '';
    $('unlock-recovery').value = '';
    openVault();
  }
});

$('lock').addEventListener('click', lock);

// --- Añadir entradas --------------------------------------------------------

$('add-open').addEventListener('click', () => {
  clearError('add-error');
  $('add-dialog').showModal();
  $('add-uri').focus();
});

$('add-cancel').addEventListener('click', () => $('add-dialog').close());

$('tab-uri').addEventListener('click', () => selectTab(true));
$('tab-manual').addEventListener('click', () => selectTab(false));

function selectTab(uri) {
  $('tab-uri').setAttribute('aria-selected', String(uri));
  $('tab-manual').setAttribute('aria-selected', String(!uri));
  $('pane-uri').hidden = !uri;
  $('pane-manual').hidden = uri;
  clearError('add-error');
  (uri ? $('add-uri') : $('add-issuer')).focus();
}

$('add-save').addEventListener('click', () => {
  clearError('add-error');
  const usingUri = !$('pane-uri').hidden;

  try {
    if (usingUri) {
      vault.addUri($('add-uri').value, now());
    } else {
      vault.addEntry(
        $('add-issuer').value,
        $('add-account').value,
        $('add-secret').value,
        $('add-algorithm').value,
        Number($('add-digits').value),
        Number($('add-period').value),
        now(),
      );
    }
  } catch (error) {
    fail('add-error', error.message);
    return;
  }

  persist();
  render();
  $('add-form').reset();
  $('add-dialog').close();
});

// --- Pintado ----------------------------------------------------------------

function openVault() {
  show('vault');
  $('tools').hidden = false;
  render();
  ticker ??= setInterval(render, 1000);
  resetIdleTimer();
}

function lock() {
  vault.lock();
  clearInterval(ticker);
  ticker = null;
  clearTimeout(idleTimer);

  $('entries').replaceChildren();
  rows.clear();
  $('tools').hidden = true;
  clearError('unlock-error');
  show('unlock');
  $('unlock-pass').focus();
}

function render() {
  const entries = vault.codes(now());
  const list = $('entries');
  const seen = new Set();

  entries.forEach((entry, position) => {
    seen.add(entry.id);
    let row = rows.get(entry.id);
    if (!row) {
      row = buildRow(entry);
      rows.set(entry.id, row);
    }
    updateRow(row, entry);

    // El core devuelve las entradas ordenadas; aquí solo se mueve lo que no
    // esté ya en su sitio, para no rehacer la lista cada segundo.
    if (list.children[position] !== row.element) {
      list.insertBefore(row.element, list.children[position] ?? null);
    }
  });

  for (const [id, row] of rows) {
    if (!seen.has(id)) {
      row.element.remove();
      rows.delete(id);
    }
  }

  $('empty').hidden = entries.length > 0;
}

function buildRow(entry) {
  const element = document.createElement('li');
  element.className = 'entry';
  element.innerHTML = `
    <div class="identity">
      <div class="issuer"></div>
      <div class="account"></div>
    </div>
    <button type="button" class="code" title="Copiar código"></button>
    <div class="actions">
      <svg class="ring" width="26" height="26" viewBox="0 0 26 26" aria-hidden="true">
        <circle class="track" cx="13" cy="13" r="${RING_RADIUS}"></circle>
        <circle class="value" cx="13" cy="13" r="${RING_RADIUS}"
                stroke-dasharray="${RING_LENGTH}" stroke-linecap="round"></circle>
      </svg>
      <button type="button" class="remove" title="Eliminar" aria-label="Eliminar">✕</button>
    </div>`;

  const row = {
    element,
    issuer: element.querySelector('.issuer'),
    account: element.querySelector('.account'),
    code: element.querySelector('.code'),
    ring: element.querySelector('.value'),
    remaining: 0,
  };

  row.code.addEventListener('click', () => {
    copy(row.code.textContent.replaceAll(' ', ''), 'Código copiado');
  });

  element.querySelector('.remove').addEventListener('click', () => {
    if (!confirm(`¿Eliminar ${entry.issuer || entry.account}?`)) return;
    vault.remove(entry.id, now());
    persist();
    render();
  });

  return row;
}

function updateRow(row, entry) {
  row.issuer.textContent = entry.issuer || entry.account;
  row.account.textContent = entry.issuer ? entry.account : '';
  row.code.textContent = group(entry.code);

  // Al empezar una ventana nueva el anillo salta hacia atrás; animarlo se ve
  // como un rebobinado.
  row.element.classList.toggle('rewound', entry.secondsRemaining > row.remaining);
  row.element.classList.toggle('expiring', entry.secondsRemaining <= 5);
  row.ring.style.strokeDashoffset = RING_LENGTH * (1 - entry.secondsRemaining / entry.period);
  row.remaining = entry.secondsRemaining;
}

/// Los códigos se leen mejor partidos por la mitad, como hacen los bancos.
function group(code) {
  const half = Math.ceil(code.length / 2);
  return `${code.slice(0, half)} ${code.slice(half)}`;
}

// --- Utilidades -------------------------------------------------------------

function show(screen) {
  for (const id of ['setup', 'recovery', 'unlock', 'vault']) {
    $(id).hidden = id !== screen;
  }
}

/// Deja pintar el estado "ocupado" antes de bloquear el hilo con Argon2id.
async function withBusy(button, label, work) {
  const original = button.textContent;
  button.textContent = label;
  button.disabled = true;
  await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));

  try {
    return work();
  } finally {
    button.textContent = original;
    button.disabled = false;
  }
}

function persist() {
  localStorage.setItem(STORAGE_KEY, toBase64(vault.export()));
}

async function copy(text, message) {
  try {
    await navigator.clipboard.writeText(text);
    toast(message);
  } catch {
    toast('El navegador no dejó copiar');
  }
}

let toastTimer = null;
function toast(message) {
  $('toast').textContent = message;
  $('toast').hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => ($('toast').hidden = true), 1800);
}

function fail(id, message) {
  $(id).textContent = message;
  $(id).hidden = false;
}

function clearError(id) {
  $(id).hidden = true;
  $(id).textContent = '';
}

function resetIdleTimer() {
  clearTimeout(idleTimer);
  if (vault?.isUnlocked) {
    idleTimer = setTimeout(lock, IDLE_LOCK_MS);
  }
}

for (const event of ['pointerdown', 'keydown']) {
  document.addEventListener(event, resetIdleTimer, { passive: true });
}

function toBase64(bytes) {
  let binary = '';
  // Fragmentado: pasar el array entero como argumentos revienta la pila.
  for (let i = 0; i < bytes.length; i += 8192) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
  }
  return btoa(binary);
}

function fromBase64(text) {
  const binary = atob(text);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}
