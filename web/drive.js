// Sincronización con el `appDataFolder` de Google Drive.
//
// Aquí vive todo lo que sabe de Google: el token, cómo se pide y cómo se
// renueva. El WASM solo recibe una función que hace peticiones, así que ni el
// core ni el puente llegan a ver una credencial. Y al revés: esto no sabe qué
// se está subiendo, porque lo que le llega ya son bytes cifrados.
//
// El flujo es el de cliente público con Google Identity Services: no hay
// backend donde esconder un client secret, así que se pide un access token de
// vida corta y se renueva en silencio cuando caduca. No se guarda en disco.

import { GOOGLE_CLIENT_ID } from './config.js';

const SCOPE = 'https://www.googleapis.com/auth/drive.appdata';
const GIS_SRC = 'https://accounts.google.com/gsi/client';

/// Que el usuario ya conectó alguna vez. Es lo único que se persiste —ni token
/// ni identidad—, y sirve para reintentar el permiso en silencio al recargar.
const CONNECTED_KEY = 'vaultrie/drive/connected';

/// Margen antes de dar un token por caducado: renovarlo justo en el límite deja
/// peticiones a medio vuelo con un token muerto.
const EXPIRY_MARGIN_MS = 60_000;

let tokenClient = null;
let token = null;
let pending = null;

export function isConfigured() {
  return GOOGLE_CLIENT_ID.length > 0;
}

/// Si el usuario ya conectó la cuenta en este navegador.
export function wasConnected() {
  return localStorage.getItem(CONNECTED_KEY) === '1';
}

export function isConnected() {
  return token !== null;
}

/// Consigue permiso para el `appDataFolder`.
///
/// `silent` es el reintento al recargar la página: si Google puede resolverlo
/// sin preguntar, lo resuelve; si no, falla en vez de abrir una ventana que el
/// usuario no ha pedido. Los navegadores bloquean los popups que no salen de
/// un clic, así que la conexión de verdad tiene que venir de uno.
export async function connect({ silent = false } = {}) {
  if (!isConfigured()) {
    throw new Error('Este despliegue no tiene configurado el client id de Google.');
  }

  await requestToken(silent ? '' : 'consent');
  localStorage.setItem(CONNECTED_KEY, '1');
}

export function disconnect() {
  const revoked = token?.value;
  token = null;
  localStorage.removeItem(CONNECTED_KEY);
  // Que el usuario recupere el permiso desde Google es cosa suya; lo mínimo es
  // que este navegador deje de poder usarlo.
  if (revoked && window.google?.accounts?.oauth2) {
    window.google.accounts.oauth2.revoke(revoked, () => {});
  }
}

/// La función que usa el WASM para hablar con Drive.
///
/// Recibe y devuelve lo mismo que espera el puente: cabeceras como pares y
/// cuerpos como `Uint8Array`. Un HTTP de error no es una excepción —el core
/// distingue un 412 de un fallo de red—, pero un fallo de red sí.
export async function send({ method, url, headers, body }) {
  let response = await fetchWith(await accessToken(), { method, url, headers, body });

  // Un 401 con un token que creíamos vivo es la sesión caducada antes de
  // tiempo: se pide otro y se reintenta una vez.
  if (response.status === 401) {
    token = null;
    response = await fetchWith(await accessToken(), { method, url, headers, body });
  }

  return {
    status: response.status,
    body: new Uint8Array(await response.arrayBuffer()),
  };
}

async function fetchWith(access, { method, url, headers, body }) {
  const requestHeaders = new Headers(headers);
  requestHeaders.set('Authorization', `Bearer ${access}`);

  return fetch(url, {
    method,
    headers: requestHeaders,
    body: body ?? undefined,
    // La carpeta es privada de la app; nada de cookies del usuario en juego.
    credentials: 'omit',
  });
}

async function accessToken() {
  if (token && token.expiresAt - EXPIRY_MARGIN_MS > Date.now()) {
    return token.value;
  }
  // Renovar en silencio: el usuario ya dio el permiso, solo caducó el token.
  await requestToken('');
  return token.value;
}

function requestToken(prompt) {
  // Dos peticiones a la vez —dos syncs solapados— tienen que compartir la
  // misma respuesta: Google no lleva bien dos ventanas de permiso abiertas.
  pending ??= startTokenRequest(prompt).finally(() => {
    pending = null;
  });
  return pending;
}

async function startTokenRequest(prompt) {
  const client = await identityClient();

  return new Promise((resolve, reject) => {
    client.callback = (response) => {
      if (response.error) {
        reject(new Error(describe(response)));
        return;
      }
      token = {
        value: response.access_token,
        expiresAt: Date.now() + Number(response.expires_in ?? 3600) * 1000,
      };
      resolve();
    };
    client.error_callback = (error) => reject(new Error(describe(error)));
    client.requestAccessToken({ prompt });
  });
}

async function identityClient() {
  await loadIdentityServices();
  tokenClient ??= window.google.accounts.oauth2.initTokenClient({
    client_id: GOOGLE_CLIENT_ID,
    scope: SCOPE,
    callback: () => {},
  });
  return tokenClient;
}

/// Carga el script de Google la primera vez que hace falta.
///
/// Va aquí y no en el `index.html` a propósito: quien no conecte la cuenta no
/// carga nada de Google, y la página sigue siendo utilizable sin red.
let identityScript = null;
function loadIdentityServices() {
  if (window.google?.accounts?.oauth2) return Promise.resolve();

  identityScript ??= new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = GIS_SRC;
    script.async = true;
    script.onload = () => resolve();
    script.onerror = () => {
      identityScript = null;
      reject(new Error('No se pudo cargar el conector de Google.'));
    };
    document.head.append(script);
  });

  return identityScript;
}

function describe(response) {
  const detail = response?.error_description || response?.error || response?.type;
  return detail ? `Google rechazó el permiso: ${detail}` : 'Google rechazó el permiso.';
}
