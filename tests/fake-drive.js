// Un `appDataFolder` de mentira, interceptando las peticiones del navegador.
//
// Habla el mismo dialecto que la API: multipart para crear, `alt=media` para
// descargar, `If-Match` para el compare-and-set y `pageToken` para paginar. Y
// exige el `Authorization`, que es la parte que solo se puede probar aquí: en
// los tests de Rust el token no existe porque el core nunca lo ve.

const CLIENT_ID = 'pruebas.apps.googleusercontent.com';
const ACCESS_TOKEN = 'token-de-prueba';

/// Google Identity Services, reducido a lo que usa `drive.js`.
const IDENTITY_STUB = `
  window.google = {
    accounts: {
      oauth2: {
        initTokenClient(config) {
          const client = {
            callback: config.callback,
            requestAccessToken() {
              client.callback({ access_token: '${ACCESS_TOKEN}', expires_in: 3600 });
            },
          };
          return client;
        },
        revoke(token, done) {
          done({ successful: true });
        },
      },
    },
  };
`;

export function createDrive() {
  return { files: [], nextId: 1 };
}

/// Todo lo que un `BrowserContext` necesita para creerse conectado a Drive.
/// Varios contextos con el mismo `drive` son varios dispositivos con la misma
/// cuenta de Google, que es el escenario que cierra la fase 1.
export async function connectFakeDrive(context, drive) {
  await context.route('**/config.js', (route) =>
    route.fulfill({
      contentType: 'text/javascript; charset=utf-8',
      body: `export const GOOGLE_CLIENT_ID = '${CLIENT_ID}';`,
    }),
  );

  await context.route('https://accounts.google.com/gsi/client', (route) =>
    route.fulfill({ contentType: 'text/javascript; charset=utf-8', body: IDENTITY_STUB }),
  );

  await context.route('https://www.googleapis.com/**', (route) =>
    route.fulfill(handle(drive, route.request())),
  );
}

/// Los ficheros de la carpeta, para mirar desde el test qué acabó subiendo.
export function contents(drive) {
  return drive.files.map((file) => ({ name: file.name, content: file.content }));
}

function handle(drive, request) {
  if (request.headers().authorization !== `Bearer ${ACCESS_TOKEN}`) {
    return json(401, { error: 'sin credencial' });
  }

  const url = new URL(request.url());
  const method = request.method();

  if (method === 'POST' && url.pathname === '/upload/drive/v3/files') {
    const { name, content } = parseMultipart(
      request.headers()['content-type'],
      request.postDataBuffer(),
    );
    return json(200, describe(create(drive, name, content)));
  }

  if (method === 'PATCH' && url.pathname.startsWith('/upload/drive/v3/files/')) {
    const file = byId(drive, url.pathname.split('/').pop());
    if (!file) return json(404, { error: 'no está' });
    if (request.headers()['if-match'] !== revisionOf(file)) {
      return json(412, { error: 'precondición fallida' });
    }

    file.revision += 1;
    file.content = request.postDataBuffer();
    return json(200, describe(file));
  }

  if (method === 'GET' && url.pathname === '/drive/v3/files') {
    return json(200, list(drive, url.searchParams));
  }

  if (method === 'GET' && url.pathname.startsWith('/drive/v3/files/')) {
    const file = byId(drive, url.pathname.split('/').pop());
    if (!file) return json(404, { error: 'no está' });
    return url.searchParams.get('alt') === 'media'
      ? { status: 200, contentType: 'application/octet-stream', body: file.content }
      : json(200, describe(file));
  }

  throw new Error(`el doble no conoce ${method} ${url.pathname}`);
}

function list(drive, params) {
  const query = params.get('q') ?? '';
  const wanted = query.match(/name = '([^']*)'/)?.[1];
  const matching = drive.files.filter((file) => wanted === undefined || file.name === wanted);

  // Páginas cortas a propósito: la paginación es de las pocas cosas que solo
  // se ejercitan si el doble insiste en partir la respuesta.
  const from = Number(params.get('pageToken') ?? 0);
  const to = Math.min(from + 3, matching.length);

  return {
    ...(to < matching.length ? { nextPageToken: String(to) } : {}),
    files: matching.slice(from, to).map(describe),
  };
}

function create(drive, name, content) {
  const file = {
    id: `f${String(drive.nextId).padStart(4, '0')}`,
    name,
    revision: 1,
    content,
  };
  drive.nextId += 1;
  drive.files.push(file);
  return file;
}

function byId(drive, id) {
  return drive.files.find((file) => file.id === id);
}

function revisionOf(file) {
  return `r${file.revision}`;
}

function describe(file) {
  return { id: file.id, name: file.name, headRevisionId: revisionOf(file) };
}

function json(status, body) {
  return { status, contentType: 'application/json', body: JSON.stringify(body) };
}

function parseMultipart(contentType, body) {
  const separator = Buffer.from(`\r\n--${contentType.split('boundary=')[1]}`);

  const metadataStart = body.indexOf('\r\n\r\n') + 4;
  const metadataEnd = body.indexOf(separator, metadataStart);
  const { name } = JSON.parse(body.subarray(metadataStart, metadataEnd).toString('utf8'));

  const rest = body.subarray(metadataEnd);
  const contentStart = rest.indexOf('\r\n\r\n') + 4;
  const contentEnd = rest.indexOf(separator, contentStart);

  return { name, content: Buffer.from(rest.subarray(contentStart, contentEnd)) };
}
