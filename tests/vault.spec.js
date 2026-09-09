// La web de punta a punta: crear el vault, ver códigos, sincronizar, y que otro
// navegador con la misma cuenta acabe viendo lo mismo. Es el criterio de cierre
// de la fase 1, comprobado sin tocar Google.

import { expect, test } from '@playwright/test';

import { connectFakeDrive, contents, createDrive } from './fake-drive.js';

const PASSPHRASE = 'correcto caballo bateria grapa';
const GITHUB = 'otpauth://totp/GitHub:joshua@germade.es?secret=JBSWY3DPEHPK3PXP&issuer=GitHub';
const AWS = 'otpauth://totp/AWS:joshua@germade.es?secret=GEZDGNBVGY3TQOJQ&issuer=AWS';

async function createVault(page, passphrase = PASSPHRASE) {
  await page.goto('/');
  await page.fill('#setup-pass', passphrase);
  await page.fill('#setup-repeat', passphrase);
  await page.click('#setup-form button[type="submit"]');
  await expect(page.locator('#recovery-key')).not.toBeEmpty();
  await page.click('#recovery-done');
  await expect(page.locator('#vault')).toBeVisible();
}

async function unlock(page, passphrase = PASSPHRASE) {
  await page.fill('#unlock-pass', passphrase);
  await page.click('#unlock-form button[type="submit"]');
  await expect(page.locator('#vault')).toBeVisible();
}

async function addEntry(page, uri) {
  await page.click('#add-open');
  await page.fill('#add-uri', uri);
  await page.click('#add-save');
}

async function connect(page) {
  await page.click('#sync-connect');
  await expect(page.locator('#sync-state')).toContainText('Sincronizado con Drive');
}

async function synced(page) {
  await expect(page.locator('#sync-state')).toContainText('Sincronizado con Drive');
  await expect(page.locator('#sync-state')).not.toHaveClass(/failed/);
}

const issuers = (page) => page.locator('.entry .issuer');

test('el vault funciona entero sin conectar Drive', async ({ page }) => {
  await createVault(page);
  await addEntry(page, GITHUB);

  await expect(issuers(page)).toHaveText(['GitHub']);
  await expect(page.locator('.entry .code')).toHaveText(/^\d{3} \d{3}$/);
  // Sin client id de Google, la web lo dice y sigue siendo utilizable entera.
  await expect(page.locator('#sync-state')).toContainText('no tiene configurada la sincronización');

  // Recargar deja el vault bloqueado, y la passphrase lo vuelve a abrir con lo
  // que había: la copia local es autosuficiente.
  await page.reload();
  await unlock(page);
  await expect(issuers(page)).toHaveText(['GitHub']);
});

test('dos navegadores con la misma cuenta acaban viendo lo mismo', async ({ browser }) => {
  const drive = createDrive();

  const primero = await browser.newContext();
  await connectFakeDrive(primero, drive);
  const ana = await primero.newPage();

  await createVault(ana);
  await addEntry(ana, GITHUB);
  await connect(ana);

  // Un navegador que no ha visto nunca este vault: se trae la cabecera de
  // Drive y desbloquea con la misma passphrase.
  const segundo = await browser.newContext();
  await connectFakeDrive(segundo, drive);
  const bruno = await segundo.newPage();

  await bruno.goto('/');
  await bruno.click('#setup-restore');
  await unlock(bruno);
  await expect(issuers(bruno)).toHaveText(['GitHub']);

  // Y lo que da de alta Bruno vuelve al primero.
  await addEntry(bruno, AWS);
  await synced(bruno);

  await ana.click('#sync-now');
  await synced(ana);
  await expect(issuers(ana)).toHaveText(['AWS', 'GitHub']);

  await primero.close();
  await segundo.close();
});

test('a Drive no llega nada en claro', async ({ browser }) => {
  const drive = createDrive();
  const context = await browser.newContext();
  await connectFakeDrive(context, drive);
  const page = await context.newPage();

  await createVault(page);
  await addEntry(page, GITHUB);
  await connect(page);

  const subido = contents(drive);
  expect(subido.length).toBeGreaterThan(0);
  for (const { name, content } of subido) {
    const texto = content.toString('utf8').toLowerCase();
    for (const secreto of ['github', 'joshua', 'germade', 'jbswy3dpehpk3pxp']) {
      expect(`${name} ${texto}`).not.toContain(secreto);
    }
  }

  await context.close();
});

test('una cuenta que ya guarda otro vault no se pisa', async ({ browser }) => {
  const drive = createDrive();

  const primero = await browser.newContext();
  await connectFakeDrive(primero, drive);
  const ana = await primero.newPage();
  await createVault(ana);
  await connect(ana);

  // Otro navegador crea su propio vault —otra cabecera, otra MK— y lo conecta
  // a la misma cuenta. Subirlo dejaría las entradas de Ana sin quien las abra.
  const segundo = await browser.newContext();
  await connectFakeDrive(segundo, drive);
  const bruno = await segundo.newPage();
  await createVault(bruno, 'otra passphrase distinta');
  await bruno.click('#sync-connect');

  await expect(bruno.locator('#sync-state')).toContainText('otro vault');
  await expect(bruno.locator('#sync-state')).toHaveClass(/failed/);
  expect(contents(drive).filter((file) => file.name === 'header')).toHaveLength(1);

  await primero.close();
  await segundo.close();
});
