// Pruebas de la capa JS: la web de verdad, en un navegador de verdad, contra un
// doble del `appDataFolder` de Drive. Lo que no cubren los tests de Rust es
// justo esto: que el puente WASM, el OAuth y el pintado encajen.
import { defineConfig, devices } from '@playwright/test';

const PORT = 4173;

export default defineConfig({
  testDir: './tests',
  // Cada test monta su propio Drive de mentira, así que no comparten estado.
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  reporter: process.env.CI ? 'list' : 'line',
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    // En entornos donde el navegador viene preinstalado y no lo baja Playwright.
    launchOptions: process.env.CHROMIUM_PATH
      ? { executablePath: process.env.CHROMIUM_PATH }
      : {},
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    // La web es estática: servirla tal cual es exactamente lo que hace Pages.
    command: `python3 -m http.server ${PORT} --bind 127.0.0.1 --directory web`,
    url: `http://127.0.0.1:${PORT}/index.html`,
    reuseExistingServer: !process.env.CI,
  },
});
