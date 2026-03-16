const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  testDir: './tests/browser',
  timeout: 30_000,
  fullyParallel: true,
  use: {
    baseURL: 'http://127.0.0.1:4174',
    headless: true
  },
  webServer: {
    command: 'npx vite --host 127.0.0.1 --port 4174',
    port: 4174,
    reuseExistingServer: true,
    timeout: 120_000
  }
});
