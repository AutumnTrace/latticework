import { defineConfig } from '@playwright/test';

const port = 4173;

export default defineConfig({
  testDir: 'e2e',
  timeout: 60_000,
  fullyParallel: true,
  reporter: process.env['CI'] ? 'github' : 'list',
  use: {
    baseURL: `http://localhost:${port}/latticework/`,
    // Use the installed Chrome instead of downloading a browser.
    channel: 'chrome',
    headless: true,
  },
  webServer: {
    command: `npm run preview -w explainer -- --port ${port} --strictPort`,
    url: `http://localhost:${port}/latticework/`,
    reuseExistingServer: !process.env['CI'],
    timeout: 60_000,
  },
});
