import { randomBytes } from 'node:crypto';
import { defineConfig, devices } from '@playwright/test';

const databaseUrl = process.env.TEST_DATABASE_URL;
if (!databaseUrl) throw new Error('TEST_DATABASE_URL is required for browser tests');
const database = new URL(databaseUrl);
if (!['localhost', '127.0.0.1', '[::1]'].includes(database.hostname) ||
    !decodeURIComponent(database.pathname).endsWith('_test')) {
  throw new Error('Browser tests require a local *_test database');
}
process.env.DATABASE_URL = databaseUrl;

export default defineConfig({
  testDir: './tests/browser',
  fullyParallel: false,
  workers: 1,
  timeout: 30_000,
  retries: 0,
  reporter: 'list',
  use: {
    baseURL: 'http://127.0.0.1:55440',
    locale: 'en-US',
    trace: 'off',
    screenshot: 'off',
    video: 'off',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
    { name: 'mobile-chromium', use: { ...devices['Pixel 7'] } },
    { name: 'mobile-webkit', use: { ...devices['iPhone 13'] } },
  ],
  webServer: {
    command: 'node scripts/start.mjs',
    url: 'http://127.0.0.1:55440/api/health',
    reuseExistingServer: false,
    env: {
      DATABASE_URL: databaseUrl,
      SECRET_ENCRYPTION_KEY: randomBytes(32).toString('base64url'),
      HOST: '127.0.0.1', PORT: '55440', NODE_ENV: 'production',
      COOKIE_SECURE: 'false', TRUSTED_PROXIES: '', ALLOWED_ORIGINS: '',
      RATE_LIMIT_CREATE_MAX: '20', RATE_LIMIT_CREATE_WINDOW_SECONDS: '3600',
      RATE_LIMIT_REVEAL_MAX: '30', RATE_LIMIT_REVEAL_WINDOW_SECONDS: '300',
      REQUEST_METRICS: 'false',
    },
  },
});
