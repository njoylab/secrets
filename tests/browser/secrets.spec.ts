import { createHash } from 'node:crypto';
import { test, expect, type Page } from '@playwright/test';
import pg from 'pg';

// The config validates the target before this destructive fixture can run.
const pool = new pg.Pool({ connectionString: process.env.TEST_DATABASE_URL });
test.beforeEach(async () => {
  await pool.query('TRUNCATE secrets, secret_receipts, rate_limits');
});
test.afterAll(async () => { await pool.end(); });

async function create(page: Page, text = 'synthetic test content', password = '') {
  await page.goto('/');
  await page.locator('#secret').fill(text);
  await page.locator('#create-password').fill(password);
  await page.locator('#create-submit').click();
  await expect(page.locator('#result-panel')).toBeVisible();
  const share = await page.locator('#result-link').inputValue();
  const control = await page.locator('#result-control-link').inputValue();
  const token = new URL(share).pathname.split('/').pop()!;
  return { share, control, token };
}

test('encrypts before transmission, preserves inert text, and never consumes through GET', async ({ page, request }) => {
  const text = '<img src=x onerror="window.injected=true">\n  € synthetic text';
  const outgoing: string[] = [];
  page.on('request', (req) => {
    if (req.method() === 'POST') outgoing.push(req.postData() ?? '');
  });
  const { share, control } = await create(page, text);
  expect(outgoing.some((body) => body.includes('synthetic text'))).toBe(false);
  await expect(page.locator('#secret')).toHaveValue('');
  for (let i = 0; i < 3; i++) {
    expect((await request.get(new URL(share).pathname)).status()).toBe(200);
    expect((await request.head(new URL(share).pathname)).status()).toBe(200);
  }
  await page.goto(share);
  await expect(page.locator('#open-submit')).toBeVisible();
  expect(new URL(page.url()).hash.length).toBe(0);
  await expect(page.locator('#secret-panel')).toBeHidden();
  await page.locator('#open-submit').click();
  await expect(page.locator('#secret-text')).toHaveText(text);
  expect(await page.evaluate(() => 'injected' in window)).toBe(false);
  await page.goto(control);
  await expect(page.locator('#control-state-read')).toBeVisible();
  await page.goto(share);
  await expect(page.locator('#open-form')).toHaveCount(0);
});

test('rejects a wrong password without consumption and clears password after creation reset', async ({ page }) => {
  const password = 'synthetic-browser-password';
  const { share, control } = await create(page, 'protected synthetic content', password);
  await page.locator('#result-another').click();
  await expect(page.locator('#create-password')).toHaveValue('');
  await expect(page.locator('#result-password')).toHaveValue('');
  const outgoing: string[] = [];
  page.on('request', (req) => { if (req.method() === 'POST') outgoing.push(req.postData() ?? ''); });
  await page.goto(share);
  await page.locator('#open-password').fill('wrong');
  await page.locator('#open-submit').click();
  await expect(page.locator('#open-status')).toHaveText('Incorrect password');
  const check = await page.context().newPage();
  await check.goto(control);
  await expect(check.locator('#control-state-pending')).toBeVisible();
  await check.close();
  await page.locator('#open-password').fill(password);
  await page.locator('#open-submit').click();
  await expect(page.locator('#secret-text')).toHaveText('protected synthetic content');
  expect(outgoing.some((body) => body.includes(password))).toBe(false);
});

test('accepts a 50 KiB secret and copies the generated link', async ({ page }) => {
  const text = 'a'.repeat(50 * 1024);
  const { share } = await create(page, text);
  await page.locator('#result-copy').click();
  await expect(page.locator('#result-copy')).toHaveAttribute('data-copied', 'true');
  await page.goto(share);
  await page.locator('#open-submit').click();
  await expect(page.locator('#secret-panel')).toBeVisible();
  expect(await page.locator('#secret-text').evaluate((el) => el.textContent?.length)).toBe(50 * 1024);
});

test('missing fragment never sends reveal and cancellation prevents reading', async ({ page }) => {
  const { share, control } = await create(page);
  let reveals = 0;
  page.on('request', (req) => { if (req.url().endsWith('/api/secrets/reveal')) reveals++; });
  await page.goto(new URL(share).pathname);
  await page.locator('#open-submit').click();
  await expect(page.locator('#open-status')).not.toBeEmpty();
  expect(reveals).toBe(0);
  await page.goto(control);
  await expect(page.locator('#control-state-pending')).toBeVisible();
  await page.locator('#control-cancel').click();
  await expect(page.locator('#control-state-cancelled')).toBeVisible();
  await page.goto(share);
  await expect(page.locator('#open-form')).toHaveCount(0);
});

test('expired records cannot be read through the real HTTP server', async ({ page, request }) => {
  const { share, control, token } = await create(page);
  await pool.query("UPDATE secrets SET expires_at = now() - interval '1 second' WHERE token_hash = $1",
    [createHash('sha256').update(token).digest('hex')]);
  await page.goto(control);
  await expect(page.locator('#control-state-expired')).toBeVisible();
  const response = await request.post('/api/secrets/reveal', { data: { token } });
  expect(response.status()).toBe(404);
  await page.goto(share);
  await expect(page.locator('#open-form')).toHaveCount(0);
});

test('exactly one HTTP reveal succeeds under concurrency', async ({ page, request }) => {
  const { token, control } = await create(page);
  const responses = await Promise.all(Array.from({ length: 8 }, () =>
    request.post('/api/secrets/reveal', { data: { token } })));
  expect(responses.filter((response) => response.status() === 200)).toHaveLength(1);
  expect(responses.filter((response) => response.status() === 404)).toHaveLength(7);
  await page.goto(control);
  await expect(page.locator('#control-state-read')).toBeVisible();
});

test('input limits, labels, keyboard access, languages and responsive layout', async ({ page }) => {
  await page.goto('/');
  await page.locator('#create-submit').click();
  await expect(page.locator('#secret')).toHaveAttribute('aria-invalid', 'true');
  await page.locator('#secret').fill('€'.repeat(18_000));
  await page.locator('#create-submit').click();
  await expect(page.locator('#create-status')).not.toBeEmpty();
  expect(await pool.query('SELECT 1 FROM secrets').then((result) => result.rowCount)).toBe(0);
  await expect(page.locator('#secret')).toHaveAccessibleName('Secret');
  await page.locator('#secret').focus();
  await page.keyboard.press('Tab');
  await expect(page.locator('#expiry')).toBeFocused();
  expect(await page.locator('#expiry').evaluate((el) => getComputedStyle(el).outlineStyle)).not.toBe('none');
  await page.getByRole('link', { name: 'Italian', exact: true }).click();
  await expect(page.locator('html')).toHaveAttribute('lang', 'it');
  await expect(page.locator('#secret')).toHaveAccessibleName('Segreto');
  await page.reload();
  await expect(page.locator('html')).toHaveAttribute('lang', 'it');
  await page.getByRole('link', { name: 'Inglese', exact: true }).click();
  await expect(page.locator('html')).toHaveAttribute('lang', 'en');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

test('HTTP protection rejects cross-origin requests, caps creation quota and hardens readiness', async ({ request }) => {
  const health = await request.get('/api/health');
  expect(health.status()).toBe(200);
  expect(await health.json()).toEqual({ ok: true });
  expect(health.headers()['cache-control']).toContain('no-store');
  expect(health.headers()['content-security-policy']).toContain("frame-ancestors 'none'");
  expect(health.headers()['referrer-policy']).toBe('no-referrer');
  const foreign = await request.post('/api/secrets', {
    headers: { origin: 'https://foreign.invalid', 'sec-fetch-site': 'cross-site' }, data: {},
  });
  expect(foreign.status()).toBe(403);
  const attempts = [];
  for (let i = 0; i < 21; i++) attempts.push(await request.post('/api/secrets', { data: {} }));
  expect(attempts.slice(0, 20).every((response) => response.status() === 422)).toBe(true);
  expect(attempts[20]!.status()).toBe(429);
  expect(Number(attempts[20]!.headers()['retry-after'])).toBeGreaterThan(0);
  const oversized = await request.post('/api/secrets', { data: 'a'.repeat(73 * 1024) });
  expect(oversized.status()).toBe(413);
});
