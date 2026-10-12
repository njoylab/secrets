import { createHash } from 'node:crypto';
import { test, expect, type Page } from '@playwright/test';
import pg from 'pg';
import { encodeQr } from '../../src/lib/qr.ts';

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

for (const failure of ['disabled', 'bundle-failure'] as const) {
  test(`sensitive forms never transmit plaintext when JavaScript is ${failure}`, async ({ browser, page }) => {
    const { share } = await create(page, 'synthetic protected content', 'synthetic password');
    const context = await browser.newContext({ javaScriptEnabled: failure !== 'disabled' });
    if (failure === 'bundle-failure') await context.route('**/_astro/*.js', (route) => route.abort());
    const fallback = await context.newPage();
    const outgoing: string[] = [];
    fallback.on('request', (request) => outgoing.push(request.url() + (request.postData() ?? '')));
    try {
      for (const [url, field, button] of [
        ['/', '#secret', '#create-submit'],
        [share, '#open-password', '#open-submit'],
      ]) {
        await fallback.goto(url!);
        await fallback.locator(field!).fill('synthetic sensitive marker');
        if (field === '#secret') await fallback.locator('#create-password').fill('synthetic password marker');
        await expect(fallback.locator(button!)).toBeDisabled({ timeout: 2000 });
        const currentUrl = fallback.url();
        await fallback.locator(field!).press('Enter');
        expect(fallback.url()).toBe(currentUrl);
        // Even a forced native submission must have no sensitive successful controls.
        await Promise.all([
          fallback.waitForEvent('framenavigated', (frame) => frame === fallback.mainFrame()),
          fallback.locator('form').evaluate((form) => (form as HTMLFormElement).submit()),
        ]);
        await fallback.waitForLoadState();
      }
      expect(outgoing.some((value) => /synthetic(?:[+% ]| sensitive| password)/.test(value))).toBe(false);
    } finally {
      await context.close();
    }
  });
}

for (const password of ['', 'synthetic locale password']) {
  test(`language changes preserve ${password ? 'password-derived' : 'plain'} fragment keys without transmitting them`, async ({ page }) => {
    const { share } = await create(page, 'synthetic locale content', password);
    const requests: string[] = [];
    page.on('request', (request) => requests.push(request.url() + (request.postData() ?? '')));
    await page.goto(share);
    await expect(page).not.toHaveURL(/#/);
    await page.locator('nav.lang a[lang="it"]').click();
    await expect(page.locator('html')).toHaveAttribute('lang', 'it');
    await expect(page).not.toHaveURL(/#/);
    await page.locator('nav.lang a[lang="en"]').click();
    await expect(page.locator('html')).toHaveAttribute('lang', 'en');
    if (password) await page.locator('#open-password').fill(password);
    await page.locator('#open-submit').click();
    await expect(page.locator('#secret-text')).toHaveText('synthetic locale content');
    const key = new URL(share).hash.slice(1).split('.')[0]!;
    expect(requests.some((value) => value.includes(key))).toBe(false);
  });
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

test('rejects password and direct API bypasses without consumption and clears password after creation reset', async ({ page, request }) => {
  const password = 'synthetic-browser-password';
  const { share, control, token } = await create(page, 'protected synthetic content', password);
  for (const revealProof of [undefined, 'x'.repeat(43)]) {
    const response = await request.post('/api/secrets/reveal', {
      data: { token, revealProof },
      headers: { origin: new URL(share).origin },
    });
    expect(response.status()).toBe(403);
  }
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

test('the footer links to the public repository in both languages', async ({ page }) => {
  await page.goto('/');
  const source = page.getByRole('link', { name: 'Source code', exact: true });
  await expect(source).toBeVisible();
  // The link leaves the origin, so it must not hand the opener over as well.
  await expect(source).toHaveAttribute('rel', /noopener/);
  await expect(source).toHaveAttribute('href', /^https:\/\//);

  await page.getByRole('link', { name: 'Italian', exact: true }).click();
  await expect(page.locator('html')).toHaveAttribute('lang', 'it');
  await expect(page.getByRole('link', { name: 'Codice sorgente', exact: true })).toBeVisible();
});

test('draws a scannable QR of the share link and clears it on reset', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('#result-qr')).toBeHidden();

  const { share } = await create(page, 'qr content');
  const canvas = page.locator('#result-qr');
  await expect(canvas).toBeVisible();
  // The accessible name comes from the visible label, not a second one set in
  // script, so a screen reader reads what the page shows.
  await expect(canvas).toHaveAccessibleName('QR code');

  // The page draws a whole number of pixels per module with a four module quiet
  // zone, so the grid can be read back exactly and compared with what the encoder
  // produces for this very link, content key included.
  const symbol = encodeQr(share);
  const quietZone = 4;
  const modules = symbol.size + quietZone * 2;
  const scale = Math.floor(232 / modules);
  const extent = modules * scale;

  const handle = await canvas.elementHandle();
  const drawn = await page.evaluate(
    ({ element: handle, size, pixels, quiet }) => {
      const element = handle as HTMLCanvasElement;
      const context = element.getContext('2d');
      if (!context) throw new Error('no 2d context');
      // Sample the centre of every module, and the four extreme pixels, which
      // have to be light for a scanner to lock on.
      const grid: boolean[][] = [];
      for (let row = 0; row < size; row += 1) {
        const line: boolean[] = [];
        for (let column = 0; column < size; column += 1) {
          const x = Math.floor((column + quiet) * pixels + pixels / 2);
          const y = Math.floor((row + quiet) * pixels + pixels / 2);
          line.push((context.getImageData(x, y, 1, 1).data[0] ?? 255) < 128);
        }
        grid.push(line);
      }
      const corners = [
        context.getImageData(0, 0, 1, 1).data[0] ?? 255,
        context.getImageData(element.width - 1, 0, 1, 1).data[0] ?? 255,
        context.getImageData(0, element.height - 1, 1, 1).data[0] ?? 255,
        context.getImageData(element.width - 1, element.height - 1, 1, 1).data[0] ?? 255,
      ];
      return { grid, corners, width: element.width, height: element.height };
    },
    { element: handle, size: symbol.size, pixels: scale, quiet: quietZone },
  );

  expect(drawn.width).toBe(extent);
  expect(drawn.height).toBe(extent);
  for (const corner of drawn.corners) expect(corner).toBeGreaterThan(200);

  expect(drawn.grid.length).toBe(symbol.size);
  for (let row = 0; row < symbol.size; row += 1) {
    expect(drawn.grid[row]).toEqual([...(symbol.modules[row] ?? [])]);
  }

  // The three finder patterns are what a scanner locks on, so they are checked
  // here independently of the encoder.
  const finderAt = (row: number, column: number): boolean => {
    const ring = '1111111';
    const light = '1000001';
    const core = '1011101';
    const expected = [ring, light, core, core, core, light, ring];
    const rows = drawn.grid.slice(row, row + 7).map((line) => line.slice(column, column + 7).map((d) => (d ? '1' : '0')).join(''));
    return rows.every((line, index) => line === expected[index]);
  };
  const size = symbol.size;
  expect(finderAt(0, 0)).toBe(true);
  expect(finderAt(0, size - 7)).toBe(true);
  expect(finderAt(size - 7, 0)).toBe(true);

  await page.locator('#result-another').click();
  await expect(canvas).toBeHidden();
  // The pixels are cleared, not merely hidden: they hold the content key.
  expect(await canvas.evaluate((element: HTMLCanvasElement) => element.width)).toBe(0);
});

test('control link reports creation, expiry and closing instants', async ({ page }) => {
  const { control } = await create(page, 'instants');

  await page.goto(control);
  await expect(page.locator('#control-state-pending')).toBeVisible();
  await expect(page.locator('#control-created')).not.toBeEmpty();
  await expect(page.locator('#control-expiry')).not.toBeEmpty();
  // Nothing has closed yet, so the closing row stays out of the layout.
  await expect(page.locator('#control-closed-row')).toBeHidden();
  // Each instant is a term and value pair inside one definition list, so the
  // label travels with the value rather than being an unassociated paragraph.
  const pairs = await page.locator('.meta-list > .meta:not([hidden])').evaluateAll((rows) =>
    rows.map((row) => ({
      term: row.querySelector('dt')?.textContent?.trim() ?? '',
      value: row.querySelector('dd')?.textContent?.trim() ?? '',
    })),
  );
  expect(pairs.map((pair) => pair.term)).toEqual(['Created', 'Expires']);
  for (const pair of pairs) expect(pair.value).not.toBe('');

  // Cancelling closes the secret, and the closing instant replaces the created one.
  await page.locator('#control-cancel').click();
  await expect(page.locator('#control-state-cancelled')).toBeVisible();
  await expect(page.locator('#control-closed')).not.toBeEmpty();
  // The creation instant went with the row, so its slot is hidden.
  await expect(page.locator('#control-created-row')).toBeHidden();

  // The control page never shows any of the secret text.
  await expect(page.locator('body')).not.toContainText('instants');
});

test('the QR code and the control instants are localised in Italian', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('link', { name: 'Italian', exact: true }).click();
  await expect(page.locator('html')).toHaveAttribute('lang', 'it');

  await page.locator('#secret').fill('prova');
  await page.locator('#create-submit').click();
  await expect(page.locator('#result-panel')).toBeVisible();

  await expect(page.locator('#result-qr-label')).toHaveText('Codice QR');
  await expect(page.locator('#result-qr-hint')).toHaveText('Scansiona per aprire il link. Contiene la chiave.');
  // The accessible name follows the visible label in this language too.
  await expect(page.locator('#result-qr')).toHaveAccessibleName('Codice QR');

  const control = await page.locator('#result-control-link').inputValue();
  await page.goto(control);
  // The labels are uppercased by CSS, so they are compared case insensitively.
  const terms = async (): Promise<string[]> =>
    (await page.locator('.meta-list > .meta:not([hidden]) dt').allInnerTexts()).map((text) => text.toLowerCase());
  expect(await terms()).toEqual(['creato', 'scadenza']);

  await page.locator('#control-cancel').click();
  await expect(page.locator('#control-state-cancelled')).toBeVisible();
  expect(await terms()).toEqual(['scadenza', 'chiuso']);
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
