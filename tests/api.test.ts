/**
 * The JSON endpoints, exercised as the browser exercises them.
 *
 * These tests drive the exported route handlers, so they cover the wire contract:
 * which fields the body must carry, which fields the reply must not, and the
 * status code each failure maps to. They also prove the two invariants that only
 * exist at this layer: a reveal is a POST, and a cancel is limited by the reveal
 * rule in its own bucket.
 */
import { beforeEach, describe, expect, it } from 'vitest';
import type { APIContext, APIRoute } from 'astro';
import { POST as createEndpoint, ALL as createAll } from '../src/pages/api/secrets/index.ts';
import { POST as revealEndpoint } from '../src/pages/api/secrets/reveal.ts';
import { POST as cancelEndpoint } from '../src/pages/api/secrets/cancel.ts';
import { POST as verifierEndpoint } from '../src/pages/api/secrets/verifier.ts';
import { CANCEL_BUCKET, REVEAL_BUCKET } from '../src/lib/rate-limit.ts';
import { MAX_PAYLOAD_BYTES } from '../src/lib/secrets.ts';
import {
  countRateLimits,
  countReceipts,
  countSecrets,
  controlLink,
  fetchRateLimitRows,
  resetEnv,
  dummyVerifier,
  sealedSecret,
  shareLink,
} from './helpers.ts';

const ORIGIN = 'https://secrets.example.com';
const CLIENT_IP = '203.0.113.7';

interface EndpointReply {
  readonly status: number;
  readonly body: Record<string, unknown>;
  readonly text: string;
}

function contextFor(path: string, body: unknown, ip = CLIENT_IP): APIContext {
  return {
    request: new Request(`${ORIGIN}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', host: 'secrets.example.com' },
      body: JSON.stringify(body),
    }),
    locals: { locale: 'en' as const, peerAddress: ip },
  } as unknown as APIContext;
}

async function call(handler: APIRoute, path: string, body: unknown, ip = CLIENT_IP): Promise<EndpointReply> {
  const response = await handler(contextFor(path, body, ip));
  const text = await response.text();
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = {};
  }
  return {
    status: response.status,
    body: (parsed ?? {}) as Record<string, unknown>,
    text,
  };
}

const create = (body: unknown, ip?: string) => call(createEndpoint, '/api/secrets', body, ip);
const reveal = (body: unknown, ip?: string) => call(revealEndpoint, '/api/secrets/reveal', body, ip);
const cancel = (body: unknown, ip?: string) => call(cancelEndpoint, '/api/secrets/cancel', body, ip);
const verifier = (body: unknown, ip?: string) => call(verifierEndpoint, '/api/secrets/verifier', body, ip);

beforeEach(async () => {
  await resetEnv();
});

describe('POST /api/secrets', () => {
  it('accepts a payload, an expiry preset and a verifier, and returns two links', async () => {
    const { payload } = await sealedSecret('wire contract');
    const reply = await create({ payload, expiresIn: '1h', verifier: await dummyVerifier() });

    expect(reply.status).toBe(201);
    expect(reply.body.ok).toBe(true);
    expect(reply.body.requiresPassword).toBe(true);
    expect(reply.text).not.toContain('pw-probe');
    // Two tokens, no absolute URL: the page owns the origin both links are built on.
    expect(String(reply.body.token)).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(String(reply.body.controlToken)).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(reply.body.url).toBeUndefined();
    expect(reply.body.controlUrl).toBeUndefined();
    expect(reply.body.expiresAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('never returns the content key, and never puts a fragment in the share url', async () => {
    const { payload, keyText } = await sealedSecret('fragment hygiene');
    const reply = await create({ payload, expiresIn: '7d' });

    // The key lives in the page, not in a response body: an observer of the JSON
    // alone cannot reconstruct the link.
    expect(reply.text).not.toContain(keyText);
    expect(reply.text).not.toContain('#');
    expect(reply.text).not.toContain(payload);
  });

  it('returns tokens that produce correct links even when the request URL is unusable', async () => {
    // Behind a proxy whose hostname is not in ALLOWED_HOSTS, the Node adapter
    // rebuilds request.url as http://localhost. Nothing derived from that URL
    // may reach the reply: the page builds both links from its own origin.
    const { payload } = await sealedSecret('misresolved host');
    const response = await createEndpoint({
      request: new Request('http://localhost/api/secrets', {
        method: 'POST',
        headers: { 'content-type': 'application/json', host: 'secrets.example.com' },
        body: JSON.stringify({ payload, expiresIn: '7d' }),
      }),
      locals: { locale: 'en', peerAddress: CLIENT_IP },
    } as unknown as APIContext);
    const text = await response.text();

    expect(text).not.toContain('localhost');
    const body = JSON.parse(text) as Record<string, unknown>;
    expect(shareLink(ORIGIN, String(body.token), 'k')).toBe(`${ORIGIN}/s/${String(body.token)}#k`);
    expect(controlLink(ORIGIN, String(body.controlToken))).toBe(`${ORIGIN}/c/${String(body.controlToken)}`);
  });

  it('returns a 422 with a typed error for an unknown expiry preset', async () => {
    const { payload } = await sealedSecret('bad preset');
    const reply = await create({ payload, expiresIn: '7' });

    expect(reply.status).toBe(422);
    expect(reply.body.error).toBe('invalidExpiry');
    expect(await countSecrets()).toBe(0);
  });

  it('returns a 422 for a missing payload, and for one over the ceiling', async () => {
    const missing = await create({ expiresIn: '7d' });
    expect(missing.status).toBe(422);
    expect(missing.body.error).toBe('payloadRequired');

    const oversized = await create({ payload: 'a'.repeat(MAX_PAYLOAD_BYTES + 1), expiresIn: '7d' });
    expect(oversized.status).toBe(422);
    expect(oversized.body.error).toBe('payloadTooLong');
    expect(await countSecrets()).toBe(0);
  });

  it('returns a 400 for a body that is not a JSON object', async () => {
    const response = await createEndpoint({
      request: new Request(`${ORIGIN}/api/secrets`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: '"just a string"',
      }),
      locals: { locale: 'en', peerAddress: CLIENT_IP },
    } as unknown as APIContext);

    expect(response.status).toBe(400);
  });

  it('answers a 405 to anything that is not a POST', async () => {
    const response = await createAll({ locals: { locale: 'en' } } as unknown as APIContext);
    expect(response.status).toBe(405);
  });

  it('refuses a cross-origin POST before creating anything', async () => {
    const { payload } = await sealedSecret('cross origin');
    const response = await createEndpoint({
      request: new Request(`${ORIGIN}/api/secrets`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'https://evil.example' },
        body: JSON.stringify({ payload, expiresIn: '7d' }),
      }),
      locals: { locale: 'en', peerAddress: CLIENT_IP },
    } as unknown as APIContext);

    expect(response.status).toBe(403);
    expect(await countSecrets()).toBe(0);
    // A refused origin must not spend the subject's budget either.
    expect(await countRateLimits()).toBe(0);
  });
});

describe('POST /api/secrets/reveal', () => {
  it('returns the sealed payload once, and 404 for every later attempt', async () => {
    const { payload } = await sealedSecret('once');
    const created = await create({ payload, expiresIn: '7d' });
    const token = String(created.body.token);

    const first = await reveal({ token });
    expect(first.status).toBe(200);
    expect(first.body.ok).toBe(true);
    expect(first.body.payload).toBe(payload);

    const second = await reveal({ token });
    expect(second.status).toBe(404);
    expect(second.body.error).toBe('unavailable');
  });

  it('refuses a password field and stores nothing', async () => {
    const { payload } = await sealedSecret('no server password');
    const reply = await create({ payload, expiresIn: '7d', password: 'pw-probe' });

    expect(reply.status).toBe(422);
    expect(reply.body.error).toBe('passwordRejected');
    expect(reply.text).not.toContain('pw-probe');
    expect(await countSecrets()).toBe(0);
  });

  it('returns the verifier without consuming, then reveal still returns the payload once', async () => {
    const { payload } = await sealedSecret('locked');
    const check = await dummyVerifier();
    const created = await create({ payload, expiresIn: '7d', verifier: check });
    const token = String(created.body.token);

    const first = await verifier({ token });
    expect(first.status).toBe(200);
    expect(first.body.verifier).toBe(check);
    expect(await countSecrets()).toBe(1);

    expect((await reveal({ token })).body.payload).toBe(payload);
    expect((await verifier({ token })).status).toBe(404);
  });

  it('answers 404, not 403, for a token that does not exist', async () => {
    const reply = await reveal({ token: 'x'.repeat(43), password: 'anything' });
    expect(reply.status).toBe(404);
  });

  it('answers 404 for a malformed token, without touching the database', async () => {
    for (const token of ['', 'not-a-token', 'x'.repeat(42), `${'x'.repeat(42)}+`]) {
      expect((await reveal({ token })).status).toBe(404);
    }
    expect(await countSecrets()).toBe(0);
  });

  it('rejects an oversized body without consuming anything', async () => {
    const { payload } = await sealedSecret('big body');
    const created = await create({ payload, expiresIn: '7d' });
    const response = await revealEndpoint({
      request: new Request(`${ORIGIN}/api/secrets/reveal`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ token: created.body.token, padding: 'x'.repeat(64 * 1024) }),
      }),
      locals: { locale: 'en', peerAddress: CLIENT_IP },
    } as unknown as APIContext);

    expect(response.status).toBe(400);
    // The payload was never read, so the secret is still redeemable.
    expect(await countSecrets()).toBe(1);
  });
});

describe('POST /api/secrets/cancel', () => {
  it('cancels a pending secret and reports the state', async () => {
    const { payload } = await sealedSecret('cancel me');
    const created = await create({ payload, expiresIn: '7d' });
    const controlToken = String(created.body.controlToken);

    const reply = await cancel({ token: controlToken });
    expect(reply.status).toBe(200);
    expect(reply.body.ok).toBe(true);
    expect(reply.body.state).toBe('cancelled');
    expect(await countSecrets()).toBe(0);
    expect(await countReceipts()).toBe(1);

    // The share link is dead, and the endpoint says nothing about the content.
    expect((await reveal({ token: String(created.body.token) })).status).toBe(404);
  });

  it('reports read after the secret was read, without changing it', async () => {
    const { payload } = await sealedSecret('already read');
    const created = await create({ payload, expiresIn: '7d' });
    const controlToken = String(created.body.controlToken);
    await reveal({ token: String(created.body.token) });

    const reply = await cancel({ token: controlToken });
    expect(reply.status).toBe(200);
    expect(reply.body.state).toBe('read');
    expect(await countReceipts()).toBe(1);
  });

  it('answers 404 for an unknown, malformed or missing control token', async () => {
    for (const token of ['x'.repeat(43), 'not-a-token', '', undefined, 42]) {
      const reply = await cancel({ token });
      expect(reply.status, String(token)).toBe(404);
      expect(reply.body.error).toBe('unavailable');
    }
  });

  it('limits cancel with the reveal rule, in its own bucket', async () => {
    // The suite allows five reveals per window. Cancel gets the same five in a
    // separate counter, so these attempts do not touch the reveal bucket.
    const { payload } = await sealedSecret('budget');
    const created = await create({ payload, expiresIn: '7d' });
    const controlToken = String(created.body.controlToken);

    const statuses: number[] = [];
    for (let attempt = 0; attempt < 7; attempt += 1) {
      statuses.push((await cancel({ token: controlToken })).status);
    }

    expect(statuses.slice(0, 5)).toEqual([200, 200, 200, 200, 200]);
    expect(statuses.slice(5)).toEqual([429, 429]);

    // The refusals land in the cancel bucket. The reveal bucket stays empty.
    expect(await fetchRateLimitRows(CANCEL_BUCKET, CLIENT_IP)).toHaveLength(1);
    expect(await fetchRateLimitRows(REVEAL_BUCKET, CLIENT_IP)).toHaveLength(0);
  });

  it('refuses a cross-origin cancel without touching the row', async () => {
    const { payload } = await sealedSecret('cancel origin');
    const created = await create({ payload, expiresIn: '7d' });
    const controlToken = String(created.body.controlToken);

    const response = await cancelEndpoint({
      request: new Request(`${ORIGIN}/api/secrets/cancel`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', origin: 'https://evil.example' },
        body: JSON.stringify({ token: controlToken }),
      }),
      locals: { locale: 'en', peerAddress: CLIENT_IP },
    } as unknown as APIContext);

    expect(response.status).toBe(403);
    expect(await countSecrets()).toBe(1);
  });
});

describe('the two links, end to end', () => {
  it('keeps the content key out of every response the server sends', async () => {
    const { payload, keyText } = await sealedSecret('end to end');
    const created = await create({ payload, expiresIn: '1d', verifier: await dummyVerifier() });
    const controlToken = String(created.body.controlToken);

    const statuses = [await reveal({ token: String(created.body.token) })];
    expect(statuses[0]?.body.payload).toBe(payload);

    const link = shareLink(ORIGIN, String(created.body.token), keyText);
    // Only the page composes the fragment, and it does it from memory.
    expect(link).toBe(`${ORIGIN}/s/${String(created.body.token)}#${keyText}`);
    expect(created.text).not.toContain(keyText);
    expect(controlLink(ORIGIN, controlToken)).not.toContain(keyText);
    expect(controlToken).not.toBe(String(created.body.token));
  });
});
