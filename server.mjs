/**
 * Production Node entry point.
 *
 * It exists because Astro's Node adapter derives the client address from
 * `X-Forwarded-For` unconditionally: an untrusted client could otherwise spoof
 * its IP and reset its own rate limit budget on every request. This wrapper runs
 * before Astro and therefore gets to decide which forwarding headers survive.
 *
 * Responsibilities, per request:
 *  1. drop any client-supplied copy of the internal IP header;
 *  2. resolve the client IP using only proxies listed in TRUSTED_PROXIES;
 *  3. strip `x-forwarded-*` from untrusted peers so Astro cannot be misled;
 *  4. hand the resolved, trustworthy IP to the app.
 */
import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';

/** Internal header carrying the IP resolved here. Never accepted from a client. */
const RESOLVED_IP_HEADER = 'x-resolved-client-ip';

const FORWARDED_HEADERS = ['x-forwarded-for', 'x-forwarded-proto', 'x-forwarded-host', 'x-forwarded-port'];

function readList(raw) {
  return (raw ?? '')
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

/** Strip IPv6 brackets and any port suffix so proxy entries can be compared directly. */
function normalizeAddress(value) {
  const trimmed = String(value ?? '').trim();
  if (trimmed.startsWith('[')) {
    const end = trimmed.indexOf(']');
    return end === -1 ? trimmed : trimmed.slice(1, end);
  }
  return trimmed.includes(':') && trimmed.split(':').length === 2
    ? trimmed.slice(0, trimmed.lastIndexOf(':'))
    : trimmed;
}

const trustedProxies = new Set(readList(process.env.TRUSTED_PROXIES).map(normalizeAddress));

function isTrustedPeer(address) {
  return trustedProxies.has(normalizeAddress(address));
}

/** Rightmost untrusted entry of the forwarding chain is the real client. */
function resolveFromForwardedFor(headerValue) {
  const chain = String(headerValue)
    .split(',')
    .map((entry) => normalizeAddress(entry))
    .filter((entry) => entry.length > 0);
  if (chain.length === 0) return undefined;

  for (let i = chain.length - 1; i >= 0; i -= 1) {
    const candidate = chain[i];
    if (!isTrustedPeer(candidate)) return candidate;
  }
  return chain[0];
}

function sanitize(req) {
  const peer = req.socket.remoteAddress;

  // A client must never be able to dictate its own resolved identity.
  delete req.headers[RESOLVED_IP_HEADER];

  if (!isTrustedPeer(peer)) {
    for (const header of FORWARDED_HEADERS) delete req.headers[header];
    req.headers[RESOLVED_IP_HEADER] = normalizeAddress(peer) || 'unknown';
    return;
  }

  const forwardedFor = req.headers['x-forwarded-for'];
  const resolved =
    (Array.isArray(forwardedFor) ? forwardedFor[0] : forwardedFor) === undefined
      ? undefined
      : resolveFromForwardedFor(Array.isArray(forwardedFor) ? forwardedFor.join(',') : forwardedFor);

  // The chain is consumed here and must not reach Astro, which would otherwise
  // re-derive the address from the same untrusted value.
  delete req.headers['x-forwarded-for'];
  req.headers[RESOLVED_IP_HEADER] = resolved ?? normalizeAddress(peer) ?? 'unknown';
}

// Astro auto-starts its own server when the build is imported; this entry point
// owns the listener instead.
process.env.ASTRO_NODE_AUTOSTART = 'disabled';

const { handler, options } = await import('./dist/server/entry.mjs');

const port = process.env.PORT ? Number.parseInt(process.env.PORT, 10) : (options.port ?? 4321);
const host = process.env.HOST ?? '0.0.0.0';

const server =
  process.env.SERVER_CERT_PATH && process.env.SERVER_KEY_PATH
    ? https.createServer(
        {
          key: fs.readFileSync(process.env.SERVER_CERT_PATH),
          cert: fs.readFileSync(process.env.SERVER_CERT_PATH),
        },
        (req, res) => {
          sanitize(req);
          handler(req, res);
        },
      )
    : http.createServer((req, res) => {
        sanitize(req);
        handler(req, res);
      });

server.listen(port, host, () => {
  process.stdout.write(`secrets listening on http://${host}:${port}\n`);
});

const shutdown = () => {
  server.close(() => process.exit(0));
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);