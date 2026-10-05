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
// Shared with src/lib/http.ts: the copy that decides whether a peer is trusted
// must be the same one the application uses.
import { normalizeAddress } from './src/lib/address.mjs';

/** Internal header carrying the IP resolved here. Never accepted from a client. */
const RESOLVED_IP_HEADER = 'x-resolved-client-ip';

const FORWARDED_HEADERS = ['x-forwarded-for', 'x-forwarded-proto', 'x-forwarded-host', 'x-forwarded-port'];

function readList(raw) {
  return (raw ?? '')
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
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
// Loopback by default: the process is meant to sit behind a local reverse proxy
// that terminates TLS, and binding every interface would publish it directly.
const host = process.env.HOST ?? '127.0.0.1';

const server =
  process.env.SERVER_CERT_PATH && process.env.SERVER_KEY_PATH
    ? https.createServer(
        {
          key: fs.readFileSync(process.env.SERVER_KEY_PATH),
          cert: fs.readFileSync(process.env.SERVER_CERT_PATH),
        },
        (req, res) => {
          handleRequest(req, res);
        },
      )
    : http.createServer((req, res) => {
        handleRequest(req, res);
      });

function handleRequest(req, res) {
  const length = req.headers['content-length'];
  if (length !== undefined && (!/^\d+$/.test(length) || Number(length) > 72 * 1024)) {
    res.writeHead(413, { 'cache-control': 'no-store', connection: 'close' });
    res.end();
    return;
  }
  sanitize(req);
  // Reject malformed authority before the adapter tries to construct its URL.
  try {
    if (!req.headers.host || /[\s/@\\?#]/.test(req.headers.host)) throw new Error();
    new URL(`http://${req.headers.host}`);
  } catch {
    res.writeHead(400, { 'cache-control': 'no-store', connection: 'close' });
    res.end();
    return;
  }
  handler(req, res);
}

server.headersTimeout = 15_000;
server.requestTimeout = 30_000;
server.setTimeout(30_000, (socket) => socket.destroy());
server.maxHeadersCount = 100;

server.listen(port, host, () => {
  process.stdout.write(`secrets listening on http://${host}:${port}\n`);
});

const shutdown = () => {
  // Do not let an idle keep-alive connection block deployment indefinitely.
  server.closeIdleConnections();
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 15_000).unref();
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
