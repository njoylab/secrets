/**
 * HTTP helpers: hardened JSON responses, client IP resolution and
 * cross-origin POST protection.
 */
import { getDictionary, type ErrorKey, type Locale } from './i18n.ts';
import { normalizeAddress } from './address.mjs';

/** Internal header set by server.mjs with the IP it resolved. Untrusted from clients. */
export const RESOLVED_IP_HEADER = 'x-resolved-client-ip';

/**
 * Policy for every response that is not a rendered page: JSON, redirects and
 * errors load nothing, so they allow nothing.
 *
 * Pages carry the policy Astro builds instead (see `security.csp` in
 * `astro.config.mjs`), because only Astro knows the hashes of the scripts and
 * styles it inlines. The middleware keeps that header and falls back to this one.
 */
export const NON_PAGE_CSP =
  "default-src 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'none'";

/** Headers applied to every sensitive response: never cached, never indexed, no referrer leakage. */
export const SENSITIVE_HEADERS: Readonly<Record<string, string>> = Object.freeze({
  'cache-control': 'no-store, no-cache, must-revalidate, private',
  pragma: 'no-cache',
  expires: '0',
  'referrer-policy': 'no-referrer',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'content-security-policy': NON_PAGE_CSP,
});

const REDIRECT_BASE = 'http://placeholder.invalid';

/**
 * Reduce an untrusted redirect target to a path on this site, or `/`.
 *
 * Whitespace and control characters are refused rather than stripped: the
 * browser's URL parser silently drops tab and newline, so `/\t/evil.example`
 * leaves the server as a path and arrives as the protocol-relative
 * `//evil.example`. The value is then resolved against a placeholder origin and
 * must stay on it; only the normalized path and query are returned, so what the
 * `Location` header carries is exactly what was checked.
 */
export function safeRedirectPath(raw: string | null | undefined): string {
  if (!raw) return '/';
  if (/[\u0000-\u0020\u007f-\u009f\s]/u.test(raw)) return '/';
  if (!raw.startsWith('/') || raw.startsWith('//') || raw.includes('\\')) return '/';

  let resolved: URL;
  try {
    resolved = new URL(raw, REDIRECT_BASE);
  } catch {
    return '/';
  }
  if (resolved.origin !== REDIRECT_BASE) return '/';
  // Dot segments can collapse into a leading `//` (`/..//evil.example`), which
  // the browser would read as protocol relative.
  const path = `${resolved.pathname}${resolved.search}`;
  return path.startsWith('//') ? '/' : path;
}

const HSTS_MAX_AGE = 'max-age=15552000';

/**
 * HSTS for HTTPS responses that are not localhost.
 *
 * Browsers ignore the header on plain HTTP. Localhost is excluded so a dev
 * server cannot pin the browser to HTTPS. `includeSubDomains` is omitted: a
 * sibling host may not speak TLS.
 */
export function hstsHeaderValue(request: Request): string | null {
  const forwarded = request.headers.get('x-forwarded-proto')?.split(',')[0]?.trim().toLowerCase();
  let https = forwarded === 'https';
  if (!https) {
    try {
      https = new URL(request.url).protocol === 'https:';
    } catch {
      https = false;
    }
  }
  if (!https) return null;

  const hostHeader = request.headers.get('host')?.split(',')[0]?.trim().toLowerCase() ?? '';
  const fromHeader = hostHeader.startsWith('[')
    ? hostHeader.slice(1, hostHeader.indexOf(']'))
    : hostHeader.replace(/:\d+$/, '');
  let fromUrl = '';
  try {
    fromUrl = new URL(request.url).hostname.toLowerCase();
  } catch {
    fromUrl = '';
  }
  const hostname = fromHeader || fromUrl;
  if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1') return null;
  return HSTS_MAX_AGE;
}

export function jsonResponse(
  body: unknown,
  init: { status: number; locale: Locale; headers?: Record<string, string> },
): Response {
  return new Response(JSON.stringify(body), {
    status: init.status,
    headers: {
      ...SENSITIVE_HEADERS,
      'content-type': 'application/json; charset=utf-8',
      ...init.headers,
    },
  });
}

export function errorResponse(
  locale: Locale,
  key: ErrorKey,
  status: number,
  retryAfterSeconds?: number,
): Response {
  return jsonResponse(
    { ok: false, error: key, message: getDictionary(locale).errors[key] },
    {
      status,
      locale,
      headers: retryAfterSeconds ? { 'retry-after': String(retryAfterSeconds) } : undefined,
    },
  );
}

/**
 * A peer matches a configured proxy only on a fully equal canonical address.
 *
 * The configured list goes through the same normalization as the peer, so
 * `::ffff:127.0.0.1` and `127.0.0.1` are one address rather than two, and a
 * shared prefix never grants trust.
 */
export function isTrustedProxy(address: string, trustedProxies: readonly string[]): boolean {
  const normalized = normalizeAddress(address);
  return trustedProxies.some((proxy) => normalizeAddress(proxy) === normalized);
}

/**
 * Resolve the client address.
 *
 * Forwarding headers are honoured only when the immediate peer is a configured
 * trusted proxy; the rightmost untrusted entry of `X-Forwarded-For` wins.
 */
export function resolveClientIp(
  headers: Headers,
  peerAddress: string | undefined,
  trustedProxies: readonly string[],
): string {
  const peer = peerAddress ?? '';
  if (trustedProxies.length === 0 || !isTrustedProxy(peer, trustedProxies)) {
    return peer === '' ? 'unknown' : normalizeAddress(peer);
  }

  const forwarded = headers.get('x-forwarded-for');
  if (!forwarded) return peer === '' ? 'unknown' : normalizeAddress(peer);

  const chain = forwarded.split(',').map((entry) => normalizeAddress(entry));
  for (let i = chain.length - 1; i >= 0; i -= 1) {
    const candidate = chain[i];
    if (!candidate) continue;
    if (!isTrustedProxy(candidate, trustedProxies)) return candidate;
  }
  return chain[0] ?? 'unknown';
}

export type CrossOriginVerdict = 'ok' | 'cross_origin';

/**
 * Reject POSTs that originate from another site.
 *
 * Same-origin browser requests carry `Origin`; when present it must be one of the
 * acceptable origins. Requests without `Origin` (curl, server-side) are allowed,
 * and `Sec-Fetch-Site` provides a second check.
 */
export function checkPostOrigin(
  request: Request,
  allowedOrigins: readonly string[],
): CrossOriginVerdict {
  // Browsers always attach Sec-Fetch-Site to cross-site requests; reject outright.
  if (request.headers.get('sec-fetch-site') === 'cross-site') return 'cross_origin';

  const origin = request.headers.get('origin');
  // Only non-browser clients omit Origin; browser same-origin POSTs always send it.
  if (origin === null) return 'ok';

  // Compare the Origin header against every origin this request legitimately
  // belongs to. Never short-circuit on the request's own origin: that would
  // accept any Origin value the caller passes in.
  return acceptableOrigins(request, allowedOrigins).has(origin) ? 'ok' : 'cross_origin';
}

/**
 * Origins that legitimately match this request.
 *
 * `request.url` cannot be trusted on its own: with no `allowedDomains` configured,
 * the Node adapter falls back to `http://localhost` and every real browser POST
 * would look cross-origin. The `Host` header is added as a fallback because a
 * cross-site attacker cannot influence it, which makes it a safe CSRF reference.
 * Forwarding headers are only considered when a trusted proxy supplied them, which
 * `server.mjs` guarantees by stripping them from untrusted peers.
 */
export function acceptableOrigins(
  request: Request,
  allowedOrigins: readonly string[],
): ReadonlySet<string> {
  const origins = new Set<string>(allowedOrigins);

  try {
    origins.add(new URL(request.url).origin);
  } catch {
    // Malformed absolute URL: fall back to the header-derived candidates below.
  }

  const forwardedHost = request.headers.get('x-forwarded-host');
  if (forwardedHost) {
    for (const origin of hostOrigins(forwardedHost, request.headers.get('x-forwarded-proto'))) {
      origins.add(origin);
    }
  }

  const host = request.headers.get('host');
  if (host) {
    for (const origin of hostOrigins(host, request.headers.get('x-forwarded-proto'))) {
      origins.add(origin);
    }
  }

  return origins;
}

/** Both schemes are accepted: the socket protocol is invisible behind a TLS proxy. */
function hostOrigins(host: string, forwardedProto: string | null): string[] {
  const hostname = host.split(',')[0]?.trim();
  if (!hostname) return [];

  const sanitized = /[/\\@\s]/.test(hostname) ? undefined : hostname;
  if (!sanitized) return [];

  const schemes = forwardedProto === 'http' || forwardedProto === 'https' ? [forwardedProto] : ['http', 'https'];
  return schemes.map((scheme) => `${scheme}://${sanitized}`);
}

/** Public origin to advertise in generated links. */
export function requestOriginFrom(request: Request): string {
  try {
    return new URL(request.url).origin;
  } catch {
    return 'null';
  }
}
