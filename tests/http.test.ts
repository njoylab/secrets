/**
 * HTTP layer: cross-origin POST protection, client address resolution and the
 * security headers carried by every sensitive response.
 *
 * Requests are synthetic: no server is started, so the checks are exactly the
 * ones a hostile page could influence (Origin, Sec-Fetch-Site, Host, X-Forwarded-*).
 */
import { describe, expect, it } from 'vitest';
import {
  RESOLVED_IP_HEADER,
  acceptableOrigins,
  checkPostOrigin,
  errorResponse,
  isTrustedProxy,
  jsonResponse,
  resolveClientIp,
} from '../src/lib/http.ts';

const NO_ORIGINS: readonly string[] = [];

function post(url: string, headers: Readonly<Record<string, string>> = {}): Request {
  return new Request(url, { method: 'POST', headers: { ...headers } });
}

function header(source: Readonly<Record<string, string>>): Headers {
  return new Headers({ ...source });
}

describe('checkPostOrigin: the request origin', () => {
  it('accepts an Origin that matches the absolute request URL', () => {
    const request = post('https://secrets.example.com/api/secrets', {
      origin: 'https://secrets.example.com',
    });
    expect(checkPostOrigin(request, NO_ORIGINS)).toBe('ok');
  });

  it('accepts an Origin derived from the Host header on http and on https', () => {
    // Behind a TLS terminating proxy the socket scheme is invisible, so both
    // schemes must be accepted when no X-Forwarded-Proto says otherwise.
    const build = (origin: string): Request =>
      post('http://localhost:4321/api/secrets', { host: 'secrets.example.com', origin });
    expect(checkPostOrigin(build('http://secrets.example.com'), NO_ORIGINS)).toBe('ok');
    expect(checkPostOrigin(build('https://secrets.example.com'), NO_ORIGINS)).toBe('ok');
    expect([...acceptableOrigins(build('http://secrets.example.com'), NO_ORIGINS)].sort()).toEqual([
      'http://localhost:4321',
      'http://secrets.example.com',
      'https://secrets.example.com',
    ]);
  });

  it('keeps a port in the Host derived origin', () => {
    expect(
      checkPostOrigin(
        post('http://localhost:4321/api/secrets', { host: 'secrets.example.com:8443', origin: 'https://secrets.example.com:8443' }),
        NO_ORIGINS,
      ),
    ).toBe('ok');
    expect(
      checkPostOrigin(
        post('http://localhost:4321/api/secrets', { host: 'secrets.example.com:8443', origin: 'https://secrets.example.com' }),
        NO_ORIGINS,
      ),
    ).toBe('cross_origin');
  });

  it('honours X-Forwarded-Host as an origin source', () => {
    const request = post('http://localhost:4321/api/secrets', {
      host: 'internal.local:4321',
      'x-forwarded-host': 'secrets.example.com',
      'x-forwarded-proto': 'https',
      origin: 'https://secrets.example.com',
    });
    expect(acceptableOrigins(request, NO_ORIGINS).has('https://secrets.example.com')).toBe(true);
    expect(checkPostOrigin(request, NO_ORIGINS)).toBe('ok');
  });

  it('restricts the Host derived origin to the forwarded scheme when there is one', () => {
    const build = (origin: string): Request =>
      post('http://localhost:4321/api/secrets', {
        host: 'secrets.example.com',
        'x-forwarded-proto': 'https',
        origin,
      });
    expect(checkPostOrigin(build('https://secrets.example.com'), NO_ORIGINS)).toBe('ok');
    expect(checkPostOrigin(build('http://secrets.example.com'), NO_ORIGINS)).toBe('cross_origin');
  });

  it('takes the first entry of a forwarded host chain', () => {
    const request = post('http://localhost:4321/api/secrets', {
      host: 'internal.local:4321',
      'x-forwarded-host': 'secrets.example.com, internal.local:4321',
      origin: 'https://secrets.example.com',
    });
    expect(checkPostOrigin(request, NO_ORIGINS)).toBe('ok');
  });
});

describe('checkPostOrigin: rejections', () => {
  it('rejects sec-fetch-site: cross-site even when Origin matches', () => {
    const request = post('https://secrets.example.com/api/secrets', {
      origin: 'https://secrets.example.com',
      'sec-fetch-site': 'cross-site',
    });
    expect(checkPostOrigin(request, NO_ORIGINS)).toBe('cross_origin');
  });

  it('rejects sec-fetch-site: cross-site before consulting allowed origins', () => {
    const request = post('https://secrets.example.com/api/secrets', {
      origin: 'https://partner.example',
      'sec-fetch-site': 'cross-site',
    });
    expect(checkPostOrigin(request, ['https://partner.example'])).toBe('cross_origin');
  });

  it('rejects a foreign Origin', () => {
    const request = post('https://secrets.example.com/api/secrets', { origin: 'https://evil.example' });
    expect(checkPostOrigin(request, NO_ORIGINS)).toBe('cross_origin');
  });

  it('rejects an Origin that only looks like the request origin', () => {
    // A parser that stops at the first dot, or one that ignores the port, would
    // accept these; exact string comparison against the acceptable set must not.
    const cases: ReadonlyArray<readonly [string, string]> = [
      ['suffix confusion', 'https://secrets.example.com.evil.example'],
      ['prefix confusion', 'https://evilexample.com'],
      ['subdomain of the attacker', 'https://secrets.example.com@evil.example'],
      ['userinfo smuggling', 'https://secrets.example.com%40evil.example'],
      ['trailing dot', 'https://secrets.example.com.'],
      ['trailing slash', 'https://secrets.example.com/'],
      ['opaque origin', 'null'],
      ['case changed scheme', 'HTTPS://secrets.example.com'],
      ['port injected', 'https://secrets.example.com:443'],
    ];
    for (const [label, origin] of cases) {
      const request = post('https://secrets.example.com/api/secrets', {
        host: 'secrets.example.com',
        origin,
      });
      expect(checkPostOrigin(request, NO_ORIGINS), label).toBe('cross_origin');
    }
  });

  it('rejects an Origin that only matches by scheme downgrade', () => {
    const request = post('https://secrets.example.com/api/secrets', {
      host: 'secrets.example.com',
      'x-forwarded-proto': 'https',
      origin: 'http://secrets.example.com',
    });
    expect(checkPostOrigin(request, NO_ORIGINS)).toBe('cross_origin');
  });

  it('rejects a sub-resource origin, which browsers never send', () => {
    const request = post('https://secrets.example.com/api/secrets', { origin: 'https://secrets.example.com/api' });
    expect(checkPostOrigin(request, NO_ORIGINS)).toBe('cross_origin');
  });
});

describe('checkPostOrigin: permissive cases', () => {
  it('accepts a request without an Origin header', () => {
    // curl and server side callers do not send Origin; only browsers can be
    // constrained by it, and they always send it on a POST.
    expect(checkPostOrigin(post('https://secrets.example.com/api/secrets'), NO_ORIGINS)).toBe('ok');
    expect(checkPostOrigin(post('https://secrets.example.com/api/secrets', { host: 'evil.example' }), NO_ORIGINS)).toBe(
      'ok',
    );
  });

  it('accepts an explicitly allowed origin, including one the request never mentions', () => {
    const request = post('https://secrets.example.com/api/secrets', { origin: 'https://partner.example' });
    expect(checkPostOrigin(request, ['https://partner.example'])).toBe('ok');
    expect(checkPostOrigin(request, ['https://other.example', 'https://partner.example'])).toBe('ok');
    expect(checkPostOrigin(request, ['https://other.example'])).toBe('cross_origin');
    expect([...acceptableOrigins(request, ['https://partner.example'])].sort()).toEqual([
      'https://partner.example',
      'https://secrets.example.com',
    ]);
  });

  it('accepts same-site requests that are not cross-site per Sec-Fetch-Site', () => {
    for (const site of ['same-origin', 'same-site', 'none']) {
      const request = post('https://secrets.example.com/api/secrets', {
        origin: 'https://secrets.example.com',
        'sec-fetch-site': site,
      });
      expect(checkPostOrigin(request, NO_ORIGINS), site).toBe('ok');
    }
  });
});

describe('checkPostOrigin: hostile Host headers', () => {
  // A cross-site attacker cannot set Host, so Host is a safe reference. It must
  // also stay a safe reference when its value is syntactically hostile.
  const hostile: ReadonlyArray<readonly [string, string, readonly string[]]> = [
    ['path in the host', 'evil.example/x', ['https://evil.example/x', 'https://evil.example']],
    ['userinfo in the host', 'user@evil.example', ['https://user@evil.example', 'https://evil.example']],
    ['backslash in the host', 'evil.example\\@secrets.example.com', ['https://evil.example']],
    ['empty host', '', ['https://', 'https://evil.example']],
    ['whitespace only host', '   ', ['https://', 'https://evil.example']],
  ];

  it.each(hostile)('does not derive an acceptable origin from a %s', (_label, host, crafted) => {
    const request = post('https://secrets.example.com/api/secrets', { host, origin: 'https://evil.example' });
    const acceptable = acceptableOrigins(request, NO_ORIGINS);
    // Only the absolute request URL may survive, and nothing derived from the
    // hostile value.
    expect([...acceptable]).toEqual(['https://secrets.example.com']);
    for (const origin of crafted) {
      expect(acceptable.has(origin), origin).toBe(false);
      expect(checkPostOrigin(post('https://secrets.example.com/api/secrets', { host, origin }), NO_ORIGINS), origin).toBe(
        'cross_origin',
      );
    }
  });

  it('refuses a parser confusion attempt against a real hostname', () => {
    const request = post('https://secrets.example.com/api/secrets', {
      host: 'secrets.example.com',
      origin: 'https://secrets.example.com.evil.example',
    });
    expect(checkPostOrigin(request, NO_ORIGINS)).toBe('cross_origin');
    expect([...acceptableOrigins(request, NO_ORIGINS)].sort()).toEqual([
      'http://secrets.example.com',
      'https://secrets.example.com',
    ]);
  });
});

describe('acceptableOrigins', () => {
  it('is a superset of the configured origins and of the request URL origin', () => {
    const request = post('https://secrets.example.com/api/secrets', { host: 'secrets.example.com' });
    const acceptable = acceptableOrigins(request, ['https://partner.example', 'http://partner.example']);
    expect(acceptable.has('https://partner.example')).toBe(true);
    expect(acceptable.has('http://partner.example')).toBe(true);
    expect(acceptable.has('https://secrets.example.com')).toBe(true);
  });

  it('adds both schemes for a forwarded host and one when the scheme is known', () => {
    const both = post('http://localhost/api/secrets', { 'x-forwarded-host': 'secrets.example.com' });
    expect(both.headers.get('x-forwarded-host')).toBe('secrets.example.com');
    expect([...acceptableOrigins(both, NO_ORIGINS)].sort()).toEqual([
      'http://localhost',
      'http://secrets.example.com',
      'https://secrets.example.com',
    ]);

    const one = post('http://localhost/api/secrets', {
      'x-forwarded-host': 'secrets.example.com',
      'x-forwarded-proto': 'https',
    });
    expect([...acceptableOrigins(one, NO_ORIGINS)].sort()).toEqual([
      'http://localhost',
      'https://secrets.example.com',
    ]);
  });

  it('ignores an unknown forwarded scheme instead of trusting it', () => {
    const request = post('http://localhost/api/secrets', {
      host: 'secrets.example.com',
      'x-forwarded-proto': 'javascript',
    });
    expect([...acceptableOrigins(request, NO_ORIGINS)].sort()).toEqual([
      'http://localhost',
      'http://secrets.example.com',
      'https://secrets.example.com',
    ]);
  });
});

describe('isTrustedProxy', () => {
  const trusted = ['192.0.2.10', '2001:db8::1'];

  it('matches an exact address', () => {
    expect(isTrustedProxy('192.0.2.10', trusted)).toBe(true);
    expect(isTrustedProxy('192.0.2.11', trusted)).toBe(false);
    expect(isTrustedProxy('2001:db8::1', trusted)).toBe(true);
    expect(isTrustedProxy('2001:db8::2', trusted)).toBe(false);
  });

  it('ignores brackets, ports and surrounding whitespace', () => {
    expect(isTrustedProxy('192.0.2.10:8080', trusted)).toBe(true);
    expect(isTrustedProxy('  192.0.2.10  ', trusted)).toBe(true);
    expect(isTrustedProxy('[2001:db8::1]', trusted)).toBe(true);
    expect(isTrustedProxy('[2001:db8::1]:443', trusted)).toBe(true);
    expect(isTrustedProxy('[2001:db8::1]:443', ['[2001:db8::1]:443'])).toBe(true);
  });

  it('trusts nobody when the list is empty', () => {
    expect(isTrustedProxy('192.0.2.10', [])).toBe(false);
    expect(isTrustedProxy('', [])).toBe(false);
  });

  it('does not treat a shared prefix as a match', () => {
    expect(isTrustedProxy('192.0.2.1', trusted)).toBe(false);
    expect(isTrustedProxy('192.0.2.100', trusted)).toBe(false);
  });
});

describe('isTrustedProxy: IPv4 mapped in IPv6', () => {
  // A dual stack listener reports its peers in the mapped form, so a proxy
  // configured as plain IPv4 must still be recognised.
  it('matches a mapped peer against a plain IPv4 entry', () => {
    expect(isTrustedProxy('::ffff:127.0.0.1', ['127.0.0.1'])).toBe(true);
    expect(isTrustedProxy('::FFFF:127.0.0.1', ['127.0.0.1'])).toBe(true);
    expect(isTrustedProxy('[::ffff:127.0.0.1]:41234', ['127.0.0.1'])).toBe(true);
  });

  it('matches a plain IPv4 peer against a mapped entry', () => {
    expect(isTrustedProxy('127.0.0.1', ['::ffff:127.0.0.1'])).toBe(true);
    expect(isTrustedProxy('127.0.0.1:41234', ['::FFFF:127.0.0.1'])).toBe(true);
  });

  it('keeps two different mapped addresses distinct', () => {
    expect(isTrustedProxy('::ffff:10.0.0.1', ['10.0.0.2'])).toBe(false);
    expect(isTrustedProxy('10.0.0.1', ['::ffff:10.0.0.2'])).toBe(false);
  });

  it('does not rewrite a plain IPv6 address', () => {
    expect(isTrustedProxy('2001:db8::1', ['2001:DB8::1'])).toBe(true);
    expect(isTrustedProxy('::1', ['127.0.0.1'])).toBe(false);
  });
});

describe('resolveClientIp', () => {
  const trusted = ['192.0.2.10', '2001:db8::1'];

  it('ignores X-Forwarded-For when no proxy is trusted', () => {
    const headers = header({ 'x-forwarded-for': '203.0.113.7' });
    expect(resolveClientIp(headers, '192.0.2.10', [])).toBe('192.0.2.10');
  });

  it('ignores X-Forwarded-For when the peer is not a trusted proxy', () => {
    const headers = header({ 'x-forwarded-for': '203.0.113.7' });
    expect(resolveClientIp(headers, '198.51.100.5', trusted)).toBe('198.51.100.5');
  });

  it('returns the rightmost untrusted hop of the chain', () => {
    const headers = header({ 'x-forwarded-for': '203.0.113.7, 192.0.2.10' });
    expect(resolveClientIp(headers, '192.0.2.10', trusted)).toBe('203.0.113.7');
  });

  it('walks several trusted hops to the first untrusted one', () => {
    const headers = header({ 'x-forwarded-for': '203.0.113.7, 198.51.100.5, 192.0.2.10, 2001:db8::1' });
    expect(resolveClientIp(headers, '2001:db8::1', trusted)).toBe('198.51.100.5');
  });

  it('lets a client spoof a hop that claims to be a trusted proxy', () => {
    // 203.0.113.9 is a public client, but it says it is 192.0.2.10: only the
    // rightmost untrusted entry counts, so the claim must not be believed.
    const headers = header({ 'x-forwarded-for': '192.0.2.10, 203.0.113.9' });
    expect(resolveClientIp(headers, '192.0.2.10', trusted)).toBe('203.0.113.9');
  });

  it('falls back to the leftmost entry when every hop is trusted', () => {
    const headers = header({ 'x-forwarded-for': '203.0.113.7, 192.0.2.10' });
    expect(resolveClientIp(headers, '192.0.2.10', [...trusted, '203.0.113.7'])).toBe('203.0.113.7');
  });

  it('returns the peer when a trusted proxy sends no X-Forwarded-For', () => {
    expect(resolveClientIp(header({}), '192.0.2.10', trusted)).toBe('192.0.2.10');
    expect(resolveClientIp(header({ 'x-forwarded-for': '' }), '192.0.2.10', trusted)).toBe('192.0.2.10');
  });

  it('normalizes IPv6 brackets, ports and whitespace to the same value', () => {
    const withXff = header({ 'x-forwarded-for': '[2001:db8::2]:443, [2001:db8::3]:80' });
    expect(resolveClientIp(withXff, '[2001:db8::1]:8443', trusted)).toBe('2001:db8::3');
    expect(resolveClientIp(header({}), '[2001:db8::1]:8443', trusted)).toBe('2001:db8::1');
    expect(resolveClientIp(header({}), '2001:db8::1', trusted)).toBe('2001:db8::1');
    expect(resolveClientIp(header({}), ' 203.0.113.7:443 ', [])).toBe('203.0.113.7');
    expect(resolveClientIp(header({ 'x-forwarded-for': ' 203.0.113.8 ' }), '192.0.2.10:1', trusted)).toBe('203.0.113.8');
  });

  it('handles IPv4 mapped addresses when resolving the chain', () => {
    // Peer is the trusted proxy, reported as a mapped address. The XFF contains
    // a plain IPv4 client. The canonical form must identify the peer as trusted
    // and return the client.
    expect(resolveClientIp(header({ 'x-forwarded-for': '203.0.113.7' }), '::ffff:192.0.2.10', trusted)).toBe('203.0.113.7');
    expect(resolveClientIp(header({ 'x-forwarded-for': '::ffff:203.0.113.7' }), '192.0.2.10', trusted)).toBe('203.0.113.7');
    expect(resolveClientIp(header({ 'x-forwarded-for': '::ffff:203.0.113.7, ::ffff:192.0.2.10' }), '::ffff:192.0.2.10', trusted)).toBe('203.0.113.7');
    expect(resolveClientIp(header({ 'x-forwarded-for': '::ffff:198.51.100.5, ::ffff:192.0.2.10, 2001:db8::1' }), '2001:db8::1', trusted)).toBe('198.51.100.5');
    // The rightmost untrusted hop wins even when a client claims to be a proxy.
    expect(resolveClientIp(header({ 'x-forwarded-for': '::ffff:192.0.2.10, ::ffff:203.0.113.9' }), '::ffff:192.0.2.10', trusted)).toBe('203.0.113.9');
  });

  it('reports unknown for an empty or missing peer', () => {
    expect(resolveClientIp(header({}), undefined, trusted)).toBe('unknown');
    expect(resolveClientIp(header({}), '', trusted)).toBe('unknown');
    expect(resolveClientIp(header({}), undefined, [])).toBe('unknown');
    expect(resolveClientIp(header({ 'x-forwarded-for': '203.0.113.7' }), undefined, trusted)).toBe('unknown');
  });

  it('ignores the internal header a client could have forged', () => {
    // The wrapper owns this header; resolveClientIp must not read it, otherwise
    // a direct request could name any identity and reset its own quota.
    const headers = header({ [RESOLVED_IP_HEADER]: '203.0.113.7' });
    expect(resolveClientIp(headers, '198.51.100.5', trusted)).toBe('198.51.100.5');
    expect(RESOLVED_IP_HEADER).toBe('x-resolved-client-ip');
  });
});

describe('sensitive response headers', () => {
  function expectHardened(response: Response): void {
    const cacheControl = response.headers.get('cache-control') ?? '';
    expect(cacheControl).toContain('no-store');
    expect(cacheControl).toContain('private');
    expect(response.headers.get('referrer-policy')).toBe('no-referrer');
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    expect(response.headers.get('x-frame-options')).toBe('DENY');
    expect(response.headers.get('pragma')).toBe('no-cache');
    expect(response.headers.get('expires')).toBe('0');
    expect(response.headers.get('content-type')).toBe('application/json; charset=utf-8');
  }

  it('hardens every jsonResponse, whatever the body', async () => {
    const responses = [
      jsonResponse({ ok: true }, { status: 200, locale: 'it' }),
      jsonResponse({ ok: false }, { status: 201, locale: 'en' }),
      jsonResponse({}, { status: 500, locale: 'en', headers: { 'x-custom': 'value' } }),
    ];
    for (const response of responses) {
      expectHardened(response);
    }
    // Caller supplied headers are merged, not dropped.
    expect(responses[2]?.headers.get('x-custom')).toBe('value');
    expect(responses[0]?.headers.get('x-custom')).toBeNull();
    expect(responses[0]?.status).toBe(200);
    expect(responses[1]?.status).toBe(201);
    expect(responses[2]?.status).toBe(500);
  });

  it('hardens every errorResponse and localizes the message', async () => {
    const italian = errorResponse('it', 'badPassword', 403);
    const english = errorResponse('en', 'badPassword', 403);
    expectHardened(italian);
    expectHardened(english);
    expect(italian.status).toBe(403);
    expect(await italian.json()).toEqual({
      ok: false,
      error: 'badPassword',
      message: 'Password errata',
    });
    expect(await english.json()).toEqual({
      ok: false,
      error: 'badPassword',
      message: 'Incorrect password',
    });
  });

  it('emits retry-after only when a retry delay is supplied', () => {
    expect(errorResponse('en', 'rateLimited', 429, 300).headers.get('retry-after')).toBe('300');
    expect(errorResponse('en', 'rateLimited', 429, 1).headers.get('retry-after')).toBe('1');
    expect(errorResponse('en', 'rateLimited', 429).headers.get('retry-after')).toBeNull();
    expect(errorResponse('en', 'crossOrigin', 403).headers.get('retry-after')).toBeNull();
  });
});
