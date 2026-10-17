import { defineMiddleware } from 'astro:middleware';
import { errorResponse, hstsHeaderValue, RESOLVED_IP_HEADER, SENSITIVE_HEADERS } from './lib/http.ts';
import { detectLocale, LOCALE_COOKIE, normalizeLocale, type Locale } from './lib/i18n.ts';
import { robotsForPath } from './lib/seo.ts';

/**
 * Read the client IP resolved by `server.mjs`.
 *
 * `context.clientAddress` is deliberately ignored: the Node adapter derives it
 * from `X-Forwarded-For` without checking who sent it, so any client could claim
 * a different identity and evade rate limiting. When the header is absent — for
 * example under `astro dev`, which bypasses the wrapper — every request shares a
 * single bucket instead of trusting a spoofable value.
 */
function resolveRequestClientIp(request: Request): string {
  return request.headers.get(RESOLVED_IP_HEADER) ?? 'unknown';
}

export const onRequest = defineMiddleware(async (context, next) => {
  // Language precedence: explicit cookie choice, then Accept-Language, then English.
  const cookieLocale = normalizeLocale(context.cookies.get(LOCALE_COOKIE)?.value);
  const locale: Locale = cookieLocale ?? detectLocale(context.request.headers.get('accept-language'));

  context.locals.locale = locale;
  context.locals.peerAddress = resolveRequestClientIp(context.request);

  const started = performance.now();
  let response: Response;
  try {
    response = await next();
  } catch {
    response = errorResponse(locale, 'serverError', 503);
  }
  if (process.env.REQUEST_METRICS === 'true') {
    // Route templates contain no tokens. Never log URLs, headers or errors.
    const route = context.routePattern || 'unmatched';
    process.stdout.write(`${JSON.stringify({
      event: 'request', route, method: context.request.method,
      status: response.status, durationMs: Math.round(performance.now() - started),
    })}\n`);
  }
  response.headers.set('content-language', locale);

  // Sensitive responses are never cached. Only the public pages may be indexed;
  // the token pages, the endpoints and unknown paths are kept out of search.
  // A rendered page already carries Astro's policy with the hashes of its inline
  // scripts and styles; replacing it would block them. Everything else gets the
  // deny-all policy from SENSITIVE_HEADERS.
  const pagePolicy = response.headers.get('content-security-policy');
  for (const [header, value] of Object.entries(SENSITIVE_HEADERS)) {
    response.headers.set(header, value);
  }
  if (pagePolicy) response.headers.set('content-security-policy', pagePolicy);
  const hsts = hstsHeaderValue(context.request);
  if (hsts) response.headers.set('strict-transport-security', hsts);
  response.headers.set('x-robots-tag', robotsForPath(context.url.pathname));

  return response;
});
