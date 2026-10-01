import { defineMiddleware } from 'astro:middleware';
import { hstsHeaderValue, SENSITIVE_HEADERS } from './lib/http.ts';
import { detectLocale, getDictionary, LOCALE_COOKIE, normalizeLocale, type Locale } from './lib/i18n.ts';
import { RESOLVED_IP_HEADER } from './lib/http.ts';

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

  const response = await next();
  response.headers.set('content-language', locale);

  // The whole service is unindexable and uncacheable: pages hold no secret, but
  // the reveal flow must never be stored by intermediaries.
  for (const [header, value] of Object.entries(SENSITIVE_HEADERS)) {
    response.headers.set(header, value);
  }
  const hsts = hstsHeaderValue(context.request);
  if (hsts) response.headers.set('strict-transport-security', hsts);
  response.headers.set('x-robots-tag', getDictionary(locale).meta.robots);

  return response;
});