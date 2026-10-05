/**
 * Shared request plumbing for the JSON endpoints.
 */
import { Buffer } from 'node:buffer';
import { getConfig } from './env.ts';
import { checkPostOrigin, errorResponse, resolveClientIp } from './http.ts';
import { consumeRateLimit, type RateLimitBucket } from './rate-limit.ts';
import type { Locale } from './i18n.ts';

export interface RequestContext {
  readonly request: Request;
  readonly locale: Locale;
  readonly clientIp: string;
}

export type GuardResult = { ok: true; context: RequestContext } | { ok: false; response: Response };

/**
 * Reject cross-origin POSTs before any body is read, then rate limit by client IP.
 * Ordering matters: a cross-origin flood must not consume a subject's quota.
 *
 * Cancel uses the reveal rule, the same max and the same window, under its own
 * bucket. The two counters are independent: spending one does not spend the other.
 */
export async function guardRequest(
  request: Request,
  locale: Locale,
  peerAddress: string | undefined,
  bucket: RateLimitBucket,
): Promise<GuardResult> {
  const config = getConfig();
  const clientIp = resolveClientIp(request.headers, peerAddress, config.trustedProxies);

  if (
    request.method === 'POST' &&
    checkPostOrigin(request, config.allowedOrigins) === 'cross_origin'
  ) {
    return { ok: false, response: errorResponse(locale, 'crossOrigin', 403) };
  }

  const rule = bucket === 'create' ? config.createRateLimit : config.revealRateLimit;
  const result = await consumeRateLimit(bucket, clientIp, rule);
  if (!result.allowed) {
    return { ok: false, response: errorResponse(locale, 'rateLimited', 429, result.retryAfterSeconds) };
  }
  return { ok: true, context: { request, locale, clientIp } };
}

/**
 * Bound the request body before JSON parsing to keep memory usage predictable.
 *
 * The default is deliberately the small cap: each route that accepts larger
 * input passes its own ceiling, so raising it here would loosen every endpoint
 * at once. `Content-Length` is checked first, so an oversized body is refused
 * without ever being read into memory.
 */
export async function readJsonBody(
  request: Request,
  maxBytes = 64 * 1024,
): Promise<Record<string, unknown> | null> {
  const declaredLength = request.headers.get('content-length');
  if (declaredLength && Number.parseInt(declaredLength, 10) > maxBytes) return null;

  if (!request.body) return null;
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
  } catch {
    return null;
  } finally {
    reader.releaseLock();
  }
  const raw = Buffer.concat(chunks, total).toString('utf8');

  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return null;
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}
