/**
 * POST /api/secrets/reveal — consume a secret exactly once.
 *
 * A GET on this path never exists: revealing requires an explicit POST, so page
 * rendering, prefetching and crawlers cannot trigger a read.
 */
import type { APIRoute } from 'astro';
import { errorResponse, jsonResponse } from '../../../lib/http.ts';
import { isValidTokenShape } from '../../../lib/crypto.ts';
import { revealSecret } from '../../../lib/secrets.ts';
import { guardRequest, readJsonBody } from '../../../lib/api-guard.ts';

export const prerender = false;

export const POST: APIRoute = async (context) => {
  const locale = context.locals.locale;
  const guard = await guardRequest(context.request, locale, context.locals.peerAddress, 'reveal');
  if (!guard.ok) return guard.response;

  const body = await readJsonBody(context.request);
  if (!body) return errorResponse(locale, 'badRequest', 400);

  const token = typeof body.token === 'string' ? body.token : '';
  if (!isValidTokenShape(token)) return errorResponse(locale, 'unavailable', 404);

  const password = typeof body.password === 'string' ? body.password : undefined;
  const result = await revealSecret(token, password);

  if (!result.ok) {
    if (result.reason === 'bad_password') {
      // 403 rather than 404: the secret exists, the credential does not match.
      return errorResponse(locale, 'badPassword', 403);
    }
    // One response for missing, expired and already consumed secrets.
    return errorResponse(locale, 'unavailable', 404);
  }

  // Content is only serialized after the deleting statement has committed.
  return jsonResponse({ ok: true, secret: result.secret }, { status: 200, locale });
};

export const ALL: APIRoute = ({ locals }) => errorResponse(locals.locale, 'badRequest', 405);