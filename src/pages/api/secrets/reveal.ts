/**
 * POST /api/secrets/reveal — consume a secret exactly once.
 *
 * A GET on this path never exists: revealing requires an explicit POST, so page
 * rendering, prefetching and crawlers cannot trigger a read. The response carries
 * the sealed payload, not the text: the browser opens it with the key from the
 * share link fragment, which never reached this process.
 */
import type { APIRoute } from 'astro';
import { errorResponse, jsonResponse } from '../../../lib/http.ts';
import { isValidTokenShape } from '../../../lib/crypto.ts';
import { revealSecret, MAX_REVEAL_BODY_BYTES } from '../../../lib/secrets.ts';
import { guardRequest, readJsonBody } from '../../../lib/api-guard.ts';

export const prerender = false;

export const POST: APIRoute = async (context) => {
  const locale = context.locals.locale;
  const guard = await guardRequest(context.request, locale, context.locals.peerAddress, 'reveal');
  if (!guard.ok) return guard.response;

  const body = await readJsonBody(context.request, MAX_REVEAL_BODY_BYTES);
  if (!body) return errorResponse(locale, 'badRequest', 400);

  const token = typeof body.token === 'string' ? body.token : '';
  if (!isValidTokenShape(token)) return errorResponse(locale, 'unavailable', 404);

  const password = typeof body.password === 'string' ? body.password : undefined;
  const revealProof = typeof body.revealProof === 'string' ? body.revealProof : undefined;
  const result = await revealSecret(token, password, revealProof);

  if (!result.ok) {
    if (result.reason === 'bad_password') {
      // 403 rather than 404: the secret exists, the credential does not match.
      return errorResponse(locale, 'badPassword', 403);
    }
    if (result.reason === 'undecryptable') {
      // The link is still there and the row was not consumed, so 404 would be a
      // lie that outlives the outage: once the key is back the reveal succeeds.
      return errorResponse(locale, 'serverError', 500);
    }
    // One response for missing, expired and already consumed secrets.
    return errorResponse(locale, 'unavailable', 404);
  }

  // Content is only serialized after the deleting statement has committed.
  return jsonResponse({ ok: true, payload: result.payload }, { status: 200, locale });
};

export const ALL: APIRoute = ({ locals }) => errorResponse(locals.locale, 'badRequest', 405);
