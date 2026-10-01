/**
 * POST /api/secrets/verifier — return the password check without consuming.
 *
 * The browser decrypts this blob with the key derived from the fragment and
 * the password. A failure stops there, so the secret row stays. The blob is
 * not the secret, and this route never deletes.
 */
import type { APIRoute } from 'astro';
import { errorResponse, jsonResponse } from '../../../lib/http.ts';
import { isValidTokenShape } from '../../../lib/crypto.ts';
import { MAX_VERIFIER_BODY_BYTES, readPasswordVerifier } from '../../../lib/secrets.ts';
import { guardRequest, readJsonBody } from '../../../lib/api-guard.ts';

export const prerender = false;

export const POST: APIRoute = async (context) => {
  const locale = context.locals.locale;
  const guard = await guardRequest(context.request, locale, context.locals.peerAddress, 'reveal');
  if (!guard.ok) return guard.response;

  const body = await readJsonBody(context.request, MAX_VERIFIER_BODY_BYTES);
  if (!body) return errorResponse(locale, 'badRequest', 400);

  const token = typeof body.token === 'string' ? body.token : '';
  if (!isValidTokenShape(token)) return errorResponse(locale, 'unavailable', 404);

  const result = await readPasswordVerifier(token);
  if (!result.ok) {
    if (result.reason === 'undecryptable') return errorResponse(locale, 'serverError', 500);
    return errorResponse(locale, 'unavailable', 404);
  }

  return jsonResponse({ ok: true, verifier: result.verifier }, { status: 200, locale });
};

export const ALL: APIRoute = ({ locals }) => errorResponse(locals.locale, 'badRequest', 405);
