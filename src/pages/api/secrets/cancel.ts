/**
 * POST /api/secrets/cancel — cancel a secret before anybody reads it.
 *
 * The body carries only the control token: this endpoint never decrypts, never
 * verifies a password and never sees the content key, so it cannot be used to
 * learn anything about the secret beyond the state the control link already shows.
 *
 * The delete is conditional on the row still being live, so a cancel that races a
 * reveal deletes nothing. The reply carries the resulting state and the page
 * renders exactly what a fresh read of the control link would show.
 */
import type { APIRoute } from 'astro';
import { errorResponse, jsonResponse } from '../../../lib/http.ts';
import { isValidTokenShape } from '../../../lib/crypto.ts';
import { cancelSecret, MAX_CANCEL_BODY_BYTES } from '../../../lib/secrets.ts';
import { guardRequest, readJsonBody } from '../../../lib/api-guard.ts';

export const prerender = false;

export const POST: APIRoute = async (context) => {
  const locale = context.locals.locale;
  const guard = await guardRequest(context.request, locale, context.locals.peerAddress, 'cancel');
  if (!guard.ok) return guard.response;

  const body = await readJsonBody(context.request, MAX_CANCEL_BODY_BYTES);
  if (!body) return errorResponse(locale, 'badRequest', 400);

  const token = typeof body.token === 'string' ? body.token : '';
  if (!isValidTokenShape(token)) return errorResponse(locale, 'unavailable', 404);

  const result = await cancelSecret(token);
  // An unknown token and an already purged receipt share the single
  // "unavailable" answer, exactly like the opening screen.
  if (!result.ok) return errorResponse(locale, 'unavailable', 404);

  return jsonResponse(
    {
      ok: true,
      state: result.status.state,
      expiresAt: result.status.expiresAt?.toISOString() ?? null,
    },
    { status: 200, locale },
  );
};

export const ALL: APIRoute = ({ locals }) => errorResponse(locals.locale, 'badRequest', 405);
