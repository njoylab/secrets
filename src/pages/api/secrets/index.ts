/**
 * POST /api/secrets — create a secret and return its tokens.
 *
 * The body carries a payload the browser already sealed with a key that never
 * leaves the client. An optional verifier is sealed under the same key after
 * the password has been mixed in. This endpoint never sees the plaintext, the
 * content key or the password. A `password` field is refused: storing one here
 * would look like protection the server cannot actually provide.
 *
 * The reply carries the two tokens, not the links. Behind a reverse proxy this
 * process may rebuild `request.url` to a host it does not recognise, and the
 * page is the only party that knows the origin the user is actually on.
 */
import type { APIRoute } from 'astro';
import { getConfig } from '../../../lib/env.ts';
import { errorResponse, jsonResponse } from '../../../lib/http.ts';
import {
  createSecret,
  MAX_CREATE_BODY_BYTES,
  SecretValidationError,
  type ExpiryPreset,
} from '../../../lib/secrets.ts';
import { guardRequest, readJsonBody } from '../../../lib/api-guard.ts';

export const prerender = false;

export const POST: APIRoute = async (context) => {
  const locale = context.locals.locale;
  const guard = await guardRequest(context.request, locale, context.locals.peerAddress, 'create');
  if (!guard.ok) return guard.response;

  const body = await readJsonBody(context.request, MAX_CREATE_BODY_BYTES);
  if (!body) return errorResponse(locale, 'badRequest', 400);
  if (hasPasswordField(body.password)) return errorResponse(locale, 'passwordRejected', 422);

  try {
    const created = await createSecret({
      payload: body.payload as string,
      expiresIn: body.expiresIn as ExpiryPreset,
      verifier: body.verifier as string | undefined,
    });

    const config = getConfig();
    return jsonResponse(
      {
        ok: true,
        // Tokens only, never an absolute URL and never a fragment: this process
        // does not necessarily know the public origin behind its proxy, and the
        // content key must never travel through this response, so the page
        // assembles both links from the origin it was served from.
        token: created.token,
        controlToken: created.controlToken,
        expiresAt: created.expiresAt.toISOString(),
        requiresPassword: typeof body.verifier === 'string' && body.verifier.length > 0,
        secureCookies: config.secureCookies,
      },
      { status: 201, locale },
    );
  } catch (error) {
    if (error instanceof SecretValidationError) {
      return errorResponse(locale, error.code, 422);
    }
    return errorResponse(locale, 'serverError', 500);
  }
};

export const ALL: APIRoute = ({ locals }) =>
  errorResponse(locals.locale, 'badRequest', 405);

/** A non-empty password field means the client expected the server to keep it. */
function hasPasswordField(value: unknown): boolean {
  if (value === undefined || value === null || value === '') return false;
  return true;
}
