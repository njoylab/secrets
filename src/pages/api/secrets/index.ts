/**
 * POST /api/secrets — create a secret and return its one-time link.
 *
 * The plaintext is accepted, validated, encrypted and hashed; nothing sensitive
 * is logged and no field beyond the request body is persisted.
 */
import type { APIRoute } from 'astro';
import { getConfig } from '../../../lib/env.ts';
import { errorResponse, jsonResponse } from '../../../lib/http.ts';
import { createSecret, MAX_CREATE_BODY_BYTES, SecretValidationError } from '../../../lib/secrets.ts';
import { guardRequest, readJsonBody } from '../../../lib/api-guard.ts';

export const prerender = false;

export const POST: APIRoute = async (context) => {
  const locale = context.locals.locale;
  const guard = await guardRequest(context.request, locale, context.locals.peerAddress, 'create');
  if (!guard.ok) return guard.response;

  const body = await readJsonBody(context.request, MAX_CREATE_BODY_BYTES);
  if (!body) return errorResponse(locale, 'badRequest', 400);

  try {
    const created = await createSecret({
      secret: body.secret as string,
      expiresInDays: body.expiresInDays as number,
      password: body.password as string | undefined,
    });

    const config = getConfig();
    const origin = new URL(context.request.url).origin;
    return jsonResponse(
      {
        ok: true,
        token: created.token,
        url: `${origin}/s/${created.token}`,
        expiresAt: created.expiresAt.toISOString(),
        requiresPassword: typeof body.password === 'string' && body.password.length > 0,
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