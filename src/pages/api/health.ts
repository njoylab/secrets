import type { APIRoute } from 'astro';
import { query } from '../../lib/db.ts';
import { jsonResponse } from '../../lib/http.ts';

export const prerender = false;

export const GET: APIRoute = async ({ locals }) => {
  try {
    const { rows } = await query<{ ready: boolean }>(
      `SELECT EXISTS (
         SELECT 1 FROM schema_migrations WHERE version = '0005_auth_key.sql'
       ) AND to_regclass('public.secrets') IS NOT NULL
         AND to_regclass('public.secret_receipts') IS NOT NULL
         AND to_regclass('public.rate_limits') IS NOT NULL AS ready`,
    );
    if (rows[0]?.ready) return jsonResponse({ ok: true }, { status: 200, locale: locals.locale });
  } catch {
    // Health responses must not disclose connection details or SQL errors.
  }
  return jsonResponse({ ok: false }, { status: 503, locale: locals.locale });
};
