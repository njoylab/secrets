/**
 * GET /api/locale?lang=it|en&next=<path> — store the language choice and return
 * to the same page. The redirect target is restricted to same-origin relative
 * paths so the endpoint cannot be used as an open redirect.
 */
import type { APIRoute } from 'astro';
import { getConfig } from '../../lib/env.ts';
import { safeRedirectPath } from '../../lib/http.ts';
import { DEFAULT_LOCALE, LOCALE_COOKIE, normalizeLocale } from '../../lib/i18n.ts';

export const prerender = false;

const ONE_YEAR_SECONDS = 60 * 60 * 24 * 365;

export const GET: APIRoute = ({ url, cookies, redirect }) => {
  const locale = normalizeLocale(url.searchParams.get('lang')) ?? DEFAULT_LOCALE;
  const next = safeRedirectPath(url.searchParams.get('next'));

  cookies.set(LOCALE_COOKIE, locale, {
    path: '/',
    maxAge: ONE_YEAR_SECONDS,
    sameSite: 'lax',
    secure: getConfig().secureCookies,
  });

  return redirect(next, 302);
};

export const ALL: APIRoute = ({ redirect }) => redirect('/');
