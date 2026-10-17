/**
 * Indexing policy.
 *
 * Only the public pages may be indexed; the token pages, the JSON endpoints and
 * unknown paths stay out of search engines. The `meta robots` tag, the
 * `x-robots-tag` header and `public/robots.txt` all resolve to this one place so
 * they cannot drift apart.
 */

export const INDEXABLE_ROBOTS = 'index, follow';
export const NOINDEX_ROBOTS = 'noindex, nofollow';

/** Public, crawlable paths. Everything else is treated as non-indexable. */
const INDEXABLE_PATHS: ReadonlySet<string> = new Set(['/', '/how', '/privacy', '/terms']);

/** Drop a trailing slash so `/how` and `/how/` share one entry point. */
function normalizePath(pathname: string): string {
  return pathname.length > 1 && pathname.endsWith('/') ? pathname.slice(0, -1) : pathname;
}

/** Robots directive for a request path: index the known public pages only. */
export function robotsForPath(pathname: string): string {
  return INDEXABLE_PATHS.has(normalizePath(pathname)) ? INDEXABLE_ROBOTS : NOINDEX_ROBOTS;
}
