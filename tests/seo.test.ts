/**
 * Indexing policy: only the known public pages may be indexed, everything else
 * — token pages, endpoints and unknown paths — stays out of search engines.
 */
import { describe, expect, it } from 'vitest';
import { INDEXABLE_ROBOTS, NOINDEX_ROBOTS, robotsForPath } from '../src/lib/seo.ts';

describe('robotsForPath', () => {
  it('indexes the public pages', () => {
    for (const path of ['/', '/how', '/privacy', '/terms']) {
      expect(robotsForPath(path), path).toBe(INDEXABLE_ROBOTS);
    }
  });

  it('treats a trailing slash like the bare path', () => {
    expect(robotsForPath('/how/')).toBe(INDEXABLE_ROBOTS);
    expect(robotsForPath('/')).toBe(INDEXABLE_ROBOTS);
  });

  it('keeps token pages, endpoints and unknown paths out of search', () => {
    for (const path of ['/s/token', '/c/token', '/api/health', '/no-such-page', '/how/extra', '']) {
      expect(robotsForPath(path), path).toBe(NOINDEX_ROBOTS);
    }
  });
});
