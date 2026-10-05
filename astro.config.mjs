import node from '@astrojs/node';
import { defineConfig } from 'astro/config';

/**
 * Hostnames this deployment answers to.
 *
 * Astro only honours `X-Forwarded-Host` when the host matches this list, and
 * with an empty list it rebuilds every `request.url` as `http://localhost`.
 * Entries may use a leading `*.` wildcard.
 *
 * This no longer decides the origin of the generated links: the page composes
 * them from the origin it was served from. It still governs Astro's own
 * same-origin check on form-like POSTs.
 *
 * Read at BUILD time. `npm run build` does not load `.env`, so export the
 * variable in the build environment: the default below covers local development
 * only, and set ALLOWED_HOSTS in production.
 */
const allowedDomains = (process.env.ALLOWED_HOSTS ?? 'localhost,127.0.0.1')
  .split(',')
  .map((entry) => entry.trim())
  .filter((entry) => entry.length > 0)
  .map((hostname) => (hostname.startsWith('*.') ? { hostname } : { hostname }));

// SSR mode: every page and endpoint is rendered by the Node server at request time.
export default defineConfig({
  output: 'server',
  adapter: node({ mode: 'standalone', bodySizeLimit: 72 * 1024 }),
  security: {
    checkOrigin: true,
    allowedDomains,
  },
  devToolbar: {
    enabled: false,
  },
});
