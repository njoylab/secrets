import node from '@astrojs/node';
import { defineConfig } from 'astro/config';

/**
 * Hostnames this deployment answers to.
 *
 * Astro only honours `X-Forwarded-Host` when the host matches this list, and
 * with an empty list it rebuilds every `request.url` as `http://localhost`, which
 * would both break generated links and make legitimate browser POSTs look
 * cross-origin. Entries may use a leading `*.` wildcard.
 *
 * Defaults cover local development only; set ALLOWED_HOSTS in production.
 */
const allowedDomains = (process.env.ALLOWED_HOSTS ?? 'localhost,127.0.0.1')
  .split(',')
  .map((entry) => entry.trim())
  .filter((entry) => entry.length > 0)
  .map((hostname) => (hostname.startsWith('*.') ? { hostname } : { hostname }));

// SSR mode: every page and endpoint is rendered by the Node server at request time.
export default defineConfig({
  output: 'server',
  adapter: node({ mode: 'standalone' }),
  security: {
    checkOrigin: true,
    allowedDomains,
  },
  devToolbar: {
    enabled: false,
  },
});