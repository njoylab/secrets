/// <reference types="astro/client" />

type Locale = import('./lib/i18n.ts').Locale;

declare namespace App {
  interface Locals {
    /** Resolved once per request by the middleware. */
    locale: Locale;
    /** Peer address reported by the Node adapter; may be empty. */
    peerAddress: string | undefined;
  }
}

interface ImportMetaEnv {
  readonly DATABASE_URL: string;
  readonly SECRET_ENCRYPTION_KEY: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}