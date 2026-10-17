/**
 * Centralized IT/EN dictionaries. Every user-facing string, including
 * validation errors and accessibility labels, resolves through `t()`.
 * Secret content is never routed through this module.
 */
import { NOINDEX_ROBOTS } from './seo.ts';

export type Locale = 'it' | 'en';

/**
 * The four expiry presets, duplicated as a plain type so this module keeps no
 * dependency on `secrets.ts`: the dictionaries are imported by pages, tests and
 * components that have no business loading the database layer.
 */
export type ExpiryPreset = '1h' | '1d' | '7d' | '30d';

export const LOCALES: readonly Locale[] = ['it', 'en'];
export const DEFAULT_LOCALE: Locale = 'en';
export const LOCALE_COOKIE = 'locale';

export type Dictionary = {
  meta: {
    title: string;
    description: string;
    robots: string;
  };
  skipToContent: string;
  javascriptRequired: string;
  language: { label: string; it: string; en: string };
  nav: { home: string };
  create: {
    title: string;
    secretLabel: string;
    secretPlaceholder: string;
    secretHint: string;
    expiryLabel: string;
    expiryOptions: Record<ExpiryPreset, string>;
    passwordLabel: string;
    passwordShow: string;
    passwordHide: string;
    submit: string;
    submitting: string;
    notePassword: string;
    noteSingleRead: string;
  };
  result: {
    title: string;
    linkLabel: string;
    controlLabel: string;
    controlHint: string;
    copy: string;
    copied: string;
    copyFailed: string;
    expires: string;
    qrLabel: string;
    qrHint: string;
    another: string;
    passwordLabel: string;
    passwordShow: string;
    passwordHide: string;
    noteKeyInFragment: string;
  };
  open: {
    title: string;
    passwordLabel: string;
    passwordOptional: string;
    passwordShow: string;
    passwordHide: string;
    reveal: string;
    revealing: string;
    unavailable: string;
    missingKey: string;
    keyFailed: string;
    noteSingleRead: string;
  };
  control: {
    title: string;
    stateLabel: string;
    pending: string;
    read: string;
    expired: string;
    cancelled: string;
    unavailable: string;
    expires: string;
    created: string;
    closed: string;
    cancel: string;
    cancelling: string;
    cancelFailed: string;
  };
  secret: {
    panelTitle: string;
    copy: string;
    copied: string;
    copyFailed: string;
    consumed: string;
    consumedHint: string;
    spentTitle: string;
    spentHint: string;
  };
  errors: {
    payloadRequired: string;
    payloadTooLong: string;
    invalidPayload: string;
    invalidAuth: string;
    invalidExpiry: string;
    passwordTooLong: string;
    passwordRejected: string;
    badPassword: string;
    badKey: string;
    unavailable: string;
    rateLimited: string;
    crossOrigin: string;
    serverError: string;
    badRequest: string;
  };
  legal: {
    updated: string;
  };
  notFound: {
    title: string;
    message: string;
    home: string;
  };
  footer: {
    limits: string;
    linksLabel: string;
    how: string;
    privacy: string;
    terms: string;
    source: string;
    sourceLabel: string;
  };
};

/** Keys accepted by the JSON error responses. */
export type ErrorKey = keyof Dictionary['errors'];

const it: Dictionary = {
  meta: {
    title: 'secrets',
    description: 'Condividi un segreto con un link monouso.',
    robots: NOINDEX_ROBOTS,
  },
  skipToContent: 'Vai al contenuto',
  javascriptRequired: 'Richiede JavaScript e una connessione sicura.',
  language: { label: 'Lingua', it: 'Italiano', en: 'Inglese' },
  nav: { home: 'Nuovo segreto' },

  create: {
    title: 'Nuovo segreto',
    secretLabel: 'Segreto',
    secretPlaceholder: 'Testo del segreto',
    secretHint: 'Massimo 50 KiB',
    expiryLabel: 'Scadenza',
    expiryOptions: { '1h': '1 ora', '1d': '1 giorno', '7d': '7 giorni', '30d': '30 giorni' },
    passwordLabel: 'Password · opzionale',
    passwordShow: 'Mostra password',
    passwordHide: 'Nascondi password',
    submit: 'Crea link',
    submitting: 'Creazione…',
    notePassword: 'Invia la password separatamente',
    noteSingleRead: 'Una sola lettura. Nessun recupero',
  },

  result: {
    title: 'Link pronto',
    linkLabel: 'Link monouso',
    controlLabel: 'Link di controllo',
    controlHint: 'Annulla il segreto. Non inviarlo a chi legge il segreto.',
    copy: 'Copia',
    copied: 'Copiato',
    copyFailed: 'Copia non riuscita',
    expires: 'Scadenza',
    qrLabel: 'Codice QR',
    qrHint: 'Scansiona per aprire il link. Contiene la chiave.',
    another: 'Nuovo segreto',
    passwordLabel: 'Password',
    passwordShow: 'Mostra password',
    passwordHide: 'Nascondi password',
    noteKeyInFragment: 'La chiave è nel link, dopo #',
  },

  open: {
    title: 'Segreto',
    passwordLabel: 'Password',
    passwordOptional: 'Password · opzionale',
    passwordShow: 'Mostra password',
    passwordHide: 'Nascondi password',
    reveal: 'Mostra segreto',
    revealing: 'Lettura…',
    unavailable: 'Link non disponibile',
    missingKey: 'Chiave assente dall’indirizzo. Il segreto non è stato consumato: riapri il link originale.',
    keyFailed: 'Chiave non valida',
    noteSingleRead: 'Una sola lettura. Nessun recupero',
  },

  control: {
    title: 'Controllo',
    stateLabel: 'Stato',
    pending: 'In attesa',
    read: 'Letto',
    expired: 'Scaduto',
    cancelled: 'Annullato',
    unavailable: 'Link non disponibile',
    expires: 'Scadenza',
    created: 'Creato',
    closed: 'Chiuso',
    cancel: 'Annulla segreto',
    cancelling: 'Annullamento…',
    cancelFailed: 'Annullamento non riuscito',
  },

  secret: {
    panelTitle: 'Contenuto',
    copy: 'Copia',
    copied: 'Copiato',
    copyFailed: 'Copia non riuscita',
    consumed: 'Segreto non disponibile',
    consumedHint: 'Questo link è stato già letto o è scaduto.',
    spentTitle: 'Link esaurito',
    spentHint: 'Il segreto è stato letto e il link non si riapre più.',
  },

  errors: {
    payloadRequired: 'Inserisci un segreto',
    payloadTooLong: 'Limite 50 KiB',
    invalidPayload: 'Segreto non valido',
    invalidAuth: 'Verifica della chiave non valida',
    invalidExpiry: 'Scadenza non valida',
    passwordTooLong: 'Password troppo lunga',
    passwordRejected: 'Non inviare la password',
    badPassword: 'Password errata',
    badKey: 'Chiave non corrispondente. Il segreto non è stato consumato.',
    unavailable: 'Link non disponibile',
    rateLimited: 'Troppe richieste. Riprova più tardi.',
    crossOrigin: 'Richiesta non consentita',
    serverError: 'Errore del server',
    badRequest: 'Richiesta non valida',
  },

  legal: { updated: 'Ultimo aggiornamento' },

  notFound: {
    title: 'Pagina non trovata',
    message: 'Questo indirizzo non esiste.',
    home: 'Crea un nuovo segreto',
  },

  footer: {
    limits: 'Limite 50 KiB · una sola lettura',
    linksLabel: 'Documenti',
    how: 'Come funziona',
    privacy: 'Informativa privacy',
    terms: 'Condizioni d\'uso',
    source: 'Codice sorgente',
    sourceLabel: 'Codice sorgente su GitHub',
  },
};

const en: Dictionary = {
  meta: {
    title: 'secrets',
    description: 'Share a secret with a one-time link.',
    robots: NOINDEX_ROBOTS,
  },
  skipToContent: 'Skip to content',
  javascriptRequired: 'Requires JavaScript and a secure connection.',
  language: { label: 'Language', it: 'Italian', en: 'English' },
  nav: { home: 'New secret' },

  create: {
    title: 'New secret',
    secretLabel: 'Secret',
    secretPlaceholder: 'Secret text',
    secretHint: '50 KiB max',
    expiryLabel: 'Expires in',
    expiryOptions: { '1h': '1 hour', '1d': '1 day', '7d': '7 days', '30d': '30 days' },
    passwordLabel: 'Password · optional',
    passwordShow: 'Show password',
    passwordHide: 'Hide password',
    submit: 'Create link',
    submitting: 'Creating…',
    notePassword: 'Send the password separately',
    noteSingleRead: 'One read only. No recovery',
  },

  result: {
    title: 'Link ready',
    linkLabel: 'One-time link',
    controlLabel: 'Control link',
    controlHint: 'Cancels the secret. Do not send it to whoever reads the secret.',
    copy: 'Copy',
    copied: 'Copied',
    copyFailed: 'Copy failed',
    expires: 'Expires',
    qrLabel: 'QR code',
    qrHint: 'Scan to open the link. It carries the key.',
    another: 'New secret',
    passwordLabel: 'Password',
    passwordShow: 'Show password',
    passwordHide: 'Hide password',
    noteKeyInFragment: 'The key is in the link, after #',
  },

  open: {
    title: 'Secret',
    passwordLabel: 'Password',
    passwordOptional: 'Password · optional',
    passwordShow: 'Show password',
    passwordHide: 'Hide password',
    reveal: 'Reveal secret',
    revealing: 'Reading…',
    unavailable: 'Link unavailable',
    missingKey: 'Key missing from the address. The secret was not consumed: open the original link again.',
    keyFailed: 'Invalid key',
    noteSingleRead: 'One read only. No recovery',
  },

  control: {
    title: 'Control',
    stateLabel: 'State',
    pending: 'Pending',
    read: 'Read',
    expired: 'Expired',
    cancelled: 'Cancelled',
    unavailable: 'Link unavailable',
    expires: 'Expires',
    created: 'Created',
    closed: 'Closed',
    cancel: 'Cancel secret',
    cancelling: 'Cancelling…',
    cancelFailed: 'Cancellation failed',
  },

  secret: {
    panelTitle: 'Content',
    copy: 'Copy',
    copied: 'Copied',
    copyFailed: 'Copy failed',
    consumed: 'Secret unavailable',
    consumedHint: 'This link was already read or has expired.',
    spentTitle: 'Link spent',
    spentHint: 'The secret was read and the link can no longer be reopened.',
  },

  errors: {
    payloadRequired: 'Enter a secret',
    payloadTooLong: '50 KiB limit',
    invalidPayload: 'Invalid secret',
    invalidAuth: 'Invalid key check',
    invalidExpiry: 'Invalid expiry',
    passwordTooLong: 'Password too long',
    passwordRejected: 'Do not send the password',
    badPassword: 'Incorrect password',
    badKey: 'Key does not match. The secret was not consumed.',
    unavailable: 'Link unavailable',
    rateLimited: 'Too many requests. Try again later.',
    crossOrigin: 'Request not allowed',
    serverError: 'Server error',
    badRequest: 'Invalid request',
  },

  legal: { updated: 'Last updated' },

  notFound: {
    title: 'Page not found',
    message: 'This address does not exist.',
    home: 'Create a new secret',
  },

  footer: {
    limits: '50 KiB limit · one read only',
    linksLabel: 'Documents',
    how: 'How it works',
    privacy: 'Privacy policy',
    terms: 'Terms of use',
    source: 'Source code',
    sourceLabel: 'Source code on GitHub',
  },
};

const dictionaries: Record<Locale, Dictionary> = { it, en };

export function normalizeLocale(value: string | undefined | null): Locale | undefined {
  if (!value) return undefined;
  const normalized = value.trim().toLowerCase().split(/[-_]/)[0];
  return (LOCALES as readonly string[]).includes(normalized ?? '') ? (normalized as Locale) : undefined;
}

/** First supported language in the `Accept-Language` header, falling back to English. */
export function detectLocale(acceptLanguage: string | null | undefined): Locale {
  if (!acceptLanguage) return DEFAULT_LOCALE;

  const ranked = acceptLanguage
    .split(',')
    .map((part) => {
      const [tag, ...params] = part.trim().split(';');
      const qParam = params.find((p) => p.trim().startsWith('q='));
      const q = qParam ? Number.parseFloat(qParam.trim().slice(2)) : 1;
      return { tag: (tag ?? '').trim(), q: Number.isFinite(q) ? q : 0 };
    })
    // q=0 means "not acceptable" (RFC 9110), so those entries must never win.
    .filter((entry) => entry.tag.length > 0 && entry.q > 0)
    .sort((a, b) => b.q - a.q);

  for (const { tag } of ranked) {
    const locale = normalizeLocale(tag);
    if (locale) return locale;
  }
  return DEFAULT_LOCALE;
}

export function getDictionary(locale: Locale): Dictionary {
  return dictionaries[locale] ?? dictionaries[DEFAULT_LOCALE];
}
