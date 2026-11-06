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
  themeToggle: string;
  javascriptRequired: string;
  noteSingleRead: string;
  language: { label: string; it: string; en: string };
  create: {
    title: string;
    secretLabel: string;
    secretHint: string;
    expiryLabel: string;
    expiryOptions: Record<ExpiryPreset, string>;
    passwordLabel: string;
    passwordShow: string;
    passwordHide: string;
    submit: string;
    submitting: string;
  };
  result: {
    title: string;
    linkLabel: string;
    controlLabel: string;
    controlHint: string;
    copy: string;
    copyLink: string;
    copyControlLink: string;
    copyPassword: string;
    copied: string;
    copyFailed: string;
    expires: string;
    qrLabel: string;
    qrHint: string;
    another: string;
    passwordLabel: string;
    passwordShow: string;
    passwordHide: string;
    notePassword: string;
  };
  open: {
    title: string;
    passwordLabel: string;
    passwordRequired: string;
    passwordShow: string;
    passwordHide: string;
    reveal: string;
    revealing: string;
    unavailable: string;
    decryptionFailed: string;
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
    home: string;
  };
  footer: {
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
  themeToggle: 'Cambia tema',
  javascriptRequired: 'Richiede JavaScript e una connessione sicura.',
  noteSingleRead: 'Il segreto si può leggere una sola volta.',
  language: { label: 'Lingua', it: 'Italiano', en: 'English' },

  create: {
    title: 'Nuovo segreto',
    secretLabel: 'Segreto',
    secretHint: 'Massimo 50 KiB',
    expiryLabel: 'Scadenza',
    expiryOptions: { '1h': '1 ora', '1d': '1 giorno', '7d': '7 giorni', '30d': '30 giorni' },
    passwordLabel: 'Password · opzionale',
    passwordShow: 'Mostra password',
    passwordHide: 'Nascondi password',
    submit: 'Crea link',
    submitting: 'Creazione…',
  },

  result: {
    title: 'Link pronto',
    linkLabel: 'Link monouso',
    controlLabel: 'Link di controllo',
    controlHint: 'Tienilo per verificare lo stato o annullare il segreto.',
    copy: 'Copia',
    copyLink: 'Copia link monouso',
    copyControlLink: 'Copia link di controllo',
    copyPassword: 'Copia password',
    copied: 'Copiato',
    copyFailed: 'Copia non riuscita',
    expires: 'Scadenza',
    qrLabel: 'Codice QR',
    qrHint: 'Scansiona per aprire il link.',
    another: 'Nuovo segreto',
    passwordLabel: 'Password',
    passwordShow: 'Mostra password',
    passwordHide: 'Nascondi password',
    notePassword: 'Invia la password su un altro canale.',
  },

  open: {
    title: 'Segreto',
    passwordLabel: 'Password',
    passwordRequired: 'Inserisci la password.',
    passwordShow: 'Mostra password',
    passwordHide: 'Nascondi password',
    reveal: 'Mostra segreto',
    revealing: 'Lettura…',
    unavailable: 'Link non disponibile',
    decryptionFailed: 'Impossibile mostrare il testo. Chiedi un nuovo link al mittente.',
  },

  control: {
    title: 'Controllo',
    stateLabel: 'Stato',
    pending: 'Non ancora letto',
    read: 'Link usato',
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
    consumedHint: 'Chiedi un nuovo link al mittente.',
    spentHint: 'Copia il testo prima di chiudere la pagina.',
  },

  errors: {
    payloadRequired: 'Inserisci un segreto',
    payloadTooLong: 'Limite 50 KiB',
    invalidPayload: 'Segreto non valido',
    invalidAuth: 'Verifica della chiave non valida',
    invalidExpiry: 'Scadenza non valida',
    passwordTooLong: 'Password troppo lunga',
    passwordRejected: 'Non inviare la password',
    badPassword: 'Controlla la password e assicurati di usare il link originale.',
    badKey: 'Riapri il link originale o chiedi al mittente di rimandartelo.',
    unavailable: 'Link non disponibile',
    rateLimited: 'Troppe richieste. Riprova più tardi.',
    crossOrigin: 'Richiesta non consentita',
    serverError: 'Errore del server',
    badRequest: 'Richiesta non valida',
  },

  legal: { updated: 'Ultimo aggiornamento' },

  notFound: {
    title: 'Pagina non trovata',
    home: 'Crea un nuovo segreto',
  },

  footer: {
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
  themeToggle: 'Toggle theme',
  javascriptRequired: 'Requires JavaScript and a secure connection.',
  noteSingleRead: 'You can read the secret only once.',
  language: { label: 'Language', it: 'Italiano', en: 'English' },

  create: {
    title: 'New secret',
    secretLabel: 'Secret',
    secretHint: '50 KiB max',
    expiryLabel: 'Expires in',
    expiryOptions: { '1h': '1 hour', '1d': '1 day', '7d': '7 days', '30d': '30 days' },
    passwordLabel: 'Password · optional',
    passwordShow: 'Show password',
    passwordHide: 'Hide password',
    submit: 'Create link',
    submitting: 'Creating…',
  },

  result: {
    title: 'Link ready',
    linkLabel: 'One-time link',
    controlLabel: 'Control link',
    controlHint: 'Keep it to check the status or cancel the secret.',
    copy: 'Copy',
    copyLink: 'Copy one-time link',
    copyControlLink: 'Copy control link',
    copyPassword: 'Copy password',
    copied: 'Copied',
    copyFailed: 'Copy failed',
    expires: 'Expires',
    qrLabel: 'QR code',
    qrHint: 'Scan to open the link.',
    another: 'New secret',
    passwordLabel: 'Password',
    passwordShow: 'Show password',
    passwordHide: 'Hide password',
    notePassword: 'Send the password through a different channel.',
  },

  open: {
    title: 'Secret',
    passwordLabel: 'Password',
    passwordRequired: 'Enter the password.',
    passwordShow: 'Show password',
    passwordHide: 'Hide password',
    reveal: 'Reveal secret',
    revealing: 'Reading…',
    unavailable: 'Link unavailable',
    decryptionFailed: 'The text could not be shown. Ask the sender for a new link.',
  },

  control: {
    title: 'Control',
    stateLabel: 'State',
    pending: 'Not yet read',
    read: 'Link used',
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
    consumedHint: 'Ask the sender for a new link.',
    spentHint: 'Copy the text before closing this page.',
  },

  errors: {
    payloadRequired: 'Enter a secret',
    payloadTooLong: '50 KiB limit',
    invalidPayload: 'Invalid secret',
    invalidAuth: 'Invalid key check',
    invalidExpiry: 'Invalid expiry',
    passwordTooLong: 'Password too long',
    passwordRejected: 'Do not send the password',
    badPassword: 'Check the password and make sure you are using the original link.',
    badKey: 'Reopen the original link or ask the sender to resend it.',
    unavailable: 'Link unavailable',
    rateLimited: 'Too many requests. Try again later.',
    crossOrigin: 'Request not allowed',
    serverError: 'Server error',
    badRequest: 'Invalid request',
  },

  legal: { updated: 'Last updated' },

  notFound: {
    title: 'Page not found',
    home: 'Create a new secret',
  },

  footer: {
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
