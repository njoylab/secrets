/**
 * Centralized IT/EN dictionaries. Every user-facing string, including
 * validation errors and accessibility labels, resolves through `t()`.
 * Secret content is never routed through this module.
 */
export type Locale = 'it' | 'en';

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
  language: { label: string; it: string; en: string };
  nav: { home: string };
  create: {
    title: string;
    secretLabel: string;
    secretPlaceholder: string;
    secretHint: string;
    expiryLabel: string;
    expirySuffix: string;
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
    copy: string;
    copied: string;
    copyFailed: string;
    expires: string;
    days: string;
    another: string;
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
    noteSingleRead: string;
  };
  secret: {
    title: string;
    copy: string;
    copied: string;
    copyFailed: string;
    consumed: string;
    consumedHint: string;
  };
  errors: {
    secretRequired: string;
    secretTooLong: string;
    invalidExpiry: string;
    passwordTooLong: string;
    badPassword: string;
    unavailable: string;
    rateLimited: string;
    crossOrigin: string;
    serverError: string;
    badRequest: string;
  };
  footer: { limits: string };
};

/** Keys accepted by the JSON error responses. */
export type ErrorKey = keyof Dictionary['errors'];

const it: Dictionary = {
  meta: {
    title: 'secrets',
    description: 'Condividi un segreto con un link monouso.',
    robots: 'noindex, nofollow',
  },
  skipToContent: 'Vai al contenuto',
  language: { label: 'Lingua', it: 'Italiano', en: 'Inglese' },
  nav: { home: 'Nuovo segreto' },

  create: {
    title: 'Nuovo segreto',
    secretLabel: 'Segreto',
    secretPlaceholder: 'Testo del segreto',
    secretHint: 'Massimo 50 KiB',
    expiryLabel: 'Scadenza · giorni',
    expirySuffix: 'giorni',
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
    copy: 'Copia',
    copied: 'Copiato',
    copyFailed: 'Copia non riuscita',
    expires: 'Scadenza',
    days: 'giorni',
    another: 'Nuovo segreto',
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
    noteSingleRead: 'Una sola lettura. Nessun recupero',
  },

  secret: {
    title: 'Segreto',
    copy: 'Copia',
    copied: 'Copiato',
    copyFailed: 'Copia non riuscita',
    consumed: 'Segreto non disponibile',
    consumedHint: 'Questo link è stato già letto o è scaduto.',
  },

  errors: {
    secretRequired: 'Inserisci un segreto',
    secretTooLong: 'Limite 50 KiB',
    invalidExpiry: 'Scadenza da 1 a 30 giorni',
    passwordTooLong: 'Password troppo lunga',
    badPassword: 'Password errata',
    unavailable: 'Link non disponibile',
    rateLimited: 'Troppe richieste. Riprova più tardi.',
    crossOrigin: 'Richiesta non consentita',
    serverError: 'Errore del server',
    badRequest: 'Richiesta non valida',
  },

  footer: { limits: 'Limite 50 KiB · una sola lettura' },
};

const en: Dictionary = {
  meta: {
    title: 'secrets',
    description: 'Share a secret with a one-time link.',
    robots: 'noindex, nofollow',
  },
  skipToContent: 'Skip to content',
  language: { label: 'Language', it: 'Italian', en: 'English' },
  nav: { home: 'New secret' },

  create: {
    title: 'New secret',
    secretLabel: 'Secret',
    secretPlaceholder: 'Secret text',
    secretHint: '50 KiB max',
    expiryLabel: 'Expires in · days',
    expirySuffix: 'days',
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
    copy: 'Copy',
    copied: 'Copied',
    copyFailed: 'Copy failed',
    expires: 'Expires',
    days: 'days',
    another: 'New secret',
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
    noteSingleRead: 'One read only. No recovery',
  },

  secret: {
    title: 'Secret',
    copy: 'Copy',
    copied: 'Copied',
    copyFailed: 'Copy failed',
    consumed: 'Secret unavailable',
    consumedHint: 'This link was already read or has expired.',
  },

  errors: {
    secretRequired: 'Enter a secret',
    secretTooLong: '50 KiB limit',
    invalidExpiry: 'Expiry from 1 to 30 days',
    passwordTooLong: 'Password too long',
    badPassword: 'Incorrect password',
    unavailable: 'Link unavailable',
    rateLimited: 'Too many requests. Try again later.',
    crossOrigin: 'Request not allowed',
    serverError: 'Server error',
    badRequest: 'Invalid request',
  },

  footer: { limits: '50 KiB limit · one read only' },
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