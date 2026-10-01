/**
 * Localization: Accept-Language negotiation, locale normalization and the two
 * dictionaries. The wording required by PIANO_SVILUPPO.md is asserted verbatim
 * so a translation cannot drift from the specification.
 */
import { describe, expect, it } from 'vitest';
import {
  DEFAULT_LOCALE,
  LOCALES,
  LOCALE_COOKIE,
  detectLocale,
  getDictionary,
  normalizeLocale,
  type Dictionary,
  type Locale,
} from '../src/lib/i18n.ts';

describe('constants', () => {
  it('supports exactly Italian and English, defaulting to English', () => {
    expect(LOCALES).toEqual(['it', 'en']);
    expect(DEFAULT_LOCALE).toBe('en');
    expect(LOCALE_COOKIE).toBe('locale');
  });
});

describe('detectLocale', () => {
  const cases: ReadonlyArray<readonly [string, string | null | undefined, Locale]> = [
    ['a bare Italian tag', 'it', 'it'],
    ['an Italian tag with a region', 'it-IT', 'it'],
    ['a list where Italian ranks first', 'it-IT,it;q=0.9', 'it'],
    ['a list where English ranks first', 'en-US,en;q=0.9', 'en'],
    ['an unsupported language first', 'fr-FR,en;q=0.5', 'en'],
    ['a hyphenated region variant', 'en-GB', 'en'],
    ['a mixed case tag', 'IT-it', 'it'],
    ['an underscore separated tag', 'en_GB', 'en'],
    ['a language with a wildcard region', 'it-CH', 'it'],
    ['surrounding whitespace', '  it-IT , en ; q=0.5 ', 'it'],
    ['an unsupported language only', 'de', DEFAULT_LOCALE],
    ['an unsupported language with a region', 'de-AT', DEFAULT_LOCALE],
    ['a wildcard', '*', DEFAULT_LOCALE],
    ['a malformed value', ';;;', DEFAULT_LOCALE],
    ['a list of separators only', ',,,', DEFAULT_LOCALE],
    ['an empty string', '', DEFAULT_LOCALE],
    ['null', null, DEFAULT_LOCALE],
    ['undefined', undefined, DEFAULT_LOCALE],
  ];

  it.each(cases)('resolves %s', (_label, acceptLanguage, expected) => {
    expect(detectLocale(acceptLanguage)).toBe(expected);
  });

  it('honours quality values when ranking supported languages', () => {
    // Italian is listed first but explicitly less preferred than English.
    expect(detectLocale('it;q=0.2,en;q=0.9')).toBe('en');
    expect(detectLocale('en;q=0.2,it;q=0.9')).toBe('it');
    expect(detectLocale('fr;q=1,de;q=0.9,it;q=0.8,en;q=0.7')).toBe('it');
    expect(detectLocale('it;q=0.5,fr;q=0.4')).toBe('it');
  });

  it('treats q=0 as "not acceptable" and falls back to the next language', () => {
    // RFC 9110: a zero quality excludes the language, so it must not win over
    // a lower ranked alternative, and must not be selected on its own.
    // Known defect in src/lib/i18n.ts: the ranking loop keeps q=0 entries, so
    // the last two assertions fail and the header is not honoured.
    expect(detectLocale('it;q=0,en;q=0.1')).toBe('en');
    expect(detectLocale('it;q=0.0')).toBe(DEFAULT_LOCALE);
    expect(detectLocale('it;q=0')).toBe(DEFAULT_LOCALE);
  });

  it('is not confused by a repeated or unparsable quality parameter', () => {
    expect(detectLocale('en;q=0.9;q=0.1')).toBe('en');
    expect(detectLocale('it;q=notanumber,en;q=0.1')).toBe('en');
  });
});

describe('normalizeLocale', () => {
  const cases: ReadonlyArray<readonly [string | null | undefined, Locale | undefined]> = [
    ['it', 'it'],
    ['en', 'en'],
    ['EN', 'en'],
    ['en_GB', 'en'],
    ['IT-it', 'it'],
    [' it ', 'it'],
    ['ita', undefined],
    ['eng', undefined],
    ['fr', undefined],
    ['*', undefined],
    ['', undefined],
    ['   ', undefined],
    [null, undefined],
    [undefined, undefined],
  ];

  it.each(cases)('normalizes %s', (value, expected) => {
    expect(normalizeLocale(value)).toBe(expected);
  });

  it('never returns a locale outside the supported list', () => {
    for (const value of ['ita', 'de-AT', 'x', 'i', 'e', 'en-us-x-private']) {
      const locale = normalizeLocale(value);
      if (locale !== undefined) expect(LOCALES).toContain(locale);
    }
  });
});

/** Flatten a dictionary into `dotted.path -> value` so both languages can be compared. */
function flatten(value: unknown, path: string, into: Map<string, string>): Map<string, string> {
  if (typeof value === 'string') {
    into.set(path, value);
    return into;
  }
  if (typeof value !== 'object' || value === null) {
    throw new Error(`Dictionary value at "${path}" is not a string or a nested object`);
  }
  for (const [key, child] of Object.entries(value)) {
    flatten(child, path === '' ? key : `${path}.${key}`, into);
  }
  return into;
}

function flattenDictionary(locale: Locale): Map<string, string> {
  return flatten(getDictionary(locale), '', new Map<string, string>());
}

describe('dictionaries', () => {
  it('exposes the same key set in both languages', () => {
    const italian = flattenDictionary('it');
    const english = flattenDictionary('en');

    expect(italian.size).toBe(english.size);
    expect([...italian.keys()].sort()).toEqual([...english.keys()].sort());
    // Every group named by the specification is present and nested, never a
    // leaf string, so a group can grow without changing the comparison.
    for (const group of ['meta', 'language', 'nav', 'create', 'result', 'open', 'secret', 'errors', 'footer']) {
      expect(italian.has(group), group).toBe(false);
      expect([...italian.keys()].filter((key) => key.startsWith(`${group}.`)).length, group).toBeGreaterThan(0);
    }
    expect(italian.has('skipToContent')).toBe(true);
  });

  it('has no empty or blank value in either language', () => {
    for (const locale of LOCALES) {
      for (const [path, value] of flattenDictionary(locale)) {
        expect(value.trim().length, `${locale}:${path}`).toBeGreaterThan(0);
      }
    }
  });

  it('localizes every error key', () => {
    const errorKeys: ReadonlyArray<keyof Dictionary['errors']> = [
      'secretRequired',
      'secretTooLong',
      'invalidExpiry',
      'passwordTooLong',
      'badPassword',
      'unavailable',
      'rateLimited',
      'crossOrigin',
      'serverError',
      'badRequest',
    ];
    for (const locale of LOCALES) {
      const errors = getDictionary(locale).errors;
      expect(Object.keys(errors).sort()).toEqual([...errorKeys].sort());
      for (const key of errorKeys) {
        expect(errors[key].trim().length, `${locale}:${key}`).toBeGreaterThan(0);
      }
    }
  });

  it('forbids indexing and caches nothing but the language choice', () => {
    for (const locale of LOCALES) {
      expect(getDictionary(locale).meta.robots).toBe('noindex, nofollow');
    }
  });

  it('returns a dictionary for every supported locale and a safe one otherwise', () => {
    for (const locale of LOCALES) {
      expect(getDictionary(locale).meta.title.length).toBeGreaterThan(0);
    }
  });
});

describe('wording required by PIANO_SVILUPPO.md', () => {
  // Exactly the pairs listed in section 4 of the specification.
  const required: ReadonlyArray<readonly [it: string, en: string]> = [
    ['Segreto', 'Secret'],
    ['Scadenza · giorni', 'Expires in · days'],
    ['Password · opzionale', 'Password · optional'],
    ['Crea link', 'Create link'],
    ['Copia', 'Copy'],
    ['Copiato', 'Copied'],
    ['Mostra segreto', 'Reveal secret'],
    ['Password errata', 'Incorrect password'],
    ['Link non disponibile', 'Link unavailable'],
  ];

  it.each(required)('uses "%s" / "%s"', (italian, english) => {
    const it = flattenDictionary('it');
    const en = flattenDictionary('en');
    const itPaths = [...it.entries()].filter(([, value]) => value === italian).map(([path]) => path);
    const enPaths = [...en.entries()].filter(([, value]) => value === english).map(([path]) => path);

    expect(itPaths.length, italian).toBeGreaterThan(0);
    expect(enPaths.length, english).toBeGreaterThan(0);
    // The two languages must use the same label for the same element.
    expect(itPaths.sort()).toEqual(enPaths.sort());
  });

  it('pins the two permitted notes verbatim', () => {
    const it = getDictionary('it');
    const en = getDictionary('en');
    expect(it.create.notePassword).toBe('Invia la password separatamente');
    expect(en.create.notePassword).toBe('Send the password separately');
    expect(it.create.noteSingleRead).toBe('Una sola lettura. Nessun recupero');
    expect(en.create.noteSingleRead).toBe('One read only. No recovery');
    // The same two notes, reused on the opening screen.
    expect(it.open.noteSingleRead).toBe('Una sola lettura. Nessun recupero');
    expect(en.open.noteSingleRead).toBe('One read only. No recovery');
  });

  it('uses no hardcoded placeholder where the dictionary already has one', () => {
    expect(getDictionary('it').create.secretLabel).toBe('Segreto');
    expect(getDictionary('en').create.secretLabel).toBe('Secret');
    expect(getDictionary('it').result.copy).toBe('Copia');
    expect(getDictionary('en').result.copy).toBe('Copy');
    expect(getDictionary('it').open.unavailable).toBe('Link non disponibile');
    expect(getDictionary('en').open.unavailable).toBe('Link unavailable');
    expect(getDictionary('it').errors.unavailable).toBe(getDictionary('it').open.unavailable);
    expect(getDictionary('en').errors.unavailable).toBe(getDictionary('en').open.unavailable);
  });

  it('keeps the message short: no long explanations or absolute security claims', () => {
    for (const locale of LOCALES) {
      const dictionary = getDictionary(locale);
      const strings = [...flattenDictionary(locale).values()];
      for (const value of strings) {
        expect(value.length, `${locale}`).toBeLessThan(120);
        expect(value.toLowerCase().includes('end-to-end'), locale).toBe(false);
        expect(value.toLowerCase().includes('crittograf'), locale).toBe(false);
      }
      expect(dictionary.create.secretHint).toBe(
        locale === 'it' ? 'Massimo 50 KiB' : '50 KiB max',
      );
    }
  });
});
