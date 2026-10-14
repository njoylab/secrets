/**
 * The "how it works" page: complete in both languages, with valid links and
 * the same honesty rules as the legal documents.
 */
import { describe, expect, it } from 'vitest';
import { getHowDocument } from '../src/lib/how.ts';
import { LEGAL_LINKS, resolveLegalText, type LegalDocument } from '../src/lib/legal.ts';
import { LOCALES, type Locale } from '../src/lib/i18n.ts';

function texts(document: LegalDocument): readonly string[] {
  return document.sections.flatMap((section) => [
    section.heading,
    ...section.blocks.flatMap((block) => (block.kind === 'list' ? block.items : [block.text])),
  ]);
}

function rendered(document: LegalDocument, locale: Locale): string {
  return texts(document)
    .flatMap((text) => resolveLegalText(text, locale))
    .map((part) => (typeof part === 'string' ? part : part.label))
    .join(' ');
}

describe('how it works', () => {
  it('is complete and parallel in both languages', () => {
    const [first, ...rest] = LOCALES.map((locale) => getHowDocument(locale));
    for (const document of [first!, ...rest]) {
      expect(document.title.trim().length).toBeGreaterThan(0);
      expect(document.summary.trim().length).toBeGreaterThan(0);
      expect(document.updated).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      for (const text of texts(document)) expect(text.trim().length).toBeGreaterThan(0);
      expect(document.sections.length).toBe(first!.sections.length);
    }
  });

  it('uses only declared link tokens', () => {
    for (const locale of LOCALES) {
      for (const text of texts(getHowDocument(locale))) {
        for (const match of text.matchAll(/\[\[([a-zA-Z]+)\]\]/g)) {
          expect(Object.keys(LEGAL_LINKS), match[1]).toContain(match[1]);
        }
      }
    }
  });

  it('never claims an audited end-to-end encryption and states the backup limit', () => {
    for (const locale of LOCALES) {
      const text = rendered(getHowDocument(locale), locale);
      const negated =
        locale === 'en'
          ? /not end-to-end encryption verified by an independent review/
          : /non è una cifratura end-to-end verificata da una revisione indipendente/i;
      expect(text, locale).toMatch(negated);
      expect(text.toLowerCase(), locale).toContain('backup');
    }
  });
});
