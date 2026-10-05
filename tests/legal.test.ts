/**
 * Legal documents: the facts a reader relies on, and the one failure a typo
 * would cause on the page.
 */
import { describe, expect, it } from 'vitest';
import {
  LEGAL_LINKS,
  OPERATOR,
  getLegalDocument,
  legalLinkLabel,
  resolveLegalText,
  type LegalDocument,
  type LegalDocumentKind,
} from '../src/lib/legal.ts';
import { LOCALES, getDictionary, type Locale } from '../src/lib/i18n.ts';

const TOKEN = /\[\[([a-zA-Z]+)\]\]/g;

const KINDS: readonly LegalDocumentKind[] = ['privacy', 'terms'];

/** Every string of a document, in the order a reader meets them. */
function texts(document: LegalDocument): readonly string[] {
  return document.sections.flatMap((section) => [
    section.heading,
    ...section.blocks.flatMap((block) => (block.kind === 'list' ? block.items : [block.text])),
  ]);
}

/** The document as rendered, with every token replaced by its label. */
function rendered(document: LegalDocument, locale: Locale): string {
  return texts(document)
    .flatMap((text) => resolveLegalText(text, locale))
    .map((part) => (typeof part === 'string' ? part : part.label))
    .join(' ');
}

describe('legal documents', () => {
  it('is complete in both languages', () => {
    for (const kind of KINDS) {
      for (const locale of LOCALES) {
        const document = getLegalDocument(kind, locale);
        expect(document.title.trim().length, `${kind}:${locale}`).toBeGreaterThan(0);
        expect(document.summary.trim().length, `${kind}:${locale}`).toBeGreaterThan(0);
        expect(document.updated, `${kind}:${locale}`).toMatch(/^\d{4}-\d{2}-\d{2}$/);
        expect(document.sections.length, `${kind}:${locale}`).toBeGreaterThan(3);
        for (const text of texts(document)) expect(text.trim().length, `${kind}:${locale}`).toBeGreaterThan(0);
      }
    }
  });

  it('reaches the controller in every document', () => {
    for (const kind of KINDS) {
      for (const locale of LOCALES) {
        const text = rendered(getLegalDocument(kind, locale), locale);
        expect(text, `${kind}:${locale}`).toContain(OPERATOR.name);
        expect(text, `${kind}:${locale}`).toContain(OPERATOR.vatId);
        expect(text, `${kind}:${locale}`).toContain(OPERATOR.contactEmail);
      }
    }
  });

  it('uses only declared link tokens, and no token is dead', () => {
    const used = new Set<string>();
    for (const kind of KINDS) {
      for (const locale of LOCALES) {
        for (const text of texts(getLegalDocument(kind, locale))) {
          for (const match of text.matchAll(TOKEN)) {
            if (match[1] === undefined) continue;
            // An unknown token would render as literal "[[...]]" on the page.
            expect(Object.keys(LEGAL_LINKS), match[1]).toContain(match[1]);
            used.add(match[1]);
          }
        }
      }
    }
    expect([...used].sort()).toEqual(Object.keys(LEGAL_LINKS).sort());
  });

  it('never claims an audited end-to-end encryption', () => {
    for (const kind of KINDS) {
      for (const locale of LOCALES) {
        const text = rendered(getLegalDocument(kind, locale), locale);
        expect(text, `${kind}:${locale}`).toMatch(/end-to-end/);
        const negated =
          locale === 'en'
            ? /not end-to-end encryption verified by an independent review/
            : /non (è )?(una )?cifratura end-to-end verificata da una revisione indipendente/;
        expect(text, `${kind}:${locale}`).toMatch(negated);
      }
    }
  });

  it('discloses the limits the implementation cannot fix', () => {
    // Backups survive a delete and the proxy may log: both are stated in every
    // language, so a reader never relies on a promise the code cannot keep.
    for (const kind of KINDS) {
      for (const locale of LOCALES) {
        const text = rendered(getLegalDocument(kind, locale), locale).toLowerCase();
        expect(text, `${kind}:${locale}`).toContain('backup');
        expect(text, `${kind}:${locale}`).toContain('proxy');
      }
    }
  });

  it('cross-references the two documents in both languages', () => {
    const it = getLegalDocument('privacy', 'it');
    const en = getLegalDocument('terms', 'en');
    expect(texts(it).join(' ')).toContain('[[terms]]');
    expect(texts(en).join(' ')).toContain('[[privacy]]');
  });
});

describe('resolveLegalText', () => {
  it('returns text and links in order', () => {
    expect(resolveLegalText('vedi [[terms]]', 'it')).toEqual([
      'vedi ',
      { href: '/terms', label: "condizioni d'uso" },
    ]);
    expect(resolveLegalText('see the [[privacy]]', 'en')).toEqual([
      'see the ',
      { href: '/privacy', label: 'privacy policy' },
    ]);
  });

  it('leaves an unknown token as text rather than inventing a link', () => {
    const parts = resolveLegalText('vedi [[nope]]', 'it');
    expect(parts.join('')).toBe('vedi [[nope]]');
    for (const part of parts) expect(typeof part).toBe('string');
  });

  it('points the umbrella links at the operator\'s own site', () => {
    expect(LEGAL_LINKS.sitePrivacy.href).toBe(OPERATOR.sitePrivacyUrl);
    expect(LEGAL_LINKS.siteTerms.href).toBe(OPERATOR.siteTermsUrl);
    expect(LEGAL_LINKS.contact.href).toBe(`mailto:${OPERATOR.contactEmail}`);
  });
});

describe('footer links', () => {
  it('labels both documents the same way the prose links to them', () => {
    for (const locale of LOCALES) {
      const footer = getDictionary(locale).footer;
      expect(footer.privacy.toLowerCase(), locale).toBe(legalLinkLabel('privacy', locale));
      expect(footer.terms.toLowerCase(), locale).toBe(legalLinkLabel('terms', locale));
    }
  });
});
