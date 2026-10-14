/**
 * Privacy policy and terms of use, in the two supported languages.
 *
 * They live here rather than in `i18n.ts` because they are documents, not
 * interface copy: `i18n.ts` holds the short strings the plan asks for, while
 * these are a handful of short paragraphs per document. Every string is
 * centralized in this file and resolved by locale.
 *
 * Two rules keep the prose honest:
 *
 * 1. Every technical statement must match the code: what `src/lib/secrets.ts`
 *    stores, how long `scripts/cleanup.mjs` keeps it, what the proxy in front of
 *    the app may log. Where the implementation cannot back a promise, the text
 *    says so, as it does for backups and for reading the content.
 * 2. Never claim audited end-to-end encryption. It is client-side encryption,
 *    which an operator able to change the page can undo.
 *
 * Inline links are written as `[[token]]` and resolved by `resolveLegalText`, so
 * a page renders prose as text and never injects markup from a string.
 */
import { DEFAULT_LOCALE, type Locale } from './i18n.ts';

/**
 * Identity of the party behind the service, as published on the operator's own
 * site. Changing the controller means changing only this object.
 *
 * The values here are placeholders. Replace every field, and the operator name
 * written into the documents below, before deploying: a privacy policy that
 * names the wrong controller is worse than no policy, and the test suite fails
 * if the prose and this object disagree.
 *
 * No VAT number is published. It is optional for this kind of notice, which the
 * controller identification in Articles 13-14 GDPR does not require, and it is
 * public registry data in any case. The name and the contact address are what
 * identify the controller here.
 */
export const OPERATOR = {
  name: 'Example Operator S.r.l.',
  contactEmail: 'privacy@example.com',
  /** General documents of the main site, which cover the site rather than this tool. */
  sitePrivacyUrl: 'https://example.com/privacy',
  siteTermsUrl: 'https://example.com/terms',
} as const;

export type LegalLinkKey = 'privacy' | 'terms' | 'sitePrivacy' | 'siteTerms' | 'contact' | 'turnstilePrivacy';

export interface LegalLinkPart {
  readonly href: string;
  readonly label: string;
}

/** The only tokens a document may use; `tests/legal.test.ts` enforces it. */
export const LEGAL_LINKS: Readonly<Record<LegalLinkKey, LegalLinkPart>> = {
  privacy: { href: '/privacy', label: 'informativa privacy' },
  terms: { href: '/terms', label: "condizioni d'uso" },
  sitePrivacy: { href: OPERATOR.sitePrivacyUrl, label: OPERATOR.sitePrivacyUrl },
  siteTerms: { href: OPERATOR.siteTermsUrl, label: OPERATOR.siteTermsUrl },
  contact: { href: `mailto:${OPERATOR.contactEmail}`, label: OPERATOR.contactEmail },
  turnstilePrivacy: { href: 'https://www.cloudflare.com/turnstile-privacy-policy/', label: 'informativa Turnstile' },
};

/** Localized labels for links whose wording differs between languages. */
const LINK_LABELS_EN: Readonly<Partial<Record<LegalLinkKey, string>>> = {
  privacy: 'privacy policy',
  terms: 'terms of use',
  turnstilePrivacy: 'Turnstile privacy notice',
};

/** The words a token stands for in a sentence. */
export function legalLinkLabel(key: LegalLinkKey, locale: Locale): string {
  if (locale !== 'en') return LEGAL_LINKS[key].label;
  return LINK_LABELS_EN[key] ?? LEGAL_LINKS[key].label;
}

/** A rendered paragraph: literal text, or a link that must not be escaped as HTML. */
export type LegalTextPart = string | LegalLinkPart;

const LINK_TOKEN = /\[\[([a-zA-Z]+)\]\]/;

/**
 * Split a document string into plain text and links.
 *
 * An unknown token is left literal, so a typo shows up on the page instead of
 * silently becoming an anchor to nowhere.
 */
export function resolveLegalText(text: string, locale: Locale): readonly LegalTextPart[] {
  const parts: LegalTextPart[] = [];
  let rest = text;

  for (;;) {
    const match = LINK_TOKEN.exec(rest);
    if (!match) break;
    const token = match[1] as LegalLinkKey;
    if (match.index > 0) parts.push(rest.slice(0, match.index));
    const link = LEGAL_LINKS[token];
    if (link) parts.push({ ...link, label: legalLinkLabel(token, locale) });
    else parts.push(match[0]);
    rest = rest.slice(match.index + match[0].length);
  }
  if (rest.length > 0) parts.push(rest);
  return parts;
}

export type LegalBlock =
  | { readonly kind: 'p'; readonly text: string }
  | { readonly kind: 'list'; readonly items: readonly string[] };

export interface LegalSection {
  readonly heading: string;
  readonly blocks: readonly LegalBlock[];
}

export interface LegalDocument {
  readonly title: string;
  /** One sentence: the meta description, and the intro under the title. */
  readonly summary: string;
  /** ISO date of the last revision; the page formats it for the reader. */
  readonly updated: string;
  readonly sections: readonly LegalSection[];
}

export type LegalDocumentKind = 'privacy' | 'terms';

const privacyIt: LegalDocument = {
  title: 'Informativa privacy',
  summary: 'Quali dati trattiamo, per quanto tempo e come esercitare i tuoi diritti.',
  updated: '2026-10-14',
  sections: [
    {
      heading: 'Titolare e finalità',
      blocks: [
        {
          kind: 'p',
          text: "Il titolare è Example Operator S.r.l. Contatti: [[contact]]. Trattiamo i dati per fornire il servizio e prevenire abusi, sulla base del legittimo interesse (art. 6.1.f GDPR). Non servono account e non facciamo marketing, profilazione o decisioni automatizzate.",
        },
      ],
    },
    {
      heading: 'Dati trattati',
      blocks: [
        {
          kind: 'list',
          items: [
            'Contenuto cifrato, impronte dei token, impronta della chiave di verifica, indicazione della password e date di creazione e scadenza.',
            'Stato e data di lettura, annullamento o scadenza, consultabili dal link di controllo.',
            'Indirizzo IP in chiaro nei contatori che limitano creazioni, letture e annullamenti.',
            'Un cookie per ricordare la lingua scelta, valido un anno. Un CDN o un reverse proxy a monte può impostare altri cookie tecnici, secondo le funzioni attive su quella distribuzione.',
          ],
        },
      ],
    },
    {
      heading: 'Protezione del segreto',
      blocks: [
        {
          kind: 'p',
          text: 'Il browser cifra il testo prima di inviarlo. La chiave resta nel link, dopo #, e non arriva al server. La password resta nel browser. Il server autorizza la lettura solo dopo aver verificato che il browser abbia la chiave corretta e, se impostata, la password. Chi ha il link completo può aprire il segreto, con la password se impostata.',
        },
        {
          kind: 'p',
          text: 'È cifratura lato client, non cifratura end-to-end verificata da una revisione indipendente. Un dispositivo compromesso o una modifica malevola del codice della pagina possono esporre il contenuto.',
        },
      ],
    },
    {
      heading: 'Conservazione',
      blocks: [
        {
          kind: 'list',
          items: [
            'Segreti: cancellati alla lettura o all’annullamento. Alla scadenza, entro 30 giorni dalla creazione, diventano inaccessibili e vengono rimossi dalla pulizia periodica.',
            'Stato del segreto: conservato fino alla scadenza originaria o a sette giorni dalla chiusura, se successivi; poi rimosso dalla pulizia periodica.',
            'Contatori IP: rimossi dalla pulizia dopo il periodo configurato, almeno pari alla finestra di conteggio più lunga (un’ora con i valori predefiniti).',
          ],
        },
        {
          kind: 'p',
          text: 'La cancellazione non elimina subito le copie nei registri del database (WAL) o nei backup. Per log tecnici e backup sotto il nostro controllo, la politica prevista è di massimo 7 giorni; la sua applicazione sull’infrastruttura resta da verificare. I dati conservati autonomamente dai fornitori seguono le rispettive politiche.',
        },
      ],
    },
    {
      heading: 'Log e fornitori',
      blocks: [
        {
          kind: 'p',
          text: 'L’applicazione non registra contenuti, password, token o corpi delle richieste. Proxy e hosting possono registrare IP, orari, percorsi richiesti e browser; i percorsi possono contenere i token, ma non la chiave dopo #. I server sono ospitati dal provider indicato nella documentazione del servizio, in un Paese riconosciuto dalla Commissione europea come adeguato per la protezione dei dati. Il provider di hosting e l’eventuale CDN a monte trattano indirizzi IP e metadati delle richieste per erogare i rispettivi servizi. Questi fornitori possono trattare i dati tecnici necessari ai rispettivi servizi. Eventuali ulteriori trasferimenti fuori dallo Spazio economico europeo richiedono le garanzie previste dal GDPR; puoi chiedere dettagli a [[contact]].',
        },
        {
          kind: 'p',
          text: 'È prevista la possibile introduzione di Cloudflare Turnstile contro gli abusi, ma non è ancora integrato nell’applicazione. Quando attivo, tratta IP e segnali tecnici del browser per distinguere persone e bot. Cloudflare usa questi segnali anche per migliorare Turnstile, come titolare autonomo: [[turnstilePrivacy]]. L’eventuale cookie cf_clearance dipende dall’attivazione della funzione pre-clearance.',
        },
      ],
    },
    {
      heading: 'Diritti e contatti',
      blocks: [
        {
          kind: 'p',
          text: 'Nei casi previsti dal GDPR puoi chiedere accesso, rettifica, cancellazione, limitazione e portabilità, oppure opporti al trattamento. Scrivi a [[contact]] senza includere il contenuto, la password o il link completo. Non possiamo decifrare o recuperare i segreti. Puoi presentare reclamo al Garante per la protezione dei dati personali o all’autorità competente nel tuo Paese.',
        },
        {
          kind: 'p',
          text: 'Questa informativa riguarda secrets. Per il sito echoValue: [[sitePrivacy]]. Per il servizio: [[terms]]. La data in alto indica l’ultima revisione; le modifiche che incidono sui tuoi diritti saranno comunicate prima di entrare in vigore.',
        },
      ],
    },
  ],
};

const privacyEn: LegalDocument = {
  title: 'Privacy policy',
  summary: 'What data we process, how long we keep it and how to exercise your rights.',
  updated: '2026-10-14',
  sections: [
    {
      heading: 'Controller and purposes',
      blocks: [
        {
          kind: 'p',
          text: 'The controller is Example Operator S.r.l. Contact: [[contact]]. We process data to provide the service and prevent abuse, based on legitimate interest (Article 6(1)(f) GDPR). No account is required. We do not use data for marketing, profiling or automated decision-making.',
        },
      ],
    },
    {
      heading: 'Data we process',
      blocks: [
        {
          kind: 'list',
          items: [
            'Encrypted content, token hashes, a hash of the verification key, whether a password is set, and creation and expiry dates.',
            'The status and time of a read, cancellation or expiry, available through the control link.',
            'Your IP address in cleartext in counters that limit creations, reads and cancellations.',
            'A cookie that remembers your language choice for one year. A CDN or reverse proxy in front may set other technical cookies, depending on the features enabled on that deployment.',
          ],
        },
      ],
    },
    {
      heading: 'Protecting the secret',
      blocks: [
        {
          kind: 'p',
          text: 'The browser encrypts the text before sending it. The key stays in the link, after #, and never reaches the server. The password stays in the browser. The server authorizes reading only after verifying that the browser holds the correct key and, if set, the password. Anyone with the complete link can open the secret, with the password if set.',
        },
        {
          kind: 'p',
          text: 'This is not end-to-end encryption verified by an independent review. A compromised device or a malicious change to the page code can expose the content.',
        },
      ],
    },
    {
      heading: 'Retention',
      blocks: [
        {
          kind: 'list',
          items: [
            'Secrets: deleted on reading or cancellation. At expiry, within 30 days of creation, they become inaccessible and are removed by periodic cleanup.',
            'Secret status: kept until the original expiry or seven days after closure, whichever is later; then removed by periodic cleanup.',
            'IP counters: removed by cleanup after the configured period, at least as long as the longest counting window (one hour with default settings).',
          ],
        },
        {
          kind: 'p',
          text: 'Deletion does not immediately remove copies from database logs (WAL) or backups. For technical logs and backups under our control, the planned policy is a maximum of 7 days; enforcement on the infrastructure remains to be verified. Data retained independently by providers follows their own policies.',
        },
      ],
    },
    {
      heading: 'Logs and providers',
      blocks: [
        {
          kind: 'p',
          text: 'The application does not log content, passwords, tokens or request bodies. A proxy and hosting provider may log IP addresses, times, requested paths and browsers; paths may include tokens, but never the key after #. The servers are hosted with the provider named in the service documentation, in a country the European Commission recognises as providing adequate data protection. The hosting provider and any CDN in front process IP addresses and request metadata to deliver their respective services. These providers may process the technical data needed for their respective services. Any further transfers outside the European Economic Area require GDPR safeguards; contact [[contact]] for details.',
        },
        {
          kind: 'p',
          text: 'Cloudflare Turnstile may be introduced to prevent abuse, but it is not yet integrated into the application. When enabled, it processes IP addresses and technical browser signals to distinguish people from bots. Cloudflare also uses these signals to improve Turnstile as an independent controller: [[turnstilePrivacy]]. A cf_clearance cookie depends on enabling the pre-clearance feature.',
        },
      ],
    },
    {
      heading: 'Rights and contact',
      blocks: [
        {
          kind: 'p',
          text: 'Where the GDPR provides for it, you can request access, rectification, erasure, restriction and portability, or object to processing. Write to [[contact]] without including the content, password or complete link. We cannot decrypt or recover secrets. You can complain to the Italian data protection authority or the competent authority in your country.',
        },
        {
          kind: 'p',
          text: 'This policy covers secrets. For the echoValue site: [[sitePrivacy]]. For this service: [[terms]]. The date above shows the last revision; changes affecting your rights will be communicated before taking effect.',
        },
      ],
    },
  ],
};

const termsIt: LegalDocument = {
  title: "Condizioni d’uso",
  summary: 'Un link, una sola lettura. Le regole e i limiti del servizio.',
  updated: '2026-10-05',
  sections: [
    {
      heading: 'Il servizio',
      blocks: [
        {
          kind: 'p',
          text: 'secrets è gestito da Example Operator S.r.l.: [[contact]]. Usandolo accetti queste condizioni. Puoi condividere testi fino a 50 KiB con un link monouso, una scadenza da un’ora a 30 giorni e una password opzionale. Il link di controllo mostra lo stato e permette di annullare il segreto. I contenuti restano tuoi. Il servizio non è destinato a minori.',
        },
      ],
    },
    {
      heading: 'Le tue responsabilità',
      blocks: [
        {
          kind: 'list',
          items: [
            'Condividi solo contenuti leciti che hai diritto di condividere, rispettando la protezione dei dati personali.',
            'Custodisci i link e invia l’eventuale password separatamente. Non tentare di accedere a segreti altrui o aggirare le protezioni e i limiti del servizio.',
            'Non affidare al servizio scambi da cui dipendono la sicurezza di persone o servizi essenziali, né dati con obblighi di protezione incompatibili con questi limiti.',
          ],
        },
      ],
    },
    {
      heading: 'Una sola lettura, nessun recupero',
      blocks: [
        {
          kind: 'p',
          text: 'Aprire il link non consuma il segreto. La richiesta di lettura lo cancella prima della consegna: se la risposta non arriva o la decifratura fallisce, non puoi riprovare e lo stato risulta “letto”. Il destinatario può conservare una copia del testo ricevuto. Se perdi il link o la password, non possiamo recuperarli. Scadenza e annullamento impediscono la lettura.',
        },
      ],
    },
    {
      heading: 'Sicurezza e privacy',
      blocks: [
        {
          kind: 'p',
          text: 'Il testo è cifrato nel browser e la chiave resta nel link. È cifratura lato client, non cifratura end-to-end verificata da una revisione indipendente: dispositivi compromessi o modifiche malevole alla pagina possono esporlo. La [[privacy]] descrive dati trattati, log di proxy e hosting e conservazione nei backup.',
        },
      ],
    },
    {
      heading: 'Disponibilità e responsabilità',
      blocks: [
        {
          kind: 'p',
          text: 'Il servizio è fornito così com’è, senza garanzie di continuità o recupero. Può essere modificato, interrotto o sospeso; applichiamo limiti alle richieste e possiamo bloccare gli abusi. Nei limiti di legge, Example Operator S.r.l. non risponde di danni indiretti, perdita di dati o mancato guadagno. Restano ferme le responsabilità non escludibili, incluse quelle per dolo o colpa grave, e i diritti dei consumatori.',
        },
      ],
    },
    {
      heading: 'Legge applicabile',
      blocks: [
        {
          kind: 'p',
          text: 'Si applica la legge italiana, senza pregiudicare le tutele inderogabili del Paese di residenza abituale del consumatore. Per domande o problemi: [[contact]]. La data in alto indica l’ultima revisione. Le condizioni generali del sito echoValue sono su [[siteTerms]].',
        },
      ],
    },
  ],
};

const termsEn: LegalDocument = {
  title: 'Terms of use',
  summary: 'One link, one read. The rules and limits of the service.',
  updated: '2026-10-05',
  sections: [
    {
      heading: 'The service',
      blocks: [
        {
          kind: 'p',
          text: 'secrets is operated by Example Operator S.r.l.: [[contact]]. By using it you accept these terms. You can share text up to 50 KiB through a one-time link, with an expiry from one hour to 30 days and an optional password. The control link shows the status and lets you cancel the secret. Your content remains yours. The service is not intended for minors.',
        },
      ],
    },
    {
      heading: 'Your responsibilities',
      blocks: [
        {
          kind: 'list',
          items: [
            'Share only lawful content you are entitled to share, respecting personal data protection requirements.',
            'Keep the links safe and send any password separately. Do not attempt to access other people’s secrets or bypass the service’s protections and limits.',
            'Do not rely on the service for exchanges affecting the safety of people or essential services, or for data with protection requirements incompatible with these limits.',
          ],
        },
      ],
    },
    {
      heading: 'One read, no recovery',
      blocks: [
        {
          kind: 'p',
          text: 'Opening the link does not consume the secret. A read request deletes it before delivery: if the response never arrives or decryption fails, you cannot retry and the status shows “read”. The recipient can keep a copy of the text received. If you lose the link or password, we cannot recover them. Expiry and cancellation prevent reading.',
        },
      ],
    },
    {
      heading: 'Security and privacy',
      blocks: [
        {
          kind: 'p',
          text: 'The browser encrypts the text and the key stays in the link. This is not end-to-end encryption verified by an independent review: compromised devices or malicious page changes can expose it. The [[privacy]] describes data processing, proxy and hosting logs, and backup retention.',
        },
      ],
    },
    {
      heading: 'Availability and liability',
      blocks: [
        {
          kind: 'p',
          text: 'The service is provided as is, with no guarantee of continuity or recovery. It may be changed, interrupted or suspended; request limits apply and we may block abuse. To the extent permitted by law, Example Operator S.r.l. is not liable for indirect damage, data loss or lost earnings. Liability that cannot legally be excluded, including for wilful misconduct or gross negligence, and consumer rights remain unaffected.',
        },
      ],
    },
    {
      heading: 'Governing law',
      blocks: [
        {
          kind: 'p',
          text: 'Italian law applies, without prejudice to mandatory protections in the consumer’s country of habitual residence. For questions or problems: [[contact]]. The date above shows the last revision. The echoValue site’s general terms are at [[siteTerms]].',
        },
      ],
    },
  ],
};

const documents: Readonly<Record<LegalDocumentKind, Readonly<Record<Locale, LegalDocument>>>> = {
  privacy: { it: privacyIt, en: privacyEn },
  terms: { it: termsIt, en: termsEn },
};

export function getLegalDocument(kind: LegalDocumentKind, locale: Locale): LegalDocument {
  return documents[kind][locale] ?? documents[kind][DEFAULT_LOCALE];
}
