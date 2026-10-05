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
 */
export const OPERATOR = {
  name: 'Example Operator S.r.l.',
  /** VAT identification number. */
  vatId: 'IT00000000000',
  contactEmail: 'privacy@example.com',
  /** General documents of the main site, which cover the site rather than this tool. */
  sitePrivacyUrl: 'https://example.com/privacy',
  siteTermsUrl: 'https://example.com/terms',
} as const;

export type LegalLinkKey = 'privacy' | 'terms' | 'sitePrivacy' | 'siteTerms' | 'contact';

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
};

/** English wording of the two in-app tokens, which are the only ones translated. */
const LINK_LABELS_EN: Readonly<Partial<Record<LegalLinkKey, string>>> = {
  privacy: 'privacy policy',
  terms: 'terms of use',
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
  summary:
    'Nessun account e nessun tracciamento: il segreto viene cifrato nel tuo browser, sul server resta solo in forma cifrata e viene cancellato alla prima lettura.',
  updated: '2026-10-05',
  sections: [
    {
      heading: 'Titolare del trattamento',
      blocks: [
        {
          kind: 'p',
          text: 'Il titolare è Example Operator S.r.l., P.IVA IT00000000000, contattabile a [[contact]]. L\'informativa riguarda solo questo servizio; per il sito echoValue valgono le informative generali pubblicate su [[sitePrivacy]] e le condizioni generali su [[siteTerms]].',
        },
      ],
    },
    {
      heading: 'Dati trattati',
      blocks: [
        {
          kind: 'list',
          items: [
            'il segreto, cifrato con AES-256-GCM nel browser e conservato anche in una seconda cifratura sotto una chiave tenuta fuori dal database: il testo in chiaro non arriva mai al server;',
            'le impronte SHA-256 del token di condivisione e del token di controllo, mai i token per esteso;',
            'se è stata impostata una password, un breve controllo cifrato; per i segreti più vecchi un hash scrypt con sale. La password non viene mai inviata al server;',
            'orario di creazione e di scadenza del segreto;',
            'il tuo indirizzo IP, usato solo come soggetto dei contatori che limitano la creazione e i tentativi di lettura, conservato in chiaro per la durata della finestra di conteggio;',
            'una ricevuta che registra solo l\'evento e l\'orario con cui il segreto è stato letto, scaduto o annullato, così il link di controllo continua a rispondere;',
            'un cookie che memorizza la sola lingua scelta, per un anno.',
          ],
        },
      ],
    },
    {
      heading: 'Base giuridica',
      blocks: [
        {
          kind: 'p',
          text: 'I dati tecnici sopra elencati sono trattati sulla base del legittimo interesse del titolare (art. 6, comma 1, lettera f del Regolamento UE 2016/679): erogare il servizio e proteggerlo da abusi. Non trattiamo dati per finalità di marketing, non usiamo profilazione né decisioni automatizzate. I dati personali che includi in un segreto restano sotto tuo controllo: ne sei il titolare del trattamento, come mittente.',
        },
      ],
    },
    {
      heading: 'Protezione del contenuto',
      blocks: [
        {
          kind: 'p',
          text: 'La chiave che apre il segreto è generata nel browser e resta nel frammento del link, dopo il #. Non viene inviata al server, quindi non compare in alcuna richiesta, intestazione, log o riga del database. Chi possiede il link può leggere il segreto, salvo che sia stata impostata una password.',
        },
        {
          kind: 'p',
          text: 'Questa è cifratura lato client, non cifratura end-to-end verificata da una revisione indipendente: un operatore che sostituisse il codice della pagina potrebbe leggere i segreti, e un dispositivo compromesso può farlo senza che nulla cambi lato server. Non usare il servizio per dati sottoposti a particolari obblighi di protezione.',
        },
      ],
    },
    {
      heading: 'Tempi di conservazione',
      blocks: [
        {
          kind: 'list',
          items: [
            'il segreto: fino alla prima lettura, all\'annullamento o alla scadenza scelta, comunque al più trenta giorni;',
            'la ricevuta: sette giorni dopo la scadenza o la chiusura, poi viene rimossa;',
            'i contatori di rate limit: per la durata della finestra di conteggio, un\'ora nella configurazione prevista;',
            'il cookie della lingua: un anno.',
          ],
        },
        {
          kind: 'p',
          text: 'La cancellazione di una riga la rimuove dal database ma non dai registri WAL né dalle copie di backup già eseguite: la cancellazione dai backup dipende dalla politica del titolare e non può essere garantita dall\'applicazione. Non è quindi possibile confermare che un segreto cancellato non esista più in un backup cifrato.',
        },
      ],
    },
    {
      heading: 'Log, cookie e terzi',
      blocks: [
        {
          kind: 'p',
          text: 'L\'applicazione non scrive log di accesso e non registra contenuti, password, token o corpi delle richieste. Dietro di essa un reverse proxy e un\'infrastruttura di hosting possono registrare indirizzo IP, data e ora, percorso richiesto e user agent, secondo la propria politica di conservazione: quei log non contengono il contenuto dei segreti. L\'unico cookie impostato è quello della lingua. I dati possono essere trattati dai fornitori di infrastruttura del titolare (hosting, database, TLS, posta elettrica), che non ricevono mai segreti in chiaro né li usano per finalità pubblicitarie. Se un fornitore tratta dati fuori dallo Spazio economico europeo, valgono le garanzie del capitolo V del Regolamento.',
        },
      ],
    },
    {
      heading: 'I tuoi diritti',
      blocks: [
        {
          kind: 'p',
          text: 'Puoi chiedere accesso, rettifica, cancellazione, limitazione, portabilità e opposizione, e proporre reclamo all\'autorità di controllo: in Italia il Garante per la protezione dei dati personali, altrove l\'autorità del tuo Paese di residenza. Scrivi a [[contact]] indicando, se possibile, il token del link interessato. Sul contenuto dei segreti le risposte sono necessariamente limitate, perché è cifrato con una chiave che il server non possiede ed è già stato cancellato nella maggior parte dei casi.',
        },
      ],
    },
    {
      heading: 'Modifiche',
      blocks: [
        {
          kind: 'p',
          text: 'La versione in vigore è questa pagina, con la data di aggiornamento in alto. Il titolare può aggiornarla e, se una modifica riduce i tuoi diritti, la comunica prima che diventi efficace. Il servizio è disciplinato dalle [[terms]] e non è destinato a minori.',
        },
      ],
    },
  ],
};

const privacyEn: LegalDocument = {
  title: 'Privacy policy',
  summary:
    'No accounts and no tracking: the secret is encrypted in your browser, the server keeps only the encrypted form, and it is deleted at the first read.',
  updated: '2026-10-05',
  sections: [
    {
      heading: 'Data controller',
      blocks: [
        {
          kind: 'p',
          text: 'The controller is Example Operator S.r.l., VAT IT00000000000, reachable at [[contact]]. This notice covers this service only; for the echoValue site the general notices on [[sitePrivacy]] and the general terms on [[siteTerms]] apply.',
        },
      ],
    },
    {
      heading: 'Data we process',
      blocks: [
        {
          kind: 'list',
          items: [
            'the secret, encrypted with AES-256-GCM in your browser and then kept under a second layer whose key is held outside the database: the plaintext never reaches the server;',
            'the SHA-256 fingerprints of the share token and of the control token, never the tokens themselves;',
            'if a password is set, a short sealed check; for older secrets a salted scrypt hash. The password never reaches the server;',
            'the creation and expiry times of the secret;',
            'your IP address, used only as the subject of the counters that limit creation and read attempts, kept in cleartext for the length of the counting window;',
            'a receipt recording only the event and time a secret was read, expired or cancelled, so the control link keeps answering;',
            'a cookie storing the language you chose, for one year.',
          ],
        },
      ],
    },
    {
      heading: 'Legal basis',
      blocks: [
        {
          kind: 'p',
          text: 'The technical data above is processed on the controller\'s legitimate interest (Article 6(1)(f) of Regulation (EU) 2016/679): to run the service and protect it from abuse. We do not process data for marketing, and we use no profiling or automated decision-making. Any personal data you include in a secret stays under your control: as the sender you are the data controller for it.',
        },
      ],
    },
    {
      heading: 'How the content is protected',
      blocks: [
        {
          kind: 'p',
          text: 'The key that opens a secret is generated in the browser and stays in the fragment of the link, after the #. It is never sent to the server, so it appears in no request, header, log or database row. Whoever holds the link can read the secret unless a password is set.',
        },
        {
          kind: 'p',
          text: 'This is client-side encryption, not end-to-end encryption verified by an independent review: an operator who replaced the page code could read the secrets, and a compromised device can do so with nothing changing on the server. Do not use the service for data subject to specific protection obligations.',
        },
      ],
    },
    {
      heading: 'Retention',
      blocks: [
        {
          kind: 'list',
          items: [
            'the secret: until the first read, a cancellation or the chosen expiry, and at most thirty days;',
            'the receipt: seven days after the expiry or the closing, then removed;',
            'the rate limit counters: for the length of the counting window, one hour in the intended configuration;',
            'the language cookie: one year.',
          ],
        },
        {
          kind: 'p',
          text: 'Deleting a row removes it from the database but not from the write-ahead log or from base backups already taken: removal from backups depends on the controller\'s policy and cannot be guaranteed by the application. We therefore cannot confirm that a deleted secret no longer exists inside an encrypted backup.',
        },
      ],
    },
    {
      heading: 'Logs, cookies and third parties',
      blocks: [
        {
          kind: 'p',
          text: 'The application writes no access log and records no content, password, token or request body. A reverse proxy and a hosting stack sit in front of it and may log IP addresses, dates and times, requested paths and user agents under their own retention policy: those logs contain no secret content. The only cookie set is the language one. Data may be processed by the controller\'s infrastructure providers (hosting, database, TLS, e-mail), which never receive secrets in cleartext and never use them for advertising. Where a provider processes data outside the European Economic Area, the safeguards of Chapter V of the Regulation apply.',
        },
      ],
    },
    {
      heading: 'Your rights',
      blocks: [
        {
          kind: 'p',
          text: 'You can ask for access, rectification, erasure, restriction, portability and objection, and you can complain to the supervisory authority: in Italy the Garante per la protezione dei dati personali, elsewhere the authority in your country of residence. Write to [[contact]], ideally quoting the token of the link. Answers about secret content are necessarily limited, because it is encrypted with a key the server does not hold and has in most cases already been deleted.',
        },
      ],
    },
    {
      heading: 'Changes',
      blocks: [
        {
          kind: 'p',
          text: 'The version in force is this page, with the date of the last revision above. The controller may update it and, if a change reduces your rights, announces it before it takes effect. The service is governed by the [[terms]] and is not intended for minors.',
        },
      ],
    },
  ],
};

const termsIt: LegalDocument = {
  title: 'Condizioni d\'uso',
  summary:
    'Le regole essenziali: uso lecito, responsabilità di chi condivide, una sola lettura senza ripristino, disponibilità senza garanzie e legge applicabile.',
  updated: '2026-10-05',
  sections: [
    {
      heading: 'Accettazione e titolare',
      blocks: [
        {
          kind: 'p',
          text: 'Queste condizioni regolano l\'uso del servizio pubblicato da Example Operator S.r.l., P.IVA IT00000000000, raggiungibile a [[contact]]. Usando il servizio le accetti, insieme alla [[privacy]]. Per il sito echoValue valgono le condizioni generali su [[siteTerms]].',
        },
      ],
    },
    {
      heading: 'Il servizio',
      blocks: [
        {
          kind: 'p',
          text: 'Il servizio trasforma un testo in un link monouso, con scadenza da un\'ora a trenta giorni e password opzionale. Il mittente riceve anche un link di controllo che indica lo stato del segreto e può annullarlo. Non è un archivio, un backup né un sistema di messaggistica. I contenuti che condividi restano tuoi: il titolare li conserva solo cifrati, per il tempo tecnico necessario alla consegna e alla cancellazione.',
        },
      ],
    },
    {
      heading: 'Uso consentito',
      blocks: [
        {
          kind: 'list',
          items: [
            'condividi solo contenuti di cui sei proprietario o di cui hai il diritto di condividere, e per cui hai una base giuridica quando contengono dati personali;',
            'non condividere contenuti illeciti o che ledono diritti altrui;',
            'non tentare di leggere segreti altrui, di aggirare una password o di ricostruire un link non destinato a te;',
            'non aggirare i limiti di frequenza né falsificare il tuo indirizzo IP;',
            'non usare il servizio per scambi di cui dipenda la sicurezza di una persona o di un servizio essenziale.',
          ],
        },
        {
          kind: 'p',
          text: 'Il titolare può limitare o sospendere un link o un indirizzo IP quando serve ad adempiere ad obblighi di legge, a difendere il servizio da abusi o a far valere queste condizioni.',
        },
      ],
    },
    {
      heading: 'Una sola lettura, nessun ripristino',
      blocks: [
        {
          kind: 'p',
          text: 'Un segreto viene cancellato prima che il contenuto ti venga consegnato. Se la cancellazione va a buon fine ma la risposta non arriva, se il collegamento si interrompe o se perdi il link, il contenuto è perso per sempre: non esistono copie, storici o recupero, e il link di controllo indicherà correttamente che è stato letto. Prima di affidare al servizio qualcosa che non puoi permetterti di perdere, valuta una copia sicura altrove.',
        },
      ],
    },
    {
      heading: 'Disponibilità',
      blocks: [
        {
          kind: 'p',
          text: 'Il servizio è fornito «così com\'è» e «come disponibile», senza garanzia di continuità e senza livello di servizio. Applica limiti di frequenza. Può essere modificato, sospeso o discontinuato con o senza preavviso, e può interrompersi per manutenzioni, guasti o problemi di rete. Non dipenderne per conservare dati, per trasmettere informazioni che non si possono perdere o per rispettare scadenze imperative.',
        },
      ],
    },
    {
      heading: 'Sicurezza e responsabilità',
      blocks: [
        {
          kind: 'p',
          text: 'Il contenuto è cifrato nel browser con AES-256-GCM e la chiave resta nel frammento del link: è un aiuto reale, ma non è una garanzia e non è una cifratura end-to-end verificata da una revisione indipendente. L\'applicazione non registra contenuti, password, token o corpi delle richieste, ma proxy e hosting possono registrare indirizzo IP, data e ora, percorso richiesto e user agent. Non usare il servizio per dati sottoposti a particolari obblighi di protezione.',
        },
        {
          kind: 'p',
          text: 'Nei limiti consentiti dalla legge il titolare non è responsabile di danni indiretti, di perdita di dati, di mancato guadagno o di indisponibilità del servizio, né della perdita definitiva di un segreto. Nulla limita le responsabilità che non possono essere limitate dalla legge, incluse quelle relative ai contratti di consumo, ai diritti dei consumatori e al dolo o alla colpa grave.',
        },
      ],
    },
    {
      heading: 'Legge applicabile e contatti',
      blocks: [
        {
          kind: 'p',
          text: 'Queste condizioni sono regolate dalla legge italiana, ferme restando le tutele imperative previste dalla legge del Paese di residenza abituale del consumatore. Prima di rivolgerti a un organo giurisdizionale puoi scrivere a [[contact]]. Per qualsiasi domanda: Example Operator S.r.l., P.IVA IT00000000000. La versione in vigore è questa pagina, con la data di aggiornamento in alto.',
        },
      ],
    },
  ],
};

const termsEn: LegalDocument = {
  title: 'Terms of use',
  summary:
    'The essentials: lawful use, the sender\'s responsibilities, one read with no recovery, availability without warranties, and governing law.',
  updated: '2026-10-05',
  sections: [
    {
      heading: 'Acceptance and operator',
      blocks: [
        {
          kind: 'p',
          text: 'These terms govern the use of the service published by Example Operator S.r.l., VAT IT00000000000, reachable at [[contact]]. By using the service you accept them together with the [[privacy]]. For the echoValue site the general terms on [[siteTerms]] apply.',
        },
      ],
    },
    {
      heading: 'The service',
      blocks: [
        {
          kind: 'p',
          text: 'The service turns a text into a one-time link, with an expiry from one hour to thirty days and an optional password. The sender also receives a control link that reports the state of the secret and can cancel it. It is not an archive, a backup or a messaging system. The content you share remains yours: the operator keeps it encrypted, only for as long as delivery and deletion require.',
        },
      ],
    },
    {
      heading: 'Acceptable use',
      blocks: [
        {
          kind: 'list',
          items: [
            'share only content you own or are entitled to share, and for which you have a legal basis when it contains personal data;',
            'do not share unlawful content or content that infringes the rights of others;',
            'do not attempt to read other people\'s secrets, bypass a password or reconstruct a link that was not meant for you;',
            'do not circumvent the rate limits or spoof your IP address;',
            'do not use the service for exchanges on which the safety of a person or of an essential service depends.',
          ],
        },
        {
          kind: 'p',
          text: 'The operator may limit or suspend a link or an IP address whenever that is needed to meet a legal obligation, to defend the service from abuse, or to enforce these terms.',
        },
      ],
    },
    {
      heading: 'One read, no recovery',
      blocks: [
        {
          kind: 'p',
          text: 'A secret is deleted before its content is handed over to you. If the deletion succeeds but the response never arrives, if the connection breaks or if you lose the link, the content is gone for good: there are no copies, no history and no retrieval, and the control link will correctly report it as read. Before handing the service something you cannot afford to lose, keep a safe copy elsewhere.',
        },
      ],
    },
    {
      heading: 'Availability',
      blocks: [
        {
          kind: 'p',
          text: 'The service is provided "as is" and "as available", with no guarantee of continuity and no service level. Rate limits apply. It may be modified, suspended or discontinued with or without notice, and it may stop because of maintenance, failures or network problems. Do not rely on it to keep data, to convey information that cannot be lost or to meet a mandatory deadline.',
        },
      ],
    },
    {
      heading: 'Security and liability',
      blocks: [
        {
          kind: 'p',
          text: 'Content is encrypted in the browser with AES-256-GCM and the key stays in the fragment of the link: a real help, but not a guarantee and not end-to-end encryption verified by an independent review. The application records no content, password, token or request body, but a proxy and the hosting stack may log IP addresses, dates and times, requested paths and user agents. Do not use the service for data subject to specific protection obligations.',
        },
        {
          kind: 'p',
          text: 'To the extent permitted by law the operator is not liable for indirect damage, for loss of data, for lost earnings or for the service being unavailable, nor for the definitive loss of a secret. Nothing limits any liability that cannot lawfully be limited, including liability under consumer contracts, statutory consumer rights, and wilful misconduct or gross negligence.',
        },
      ],
    },
    {
      heading: 'Governing law and contact',
      blocks: [
        {
          kind: 'p',
          text: 'These terms are governed by Italian law, without prejudice to the mandatory protections of the law of the consumer\'s habitual residence. Before turning to a court you can write to [[contact]]. For any question: Example Operator S.r.l., VAT IT00000000000. The version in force is this page, with the date of the last revision above.',
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
