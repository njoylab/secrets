/**
 * The "how it works" page, in the two supported languages.
 *
 * It reuses the document shape of `legal.ts` so the same layout renders it,
 * and the same rules apply: every statement must match the code and
 * `docs/security.md`, and the prose never claims audited end-to-end encryption.
 */
import { DEFAULT_LOCALE, type Locale } from './i18n.ts';
import type { LegalDocument } from './legal.ts';

const howIt: LegalDocument = {
  title: 'Come funziona',
  summary: 'Cosa succede a un segreto, dalla creazione alla lettura.',
  updated: '2026-11-06',
  sections: [
    {
      heading: '1. Creazione',
      blocks: [
        {
          kind: 'p',
          text: 'Il browser cifra il testo prima di inviarlo. Il server riceve il testo cifrato, la scadenza scelta, un dato per verificare la richiesta di lettura e l’indicazione che il segreto è protetto da password, se l’hai impostata. Puoi condividere fino a 50 KiB per 1 ora, 1 giorno, 7 giorni o 30 giorni.',
        },
        {
          kind: 'p',
          text: 'Condividi il link completo. La parte dopo # contiene la chiave che serve al browser per decifrare il testo e non viene inviata al server.',
        },
      ],
    },
    {
      heading: '2. Due link',
      blocks: [
        {
          kind: 'list',
          items: [
            'Link monouso: va al destinatario. Permette una sola lettura.',
            'Link di controllo: tienilo per verificare lo stato o annullare il segreto prima che venga letto o scada. Non permette di leggere il testo.',
          ],
        },
      ],
    },
    {
      heading: '3. Password opzionale',
      blocks: [
        {
          kind: 'p',
          text: 'Se imposti una password, per leggere il segreto servono sia il link sia la password. La password resta nel browser. Inviala su un altro canale.',
        },
        {
          kind: 'p',
          text: 'Se sbagli password, puoi riprovare. Il servizio limita il numero di tentativi.',
        },
      ],
    },
    {
      heading: '4. Lettura',
      blocks: [
        {
          kind: 'p',
          text: 'Puoi aprire il link senza usare l’unica lettura. Quando premi «Mostra segreto» e la verifica riesce, il server cancella il segreto prima di inviare il testo cifrato al browser.',
        },
        {
          kind: 'p',
          text: 'Dopo la cancellazione, il link di controllo indica «Link usato». Se il testo non arriva o il browser non riesce a mostrarlo, chiedi al mittente un nuovo link.',
        },
      ],
    },
    {
      heading: '5. Cosa conserva il server',
      blocks: [
        {
          kind: 'list',
          items: [
            'Il testo cifrato dal browser, cifrato una seconda volta con una chiave tenuta fuori dal database.',
            'Le impronte dei due token e un dato di verifica protetto da una chiave del servizio.',
            'Dopo la lettura o l’annullamento resta solo lo stato con le relative date, senza il testo. Alla scadenza il testo diventa subito inaccessibile e viene rimosso dalla pulizia periodica. Lo stato resta fino alla scadenza originale o a 7 giorni dalla chiusura, a seconda di quale data viene dopo.',
          ],
        },
      ],
    },
    {
      heading: '6. Limiti',
      blocks: [
        {
          kind: 'list',
          items: [
            'Non è una cifratura end-to-end verificata da una revisione indipendente: un dispositivo compromesso o una modifica malevola della pagina possono esporre il segreto.',
            'Chiunque abbia il link completo, e la password se impostata, può leggerlo una volta.',
            'Dopo la cancellazione, copie cifrate del testo possono restare nei registri e nei backup del database.',
            'I dettagli sul trattamento dei dati sono nella [[privacy]].',
          ],
        },
      ],
    },
  ],
};

const howEn: LegalDocument = {
  title: 'How it works',
  summary: 'What happens to a secret, from creation to reading.',
  updated: '2026-11-06',
  sections: [
    {
      heading: '1. Creation',
      blocks: [
        {
          kind: 'p',
          text: 'Your browser encrypts the text before sending it. The server receives the encrypted text, the chosen expiry, data to verify the request to read it, and whether you set a password. You can share up to 50 KiB for 1 hour, 1 day, 7 days or 30 days.',
        },
        {
          kind: 'p',
          text: 'Share the full link. The part after # contains the key your browser needs to decrypt the text and is never sent to the server.',
        },
      ],
    },
    {
      heading: '2. Two links',
      blocks: [
        {
          kind: 'list',
          items: [
            'One-time link: send it to the recipient. It allows a single read.',
            'Control link: keep it to check the status or cancel the secret before it is read or expires. It cannot be used to read the text.',
          ],
        },
      ],
    },
    {
      heading: '3. Optional password',
      blocks: [
        {
          kind: 'p',
          text: 'If you set a password, the recipient needs both the link and the password to read the secret. The password stays in the browser. Send it through a different channel.',
        },
        {
          kind: 'p',
          text: 'If you enter the wrong password, you can try again. The service limits the number of attempts.',
        },
      ],
    },
    {
      heading: '4. Reading',
      blocks: [
        {
          kind: 'p',
          text: 'You can open the link without using up the one-time read. When you select “Reveal secret” and verification succeeds, the server deletes the secret before sending the encrypted text to your browser.',
        },
        {
          kind: 'p',
          text: 'After deletion, the control link shows “Link used”. If the text does not arrive or your browser cannot display it, ask the sender for a new link.',
        },
      ],
    },
    {
      heading: '5. What the server keeps',
      blocks: [
        {
          kind: 'list',
          items: [
            'The ciphertext from the browser, encrypted a second time with a key kept outside the database.',
            'Hashes of both tokens and verification data protected by a key held by the service.',
            'After a read or cancellation, only the status and its timestamps remain. On expiry the text immediately becomes inaccessible, and periodic cleanup removes it. The status is kept until the original expiry or 7 days after closure, whichever is later.',
          ],
        },
      ],
    },
    {
      heading: '6. Limits',
      blocks: [
        {
          kind: 'list',
          items: [
            'This is not end-to-end encryption verified by an independent review: a compromised device or a malicious change to the page can expose the secret.',
            'Anyone holding the full link, and the password if set, can read it once.',
            'Encrypted copies of the text can remain in database logs and backups after deletion.',
            'Data processing is described in the [[privacy]].',
          ],
        },
      ],
    },
  ],
};

const documents: Readonly<Record<Locale, LegalDocument>> = { it: howIt, en: howEn };

export function getHowDocument(locale: Locale): LegalDocument {
  return documents[locale] ?? documents[DEFAULT_LOCALE];
}
