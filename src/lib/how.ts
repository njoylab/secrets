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
  updated: '2026-10-14',
  sections: [
    {
      heading: '1. Creazione',
      blocks: [
        {
          kind: 'p',
          text: 'Il browser genera una chiave casuale e cifra il testo con AES-256-GCM prima di inviarlo. Al server arrivano solo il testo cifrato e la scadenza scelta: 1 ora, 1 giorno, 7 giorni o 30 giorni. Limite: 50 KiB.',
        },
        {
          kind: 'p',
          text: 'La chiave è nel link, dopo #. I browser non inviano quella parte al server, che quindi non può decifrare il testo.',
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
            'Link di controllo: tienilo tu. Mostra lo stato (in attesa, letto, scaduto, annullato) e permette di annullare il segreto finché nessuno lo ha letto. Non permette di leggerlo.',
          ],
        },
      ],
    },
    {
      heading: '3. Password opzionale',
      blocks: [
        {
          kind: 'p',
          text: 'La password viene combinata con la chiave del link nel browser. Non viene inviata né salvata: senza password il link da solo non basta. Inviala su un canale diverso dal link.',
        },
        {
          kind: 'p',
          text: 'Una password errata non consuma il segreto. I tentativi sono limitati per indirizzo IP e possono avvenire solo tramite il servizio.',
        },
      ],
    },
    {
      heading: '4. Lettura',
      blocks: [
        {
          kind: 'p',
          text: 'Aprire il link non consuma nulla: anteprime di chat e prefetch sono innocui. Il segreto viene consumato solo quando il destinatario preme «Mostra segreto». Il server lo cancella e poi consegna il testo cifrato, che il browser decifra.',
        },
        {
          kind: 'p',
          text: 'Una sola lettura, nessun recupero. Se la risposta si perde dopo la cancellazione, il segreto non è più leggibile e il link di controllo indica «letto». Se il destinatario trova il link già non disponibile, qualcun altro potrebbe averlo aperto prima.',
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
            "Gli hash dei due link e un'impronta di verifica: nulla da cui ricavare la chiave o la password.",
            'Dopo lettura, scadenza o annullamento, solo una ricevuta con stato e orari, senza contenuto. Resta fino alla scadenza originale e almeno 7 giorni dopo la chiusura.',
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
            'La cancellazione non rimuove subito i dati da log di transazione e backup del database, che restano comunque cifrati.',
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
  updated: '2026-10-14',
  sections: [
    {
      heading: '1. Creation',
      blocks: [
        {
          kind: 'p',
          text: 'Your browser generates a random key and encrypts the text with AES-256-GCM before sending it. The server receives only the ciphertext and the chosen expiry: 1 hour, 1 day, 7 days or 30 days. Limit: 50 KiB.',
        },
        {
          kind: 'p',
          text: 'The key is in the link, after #. Browsers never send that part to the server, so the server cannot decrypt the text.',
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
            'Control link: keep it. It shows the state (pending, read, expired, cancelled) and lets you cancel the secret until someone reads it. It cannot read the secret.',
          ],
        },
      ],
    },
    {
      heading: '3. Optional password',
      blocks: [
        {
          kind: 'p',
          text: 'The password is combined with the link key in the browser. It is never sent or stored: without it, the link alone is not enough. Send it over a different channel than the link.',
        },
        {
          kind: 'p',
          text: 'A wrong password does not consume the secret. Attempts are rate limited per IP address and can only be made through the service.',
        },
      ],
    },
    {
      heading: '4. Reading',
      blocks: [
        {
          kind: 'p',
          text: 'Opening the link consumes nothing: chat previews and prefetching are harmless. The secret is consumed only when the recipient presses “Reveal secret”. The server deletes it, then returns the ciphertext, which the browser decrypts.',
        },
        {
          kind: 'p',
          text: 'One read, no recovery. If the response is lost after the deletion, the secret can no longer be read and the control link shows “read”. If the recipient finds the link already unavailable, someone else may have opened it first.',
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
            'Hashes of both links and a verification fingerprint: nothing that yields the key or the password.',
            'After a read, expiry or cancellation, only a receipt with the state and times, without content. It is kept until the original expiry and for at least 7 days after closing.',
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
            'Deletion does not immediately remove data from database transaction logs and backups, where it stays encrypted.',
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
