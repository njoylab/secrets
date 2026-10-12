# QR code and control timestamps

These features expose only information already available through the links.

**The QR code** of the share link is drawn by `src/lib/qr.ts`, a byte-mode
encoder written for this project: Reed-Solomon over GF(256), block interleaving,
the eight data masks with the four penalty rules, and the BCH format and version
information. It runs in the browser on a `<canvas>` and draws runs of dark
modules, so no image request, data URL or third-party script is involved and no
asset reaches the page from anywhere but this origin.

The encoder is deliberately narrow: byte mode only, no ECI, no kanji, no Micro
QR. It exists to render one short ASCII link, and everything else is left out
rather than half implemented. Because a silent bug here produces a code no
scanner can read, `tests/qr.test.ts` verifies it by decoding its own output back
(format information, unmask, zigzag walk, de-interleave, then a Reed-Solomon
syndrome check per block) and cross-checks the resulting codewords against
`qrcode-generator`, pinned as a **dev** dependency for that purpose only. It is
never imported by `src/` and never reaches the bundle. The one thing the two
implementations are allowed to disagree on is which mask they pick, since the
reference library scores masks with a non-standard penalty function.

The code encodes the full share link including the key in its fragment, so it is
drawn only once the link exists and the canvas is cleared when the result panel
is reset, rather than left holding key material behind a hidden element.

**The control link instants** come from columns that already existed:
`secrets.created_at` and `secret_receipts.closed_at`. No migration was needed.
A pending secret shows when it was created and when it expires; once it closes,
the row is gone, so the creation instant disappears and the closing instant takes
its place. The cancel endpoint returns the instants alongside the new state so
the page repaints in place instead of waiting for a reload. These are instants
and nothing else: `tests/secrets.test.ts` enumerates the fields a control link
may return and fails if anything else appears.
