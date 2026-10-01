/**
 * Canonical form of a network address.
 *
 * This module is plain ESM JavaScript on purpose: `server.mjs` is the code that
 * decides which peer is a trusted proxy, and a Node entry point cannot import
 * TypeScript. Both sides must agree, because fixing only the TypeScript copy
 * would leave the production bug in place.
 *
 * The canonical form strips presentation noise only. Two addresses are equal
 * when their canonical forms are equal as strings: a shared prefix is never
 * enough, so `10.0.0.1` and `10.0.0.2` stay distinct.
 */

/** Strip IPv6 brackets and, for a bare IPv4 literal, a trailing port. */
function stripBracketsAndPort(value) {
  if (value.startsWith('[')) {
    const end = value.indexOf(']');
    return end === -1 ? value : value.slice(1, end);
  }
  // A single colon means an IPv4 literal with a port; more than one is an IPv6
  // address, where the last group is part of the address itself.
  const parts = value.split(':');
  if (parts.length !== 2) return value;
  const [host, port] = parts;
  // Only a numeric port is stripped. Anything else is left alone so an address
  // that merely looks like `host:something` fails to match rather than matching
  // a different host.
  return port !== undefined && /^\d*$/.test(port) ? (host ?? '') : value;
}

/**
 * Unwrap an IPv4-mapped IPv6 address such as `::ffff:127.0.0.1`.
 *
 * A dual stack listener reports its peers in the mapped form, so the same proxy
 * would appear as two different addresses and never match a plain IPv4 entry in
 * TRUSTED_PROXIES. The prefix is case insensitive; the result is only accepted
 * when the tail really is a dotted quad, otherwise the address is left as it is.
 */
function unwrapIpv4Mapped(value) {
  const match = /^::ffff:(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(value);
  if (!match) return value;
  const octets = match.slice(1).map((octet) => Number.parseInt(octet, 10));
  if (octets.some((octet) => octet > 255)) return value;
  return octets.join('.');
}

/** Canonical text for an address, safe to compare with `===`. */
export function normalizeAddress(value) {
  const trimmed = String(value ?? '')
    .trim()
    .toLowerCase();
  return unwrapIpv4Mapped(stripBracketsAndPort(trimmed));
}
