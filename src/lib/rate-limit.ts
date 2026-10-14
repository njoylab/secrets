/**
 * PostgreSQL-backed fixed-window counters.
 *
 * Counters live in the database so limits stay consistent across every server
 * instance without adding Redis. The check and the increment happen in a single
 * statement, so concurrent requests cannot both observe the same count.
 */
import { query } from './db.ts';
import type { RateLimitRule } from './env.ts';

export const CREATE_BUCKET = 'create';
export const REVEAL_BUCKET = 'reveal';
/** Cancel uses the reveal max and window, counted in its own bucket. */
export const CANCEL_BUCKET = 'cancel';

/** Every bucket the application charges against a per-IP budget. */
export type RateLimitBucket = typeof CREATE_BUCKET | typeof REVEAL_BUCKET | typeof CANCEL_BUCKET;

interface RateLimitRow {
  hits: number;
  retry_after: number | null;
}

export interface RateLimitResult {
  readonly allowed: boolean;
  readonly remaining: number;
  readonly retryAfterSeconds: number;
}

/**
 * Take one unit of budget for a subject, in a single statement.
 *
 * Two invariants hold inside that statement:
 * - the counter stops at `max + 1` while the window is open. Capping it at `max`
 *   would be a hole, because `allowed` is `hits <= max` and the subject would
 *   stay allowed for the rest of the window. One request past the cap is enough
 *   to keep the answer "refused" and the row bounded.
 * - the window start is never moved by a refused call, so a flood cannot buy a
 *   fresh window by continuing to try.
 *
 * The returned `retry_after` is what is left of the window, so a refusal can
 * tell the caller when to come back instead of always announcing the full
 * window.
 */
export async function consumeRateLimit(
  bucket: string,
  subject: string,
  rule: RateLimitRule,
): Promise<RateLimitResult> {
  const { rows } = await query<RateLimitRow>(
    `INSERT INTO rate_limits (bucket, subject, window_started_at, hits)
     VALUES ($1, $2, now(), 1)
     ON CONFLICT (bucket, subject) DO UPDATE
       SET hits = CASE
                    WHEN rate_limits.window_started_at <= now() - make_interval(secs => $3::double precision)
                    THEN 1
                    ELSE LEAST(rate_limits.hits + 1, $4::int + 1)
                  END,
            window_started_at = CASE
                    WHEN rate_limits.window_started_at <= now() - make_interval(secs => $3::double precision)
                    THEN now()
                    ELSE rate_limits.window_started_at
                  END
     RETURNING rate_limits.hits,
               GREATEST(0, EXTRACT(EPOCH FROM (rate_limits.window_started_at + make_interval(secs => $3::double precision) - now())))::int AS retry_after`,
    [bucket, subject, rule.windowSeconds, rule.max],
  );

  const row = rows[0];
  const hits = row?.hits ?? 1;
  const allowed = hits <= rule.max;
  return {
    allowed,
    remaining: Math.max(0, rule.max - hits),
    // An allowed call keeps reporting the whole window, as it always did. Only a
    // refusal needs the remainder, and never less than a second.
    retryAfterSeconds: allowed ? rule.windowSeconds : Math.max(1, row?.retry_after ?? rule.windowSeconds),
  };
}

/**
 * The identity a client's budget is charged to.
 *
 * IPv4 addresses are used as they are. An IPv6 address is reduced to its /64:
 * that is the smallest block a provider assigns to one subscriber, and every
 * address inside it is free to the client, so counting full addresses would hand
 * out an unlimited budget. Anything that does not parse, including `unknown`, is
 * returned unchanged. Only the rate limit sees this value.
 */
export function rateLimitSubject(clientIp: string): string {
  const groups = parseIpv6Groups(clientIp);
  if (!groups) return clientIp;
  return `${groups.slice(0, 4).map((group) => group.toString(16)).join(':')}::/64`;
}

/** The eight 16-bit groups of an IPv6 literal, with `::` expanded, or null. */
function parseIpv6Groups(value: string): number[] | null {
  if (!value.includes(':')) return null;
  const halves = value.split('::');
  if (halves.length > 2) return null;

  const toGroups = (part: string): string[] | null => {
    if (part === '') return [];
    const parts = part.split(':');
    // An embedded dotted quad (`64:ff9b::192.0.2.1`) fills the last two groups.
    const last = parts[parts.length - 1] ?? '';
    if (last.includes('.')) {
      const octets = last.split('.');
      if (octets.length !== 4 || octets.some((octet) => !/^\d{1,3}$/.test(octet) || Number(octet) > 255)) {
        return null;
      }
      const [a, b, c, d] = octets.map(Number) as [number, number, number, number];
      parts.splice(-1, 1, ((a << 8) | b).toString(16), ((c << 8) | d).toString(16));
    }
    return parts;
  };

  // A dotted quad is only valid as the final groups of the address.
  if (halves.length === 2 && (halves[0] ?? '').includes('.')) return null;
  const head = toGroups(halves[0] ?? '');
  const tail = halves.length === 2 ? toGroups(halves[1] ?? '') : [];
  if (!head || !tail) return null;

  let groups: string[];
  if (halves.length === 2) {
    const missing = 8 - head.length - tail.length;
    if (missing < 1) return null;
    groups = [...head, ...Array<string>(missing).fill('0'), ...tail];
  } else {
    groups = head;
  }
  if (groups.length !== 8 || !groups.every((group) => /^[0-9a-f]{1,4}$/i.test(group))) return null;
  return groups.map((group) => Number.parseInt(group, 16));
}
