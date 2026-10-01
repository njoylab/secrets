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
/** Cancellation is as expensive to abuse as a reveal attempt, so it shares its budget. */
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

/** Best-effort probe used on GET pages, where the user still needs a usable form. */
export async function peekRateLimit(
  bucket: string,
  subject: string,
  rule: RateLimitRule,
): Promise<RateLimitResult> {
  const { rows } = await query<RateLimitRow>(
    `SELECT hits,
            GREATEST(0, EXTRACT(EPOCH FROM (rate_limits.window_started_at + make_interval(secs => $3::double precision) - now())))::int AS retry_after
       FROM rate_limits
      WHERE bucket = $1 AND subject = $2`,
    [bucket, subject, rule.windowSeconds],
  );

  const row = rows[0];
  if (!row) return { allowed: true, remaining: rule.max, retryAfterSeconds: rule.windowSeconds };
  return {
    allowed: row.hits < rule.max,
    remaining: Math.max(0, rule.max - row.hits),
    retryAfterSeconds: row.retry_after ?? rule.windowSeconds,
  };
}