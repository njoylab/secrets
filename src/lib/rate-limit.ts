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

interface RateLimitRow {
  hits: number;
}

interface RateLimitPeekRow extends RateLimitRow {
  retry_after: number | null;
}

export interface RateLimitResult {
  readonly allowed: boolean;
  readonly remaining: number;
  readonly retryAfterSeconds: number;
}

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
                    ELSE rate_limits.hits + 1
                  END,
           window_started_at = CASE
                    WHEN rate_limits.window_started_at <= now() - make_interval(secs => $3::double precision)
                    THEN now()
                    ELSE rate_limits.window_started_at
                  END
     RETURNING hits`,
    [bucket, subject, rule.windowSeconds],
  );

  const hits = rows[0]?.hits ?? 1;
  return {
    allowed: hits <= rule.max,
    remaining: Math.max(0, rule.max - hits),
    retryAfterSeconds: rule.windowSeconds,
  };
}

/** Best-effort probe used on GET pages, where the user still needs a usable form. */
export async function peekRateLimit(
  bucket: string,
  subject: string,
  rule: RateLimitRule,
): Promise<RateLimitResult> {
  const { rows } = await query<RateLimitPeekRow>(
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