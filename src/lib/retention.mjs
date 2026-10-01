/**
 * Retention of the rate limit counters, shared between the maintenance script
 * and the test suite.
 *
 * Plain ESM JavaScript on purpose: `scripts/cleanup.mjs` is a Node script and
 * cannot import TypeScript. Keeping the calculation here means the effective
 * retention can be proven without connecting to a database or running the
 * script.
 *
 * The defaults mirror `src/lib/env.ts`, which applies the same three values to
 * the running application.
 */

export const DEFAULT_CLEANUP_KEEP_COUNTER_SECONDS = 3600;
export const DEFAULT_RATE_LIMIT_CREATE_WINDOW_SECONDS = 3600;
export const DEFAULT_RATE_LIMIT_REVEAL_WINDOW_SECONDS = 300;

/**
 * Parse a seconds value, or return `undefined` when it is absent or unusable.
 *
 * Strict on purpose: only a run of digits is accepted, so a value such as
 * `100foo` is rejected rather than silently read as `100`. The caller decides
 * whether that is a hard failure or a fallback to the default.
 *
 * @param {string | undefined} raw
 * @returns {number | undefined}
 */
export function parseSeconds(raw) {
  if (raw === undefined || raw === null) return undefined;
  const text = String(raw).trim();
  if (!/^\d+$/.test(text)) return undefined;
  const parsed = Number(text);
  if (!Number.isSafeInteger(parsed)) return undefined;
  return parsed;
}

/** A blank or unusable value falls back to the default instead of failing here. */
function readSeconds(raw, fallback) {
  const parsed = parseSeconds(raw);
  return parsed === undefined ? fallback : parsed;
}

/**
 * A counter is identified by the start of its window, so deleting a row whose
 * window is still open would reset that subject's budget. The configured
 * retention is therefore a floor: it is raised to the longest rate limit window,
 * and the caller reports the difference so the configuration can be corrected.
 *
 * @param {Record<string, string | undefined>} [env]
 * @returns {{ configuredSeconds: number, effectiveSeconds: number }}
 */
export function counterRetention(env = process.env) {
  const configuredSeconds = readSeconds(env.CLEANUP_KEEP_COUNTER_SECONDS, DEFAULT_CLEANUP_KEEP_COUNTER_SECONDS);
  const createWindowSeconds = readSeconds(
    env.RATE_LIMIT_CREATE_WINDOW_SECONDS,
    DEFAULT_RATE_LIMIT_CREATE_WINDOW_SECONDS,
  );
  const revealWindowSeconds = readSeconds(
    env.RATE_LIMIT_REVEAL_WINDOW_SECONDS,
    DEFAULT_RATE_LIMIT_REVEAL_WINDOW_SECONDS,
  );
  return {
    configuredSeconds,
    effectiveSeconds: Math.max(configuredSeconds, createWindowSeconds, revealWindowSeconds),
  };
}
