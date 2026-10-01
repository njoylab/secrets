/**
 * Type surface of the plain ESM retention module, so TypeScript callers get the
 * same signature without a build step.
 */
export declare const DEFAULT_CLEANUP_KEEP_COUNTER_SECONDS: number;
export declare const DEFAULT_RATE_LIMIT_CREATE_WINDOW_SECONDS: number;
export declare const DEFAULT_RATE_LIMIT_REVEAL_WINDOW_SECONDS: number;

export interface CounterRetention {
  /** Value of CLEANUP_KEEP_COUNTER_SECONDS, or its default. */
  readonly configuredSeconds: number;
  /** Longest window the script must not cut short, never below the configured value. */
  readonly effectiveSeconds: number;
}

/** The value as a non-negative safe integer, or `undefined` when absent or unusable. */
export declare function parseSeconds(raw: string | undefined): number | undefined;

export declare function counterRetention(
  env?: Record<string, string | undefined>,
): CounterRetention;
