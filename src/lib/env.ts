/**
 * Environment configuration, parsed lazily so tests can mutate `process.env`
 * before the first request without relying on module load order.
 */
import { Buffer } from 'node:buffer';
import { randomBytes } from 'node:crypto';

export interface RateLimitRule {
  readonly max: number;
  readonly windowSeconds: number;
}

export interface AppConfig {
  readonly databaseUrl: string;
  readonly encryptionKey: Buffer;
  /** Proxy addresses allowed to supply forwarding headers. Empty means "trust nobody". */
  readonly trustedProxies: readonly string[];
  /** Extra origins accepted for same-origin POSTs. Empty means "accept the request's own origin only". */
  readonly allowedOrigins: readonly string[];
  readonly createRateLimit: RateLimitRule;
  readonly revealRateLimit: RateLimitRule;
  readonly secureCookies: boolean;
  /** Public repository linked from the footer. Empty means "show no link". */
  readonly sourceUrl: string;
}

export class ConfigError extends Error {}

const ENCRYPTION_KEY_BYTES = 32;

function readPositiveInt(raw: string | undefined, fallback: number): number {
  if (raw === undefined || raw.trim() === '') return fallback;
  if (!/^\d+$/.test(raw.trim())) throw new ConfigError('Expected a positive integer');
  const parsed = Number(raw.trim());
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new ConfigError('Expected a positive integer');
  }
  return parsed;
}

function readBoolean(raw: string | undefined, fallback: boolean): boolean {
  if (raw === undefined || raw.trim() === '') return fallback;
  const normalized = raw.trim().toLowerCase();
  if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
  throw new ConfigError(`Expected a boolean, received "${raw}"`);
}

function readList(raw: string | undefined): readonly string[] {
  if (raw === undefined || raw.trim() === '') return [];
  return raw
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

/**
 * The footer link, validated because it is rendered as an href: only an absolute
 * HTTPS URL with no credentials, so a misconfiguration cannot emit a
 * `javascript:` or `data:` URL into every page.
 */
function readSourceUrl(raw: string | undefined): string {
  if (raw === undefined || raw.trim() === '') return '';
  let parsed: URL;
  try {
    parsed = new URL(raw.trim());
  } catch {
    throw new ConfigError('SOURCE_URL must be an absolute URL');
  }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password) {
    throw new ConfigError('SOURCE_URL must be an HTTPS URL without credentials');
  }
  return parsed.toString();
}

function parseEncryptionKey(raw: string | undefined): Buffer {
  if (raw === undefined || raw.trim() === '') {
    throw new ConfigError('SECRET_ENCRYPTION_KEY is required (32 random bytes, base64url)');
  }
  let key: Buffer;
  try {
    key = Buffer.from(raw.trim(), 'base64url');
  } catch {
    throw new ConfigError('SECRET_ENCRYPTION_KEY must be valid base64url');
  }
  if (key.byteLength !== ENCRYPTION_KEY_BYTES) {
    throw new ConfigError(
      `SECRET_ENCRYPTION_KEY must decode to ${ENCRYPTION_KEY_BYTES} bytes, got ${key.byteLength}`,
    );
  }
  if (key.toString('base64url') !== raw.trim()) {
    throw new ConfigError('SECRET_ENCRYPTION_KEY must be canonical base64url');
  }
  return key;
}

let cached: AppConfig | undefined;

export function getConfig(): AppConfig {
  if (cached) return cached;

  const databaseUrl = process.env.DATABASE_URL?.trim();
  if (!databaseUrl) throw new ConfigError('DATABASE_URL is required');

  const secureCookies =
    process.env.COOKIE_SECURE !== undefined
      ? readBoolean(process.env.COOKIE_SECURE, true)
      : process.env.NODE_ENV === 'production';

  cached = {
    databaseUrl,
    encryptionKey: parseEncryptionKey(process.env.SECRET_ENCRYPTION_KEY),
    trustedProxies: readList(process.env.TRUSTED_PROXIES),
    allowedOrigins: readList(process.env.ALLOWED_ORIGINS),
    createRateLimit: {
      max: readPositiveInt(process.env.RATE_LIMIT_CREATE_MAX, 20),
      windowSeconds: readPositiveInt(process.env.RATE_LIMIT_CREATE_WINDOW_SECONDS, 3600),
    },
    revealRateLimit: {
      max: readPositiveInt(process.env.RATE_LIMIT_REVEAL_MAX, 30),
      windowSeconds: readPositiveInt(process.env.RATE_LIMIT_REVEAL_WINDOW_SECONDS, 300),
    },
    secureCookies,
    sourceUrl: readSourceUrl(process.env.SOURCE_URL),
  };
  return cached;
}

/** Test helper: drop the memoized configuration. */
export function resetConfigCache(): void {
  cached = undefined;
}

/** Generate a fresh base64url encoded 256-bit encryption key. */
export function generateEncryptionKey(): string {
  return randomBytes(ENCRYPTION_KEY_BYTES).toString('base64url');
}
