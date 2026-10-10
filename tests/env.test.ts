/**
 * Configuration parsing, limited to SOURCE_URL.
 *
 * The value is rendered as an href in every page footer, so a bad value would
 * emit an attacker-chosen scheme into the markup of every visitor. Startup has
 * to reject it instead.
 */
import { describe, expect, it } from 'vitest';
import { ConfigError, getConfig, resetConfigCache } from '../src/lib/env.ts';
import { resetEnv } from './setup.ts';

function readSourceUrl(): string | ConfigError {
  resetConfigCache();
  try {
    return getConfig().sourceUrl;
  } catch (error) {
    if (error instanceof ConfigError) return error;
    throw error;
  }
}

describe('SOURCE_URL', () => {
  it('is absent by default, so the footer renders no link', async () => {
    await resetEnv({ SOURCE_URL: undefined });
    expect(readSourceUrl()).toBe('');
    await resetEnv({ SOURCE_URL: '   ' });
    expect(readSourceUrl()).toBe('');
  });

  it('accepts an absolute HTTPS repository URL', async () => {
    await resetEnv({ SOURCE_URL: 'https://github.com/example/secrets' });
    expect(readSourceUrl()).toBe('https://github.com/example/secrets');
  });

  it('rejects anything that is not a plain HTTPS URL', async () => {
    for (const value of [
      'javascript:alert(1)',
      'data:text/html,<script>',
      '/relative/path',
      'github.com/example/secrets',
      'http://github.com/example/secrets',
      'https://user:pass@github.com/example/secrets',
    ]) {
      await resetEnv({ SOURCE_URL: value });
      expect(readSourceUrl(), value).toBeInstanceOf(ConfigError);
    }
  });
});
