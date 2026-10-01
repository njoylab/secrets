/**
 * Type surface of the plain ESM address module, so TypeScript callers get the
 * same signature without the build step that `server.mjs` cannot have.
 */
export declare function normalizeAddress(value: string | undefined | null): string;
