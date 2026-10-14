/**
 * Type surface of the plain ESM cleanup module, so TypeScript callers get the
 * same signature without a build step.
 */
export declare const RECEIPT_RETENTION_DAYS: number;

export interface Queryable {
  query(text: string, values?: unknown[]): Promise<{ rows: any[] }>;
}

export interface PurgeResult {
  /** Expired secrets deleted. */
  readonly secrets: number;
  /** `expired` receipts written for those secrets. */
  readonly receiptsWritten: number;
  /** Spent receipts deleted. */
  readonly receipts: number;
  /** Idle rate limit counters deleted. */
  readonly counters: number;
}

export declare function purgeExpired(db: Queryable, counterRetentionSeconds: number): Promise<PurgeResult>;
