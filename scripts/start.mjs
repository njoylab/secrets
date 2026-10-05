/** Apply forward-compatible migrations before the application accepts traffic. */
try {
  await import('./migrate.mjs');
  await import('../server.mjs');
} catch {
  process.stderr.write('startup failed; check database connectivity and runtime configuration\n');
  process.exitCode = 1;
}
