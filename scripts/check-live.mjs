/** Read-only deployment checks. Never visit share or control URLs. */
const monitorOrigin = process.env.MONITOR_ORIGIN;
if (!monitorOrigin) throw new Error('MONITOR_ORIGIN is required: set it to the HTTPS origin to verify');
const origin = new URL(monitorOrigin);
if (origin.protocol !== 'https:' || origin.pathname !== '/' || origin.search || origin.hash ||
    origin.username || origin.password) {
  throw new Error('MONITOR_ORIGIN must be an HTTPS origin');
}

const failures = [];
try {
  const home = await fetch(origin, { redirect: 'manual', signal: AbortSignal.timeout(15_000) });
  if (home.status !== 200) failures.push('homepage');
  if (!home.headers.get('cache-control')?.includes('no-store')) failures.push('cache');
  if (home.headers.get('referrer-policy') !== 'no-referrer') failures.push('referrer');
  if (home.headers.get('x-frame-options') !== 'DENY') failures.push('framing');
  if (!/max-age=[1-9]\d*/.test(home.headers.get('strict-transport-security') ?? '')) failures.push('hsts');
  if (!home.headers.get('content-security-policy')?.includes("frame-ancestors 'none'")) failures.push('csp');
  if (!home.headers.get('x-robots-tag')?.includes('index, follow')) failures.push('indexing');
  await home.body?.cancel();
  const health = await fetch(new URL('/api/health', origin), {
    redirect: 'manual', signal: AbortSignal.timeout(15_000),
  });
  if (health.status !== 200 || (await health.json()).ok !== true) failures.push('readiness');
  if (!health.headers.get('x-robots-tag')?.includes('noindex')) failures.push('api-indexing');
} catch {
  failures.push('connection-or-response');
}
const result = { event: 'deployment_check', ok: failures.length === 0, failures };
process.stdout.write(`${JSON.stringify(result)}\n`);
if (failures.length > 0) process.exitCode = 1;
