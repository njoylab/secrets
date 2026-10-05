import { describe, expect, it } from 'vitest';
import { readJsonBody } from '../src/lib/api-guard.ts';

describe('bounded JSON request streams', () => {
  it('cancels an oversized chunked body without reading its tail', async () => {
    let cancelled = false;
    let tailRead = false;
    let chunk = 0;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (chunk++ === 0) controller.enqueue(new TextEncoder().encode('{"a":"'));
        else if (chunk === 2) controller.enqueue(new Uint8Array(32));
        else {
          tailRead = true;
          controller.enqueue(new Uint8Array(1024));
          controller.close();
        }
      },
      cancel() { cancelled = true; },
    }, { highWaterMark: 0 });
    const request = new Request('http://localhost/api/secrets', {
      method: 'POST', body, duplex: 'half',
    } as RequestInit);
    expect(await readJsonBody(request, 16)).toBeNull();
    expect(cancelled).toBe(true);
    expect(tailRead).toBe(false);
  });

  it('decodes multibyte JSON split across chunk boundaries and accepts the exact ceiling', async () => {
    const encoded = new TextEncoder().encode('{"text":"€"}');
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        for (const byte of encoded) controller.enqueue(Uint8Array.of(byte));
        controller.close();
      },
    });
    const request = new Request('http://localhost/api/secrets', {
      method: 'POST', body, duplex: 'half',
    } as RequestInit);
    expect(await readJsonBody(request, encoded.byteLength)).toEqual({ text: '€' });
  });
});
