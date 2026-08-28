const UPSTREAM_OCSP_URL = 'http://www.freetsa.org:2560';
const ALLOWED_ORIGIN = 'https://ikcloudx.github.io';
const MAX_REQUEST_BYTES = 16 * 1024;
const MAX_RESPONSE_BYTES = 256 * 1024;
const UPSTREAM_TIMEOUT_MS = 5_000;

interface RateLimitBinding {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

interface Env {
  OCSP_RATE_LIMITER?: RateLimitBinding;
}

function corsHeaders(origin: string | null): Headers {
  const headers = new Headers({ Vary: 'Origin' });
  if (origin === ALLOWED_ORIGIN) {
    headers.set('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
    headers.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
    headers.set('Access-Control-Allow-Headers', 'Content-Type');
    headers.set('Access-Control-Max-Age', '600');
  }
  return headers;
}

function jsonError(status: number, message: string, origin: string | null, retryAfterSeconds?: number): Response {
  const headers = corsHeaders(origin);
  headers.set('Content-Type', 'application/json; charset=utf-8');
  headers.set('Cache-Control', 'no-store');
  if (retryAfterSeconds !== undefined) headers.set('Retry-After', String(retryAfterSeconds));
  return new Response(JSON.stringify({ error: message }), { status, headers });
}

function safeErrorDetails(error: unknown): { name: string; message: string } {
  const name = error instanceof Error ? error.name : 'UnknownError';
  const message = error instanceof Error ? error.message : String(error);
  return {
    name: name.slice(0, 64),
    message: message.slice(0, 256),
  };
}

async function readBounded(response: Response, maxBytes: number): Promise<ArrayBuffer> {
  const declaredLength = Number(response.headers.get('content-length'));
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    throw new Error('upstream response too large');
  }
  if (!response.body) {
    const body = await response.arrayBuffer();
    if (body.byteLength > maxBytes) throw new Error('upstream response too large');
    return body;
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new Error('upstream response too large');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result.buffer;
}

export default {
  async fetch(request: Request, env: Env = {}): Promise<Response> {
    const requestUrl = new URL(request.url);
    const origin = request.headers.get('Origin');

    if (origin && origin !== ALLOWED_ORIGIN) {
      return jsonError(403, 'origin not allowed', origin);
    }
    if (requestUrl.pathname !== '/ocsp') {
      return jsonError(404, 'not found', origin);
    }
    if (request.method === 'OPTIONS') {
      const headers = corsHeaders(origin);
      headers.set('Cache-Control', 'no-store');
      return new Response(null, { status: 204, headers });
    }
    if (request.method !== 'POST') {
      return jsonError(405, 'method not allowed', origin);
    }
    const contentType = (request.headers.get('Content-Type') || '').split(';', 1)[0].trim().toLowerCase();
    if (contentType !== 'application/ocsp-request') {
      return jsonError(415, 'Content-Type must be application/ocsp-request', origin);
    }
    const declaredLength = Number(request.headers.get('Content-Length'));
    if (Number.isFinite(declaredLength) && declaredLength > MAX_REQUEST_BYTES) {
      return jsonError(413, 'request too large', origin);
    }
    if (env.OCSP_RATE_LIMITER) {
      const clientAddress = request.headers.get('cf-connecting-ip')?.trim() || 'anonymous';
      try {
        const { success } = await env.OCSP_RATE_LIMITER.limit({ key: `ocsp:${clientAddress}` });
        if (!success) return jsonError(429, 'rate limit exceeded', origin, 60);
      } catch (error) {
        console.error('OCSP rate limiter unavailable', safeErrorDetails(error));
        return jsonError(503, 'rate limiter unavailable', origin);
      }
    }
    const requestBody = await request.arrayBuffer();
    if (requestBody.byteLength === 0 || requestBody.byteLength > MAX_REQUEST_BYTES) {
      return jsonError(413, 'request too large', origin);
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);
    let phase = 'fetch';
    try {
      const upstream = await fetch(UPSTREAM_OCSP_URL, {
        method: 'POST',
        // Workers supports only "follow" and "manual". Keep redirects
        // visible and reject them below instead of forwarding elsewhere.
        redirect: 'manual',
        headers: {
          Accept: 'application/ocsp-response',
          'Content-Type': 'application/ocsp-request',
        },
        body: requestBody,
        signal: controller.signal,
      });
      if (!upstream.ok) {
        console.error('OCSP upstream returned a non-success status', {
          phase,
          status: upstream.status,
        });
        return jsonError(502, 'OCSP upstream returned an error', origin);
      }
      phase = 'read-response';
      const responseBody = await readBounded(upstream, MAX_RESPONSE_BYTES);
      const headers = corsHeaders(origin);
      headers.set('Content-Type', 'application/ocsp-response');
      headers.set('Cache-Control', 'no-store');
      return new Response(responseBody, { status: 200, headers });
    } catch (error) {
      console.error('OCSP upstream request failed', {
        phase,
        requestBytes: requestBody.byteLength,
        ...safeErrorDetails(error),
      });
      return jsonError(502, 'OCSP upstream is unavailable', origin);
    } finally {
      clearTimeout(timeout);
    }
  },
};
