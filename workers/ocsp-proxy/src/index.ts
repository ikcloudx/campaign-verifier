const UPSTREAM_OCSP_URL = 'http://www.freetsa.org:2560';
const ALLOWED_ORIGIN = 'https://ikcloudx.github.io';
const MAX_REQUEST_BYTES = 16 * 1024;
const MAX_RESPONSE_BYTES = 256 * 1024;
const UPSTREAM_TIMEOUT_MS = 5_000;

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

function jsonError(status: number, message: string, origin: string | null): Response {
  const headers = corsHeaders(origin);
  headers.set('Content-Type', 'application/json; charset=utf-8');
  headers.set('Cache-Control', 'no-store');
  return new Response(JSON.stringify({ error: message }), { status, headers });
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
  async fetch(request: Request): Promise<Response> {
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
    const requestBody = await request.arrayBuffer();
    if (requestBody.byteLength === 0 || requestBody.byteLength > MAX_REQUEST_BYTES) {
      return jsonError(413, 'request too large', origin);
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);
    try {
      const upstream = await fetch(UPSTREAM_OCSP_URL, {
        method: 'POST',
        redirect: 'error',
        headers: {
          Accept: 'application/ocsp-response',
          'Content-Type': 'application/ocsp-request',
        },
        body: requestBody,
        signal: controller.signal,
      });
      if (!upstream.ok) return jsonError(502, 'OCSP upstream returned an error', origin);
      const responseBody = await readBounded(upstream, MAX_RESPONSE_BYTES);
      const headers = corsHeaders(origin);
      headers.set('Content-Type', 'application/ocsp-response');
      headers.set('Cache-Control', 'no-store');
      return new Response(responseBody, { status: 200, headers });
    } catch {
      return jsonError(502, 'OCSP upstream is unavailable', origin);
    } finally {
      clearTimeout(timeout);
    }
  },
};
