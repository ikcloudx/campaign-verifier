# FreeTSA OCSP proxy

This Worker is a deliberately narrow relay for the FreeTSA OCSP endpoint. It
does not parse OCSP, decide whether a certificate is good, or return a trusted
boolean. The browser receives the raw signed `OCSPResponse` and verifies it
with PKI.js and the pinned FreeTSA root.

## Deploy

Install Wrangler in the operator environment, authenticate to the intended
Cloudflare account, and run:

```bash
cd workers/ocsp-proxy
npx wrangler deploy
```

Bind the deployed Worker to an HTTPS custom hostname, for example
`ocsp.kcloudx.com`, and expose the `/ocsp` path. The `allow_custom_ports`
compatibility flag is required because the FreeTSA responder uses HTTP port
2560. Verify the deployed Worker with a real DER OCSP request before enabling
the browser client.

After the hostname is ready, set `FREETSA_OCSP_PROXY_URL` in
`src/revocation-config.ts` to the exact URL, for example:

```ts
export const FREETSA_OCSP_PROXY_URL = 'https://ocsp.kcloudx.com/ocsp';
```

The Pages site can then be rebuilt and deployed. Until that value is set, the
browser continues to use the mirrored CRL without attempting OCSP.

## Contract and safety limits

- Only `POST /ocsp` and CORS preflight `OPTIONS /ocsp` are accepted.
- The only browser origin allowed by CORS is `https://ikcloudx.github.io`.
- The upstream URL is fixed in source; callers cannot select an arbitrary URL.
- Request and response sizes are bounded, redirects are rejected, and the
  upstream request has a five-second timeout.
- Responses are marked `Cache-Control: no-store` so a stale proxy cache cannot
  be mistaken for a fresh OCSP check.
