/** FreeTSA profile used by the browser verifier and the scheduled mirror. */
export const FREETSA_TSA_URL = 'https://freetsa.org/tsr';
/** Relative path published by the Pages site and therefore readable by fetch. */
export const FREETSA_CRL_MIRROR_PATH = 'revocation/freetsa-root-ca.crl';
/** Official FreeTSA source used by the scheduled mirror workflow. */
export const FREETSA_CRL_SOURCE_URL = 'https://www.freetsa.org/crl/root_ca.crl';
/**
 * Optional HTTPS relay for FreeTSA's HTTP-only OCSP endpoint. Keep empty until
 * the relay has been deployed and its exact origin has been configured.
 */
export const FREETSA_OCSP_PROXY_URL = '';
/** Keep the browser parser bounded even if a mirror is compromised. */
export const MAX_REVOCATION_CRL_BYTES = 2 * 1024 * 1024;
/** OCSP requests are small; this also bounds a compromised caller or proxy. */
export const MAX_REVOCATION_OCSP_REQUEST_BYTES = 16 * 1024;
/** Keep the browser parser bounded before handing bytes to PKI.js. */
export const MAX_REVOCATION_OCSP_BYTES = 256 * 1024;
/** Small allowance for clock skew between the browser and the CA. */
export const REVOCATION_CLOCK_SKEW_MS = 5 * 60 * 1000;
/** FreeTSA omits nextUpdate; do not accept an unboundedly old response. */
export const OCSP_MAX_AGE_MS = 24 * 60 * 60 * 1000;
/** OCSP uses the same clock-skew policy as the mirrored CRL. */
export const OCSP_CLOCK_SKEW_MS = REVOCATION_CLOCK_SKEW_MS;
