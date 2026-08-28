/** FreeTSA profile used by the browser verifier and the scheduled mirror. */
export const FREETSA_TSA_URL = 'https://freetsa.org/tsr';
/** Relative path published by the Pages site and therefore readable by fetch. */
export const FREETSA_CRL_MIRROR_PATH = 'revocation/freetsa-root-ca.crl';
/** Official FreeTSA source used by the scheduled mirror workflow. */
export const FREETSA_CRL_SOURCE_URL = 'https://www.freetsa.org/crl/root_ca.crl';
/** Keep the browser parser bounded even if a mirror is compromised. */
export const MAX_REVOCATION_CRL_BYTES = 2 * 1024 * 1024;
/** Small allowance for clock skew between the browser and the CA. */
export const REVOCATION_CLOCK_SKEW_MS = 5 * 60 * 1000;
