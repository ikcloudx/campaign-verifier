import * as asn1js from 'asn1js';
import {
  AlgorithmIdentifier,
  BasicConstraints,
  Certificate,
  ContentInfo,
  ExtKeyUsage,
  SignedData,
  TimeStampResp,
  TSTInfo,
} from 'pkijs';
import { FREETSA_TSA_URL } from './revocation-config.ts';
import { verifyCertificateWithCrl } from './revocation.ts';

export { FREETSA_TSA_URL } from './revocation-config.ts';

export interface Rfc3161Check {
  id: string;
  label: string;
  ok: boolean;
  detail: string;
  warning?: boolean;
}

export interface Rfc3161VerificationResult {
  checks: Rfc3161Check[];
  ok: boolean;
  generatedAt?: Date;
  policy?: string;
  signerSubject?: string;
}

export interface Rfc3161VerificationOptions {
  /** Raw DER or PEM CRL mirrored by the verifier's static site. */
  revocationCrlBytes?: Uint8Array;
  /** A fetch/transport error is rendered as a failed revocation check. */
  revocationError?: string;
  /** Injectable for deterministic tests; production uses the current time. */
  revocationCheckDate?: Date;
}

/** FreeTSA's published root CA, downloaded and fingerprinted independently. */
const FREETSA_ROOT_PEM = `-----BEGIN CERTIFICATE-----
MIIH/zCCBeegAwIBAgIJAMHphhYNqOmAMA0GCSqGSIb3DQEBDQUAMIGVMREwDwYD
VQQKEwhGcmVlIFRTQTEQMA4GA1UECxMHUm9vdCBDQTEYMBYGA1UEAxMPd3d3LmZy
ZWV0c2Eub3JnMSIwIAYJKoZIhvcNAQkBFhNidXNpbGV6YXNAZ21haWwuY29tMRIw
EAYDVQQHEwlXdWVyemJ1cmcxDzANBgNVBAgTBkJheWVybjELMAkGA1UEBhMCREUw
HhcNMTYwMzEzMDE1MjEzWhcNNDEwMzA3MDE1MjEzWjCBlTERMA8GA1UEChMIRnJl
ZSBUU0ExEDAOBgNVBAsTB1Jvb3QgQ0ExGDAWBgNVBAMTD3d3dy5mcmVldHNhLm9y
ZzEiMCAGCSqGSIb3DQEJARYTYnVzaWxlemFzQGdtYWlsLmNvbTESMBAGA1UEBxMJ
V3VlcnpidXJnMQ8wDQYDVQQIEwZCYXllcm4xCzAJBgNVBAYTAkRFMIICIjANBgkq
hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtgKODjAy8REQ2WTNqUudAnjhlCrpE6ql
mQfNppeTmVvZrH4zutn+NwTaHAGpjSGv4/WRpZ1wZ3BRZ5mPUBZyLgq0YrIfQ5Fx
0s/MRZPzc1r3lKWrMR9sAQx4mN4z11xFEO529L0dFJjPF9MD8Gpd2feWzGyptlel
b+PqT+++fOa2oY0+NaMM7l/xcNHPOaMz0/2olk0i22hbKeVhvokPCqhFhzsuhKsm
q4Of/o+t6dI7sx5h0nPMm4gGSRhfq+z6BTRgCrqQG2FOLoVFgt6iIm/BnNffUr7V
DYd3zZmIwFOj/H3DKHoGik/xK3E82YA2ZulVOFRW/zj4ApjPa5OFbpIkd0pmzxzd
EcL479hSA9dFiyVmSxPtY5ze1P+BE9bMU1PScpRzw8MHFXxyKqW13Qv7LWw4sbk3
SciB7GACbQiVGzgkvXG6y85HOuvWNvC5GLSiyP9GlPB0V68tbxz4JVTRdw/Xn/XT
FNzRBM3cq8lBOAVt/PAX5+uFcv1S9wFE8YjaBfWCP1jdBil+c4e+0tdywT2oJmYB
BF/kEt1wmGwMmHunNEuQNzh1FtJY54hbUfiWi38mASE7xMtMhfj/C4SvapiDN837
gYaPfs8x3KZxbX7C3YAsFnJinlwAUss1fdKar8Q/YVs7H/nU4c4Ixxxz4f67fcVq
M2ITKentbCMCAwEAAaOCAk4wggJKMAwGA1UdEwQFMAMBAf8wDgYDVR0PAQH/BAQD
AgHGMB0GA1UdDgQWBBT6VQ2MNGZRQ0z357OnbJWveuaklzCBygYDVR0jBIHCMIG/
gBT6VQ2MNGZRQ0z357OnbJWveuakl6GBm6SBmDCBlTERMA8GA1UEChMIRnJlZSBU
U0ExEDAOBgNVBAsTB1Jvb3QgQ0ExGDAWBgNVBAMTD3d3dy5mcmVldHNhLm9yZzEi
MCAGCSqGSIb3DQEJARYTYnVzaWxlemFzQGdtYWlsLmNvbTESMBAGA1UEBxMJV3Vl
cnpidXJnMQ8wDQYDVQQIEwZCYXllcm4xCzAJBgNVBAYTAkRFggkAwemGFg2o6YAw
MwYDVR0fBCwwKjAooCagJIYiaHR0cDovL3d3dy5mcmVldHNhLm9yZy9yb290X2Nh
LmNybDCBzwYDVR0gBIHHMIHEMIHBBgorBgEEAYHyJAEBMIGyMDMGCCsGAQUFBwIB
FidodHRwOi8vd3d3LmZyZWV0c2Eub3JnL2ZyZWV0c2FfY3BzLmh0bWwwMgYIKwYB
BQUHAgEWJmh0dHA6Ly93d3cuZnJlZXRzYS5vcmcvZnJlZXRzYV9jcHMucGRmMEcG
CCsGAQUFBwICMDsaOUZyZWVUU0EgdHJ1c3RlZCB0aW1lc3RhbXBpbmcgU29mdHdh
cmUgYXMgYSBTZXJ2aWNlIChTYWFTKTA3BggrBgEFBQcBAQQrMCkwJwYIKwYBBQUH
MAGGG2h0dHA6Ly93d3cuZnJlZXRzYS5vcmc6MjU2MDANBgkqhkiG9w0BAQ0FAAOC
AgEAaK9+v5OFYu9M6ztYC+L69sw1omdyli89lZAfpWMMh9CRmJhM6KBqM/ipwoLt
nxyxGsbCPhcQjuTvzm+ylN6VwTMmIlVyVSLKYZcdSjt/eCUN+41K7sD7GVmxZBAF
ILnBDmTGJmLkrU0KuuIpj8lI/E6Z6NnmuP2+RAQSHsfBQi6sssnXMo4HOW5gtPO7
gDrUpVXID++1P4XndkoKn7Svw5n0zS9fv1hxBcYIHPPQUze2u30bAQt0n0iIyRLz
aWuhtpAtd7ffwEbASgzB7E+NGF4tpV37e8KiA2xiGSRqT5ndu28fgpOY87gD3ArZ
DctZvvTCfHdAS5kEO3gnGGeZEVLDmfEsv8TGJa3AljVa5E40IQDsUXpQLi8G+UC4
1DWZu8EVT4rnYaCw1VX7ShOR1PNCCvjb8S8tfdudd9zhU3gEB0rxdeTy1tVbNLXW
99y90xcwr1ZIDUwM/xQ/noO8FRhm0LoPC73Ef+J4ZBdrvWwauF3zJe33d4ibxEcb
8/pz5WzFkeixYM2nsHhqHsBKw7JPouKNXRnl5IAE1eFmqDyC7G/VT7OF669xM6hb
Ut5G21JE4cNK6NNucS+fzg1JPX0+3VhsYZjj7D5uljRvQXrJ8iHgr/M6j2oLHvTA
I2MLdq2qjZFDOCXsxBxJpbmLGBx9ow6ZerlUxzws2AWv2pk=
-----END CERTIFICATE-----`;

export const FREETSA_ROOT_SHA256 = 'a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc';
export const FREETSA_POLICY_OID = '1.2.3.4.1';
/** Keep the parser bounded even when it is called outside the UI fetch guard. */
export const MAX_RFC3161_RECEIPT_BYTES = 2 * 1024 * 1024;

const SHA1_OID = '1.3.14.3.2.26';
const SHA256_OID = '2.16.840.1.101.3.4.2.1';
const SHA384_OID = '2.16.840.1.101.3.4.2.2';
const SHA512_OID = '2.16.840.1.101.3.4.2.3';
const TIME_STAMPING_EKU = '1.3.6.1.5.5.7.3.8';
const BASIC_CONSTRAINTS_OID = '2.5.29.19';
const KEY_USAGE_OID = '2.5.29.15';
const EXT_KEY_USAGE_OID = '2.5.29.37';
const SIGNING_CERTIFICATE_OID = '1.2.840.113549.1.9.16.2.12';
const SIGNING_CERTIFICATE_V2_OID = '1.2.840.113549.1.9.16.2.47';
const KNOWN_CRITICAL_CERTIFICATE_EXTENSIONS = new Set([
  BASIC_CONSTRAINTS_OID,
  KEY_USAGE_OID,
  EXT_KEY_USAGE_OID,
]);

const HASH_ALGORITHMS: Record<string, 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512'> = {
  [SHA1_OID]: 'SHA-1',
  [SHA256_OID]: 'SHA-256',
  [SHA384_OID]: 'SHA-384',
  [SHA512_OID]: 'SHA-512',
};

/**
 * SHA-1 is retained in HASH_ALGORITHMS because ESSCertID v1 uses SHA-1 to
 * identify the signing certificate.  It is not accepted for a new
 * TimeStampToken MessageImprint.
 */
const MESSAGE_IMPRINT_ALGORITHMS: Record<string, 'SHA-256' | 'SHA-384' | 'SHA-512'> = {
  [SHA256_OID]: 'SHA-256',
  [SHA384_OID]: 'SHA-384',
  [SHA512_OID]: 'SHA-512',
};

function check(id: string, label: string, ok: boolean, detail: string, warning = false): Rfc3161Check {
  return { id, label, ok, detail, ...(warning ? { warning: true } : {}) };
}

function finish(
  checks: Rfc3161Check[],
  metadata: Omit<Rfc3161VerificationResult, 'checks' | 'ok'> = {},
): Rfc3161VerificationResult {
  return { checks, ok: checks.every((item) => item.ok), ...metadata };
}

function exactArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function pemToBytes(pem: string): Uint8Array {
  const encoded = pem.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s/g, '');
  const binary = atob(encoded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function parseExactResponse(bytes: Uint8Array): TimeStampResp {
  const raw = exactArrayBuffer(bytes);
  const decoded = asn1js.fromBER(raw);
  if (decoded.offset === -1 || decoded.offset !== bytes.byteLength) {
    throw new Error('TimeStampResp 包含无效 ASN.1，或末尾存在未解析字节。');
  }
  return new TimeStampResp({ schema: decoded.result });
}

function parseExactTstInfo(bytes: Uint8Array): TSTInfo {
  const decoded = asn1js.fromBER(bytes);
  if (decoded.offset === -1 || decoded.offset !== bytes.byteLength) {
    throw new Error('TSTInfo 包含无效 ASN.1，或末尾存在未解析字节。');
  }
  return new TSTInfo({ schema: decoded.result });
}

async function digestBytes(algorithm: AlgorithmIdentifierName, bytes: Uint8Array): Promise<Uint8Array> {
  const digest = await globalThis.crypto.subtle.digest(algorithm, bytes as unknown as BufferSource);
  return new Uint8Array(digest);
}

type AlgorithmIdentifierName = 'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512';

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) difference |= left[index] ^ right[index];
  return difference === 0;
}

function child(node: unknown, index: number): unknown {
  if (!(node instanceof asn1js.Sequence)) return undefined;
  return node.valueBlock.value[index];
}

function octets(node: unknown): Uint8Array | undefined {
  return node instanceof asn1js.OctetString ? node.valueBlock.valueHexView : undefined;
}

function extension(certificate: Certificate, id: string) {
  return certificate.extensions?.find((item) => item.extnID === id);
}

function subjectLabel(certificate: Certificate): string {
  return certificate.subject.typesAndValues
    .map((item) => `${item.type}=${String(item.value.valueBlock.value ?? '')}`)
    .join(', ');
}

async function verifySigningCertificateAttribute(
  signedData: SignedData,
  signerCertificate: Certificate,
): Promise<boolean> {
  const attributes = signedData.signerInfos[0]?.signedAttrs?.attributes ?? [];
  const attribute = attributes.find((item) => (
    item.type === SIGNING_CERTIFICATE_OID || item.type === SIGNING_CERTIFICATE_V2_OID
  ));
  if (!attribute || attribute.values.length !== 1) return false;

  let hashAlgorithm: AlgorithmIdentifierName = 'SHA-1';
  const signingCertificate = attribute.values[0];
  const certificateIds = child(signingCertificate, 0);
  if (!(certificateIds instanceof asn1js.Sequence)) return false;

  const certificateDer = new Uint8Array(signerCertificate.toSchema(true).toBER(false));
  for (const value of certificateIds.valueBlock.value) {
    const essCertId = value as asn1js.BaseBlock;
    let certificateHash: Uint8Array | undefined;
    hashAlgorithm = 'SHA-1';
    if (attribute.type === SIGNING_CERTIFICATE_OID) {
      certificateHash = octets(child(essCertId, 0));
    } else {
      // ESSCertIDv2 places the optional AlgorithmIdentifier before certHash;
      // when omitted, SHA-256 is the default (RFC 5035).
      const first = child(essCertId, 0);
      if (first instanceof asn1js.OctetString) {
        hashAlgorithm = 'SHA-256';
        certificateHash = first.valueBlock.valueHexView;
      } else if (first !== undefined) {
        const algorithm = AlgorithmIdentifier.fromBER(
          (first as asn1js.BaseBlock).toBER(false),
        );
        const parsedAlgorithm = HASH_ALGORITHMS[algorithm.algorithmId];
        if (!parsedAlgorithm) continue;
        hashAlgorithm = parsedAlgorithm;
        certificateHash = octets(child(essCertId, 1));
      }
    }
    if (!certificateHash) continue;
    const calculated = await digestBytes(hashAlgorithm, certificateDer);
    if (equalBytes(calculated, certificateHash)) return true;
  }
  return false;
}

function certificateKeyUsageAllowsSigning(certificate: Certificate): boolean {
  const usage = extension(certificate, KEY_USAGE_OID)?.parsedValue;
  if (!(usage instanceof asn1js.BitString)) return false;
  const bits = usage.valueBlock.valueHexView;
  return bits.byteLength > 0 && (bits[0] & 0x80) !== 0;
}

function certificateIdentityAllowsTimestamp(certificate: Certificate): boolean {
  const basicConstraintsExtension = extension(certificate, BASIC_CONSTRAINTS_OID);
  const basicConstraints = basicConstraintsExtension?.parsedValue;
  const isNotCa = !basicConstraintsExtension
    || (basicConstraints instanceof BasicConstraints && basicConstraints.cA === false);
  const eku = extension(certificate, EXT_KEY_USAGE_OID);
  const purposes = eku?.parsedValue instanceof ExtKeyUsage
    ? eku.parsedValue.keyPurposes
    : [];
  const hasOnlyTimestampingEku = Boolean(
    eku?.critical
      && purposes.length === 1
      && purposes[0] === TIME_STAMPING_EKU,
  );
  return isNotCa && hasOnlyTimestampingEku && certificateKeyUsageAllowsSigning(certificate);
}

function certificateCriticalExtensionsKnown(certificate: Certificate): boolean {
  return !(certificate.extensions || []).some(
    (item) => item.critical && !KNOWN_CRITICAL_CERTIFICATE_EXTENSIONS.has(item.extnID),
  );
}

function parseTrustedRoot(): Certificate {
  return Certificate.fromBER(exactArrayBuffer(pemToBytes(FREETSA_ROOT_PEM)));
}

export async function verifyRfc3161Receipt(
  receiptBytes: Uint8Array,
  dataBytes: Uint8Array,
  tsaUrl?: string,
  options: Rfc3161VerificationOptions = {},
): Promise<Rfc3161VerificationResult> {
  const checks: Rfc3161Check[] = [];
  const sizeOk = receiptBytes.byteLength <= MAX_RFC3161_RECEIPT_BYTES;
  checks.push(check(
    'rfc3161-size',
    'RFC 3161 receipt 大小限制',
    sizeOk,
    sizeOk
      ? `TSR 大小为 ${receiptBytes.byteLength} 字节。`
      : `TSR 超过 ${MAX_RFC3161_RECEIPT_BYTES} 字节上限。`,
  ));
  if (!sizeOk) return finish(checks);

  let response: TimeStampResp;
  try {
    response = parseExactResponse(receiptBytes);
    checks.push(check('rfc3161-structure', 'RFC 3161 ASN.1 结构', true, 'TSR 可解析为完整的 TimeStampResp。'));
  } catch (error) {
    checks.push(check(
      'rfc3161-structure',
      'RFC 3161 ASN.1 结构',
      false,
      error instanceof Error ? error.message : 'TSR 不是有效的 ASN.1。',
    ));
    return finish(checks);
  }

  const statusGranted = response.status.status === 0 || response.status.status === 1;
  checks.push(check(
    'rfc3161-status',
    'RFC 3161 响应状态',
    statusGranted,
    statusGranted ? 'TSP 响应状态为 granted 或 grantedWithMods。' : `TSP 响应状态为 ${response.status.status}。`,
  ));

  const token = response.timeStampToken;
  const tokenPresent = Boolean(token);
  checks.push(check(
    'rfc3161-token',
    'TimeStampToken 内容',
    tokenPresent,
    tokenPresent ? '响应包含 TimeStampToken。' : '响应不包含 TimeStampToken。',
  ));
  if (!token) return finish(checks);

  const signedDataContent = token.contentType === ContentInfo.SIGNED_DATA;
  checks.push(check(
    'rfc3161-content-type',
    'CMS SignedData 内容类型',
    signedDataContent,
    signedDataContent ? 'TimeStampToken 的内容类型为 CMS SignedData。' : `内容类型为 ${token.contentType}。`,
  ));
  if (!signedDataContent) return finish(checks);

  let signedData: SignedData;
  try {
    signedData = new SignedData({ schema: token.content });
  } catch (error) {
    checks.push(check(
      'rfc3161-signed-data',
      'CMS SignedData 结构',
      false,
      error instanceof Error ? error.message : 'CMS SignedData 无法解析。',
    ));
    return finish(checks);
  }
  checks.push(check('rfc3161-signed-data', 'CMS SignedData 结构', true, 'CMS SignedData 结构完整。'));

  const oneSigner = signedData.signerInfos.length === 1;
  checks.push(check(
    'rfc3161-signer-count',
    'TSA 签名者数量',
    oneSigner,
    oneSigner ? 'TimeStampToken 只有一个 TSA 签名者。' : `TimeStampToken 包含 ${signedData.signerInfos.length} 个签名者。`,
  ));
  if (!oneSigner) return finish(checks);

  const tstContent = signedData.encapContentInfo.eContentType === '1.2.840.113549.1.9.16.1.4';
  checks.push(check(
    'rfc3161-tst-content',
    'TSTInfo 内容类型',
    tstContent,
    tstContent ? 'CMS 封装内容为 id-ct-TSTInfo。' : `封装内容类型为 ${signedData.encapContentInfo.eContentType}。`,
  ));
  const encodedTst = signedData.encapContentInfo.eContent?.valueBlock.valueHexView;
  const hasTst = Boolean(encodedTst);
  checks.push(check(
    'rfc3161-tst-present',
    'TSTInfo 内容存在',
    hasTst,
    hasTst ? 'CMS 中包含 DER 编码的 TSTInfo。' : 'CMS 中缺少 TSTInfo。',
  ));
  if (!tstContent || !encodedTst) return finish(checks);

  let tstInfo: TSTInfo;
  try {
    tstInfo = parseExactTstInfo(encodedTst);
  } catch (error) {
    checks.push(check(
      'rfc3161-tst-structure',
      'TSTInfo ASN.1 结构',
      false,
      error instanceof Error ? error.message : 'TSTInfo 不是有效的 ASN.1。',
    ));
    return finish(checks);
  }
  checks.push(check('rfc3161-tst-structure', 'TSTInfo ASN.1 结构', true, 'TSTInfo 结构完整。'));

  const tstVersionOk = tstInfo.version === 1;
  checks.push(check(
    'rfc3161-tst-version',
    'TSTInfo 版本',
    tstVersionOk,
    tstVersionOk ? 'TSTInfo 版本为 v1。' : `TSTInfo 版本为 ${tstInfo.version}。`,
  ));

  const messageImprintOid = tstInfo.messageImprint.hashAlgorithm.algorithmId;
  const hashAlgorithm = HASH_ALGORITHMS[messageImprintOid];
  const messageImprintAlgorithm = MESSAGE_IMPRINT_ALGORITHMS[messageImprintOid];
  const hashAlgorithmOk = Boolean(messageImprintAlgorithm);
  checks.push(check(
    'rfc3161-imprint-algorithm',
    'MessageImprint 哈希算法',
    hashAlgorithmOk,
    messageImprintAlgorithm
      ? `MessageImprint 使用 ${messageImprintAlgorithm}。`
      : hashAlgorithm === 'SHA-1'
        ? '不接受 SHA-1 MessageImprint；新时间戳必须使用 SHA-256、SHA-384 或 SHA-512。'
        : `不支持 MessageImprint 算法 ${messageImprintOid}。`,
  ));

  let imprintMatches = false;
  if (messageImprintAlgorithm) {
    const calculated = await digestBytes(messageImprintAlgorithm, dataBytes);
    imprintMatches = equalBytes(calculated, tstInfo.messageImprint.hashedMessage.valueBlock.valueHexView);
  }
  checks.push(check(
    'rfc3161-message-imprint',
    '原始数据 MessageImprint',
    imprintMatches,
    imprintMatches ? 'TSR 中的 MessageImprint 与归档 JSON 原始字节一致。' : 'TSR 中的 MessageImprint 与归档 JSON 原始字节不一致。',
  ));

  const tsaProfileKnown = tsaUrl === undefined || tsaUrl === FREETSA_TSA_URL;
  checks.push(check(
    'rfc3161-tsa-profile',
    'TSA 信任配置',
    tsaProfileKnown,
    tsaProfileKnown
      ? `使用 FreeTSA profile（${FREETSA_TSA_URL}）。`
      : `当前 verifier 未配置 ${tsaUrl} 的独立信任根，不能使用 FreeTSA 根代替。`,
  ));

  const policyKnown = tsaProfileKnown && tstInfo.policy === FREETSA_POLICY_OID;
  checks.push(check(
    'rfc3161-policy',
    'TSA 策略标识',
    policyKnown,
    policyKnown
      ? `TSA policy OID 为 ${tstInfo.policy}。`
      : `FreeTSA profile 预期 policy OID ${FREETSA_POLICY_OID}，实际为 ${tstInfo.policy}。`,
  ));

  let signatureResult: Awaited<ReturnType<SignedData['verify']>> | undefined;
  let signerCertificate: Certificate | null = null;
  try {
    signatureResult = await signedData.verify({
      signer: 0,
      data: exactArrayBuffer(dataBytes),
      checkChain: false,
      extendedMode: true,
    });
    signerCertificate = signatureResult.signerCertificate ?? null;
    checks.push(check(
      'rfc3161-cms-signature',
      'CMS/TSA 签名',
      signatureResult.signatureVerified === true,
      signatureResult.signatureVerified === true
        ? 'CMS signed attributes 和 TSA 数字签名验证通过。'
        : 'CMS TSA 数字签名验证失败。',
    ));
  } catch (error) {
    checks.push(check(
      'rfc3161-cms-signature',
      'CMS/TSA 签名',
      false,
      error instanceof Error ? error.message : 'CMS TSA 数字签名验证失败。',
    ));
  }

  let signingCertificateAttributeOk = false;
  let signingCertificateAttributeError: string | undefined;
  if (signerCertificate) {
    try {
      signingCertificateAttributeOk = await verifySigningCertificateAttribute(signedData, signerCertificate);
    } catch (error) {
      signingCertificateAttributeError = error instanceof Error ? error.message : '证书标识属性无法解析。';
    }
  }
  checks.push(check(
    'rfc3161-signing-certificate',
    'TSA 证书标识属性',
    signingCertificateAttributeOk,
    signingCertificateAttributeOk
      ? 'SigningCertificate/SigningCertificateV2 中的证书摘要与签名证书一致。'
      : signingCertificateAttributeError || 'SigningCertificate/SigningCertificateV2 缺失，或未匹配签名证书。',
  ));

  let rootCertificate: Certificate;
  try {
    rootCertificate = parseTrustedRoot();
    const rootFingerprint = await digestBytes('SHA-256', new Uint8Array(rootCertificate.toSchema(true).toBER(false)));
    const rootFingerprintHex = Array.from(rootFingerprint, (byte) => byte.toString(16).padStart(2, '0')).join('');
    const rootPinned = rootFingerprintHex === FREETSA_ROOT_SHA256;
    checks.push(check(
      'rfc3161-trust-anchor',
      '固定 TSA 信任根',
      rootPinned,
      rootPinned
        ? `使用内置 FreeTSA 根证书（SHA-256 ${FREETSA_ROOT_SHA256}）。`
        : `内置信任根指纹不匹配（${rootFingerprintHex}）。`,
    ));
  } catch (error) {
    checks.push(check(
      'rfc3161-trust-anchor',
      '固定 TSA 信任根',
      false,
      error instanceof Error ? error.message : '内置 TSA 信任根无法解析。',
    ));
    return finish(checks, { generatedAt: tstInfo.genTime, policy: tstInfo.policy });
  }

  let chainResult: Awaited<ReturnType<SignedData['verify']>> | undefined;
  try {
    chainResult = await signedData.verify({
      signer: 0,
      data: exactArrayBuffer(dataBytes),
      trustedCerts: [rootCertificate],
      checkChain: true,
      extendedMode: true,
    });
    signerCertificate = chainResult.signerCertificate ?? signerCertificate;
    checks.push(check(
      'rfc3161-certificate-chain',
      'TSA 证书链',
      chainResult.signerCertificateVerified === true,
      chainResult.signerCertificateVerified === true
        ? `证书链验证通过（${chainResult.certificatePath.length} 个证书，检查时间为 genTime）。`
        : 'TSA 证书链验证失败。',
    ));
  } catch (error) {
    checks.push(check(
      'rfc3161-certificate-chain',
      'TSA 证书链',
      false,
      error instanceof Error ? error.message : 'TSA 证书链验证失败。',
    ));
  }

  const identityOk = signerCertificate ? certificateIdentityAllowsTimestamp(signerCertificate) : false;
  checks.push(check(
    'rfc3161-certificate-usage',
    'TSA 证书用途',
    identityOk,
    identityOk
      ? 'TSA 证书为非 CA，并包含 critical 且仅用于 timeStamping 的 EKU。'
      : 'TSA 证书的 Basic Constraints、Key Usage 或 timeStamping EKU 不符合要求。',
  ));

  const certificatesToCheck = chainResult?.certificatePath?.length
    ? chainResult.certificatePath
    : signerCertificate
      ? [signerCertificate]
      : [];
  const criticalExtensionsOk = certificatesToCheck.length > 0
    && certificatesToCheck.every(certificateCriticalExtensionsKnown);
  checks.push(check(
    'rfc3161-critical-extensions',
    '证书链关键扩展',
    criticalExtensionsOk,
    criticalExtensionsOk
      ? '证书链中的 critical 扩展均在 verifier 的允许列表内。'
      : '证书链包含 verifier 未识别的 critical 扩展，不能安全忽略。',
  ));

  const tsaIdentityOk = !tstInfo.tsa || (
    tstInfo.tsa.type === 4
      && signerCertificate !== null
      && tstInfo.tsa.value?.isEqual?.(signerCertificate.subject) === true
  );
  checks.push(check(
    'rfc3161-tsa-identity',
    'TSA 身份标识',
    tsaIdentityOk,
    tsaIdentityOk ? 'TSTInfo 的 TSA 名称与签名证书主体一致。' : 'TSTInfo 的 TSA 名称与签名证书主体不一致。',
  ));

  if (options.revocationCrlBytes && signerCertificate) {
    const revocation = await verifyCertificateWithCrl(
      options.revocationCrlBytes,
      signerCertificate,
      rootCertificate,
      { checkDate: options.revocationCheckDate },
    );
    checks.push(check(
      'rfc3161-revocation',
      'TSA 吊销状态（CRL）',
      revocation.ok,
      revocation.detail,
    ));
  } else if (options.revocationCrlBytes) {
    checks.push(check(
      'rfc3161-revocation',
      'TSA 吊销状态（CRL）',
      false,
      '无法确定 TSA 签名证书，不能执行 CRL 序列号检查。',
    ));
  } else if (options.revocationError) {
    checks.push(check(
      'rfc3161-revocation',
      'TSA 吊销状态（CRL）',
      false,
      `无法读取同源 CRL：${options.revocationError}`,
    ));
  } else {
    checks.push(check(
      'rfc3161-revocation',
      'TSA 吊销状态（CRL）',
      true,
      '未提供同源 CRL；浏览器仅完成签名、证书链和证书用途验证。',
      true,
    ));
  }

  return finish(checks, {
    generatedAt: tstInfo.genTime,
    policy: tstInfo.policy,
    signerSubject: signerCertificate ? subjectLabel(signerCertificate) : undefined,
  });
}
