import * as asn1js from 'asn1js';
import {
  BasicConstraints,
  BasicOCSPResponse,
  Certificate,
  CertID,
  ExtKeyUsage,
  Extension,
  OCSPRequest,
  OCSPResponse,
  Request,
  RelativeDistinguishedNames,
  id_PKIX_OCSP_Basic,
} from 'pkijs';
import {
  MAX_REVOCATION_OCSP_BYTES,
  MAX_REVOCATION_OCSP_REQUEST_BYTES,
  OCSP_CLOCK_SKEW_MS,
  OCSP_MAX_AGE_MS,
} from './revocation-config.ts';

export const OCSP_NONCE_OID = '1.3.6.1.5.5.7.48.1.2';
export const OCSP_SIGNING_EKU = '1.3.6.1.5.5.7.3.9';
export const SHA256_OID = '2.16.840.1.101.3.4.2.1';

const BASIC_CONSTRAINTS_OID = '2.5.29.19';
const KEY_USAGE_OID = '2.5.29.15';
const EXT_KEY_USAGE_OID = '2.5.29.37';

export type OcspStatus = 'good' | 'revoked' | 'unknown';

export interface OcspRequestResult {
  requestBytes: Uint8Array;
  nonce: Uint8Array;
  certId: CertID;
}

export interface OcspVerificationOptions {
  /** Time at which the response is evaluated; production defaults to now. */
  checkDate?: Date;
  /** Allowed clock skew for producedAt/thisUpdate/nextUpdate. */
  clockSkewMs?: number;
  /** Maximum age when the responder omits nextUpdate. */
  maxAgeMs?: number;
  /** Nonce sent with the request, when nonce binding is required. */
  expectedNonce?: Uint8Array;
}

export interface OcspVerificationResult {
  ok: boolean;
  status?: OcspStatus;
  detail: string;
  serial?: string;
  producedAt?: Date;
  thisUpdate?: Date;
  nextUpdate?: Date;
  responderSubject?: string;
}

function exactArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) difference |= left[index] ^ right[index];
  return difference === 0;
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}

function serialHex(serial: asn1js.Integer): string {
  return Array.from(serial.valueBlock.valueHexView, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function certificateDer(certificate: Certificate): Uint8Array {
  return new Uint8Array(certificate.toSchema(true).toBER(false));
}

function subjectLabel(certificate: Certificate): string {
  return certificate.subject.typesAndValues
    .map((item) => `${item.type}=${String(item.value.valueBlock.value ?? '')}`)
    .join(', ');
}

/**
 * Build a bounded SHA-256 OCSP request for one certificate. The request is
 * intentionally created in the browser so the proxy cannot change the
 * certificate being checked without the browser detecting a CertID mismatch.
 */
export async function createOcspRequest(
  certificate: Certificate,
  issuerCertificate: Certificate,
  requestedNonce?: Uint8Array,
): Promise<OcspRequestResult> {
  const nonce = requestedNonce
    ? new Uint8Array(requestedNonce)
    : globalThis.crypto.getRandomValues(new Uint8Array(16));
  if (nonce.byteLength === 0 || nonce.byteLength > 32) {
    throw new Error('OCSP nonce 长度必须介于 1 到 32 字节。');
  }

  const certId = await CertID.create(certificate, {
    hashAlgorithm: 'SHA-256',
    issuerCertificate,
  });
  const request = new OCSPRequest();
  request.tbsRequest.requestList.push(new Request({ reqCert: certId }));
  const nonceValue = new asn1js.OctetString({ valueHex: exactArrayBuffer(nonce) }).toBER(false);
  request.tbsRequest.requestExtensions = [new Extension({
    extnID: OCSP_NONCE_OID,
    extnValue: nonceValue,
  })];

  const requestBytes = new Uint8Array(request.toSchema(true).toBER(false));
  if (requestBytes.byteLength > MAX_REVOCATION_OCSP_REQUEST_BYTES) {
    throw new Error(`OCSP 请求超过 ${Math.floor(MAX_REVOCATION_OCSP_REQUEST_BYTES / 1024)} KiB 限制。`);
  }
  return { requestBytes, nonce, certId };
}

function parseExactOcspResponse(bytes: Uint8Array): {
  response: OCSPResponse;
  basic: BasicOCSPResponse;
} {
  if (bytes.byteLength === 0) throw new Error('OCSP 响应为空。');
  if (bytes.byteLength > MAX_REVOCATION_OCSP_BYTES) {
    throw new Error(`OCSP 响应超过 ${Math.floor(MAX_REVOCATION_OCSP_BYTES / 1024)} KiB 限制。`);
  }
  const decoded = asn1js.fromBER(exactArrayBuffer(bytes));
  if (decoded.offset === -1 || decoded.offset !== bytes.byteLength) {
    throw new Error('OCSP 响应包含无效 ASN.1，或末尾存在未解析字节。');
  }
  const response = new OCSPResponse({ schema: decoded.result });
  if (response.responseStatus.valueBlock.valueDec !== 0) {
    throw new Error(`OCSP 响应状态不是 successful（${response.responseStatus.valueBlock.valueDec}）。`);
  }
  if (!response.responseBytes) throw new Error('OCSP 响应缺少 ResponseBytes。');
  if (response.responseBytes.responseType !== id_PKIX_OCSP_Basic) {
    throw new Error(`不支持的 OCSP 响应类型 ${response.responseBytes.responseType}。`);
  }
  const basicBytes = response.responseBytes.response.valueBlock.valueHexView;
  const basicDecoded = asn1js.fromBER(exactArrayBuffer(basicBytes));
  if (basicDecoded.offset === -1 || basicDecoded.offset !== basicBytes.byteLength) {
    throw new Error('BasicOCSPResponse 包含无效 ASN.1，或末尾存在未解析字节。');
  }
  return {
    response,
    basic: new BasicOCSPResponse({ schema: basicDecoded.result }),
  };
}

function isSameCertificate(left: Certificate, right: Certificate): boolean {
  return left === right || equalBytes(certificateDer(left), certificateDer(right));
}

async function responderMatches(
  certificate: Certificate,
  responderId: unknown,
): Promise<boolean> {
  if (responderId instanceof RelativeDistinguishedNames) {
    return certificate.subject.isEqual(responderId);
  }
  if (responderId instanceof asn1js.OctetString) {
    const keyBytes = certificate.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHexView;
    const digest = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-1', keyBytes as BufferSource));
    return equalBytes(digest, responderId.valueBlock.valueHexView);
  }
  return false;
}

async function findResponderCertificate(
  basic: BasicOCSPResponse,
  issuerCertificate: Certificate,
): Promise<Certificate> {
  const candidates = (basic.certs || []).filter((item): item is Certificate => item instanceof Certificate);
  if (!candidates.some((candidate) => isSameCertificate(candidate, issuerCertificate))) {
    candidates.push(issuerCertificate);
  }
  for (const candidate of candidates) {
    if (await responderMatches(candidate, basic.tbsResponseData.responderID)) return candidate;
  }
  throw new Error('OCSP 响应中找不到与 responderID 匹配的响应者证书。');
}

function responderIsAuthorized(responder: Certificate, issuer: Certificate): boolean {
  if (isSameCertificate(responder, issuer)) return true;
  if (!responder.issuer.isEqual(issuer.subject)) return false;

  const basicConstraints = responder.extensions?.find((item) => item.extnID === BASIC_CONSTRAINTS_OID)?.parsedValue;
  if (basicConstraints instanceof BasicConstraints && basicConstraints.cA) return false;
  const keyUsage = responder.extensions?.find((item) => item.extnID === KEY_USAGE_OID)?.parsedValue;
  if (keyUsage instanceof asn1js.BitString) {
    const bits = keyUsage.valueBlock.valueHexView;
    if (bits.byteLength === 0 || (bits[0] & 0xc0) === 0) return false;
  }
  const eku = responder.extensions?.find((item) => item.extnID === EXT_KEY_USAGE_OID)?.parsedValue;
  return eku instanceof ExtKeyUsage && eku.keyPurposes.includes(OCSP_SIGNING_EKU);
}

function parseNonce(extension: Extension): Uint8Array {
  const encoded = extension.extnValue.valueBlock.valueHexView;
  const decoded = asn1js.fromBER(exactArrayBuffer(encoded));
  if (decoded.offset === -1 || decoded.offset !== encoded.byteLength || !(decoded.result instanceof asn1js.OctetString)) {
    throw new Error('OCSP nonce 扩展不是有效的 OCTET STRING。');
  }
  return decoded.result.valueBlock.valueHexView;
}

function checkNonce(basic: BasicOCSPResponse, expectedNonce?: Uint8Array): void {
  if (!expectedNonce) return;
  const nonceExtension = basic.tbsResponseData.responseExtensions?.find((item) => item.extnID === OCSP_NONCE_OID);
  if (!nonceExtension) throw new Error('OCSP 响应未回显请求 nonce。');
  if (!equalBytes(parseNonce(nonceExtension), expectedNonce)) {
    throw new Error('OCSP 响应 nonce 与请求不一致。');
  }
}

function statusFromCertStatus(certStatus: asn1js.BaseBlock): OcspStatus {
  if (certStatus.idBlock.tagNumber === 0 && !certStatus.idBlock.isConstructed) return 'good';
  if (certStatus.idBlock.tagNumber === 1 && certStatus.idBlock.isConstructed) return 'revoked';
  return 'unknown';
}

function invalid(detail: string, status?: OcspStatus): OcspVerificationResult {
  return { ok: false, ...(status ? { status } : {}), detail };
}

/**
 * Verify one raw OCSP response with PKI.js and a pinned issuer certificate.
 * The library performs ASN.1, response-signature and certificate-chain work;
 * this adapter adds CertID, responder authorization, nonce and freshness
 * policy checks that are specific to this verifier.
 */
export async function verifyCertificateWithOcsp(
  responseBytes: Uint8Array,
  certificate: Certificate,
  issuerCertificate: Certificate,
  options: OcspVerificationOptions = {},
): Promise<OcspVerificationResult> {
  const serial = serialHex(certificate.serialNumber);
  try {
    if (!certificate.issuer.isEqual(issuerCertificate.subject)) {
      return invalid('OCSP 检查要求 TSA 证书由固定 FreeTSA 根证书直接签发。');
    }
    const { basic } = parseExactOcspResponse(responseBytes);
    const responder = await findResponderCertificate(basic, issuerCertificate);
    if (!responderIsAuthorized(responder, issuerCertificate)) {
      return invalid('OCSP 响应者证书未由 TSA CA 直接授权，或缺少 id-kp-OCSPSigning EKU。');
    }

    if (!basic.certs) basic.certs = [];
    if (!basic.certs.some((candidate) => candidate instanceof Certificate && isSameCertificate(candidate, responder))) {
      basic.certs.push(responder);
    }
    const signatureVerified = await basic.verify({ trustedCerts: [issuerCertificate] });
    if (!signatureVerified) return invalid('OCSP Basic 响应签名验证失败。');
    checkNonce(basic, options.expectedNonce);

    const expectedCertId = await CertID.create(certificate, {
      hashAlgorithm: 'SHA-256',
      issuerCertificate,
    });
    const matchingResponses = basic.tbsResponseData.responses.filter((item) => item.certID.isEqual(expectedCertId));
    if (matchingResponses.length === 0) {
      return invalid(`OCSP 响应未包含 TSA 证书序列号 ${serial} 的匹配 CertID。`);
    }
    if (matchingResponses.length !== 1) {
      return invalid(`OCSP 响应包含 ${matchingResponses.length} 个相同 TSA 证书的 CertID，无法确定唯一状态。`);
    }
    const matchingResponse = matchingResponses[0];

    const status = statusFromCertStatus(matchingResponse.certStatus);
    const producedAt = basic.tbsResponseData.producedAt;
    const thisUpdate = matchingResponse.thisUpdate;
    const nextUpdate = matchingResponse.nextUpdate;
    const checkDate = options.checkDate ?? new Date();
    const clockSkewMs = options.clockSkewMs ?? OCSP_CLOCK_SKEW_MS;
    const maxAgeMs = options.maxAgeMs ?? OCSP_MAX_AGE_MS;
    if (!Number.isFinite(checkDate.getTime())) return invalid('OCSP 检查时间无效。', status);
    if (!Number.isFinite(producedAt?.getTime()) || !Number.isFinite(thisUpdate?.getTime())) {
      return invalid('OCSP 响应缺少有效的 producedAt 或 thisUpdate。', status);
    }
    if (!Number.isFinite(clockSkewMs) || clockSkewMs < 0 || !Number.isFinite(maxAgeMs) || maxAgeMs < 0) {
      return invalid('OCSP 时钟容差或最大响应年龄无效。', status);
    }
    if (producedAt.getTime() > checkDate.getTime() + clockSkewMs) {
      return invalid(`OCSP 响应尚未产生（producedAt ${producedAt.toISOString()}）。`, status);
    }
    if (thisUpdate.getTime() > checkDate.getTime() + clockSkewMs) {
      return invalid(`OCSP 状态尚未生效（thisUpdate ${thisUpdate.toISOString()}）。`, status);
    }
    if (producedAt.getTime() + clockSkewMs < thisUpdate.getTime()) {
      return invalid('OCSP producedAt 早于 thisUpdate。', status);
    }
    if (nextUpdate) {
      if (!Number.isFinite(nextUpdate.getTime()) || nextUpdate.getTime() <= thisUpdate.getTime()) {
        return invalid('OCSP nextUpdate 无效或不晚于 thisUpdate。', status);
      }
      if (nextUpdate.getTime() < checkDate.getTime() - clockSkewMs) {
        return invalid(`OCSP 响应已过期（nextUpdate ${nextUpdate.toISOString()}）。`, status);
      }
    } else if (checkDate.getTime() - thisUpdate.getTime() > maxAgeMs + clockSkewMs) {
      return invalid(`OCSP 响应没有 nextUpdate，且已超过 ${Math.floor(maxAgeMs / 3600000)} 小时最大年龄。`, status);
    }

    const timeDetail = nextUpdate
      ? `有效期 ${thisUpdate.toISOString()} 至 ${nextUpdate.toISOString()}`
      : `thisUpdate ${thisUpdate.toISOString()}（未提供 nextUpdate，最大年龄 ${Math.floor(maxAgeMs / 3600000)} 小时）`;
    const subject = subjectLabel(responder);
    if (status === 'good') {
      return {
        ok: true,
        status,
        serial,
        producedAt,
        thisUpdate,
        nextUpdate,
        responderSubject: subject,
        detail: `OCSP 签名、响应者证书链、CertID 和时效验证通过；TSA 证书序列号 ${serial} 状态为 good（${timeDetail}）。`,
      };
    }
    if (status === 'revoked') {
      return {
        ok: false,
        status,
        serial,
        producedAt,
        thisUpdate,
        nextUpdate,
        responderSubject: subject,
        detail: `OCSP 签名和 CertID 验证通过，但 TSA 证书序列号 ${serial} 状态为 revoked（${timeDetail}）。`,
      };
    }
    return {
      ok: false,
      status,
      serial,
      producedAt,
      thisUpdate,
      nextUpdate,
      responderSubject: subject,
      detail: `OCSP 签名和 CertID 验证通过，但 TSA 证书序列号 ${serial} 状态为 unknown（${timeDetail}）。`,
    };
  } catch (error) {
    return invalid(`OCSP 验证失败：${errorMessage(error, '未知错误')}`);
  }
}
