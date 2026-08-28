import * as asn1js from 'asn1js';
import { Certificate, CertificateRevocationList } from 'pkijs';
import { MAX_REVOCATION_CRL_BYTES, REVOCATION_CLOCK_SKEW_MS } from './revocation-config.ts';
export {
  FREETSA_CRL_MIRROR_PATH,
  FREETSA_CRL_SOURCE_URL,
  FREETSA_TSA_URL,
  MAX_REVOCATION_CRL_BYTES,
  REVOCATION_CLOCK_SKEW_MS,
} from './revocation-config.ts';

const CRL_REASON_OID = '2.5.29.21';
const CRL_REASONS: Record<number, string> = {
  0: 'unspecified',
  1: 'keyCompromise',
  2: 'cACompromise',
  3: 'affiliationChanged',
  4: 'superseded',
  5: 'cessationOfOperation',
  6: 'certificateHold',
  8: 'removeFromCRL',
  9: 'privilegeWithdrawn',
  10: 'aACompromise',
};

export interface CrlVerificationResult {
  ok: boolean;
  detail: string;
  thisUpdate?: Date;
  nextUpdate?: Date;
  revocationDate?: Date;
  serial?: string;
}

export interface CrlVerificationOptions {
  checkDate?: Date;
  clockSkewMs?: number;
}

function exactArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}

function decodePemOrDer(bytes: Uint8Array): Uint8Array {
  let text: string;
  try {
    text = new TextDecoder('ascii', { fatal: true }).decode(bytes).trim();
  } catch {
    return bytes;
  }

  if (!text.startsWith('-----BEGIN')) return bytes;
  const match = text.match(
    /^-----BEGIN (?:X509 )?CRL-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END (?:X509 )?CRL-----$/,
  );
  if (!match) throw new Error('CRL PEM 包含无效的 BEGIN/END 标记。');
  const encoded = match[1].replace(/\s+/g, '');
  if (!encoded || encoded.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) {
    throw new Error('CRL PEM 包含无效的 Base64 内容。');
  }
  try {
    const binary = atob(encoded);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    throw new Error('CRL PEM 的 Base64 内容无法解码。');
  }
}

/** Parse a complete DER CRL or a complete PEM-wrapped CRL. */
export function parseCertificateRevocationList(bytes: Uint8Array): CertificateRevocationList {
  if (bytes.byteLength === 0) throw new Error('CRL 为空。');
  if (bytes.byteLength > MAX_REVOCATION_CRL_BYTES) {
    throw new Error(`CRL 超过 ${Math.floor(MAX_REVOCATION_CRL_BYTES / 1024)} KiB 限制。`);
  }
  const der = decodePemOrDer(bytes);
  if (der.byteLength > MAX_REVOCATION_CRL_BYTES) {
    throw new Error(`CRL 解码后超过 ${Math.floor(MAX_REVOCATION_CRL_BYTES / 1024)} KiB 限制。`);
  }
  const decoded = asn1js.fromBER(exactArrayBuffer(der));
  if (decoded.offset === -1 || decoded.offset !== der.byteLength) {
    throw new Error('CRL 包含无效 ASN.1，或末尾存在未解析字节。');
  }
  return CertificateRevocationList.fromBER(exactArrayBuffer(der));
}

function serialHex(serial: asn1js.Integer): string {
  return Array.from(serial.valueBlock.valueHexView, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function revokedReason(entry: NonNullable<CertificateRevocationList['revokedCertificates']>[number]): string | undefined {
  const extension = entry.crlEntryExtensions?.extensions.find((item) => item.extnID === CRL_REASON_OID);
  if (!extension) return undefined;
  try {
    const encodedReason = extension.extnValue.valueBlock.valueHexView;
    const decoded = asn1js.fromBER(exactArrayBuffer(encodedReason));
    if (decoded.offset === -1 || decoded.offset !== extension.extnValue.valueBlock.valueHexView.byteLength) {
      return 'unknown (invalid CRLReason ASN.1)';
    }
    const value = decoded.result;
    if (value instanceof asn1js.Enumerated || value instanceof asn1js.Integer) {
      return CRL_REASONS[value.valueBlock.valueDec] || `unknown (${value.valueBlock.valueDec})`;
    }
  } catch {
    return 'unknown (invalid CRLReason ASN.1)';
  }
  return 'unknown';
}

function invalid(detail: string): CrlVerificationResult {
  return { ok: false, detail };
}

/**
 * Verify a CA-signed CRL and use it to check one certificate serial number.
 * The caller is responsible for pinning the issuer certificate as a trust
 * anchor; this function never trusts certificates embedded in the CRL.
 */
export async function verifyCertificateWithCrl(
  crlBytes: Uint8Array,
  certificate: Certificate,
  issuerCertificate: Certificate,
  options: CrlVerificationOptions = {},
): Promise<CrlVerificationResult> {
  let crl: CertificateRevocationList;
  try {
    crl = parseCertificateRevocationList(crlBytes);
  } catch (error) {
    return invalid(errorMessage(error, 'CRL 无法解析。'));
  }

  if (!crl.issuer.isEqual(issuerCertificate.subject) || !certificate.issuer.isEqual(issuerCertificate.subject)) {
    return invalid('CRL 签发者与 TSA 证书的签发者不一致。');
  }
  if (crl.signature.algorithmId !== crl.signatureAlgorithm.algorithmId) {
    return invalid('CRL 的 TBS 签名算法与外层签名算法不一致。');
  }

  let signatureVerified = false;
  try {
    signatureVerified = await crl.verify({ issuerCertificate });
  } catch (error) {
    return invalid(`CRL 签名验证失败：${errorMessage(error, '未知错误')}`);
  }
  if (!signatureVerified) return invalid('CRL 签名验证失败。');

  const thisUpdate = crl.thisUpdate?.value;
  const nextUpdate = crl.nextUpdate?.value;
  const checkDate = options.checkDate ?? new Date();
  const clockSkewMs = options.clockSkewMs ?? REVOCATION_CLOCK_SKEW_MS;
  if (!thisUpdate || !Number.isFinite(thisUpdate.getTime()) || !nextUpdate || !Number.isFinite(nextUpdate.getTime())) {
    return invalid('CRL 缺少有效的 thisUpdate 或 nextUpdate。');
  }
  if (!Number.isFinite(checkDate.getTime())) return invalid('CRL 检查时间无效。');
  if (!Number.isFinite(clockSkewMs) || clockSkewMs < 0) return invalid('CRL 时钟容差无效。');
  if (nextUpdate.getTime() <= thisUpdate.getTime()) return invalid('CRL 的 nextUpdate 不晚于 thisUpdate。');
  if (thisUpdate.getTime() > checkDate.getTime() + clockSkewMs) {
    return invalid(`CRL 尚未生效（thisUpdate ${thisUpdate.toISOString()}）。`);
  }
  if (nextUpdate.getTime() < checkDate.getTime() - clockSkewMs) {
    return invalid(`CRL 已过期（nextUpdate ${nextUpdate.toISOString()}）。`);
  }

  const serial = serialHex(certificate.serialNumber);
  const revoked = crl.revokedCertificates?.find((entry) => entry.userCertificate.isEqual(certificate.serialNumber));
  if (revoked) {
    const revocationDate = revoked.revocationDate.value;
    if (!revocationDate || !Number.isFinite(revocationDate.getTime())) {
      return invalid(`TSA 证书序列号 ${serial} 的 CRL 吊销日期无效。`);
    }
    const reason = revokedReason(revoked);
    return {
      ok: false,
      detail: `TSA 证书序列号 ${serial} 已被 CRL 吊销（${revocationDate.toISOString()}${reason ? `，原因 ${reason}` : ''}）。`,
      thisUpdate,
      nextUpdate,
      revocationDate,
      serial,
    };
  }

  return {
    ok: true,
    detail: `CRL 签名和有效期验证通过（${thisUpdate.toISOString()} 至 ${nextUpdate.toISOString()}）；TSA 证书序列号 ${serial} 未被列入吊销列表。`,
    thisUpdate,
    nextUpdate,
    serial,
  };
}
