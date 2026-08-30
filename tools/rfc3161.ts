import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const SHA256_OID = '2.16.840.1.101.3.4.2.1';
const SIGNED_DATA_OID = '1.2.840.113549.1.7.2';
const TST_INFO_OID = '1.2.840.113549.1.9.16.1.4';
const MAX_TIMESTAMP_INPUT_BYTES = 16 * 1024 * 1024;

export interface TimestampReceiptDetails {
  generatedAt: string;
  generatedAtMs: number;
  accuracy: {
    seconds: number;
    millis: number;
    micros: number;
    totalMicros: string;
  } | null;
  dataSha256: string;
  receiptSha256: string;
  messageImprintAlgorithm: string;
  messageImprintSha256: string;
  policyOid: string;
}

export interface TimestampVerificationOptions {
  dataPath: string;
  receiptPath: string;
  caPath: string;
  untrustedPath?: string;
  policy?: string;
  roundTime?: string | number;
  /** Maximum permitted accuracy in milliseconds when the token omits accuracy. */
  maxAccuracyMs?: number;
  opensslPath?: string;
}

export interface TimestampVerificationResult extends TimestampReceiptDetails {
  signatureVerified: true;
  beforeRound: boolean | null;
  roundTime?: string;
}

export class TimestampReceiptError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'TimestampReceiptError';
    this.code = code;
  }
}

interface DerElement {
  tag: number;
  constructed: boolean;
  start: number;
  end: number;
  next: number;
}

interface ParsedTimestampReceiptDetails extends TimestampReceiptDetails {
  generatedAtEpochMicros: bigint;
  accuracyMicros: bigint;
}

function fail(code: string, message: string): never {
  throw new TimestampReceiptError(code, message);
}

function requireTag(element: DerElement, tag: number, label: string): void {
  if (element.tag !== tag) {
    fail('TSA_RECEIPT_MALFORMED', `${label} has an unexpected ASN.1 tag`);
  }
}

function readDerElement(bytes: Uint8Array, offset: number): DerElement {
  if (offset >= bytes.length) fail('TSA_RECEIPT_MALFORMED', 'ASN.1 element is truncated');
  const tag = bytes[offset];
  // RFC 3161 structures used here only need low-tag-number encodings. Reject
  // high-tag-number forms instead of silently interpreting a different tree.
  if ((tag & 0x1f) === 0x1f) fail('TSA_RECEIPT_MALFORMED', 'high-tag-number ASN.1 is not supported');
  let cursor = offset + 1;
  if (cursor >= bytes.length) fail('TSA_RECEIPT_MALFORMED', 'ASN.1 length is truncated');
  const firstLength = bytes[cursor++];
  let length: number;
  if (firstLength === 0x80) {
    fail('TSA_RECEIPT_MALFORMED', 'indefinite-length ASN.1 is not valid DER');
  }
  if ((firstLength & 0x80) === 0) {
    length = firstLength;
  } else {
    const octets = firstLength & 0x7f;
    if (octets === 0 || octets > 4 || cursor + octets > bytes.length) {
      fail('TSA_RECEIPT_MALFORMED', 'ASN.1 length is invalid');
    }
    if (bytes[cursor] === 0) fail('TSA_RECEIPT_MALFORMED', 'ASN.1 length is not minimally encoded');
    length = 0;
    for (let index = 0; index < octets; index += 1) {
      length = (length * 256) + bytes[cursor + index];
    }
    cursor += octets;
  }
  const end = cursor + length;
  if (end > bytes.length) fail('TSA_RECEIPT_MALFORMED', 'ASN.1 element exceeds the receipt length');
  return {
    tag,
    constructed: (tag & 0x20) !== 0,
    start: cursor,
    end,
    next: end,
  };
}

function children(bytes: Uint8Array, element: DerElement, label: string): DerElement[] {
  if (!element.constructed) fail('TSA_RECEIPT_MALFORMED', `${label} is not a constructed ASN.1 value`);
  const result: DerElement[] = [];
  let cursor = element.start;
  while (cursor < element.end) {
    const child = readDerElement(bytes, cursor);
    if (child.next > element.end) fail('TSA_RECEIPT_MALFORMED', `${label} contains a truncated child`);
    result.push(child);
    cursor = child.next;
  }
  if (cursor !== element.end) fail('TSA_RECEIPT_MALFORMED', `${label} has an invalid child boundary`);
  return result;
}

function content(bytes: Uint8Array, element: DerElement): Uint8Array {
  return bytes.subarray(element.start, element.end);
}

function decodeIntegerValue(bytes: Uint8Array, element: DerElement, label: string): bigint {
  requireTag(element, 0x02, label);
  const value = content(bytes, element);
  if (!value.length || (value[0] & 0x80) !== 0) {
    fail('TSA_RECEIPT_MALFORMED', `${label} must be a non-negative INTEGER`);
  }
  let result = 0n;
  for (const octet of value) result = (result << 8n) | BigInt(octet);
  return result;
}

function decodeSmallInteger(bytes: Uint8Array, element: DerElement, label: string): number {
  const result = decodeIntegerValue(bytes, element, label);
  if (result > BigInt(Number.MAX_SAFE_INTEGER)) {
    fail('TSA_RECEIPT_MALFORMED', `${label} is too large`);
  }
  return Number(result);
}

function decodeImplicitSmallInteger(bytes: Uint8Array, element: DerElement, tag: number, label: string): number {
  requireTag(element, tag, label);
  const value = content(bytes, element);
  if (!value.length || (value[0] & 0x80) !== 0) {
    fail('TSA_RECEIPT_MALFORMED', `${label} must be a non-negative INTEGER`);
  }
  let result = 0n;
  for (const octet of value) result = (result << 8n) | BigInt(octet);
  if (result > BigInt(Number.MAX_SAFE_INTEGER)) {
    fail('TSA_RECEIPT_MALFORMED', `${label} is too large`);
  }
  return Number(result);
}

function decodeOid(bytes: Uint8Array, element: DerElement, label: string): string {
  requireTag(element, 0x06, label);
  const value = content(bytes, element);
  if (!value.length) fail('TSA_RECEIPT_MALFORMED', `${label} is empty`);
  const arcs: string[] = [];
  let current = 0n;
  let terminated = false;
  for (const octet of value) {
    current = (current << 7n) | BigInt(octet & 0x7f);
    if ((octet & 0x80) === 0) {
      arcs.push(current.toString());
      current = 0n;
      terminated = true;
    } else {
      terminated = false;
    }
  }
  if (!terminated || arcs.length === 0) fail('TSA_RECEIPT_MALFORMED', `${label} is truncated`);
  const first = BigInt(arcs.shift() as string);
  const firstArc = first < 40n ? 0n : first < 80n ? 1n : 2n;
  const secondArc = first - (firstArc * 40n);
  return [firstArc.toString(), secondArc.toString(), ...arcs].join('.');
}

function bytesToHex(value: Uint8Array): string {
  return Array.from(value, (octet) => octet.toString(16).padStart(2, '0')).join('');
}

function decodeGeneralizedTime(bytes: Uint8Array, element: DerElement): {
  iso: string;
  ms: number;
  epochMicros: bigint;
} {
  requireTag(element, 0x18, 'TSTInfo.genTime');
  const value = Buffer.from(content(bytes, element)).toString('ascii');
  const match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d+))?Z$/.exec(value);
  if (!match) fail('TSA_RECEIPT_MALFORMED', 'TSTInfo.genTime is not a UTC GeneralizedTime');
  const [, yearText, monthText, dayText, hourText, minuteText, secondText, fraction = ''] = match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  if (year < 1 || month < 1 || month > 12 || day < 1 || day > 31
    || hour > 23 || minute > 59 || second > 59) {
    fail('TSA_RECEIPT_MALFORMED', 'TSTInfo.genTime has an invalid date or time');
  }
  const fractionMs = fraction ? Number(fraction.slice(0, 3).padEnd(3, '0')) : 0;
  const fractionMicros = fraction ? Number(fraction.slice(3, 6).padEnd(3, '0')) : 0;
  const hasSubMicrosecondFraction = fraction.length > 6 && /[1-9]/.test(fraction.slice(6));
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(hour, minute, second, fractionMs);
  const ms = date.getTime();
  if (Number.isNaN(ms)
    || date.getUTCFullYear() !== year
    || date.getUTCMonth() !== month - 1
    || date.getUTCDate() !== day
    || date.getUTCHours() !== hour
    || date.getUTCMinutes() !== minute
    || date.getUTCSeconds() !== second) {
    fail('TSA_RECEIPT_MALFORMED', 'TSTInfo.genTime contains an impossible date');
  }
  return {
    iso: date.toISOString(),
    ms,
    // Keep the comparison conservative when GeneralizedTime carries more
    // than microsecond precision: rounding up cannot turn an uncertain
    // timestamp into a false "before round" result.
    epochMicros: (BigInt(ms) * 1000n) + BigInt(fractionMicros)
      + (hasSubMicrosecondFraction ? 1n : 0n),
  };
}

function parseAccuracy(bytes: Uint8Array, element: DerElement): {
  seconds: number;
  millis: number;
  micros: number;
  totalMicros: bigint;
} {
  requireTag(element, 0x30, 'TSTInfo.accuracy');
  const fields = children(bytes, element, 'TSTInfo.accuracy');
  let seconds = 0;
  let millis = 0;
  let micros = 0;
  let previousTag = -1;
  for (const field of fields) {
    if (field.tag <= previousTag) {
      fail('TSA_RECEIPT_MALFORMED', 'TSTInfo.accuracy fields are duplicated or out of order');
    }
    previousTag = field.tag;
    if (field.tag === 0x02) {
      seconds = decodeSmallInteger(bytes, field, 'TSTInfo.accuracy.seconds');
    } else if (field.tag === 0x80) {
      millis = decodeImplicitSmallInteger(bytes, field, 0x80, 'TSTInfo.accuracy.millis');
      if (millis < 1 || millis > 999) {
        fail('TSA_RECEIPT_MALFORMED', 'TSTInfo.accuracy.millis must be between 1 and 999');
      }
    } else if (field.tag === 0x81) {
      micros = decodeImplicitSmallInteger(bytes, field, 0x81, 'TSTInfo.accuracy.micros');
      if (micros < 1 || micros > 999) {
        fail('TSA_RECEIPT_MALFORMED', 'TSTInfo.accuracy.micros must be between 1 and 999');
      }
    } else {
      fail('TSA_RECEIPT_MALFORMED', 'TSTInfo.accuracy contains an unexpected field');
    }
  }
  return {
    seconds,
    millis,
    micros,
    totalMicros: (BigInt(seconds) * 1_000_000n) + (BigInt(millis) * 1_000n) + BigInt(micros),
  };
}

function parseTstInfo(bytes: Uint8Array): ParsedTimestampReceiptDetails {
  const root = readDerElement(bytes, 0);
  requireTag(root, 0x30, 'TSTInfo');
  if (root.next !== bytes.length) fail('TSA_RECEIPT_MALFORMED', 'TSTInfo contains trailing bytes');
  const fields = children(bytes, root, 'TSTInfo');
  if (fields.length < 5) fail('TSA_RECEIPT_MALFORMED', 'TSTInfo is missing required fields');
  const version = decodeSmallInteger(bytes, fields[0], 'TSTInfo.version');
  if (version !== 1) fail('TSA_RECEIPT_MALFORMED', `unsupported TSTInfo.version ${version}`);
  const policyOid = decodeOid(bytes, fields[1], 'TSTInfo.policy');

  requireTag(fields[2], 0x30, 'TSTInfo.messageImprint');
  const imprintFields = children(bytes, fields[2], 'TSTInfo.messageImprint');
  if (imprintFields.length !== 2) fail('TSA_RECEIPT_MALFORMED', 'TSTInfo.messageImprint is malformed');
  requireTag(imprintFields[0], 0x30, 'TSTInfo.messageImprint.algorithm');
  const algorithmFields = children(bytes, imprintFields[0], 'TSTInfo.messageImprint.algorithm');
  if (!algorithmFields.length) fail('TSA_RECEIPT_MALFORMED', 'TSTInfo.messageImprint algorithm is missing');
  const messageImprintAlgorithm = decodeOid(bytes, algorithmFields[0], 'TSTInfo.messageImprint.algorithm');
  requireTag(imprintFields[1], 0x04, 'TSTInfo.messageImprint.digest');
  const messageImprintSha256 = bytesToHex(content(bytes, imprintFields[1]));
  if (messageImprintAlgorithm !== SHA256_OID || content(bytes, imprintFields[1]).length !== 32) {
    fail('TSA_RECEIPT_UNSUPPORTED_DIGEST', 'RFC 3161 receipt must use a 32-byte SHA-256 message imprint');
  }

  // RFC 3161 serial numbers are commonly wider than JavaScript's safe integer
  // range. Validate their DER sign/shape, but never coerce them to Number.
  decodeIntegerValue(bytes, fields[3], 'TSTInfo.serialNumber');
  const generated = decodeGeneralizedTime(bytes, fields[4]);
  let accuracy: ParsedTimestampReceiptDetails['accuracy'] = null;
  let accuracyMicros = 0n;
  if (fields[5]?.tag === 0x30) {
    const parsedAccuracy = parseAccuracy(bytes, fields[5]);
    accuracy = {
      seconds: parsedAccuracy.seconds,
      millis: parsedAccuracy.millis,
      micros: parsedAccuracy.micros,
      totalMicros: parsedAccuracy.totalMicros.toString(),
    };
    accuracyMicros = parsedAccuracy.totalMicros;
  }
  return {
    generatedAt: generated.iso,
    generatedAtMs: generated.ms,
    accuracy,
    dataSha256: '',
    receiptSha256: '',
    messageImprintAlgorithm,
    messageImprintSha256,
    policyOid,
    generatedAtEpochMicros: generated.epochMicros,
    accuracyMicros,
  };
}

function parseTimestampToken(receipt: Uint8Array): Uint8Array {
  const response = readDerElement(receipt, 0);
  requireTag(response, 0x30, 'TimeStampResp');
  if (response.next !== receipt.length) fail('TSA_RECEIPT_MALFORMED', 'TimeStampResp contains trailing bytes');
  const responseFields = children(receipt, response, 'TimeStampResp');
  if (!responseFields.length || responseFields.length > 2) {
    fail('TSA_RECEIPT_MALFORMED', 'TimeStampResp status/token fields are malformed');
  }
  requireTag(responseFields[0], 0x30, 'TimeStampResp.status');
  const statusFields = children(receipt, responseFields[0], 'TimeStampResp.status');
  if (!statusFields.length) fail('TSA_RECEIPT_MALFORMED', 'TimeStampResp.status is empty');
  const status = decodeSmallInteger(receipt, statusFields[0], 'TimeStampResp.status.status');
  if (status !== 0 && status !== 1) {
    fail('TSA_RECEIPT_REJECTED', `TSA returned a non-granted status (${status})`);
  }
  if (responseFields.length < 2) {
    fail('TSA_RECEIPT_MALFORMED', 'granted TimeStampResp has no timestamp token');
  }

  requireTag(responseFields[1], 0x30, 'TimeStampResp.timeStampToken');
  const contentInfoFields = children(receipt, responseFields[1], 'ContentInfo');
  if (contentInfoFields.length < 2
    || decodeOid(receipt, contentInfoFields[0], 'ContentInfo.contentType') !== SIGNED_DATA_OID) {
    fail('TSA_RECEIPT_MALFORMED', 'TimeStampResp token is not CMS SignedData');
  }
  requireTag(contentInfoFields[1], 0xa0, 'ContentInfo.content');
  const signedDataValues = children(receipt, contentInfoFields[1], 'ContentInfo.content');
  if (signedDataValues.length !== 1) fail('TSA_RECEIPT_MALFORMED', 'CMS SignedData wrapper is malformed');
  const signedData = signedDataValues[0];
  requireTag(signedData, 0x30, 'SignedData');
  const signedDataFields = children(receipt, signedData, 'SignedData');
  if (signedDataFields.length < 3) fail('TSA_RECEIPT_MALFORMED', 'SignedData is missing encapContentInfo');
  const encapContentInfo = signedDataFields[2];
  requireTag(encapContentInfo, 0x30, 'SignedData.encapContentInfo');
  const encapFields = children(receipt, encapContentInfo, 'SignedData.encapContentInfo');
  if (encapFields.length < 2
    || decodeOid(receipt, encapFields[0], 'encapContentInfo.contentType') !== TST_INFO_OID) {
    fail('TSA_RECEIPT_MALFORMED', 'CMS token does not contain id-ct-TSTInfo');
  }
  requireTag(encapFields[1], 0xa0, 'encapContentInfo.eContent');
  const eContent = children(receipt, encapFields[1], 'encapContentInfo.eContent');
  if (eContent.length !== 1) fail('TSA_RECEIPT_MALFORMED', 'encapContentInfo.eContent is malformed');
  requireTag(eContent[0], 0x04, 'encapContentInfo.eContent.value');
  return content(receipt, eContent[0]);
}

function inspectTimestampReceiptInternal(data: Uint8Array, receipt: Uint8Array): ParsedTimestampReceiptDetails {
  const tstInfo = parseTstInfo(parseTimestampToken(receipt));
  const dataSha256 = bytesToHex(new Uint8Array(createHash('sha256').update(data).digest()));
  if (tstInfo.messageImprintSha256 !== dataSha256) {
    fail('TSA_MESSAGE_IMPRINT_MISMATCH', 'RFC 3161 message imprint does not match the archived data bytes');
  }
  const receiptSha256 = bytesToHex(new Uint8Array(createHash('sha256').update(receipt).digest()));
  return { ...tstInfo, dataSha256, receiptSha256 };
}

export function inspectTimestampReceipt(data: Uint8Array, receipt: Uint8Array): TimestampReceiptDetails {
  const { generatedAtEpochMicros: _generatedAtEpochMicros, accuracyMicros: _accuracyMicros, ...details } =
    inspectTimestampReceiptInternal(data, receipt);
  return details;
}

function readBoundedFile(filePath: string, label: string): Uint8Array {
  let size: number;
  try {
    const stat = statSync(filePath);
    if (!stat.isFile()) fail('TSA_INPUT_INVALID', `${label} is not a regular file`);
    size = stat.size;
  } catch (error) {
    if (error instanceof TimestampReceiptError) throw error;
    fail('TSA_INPUT_INVALID', `${label} cannot be read`);
  }
  if (size > MAX_TIMESTAMP_INPUT_BYTES) {
    fail('TSA_INPUT_TOO_LARGE', `${label} exceeds the ${MAX_TIMESTAMP_INPUT_BYTES} byte limit`);
  }
  try {
    const bytes = new Uint8Array(readFileSync(filePath));
    if (bytes.byteLength > MAX_TIMESTAMP_INPUT_BYTES) {
      fail('TSA_INPUT_TOO_LARGE', `${label} exceeds the ${MAX_TIMESTAMP_INPUT_BYTES} byte limit`);
    }
    return bytes;
  } catch (error) {
    if (error instanceof TimestampReceiptError) throw error;
    fail('TSA_INPUT_INVALID', `${label} cannot be read`);
  }
}

function parseRoundTime(value: string | number): { iso: string; ms: number; micros: bigint } {
  const numeric = typeof value === 'number'
    ? value
    : /^\d+(?:\.\d+)?$/.test(value.trim()) ? Number(value) : Number.NaN;
  const ms = Number.isFinite(numeric)
    ? (numeric < 1e12 ? numeric * 1000 : numeric)
    : Date.parse(String(value));
  if (!Number.isFinite(ms)) fail('TSA_ROUND_TIME_INVALID', 'round time is not a valid ISO date or epoch value');
  const date = new Date(ms);
  if (Number.isNaN(date.getTime())) fail('TSA_ROUND_TIME_INVALID', 'round time is not a valid date');
  const micros = Math.ceil(ms * 1000);
  if (!Number.isSafeInteger(micros)) {
    fail('TSA_ROUND_TIME_INVALID', 'round time is outside the supported precision range');
  }
  return { iso: date.toISOString(), ms, micros: BigInt(micros) };
}

function assertReadablePath(filePath: string, label: string): void {
  try {
    const stat = statSync(filePath);
    if (!stat.isFile()) fail('TSA_INPUT_INVALID', `${label} is not a regular file`);
  } catch (error) {
    if (error instanceof TimestampReceiptError) throw error;
    fail('TSA_INPUT_INVALID', `${label} cannot be read`);
  }
}

function opensslFailure(result: { status: number | null; error?: Error; stderr?: string; stdout?: string }): never {
  if (result.error) fail('TSA_OPENSSL_UNAVAILABLE', `OpenSSL could not be started: ${result.error.message}`);
  const detail = `${result.stderr || result.stdout || 'OpenSSL rejected the timestamp receipt'}`
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 1000);
  fail('TSA_SIGNATURE_INVALID', detail || `OpenSSL exited with status ${String(result.status)}`);
}

export function verifyTimestampReceipt(options: TimestampVerificationOptions): TimestampVerificationResult {
  assertReadablePath(options.dataPath, 'data file');
  assertReadablePath(options.receiptPath, 'receipt file');
  assertReadablePath(options.caPath, 'TSA CA bundle');
  if (options.untrustedPath) assertReadablePath(options.untrustedPath, 'TSA untrusted bundle');
  const data = readBoundedFile(options.dataPath, 'data file');
  const receipt = readBoundedFile(options.receiptPath, 'receipt file');
  const parsedDetails = inspectTimestampReceiptInternal(data, receipt);
  const {
    generatedAtEpochMicros: _generatedAtEpochMicros,
    accuracyMicros: _accuracyMicros,
    ...details
  } = parsedDetails;
  const round = options.roundTime === undefined ? undefined : parseRoundTime(options.roundTime);
  let effectiveAccuracyMicros = parsedDetails.accuracyMicros;
  if (round && !parsedDetails.accuracy) {
    if (options.maxAccuracyMs === undefined) {
      fail('TSA_ACCURACY_UNAVAILABLE', 'TSTInfo omits accuracy; provide maxAccuracyMs to establish a conservative upper bound');
    }
    if (!Number.isFinite(options.maxAccuracyMs)
      || options.maxAccuracyMs < 0
      || options.maxAccuracyMs > Number.MAX_SAFE_INTEGER / 1000) {
      fail('TSA_ACCURACY_INVALID', 'maxAccuracyMs must be a finite non-negative number');
    }
    effectiveAccuracyMicros = BigInt(Math.ceil(options.maxAccuracyMs * 1000));
  }
  const latestPossibleTimestampMicros = parsedDetails.generatedAtEpochMicros + effectiveAccuracyMicros;
  const beforeRound = round ? latestPossibleTimestampMicros < round.micros : null;
  if (round && !beforeRound) {
    fail('TSA_TIMESTAMP_AFTER_ROUND', `timestamp ${details.generatedAt} is not before drand round time ${round.iso}`);
  }
  if (options.policy && !/^\d+(?:\.\d+)+$/.test(options.policy)) {
    fail('TSA_POLICY_INVALID', 'TSA policy must be an object identifier such as 1.2.3.4');
  }

  const temporaryDirectory = mkdtempSync(join(tmpdir(), 'campaign-verifier-rfc3161-'));
  const exactReceiptPath = join(temporaryDirectory, 'receipt.tsr');
  try {
    writeFileSync(exactReceiptPath, receipt, { flag: 'wx', mode: 0o600 });
  } catch (error) {
    rmSync(temporaryDirectory, { recursive: true, force: true });
    fail('TSA_INPUT_INVALID', `cannot prepare an immutable receipt copy: ${error instanceof Error ? error.message : String(error)}`);
  }
  const args = [
    'ts', '-verify', '-digest', details.dataSha256, '-in', exactReceiptPath,
    '-CAfile', options.caPath,
    ...(options.untrustedPath ? ['-untrusted', options.untrustedPath] : []),
    ...(options.policy ? ['-policy', options.policy] : []),
  ];
  try {
    const result = spawnSync(options.opensslPath || 'openssl', args, {
      encoding: 'utf8',
      maxBuffer: 64 * 1024,
      windowsHide: true,
    });
    if (result.status !== 0) opensslFailure(result);
    return {
      ...details,
      signatureVerified: true,
      beforeRound,
      ...(round ? { roundTime: round.iso } : {}),
    };
  } finally {
    rmSync(temporaryDirectory, { recursive: true, force: true });
  }
}
