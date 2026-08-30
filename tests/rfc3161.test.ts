import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  inspectTimestampReceipt,
  TimestampReceiptError,
  verifyTimestampReceipt,
} from '../tools/rfc3161.ts';

const SHA256_OID = '2.16.840.1.101.3.4.2.1';
const SIGNED_DATA_OID = '1.2.840.113549.1.7.2';
const TST_INFO_OID = '1.2.840.113549.1.9.16.1.4';

function der(tag: number, value: Uint8Array): Uint8Array {
  const length = value.byteLength;
  const lengthBytes = length < 128
    ? Uint8Array.of(length)
    : (() => {
        const octets: number[] = [];
        let remaining = length;
        while (remaining > 0) {
          octets.unshift(remaining & 0xff);
          remaining >>>= 8;
        }
        return Uint8Array.of(0x80 | octets.length, ...octets);
      })();
  return Uint8Array.of(tag, ...lengthBytes, ...value);
}

function concat(...values: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(values.reduce((total, value) => total + value.byteLength, 0));
  let offset = 0;
  for (const value of values) {
    result.set(value, offset);
    offset += value.byteLength;
  }
  return result;
}

function sequence(...values: Uint8Array[]): Uint8Array {
  return der(0x30, concat(...values));
}

function setOf(...values: Uint8Array[]): Uint8Array {
  return der(0x31, concat(...values));
}

function octet(value: Uint8Array): Uint8Array {
  return der(0x04, value);
}

function integer(value: number | Uint8Array): Uint8Array {
  if (value instanceof Uint8Array) return der(0x02, value);
  if (value < 0 || !Number.isSafeInteger(value)) throw new Error('test integer must be non-negative');
  const octets: number[] = [];
  let remaining = value;
  do {
    octets.unshift(remaining & 0xff);
    remaining = Math.floor(remaining / 256);
  } while (remaining > 0);
  if (octets[0] & 0x80) octets.unshift(0);
  return der(0x02, Uint8Array.from(octets));
}

function oid(value: string): Uint8Array {
  const arcs = value.split('.').map((part) => BigInt(part));
  if (arcs.length < 2 || arcs[0] > 2n || arcs[1] < 0n || (arcs[0] < 2n && arcs[1] >= 40n)) {
    throw new Error(`invalid test OID: ${value}`);
  }
  const encoded: number[] = [];
  const first = (arcs[0] * 40n) + arcs[1];
  for (const arc of [first, ...arcs.slice(2)]) {
    const octets = [Number(arc & 0x7fn)];
    let remaining = arc >> 7n;
    while (remaining > 0n) {
      octets.unshift(Number(remaining & 0x7fn) | 0x80);
      remaining >>= 7n;
    }
    encoded.push(...octets);
  }
  return der(0x06, Uint8Array.from(encoded));
}

function generalizedTime(value: string): Uint8Array {
  return der(0x18, new TextEncoder().encode(value));
}

function hex(value: string): Uint8Array {
  return Uint8Array.from(value.match(/../g) || [], (part) => Number.parseInt(part, 16));
}

function timestampReceipt(
  data: Uint8Array,
  generatedAt: string,
  imprint = data,
  accuracy?: { seconds?: number; millis?: number; micros?: number },
): Uint8Array {
  const digest = sha256(imprint);
  const accuracyFields = accuracy
    ? [
        ...(accuracy.seconds === undefined ? [] : [integer(accuracy.seconds)]),
        ...(accuracy.millis === undefined ? [] : [der(0x80, integer(accuracy.millis).subarray(2))]),
        ...(accuracy.micros === undefined ? [] : [der(0x81, integer(accuracy.micros).subarray(2))]),
      ]
    : [];
  const tstInfo = sequence(
    integer(1),
    oid('1.2.3.4'),
    sequence(
      sequence(oid(SHA256_OID), der(0x05, new Uint8Array())),
      octet(digest),
    ),
    integer(hex('0102030405060708090a0b0c0d0e0f101112131415161718')), 
    generalizedTime(generatedAt),
    ...(accuracy ? [sequence(...accuracyFields)] : []),
  );
  const encapContentInfo = sequence(
    oid(TST_INFO_OID),
    der(0xa0, octet(tstInfo)),
  );
  const signedData = sequence(
    integer(1),
    setOf(),
    encapContentInfo,
    setOf(),
  );
  const contentInfo = sequence(
    oid(SIGNED_DATA_OID),
    der(0xa0, signedData),
  );
  return sequence(sequence(integer(0)), contentInfo);
}

function sha256(value: Uint8Array): Uint8Array {
  // Test vectors use Node's synchronous hash so this helper remains usable by
  // the synchronous DER fixture builder.
  return new Uint8Array(createHash('sha256').update(value).digest());
}

test('parses a granted RFC 3161 response and validates its SHA-256 imprint', () => {
  const data = new TextEncoder().encode('{"commitmentHash":"abc"}\n');
  const receipt = timestampReceipt(data, '20260830040506.123Z');
  const result = inspectTimestampReceipt(data, receipt);

  assert.equal(result.generatedAt, '2026-08-30T04:05:06.123Z');
  assert.equal(result.dataSha256, result.messageImprintSha256);
  assert.equal(result.messageImprintAlgorithm, SHA256_OID);
  assert.equal(result.receiptSha256.length, 64);
  assert.equal(result.accuracy, null);
});

test('parses RFC 3161 accuracy components without losing microseconds', () => {
  const data = new TextEncoder().encode('accuracy');
  const receipt = timestampReceipt(data, '20260830040506.123456Z', data, {
    seconds: 1,
    millis: 250,
    micros: 7,
  });
  const result = inspectTimestampReceipt(data, receipt);

  assert.deepEqual(result.accuracy, {
    seconds: 1,
    millis: 250,
    micros: 7,
    totalMicros: '1250007',
  });
  assert.equal(result.generatedAt, '2026-08-30T04:05:06.123Z');
});

test('uses the accuracy-adjusted upper bound for the round boundary', () => {
  const data = new TextEncoder().encode('accuracy-boundary');
  const receipt = timestampReceipt(data, '20260830040506.123456Z', data, {
    seconds: 1,
    millis: 250,
  });
  const directory = mkdtempSync(join(tmpdir(), 'campaign-verifier-test-'));
  const dataPath = join(directory, 'data');
  const receiptPath = join(directory, 'receipt.tsr');
  const caPath = join(directory, 'ca.pem');
  writeFileSync(dataPath, data);
  writeFileSync(receiptPath, receipt);
  writeFileSync(caPath, 'not a certificate');
  try {
    assert.throws(
      () => verifyTimestampReceipt({
        dataPath,
        receiptPath,
        caPath,
        roundTime: '2026-08-30T04:05:07.000Z',
      }),
      (error) => error instanceof TimestampReceiptError
        && error.code === 'TSA_TIMESTAMP_AFTER_ROUND',
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('requires an explicit accuracy bound when a receipt omits accuracy', () => {
  const data = new TextEncoder().encode('missing-accuracy');
  const receipt = timestampReceipt(data, '20260830040506Z');
  const directory = mkdtempSync(join(tmpdir(), 'campaign-verifier-test-'));
  const dataPath = join(directory, 'data');
  const receiptPath = join(directory, 'receipt.tsr');
  const caPath = join(directory, 'ca.pem');
  writeFileSync(dataPath, data);
  writeFileSync(receiptPath, receipt);
  writeFileSync(caPath, 'not a certificate');
  try {
    assert.throws(
      () => verifyTimestampReceipt({
        dataPath,
        receiptPath,
        caPath,
        roundTime: '2026-08-30T04:05:07.000Z',
      }),
      (error) => error instanceof TimestampReceiptError
        && error.code === 'TSA_ACCURACY_UNAVAILABLE',
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('rejects a receipt whose message imprint covers different bytes', () => {
  const data = new TextEncoder().encode('archived commitment');
  const receipt = timestampReceipt(data, '20260830040506Z', new TextEncoder().encode('different bytes'));

  assert.throws(
    () => inspectTimestampReceipt(data, receipt),
    (error) => error instanceof TimestampReceiptError
      && error.code === 'TSA_MESSAGE_IMPRINT_MISMATCH',
  );
});

test('rejects malformed or non-granted timestamp responses', () => {
  const data = new TextEncoder().encode('data');
  const granted = timestampReceipt(data, '20260830040506Z');
  const trailing = concat(granted, Uint8Array.of(0));
  assert.throws(
    () => inspectTimestampReceipt(data, trailing),
    (error) => error instanceof TimestampReceiptError && error.code === 'TSA_RECEIPT_MALFORMED',
  );

  const rejected = sequence(sequence(integer(2)));
  assert.throws(
    () => inspectTimestampReceipt(data, rejected),
    (error) => error instanceof TimestampReceiptError && error.code === 'TSA_RECEIPT_REJECTED',
  );
});
