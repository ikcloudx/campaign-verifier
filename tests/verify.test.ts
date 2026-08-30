import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import * as asn1js from 'asn1js';
import { Accuracy, Certificate, GeneralName, OCSPRequest, SignedData, TimeStampResp, TSTInfo } from 'pkijs';
import {
  createDrawSeed,
  createSegmentedSnapshotManifest,
  createSnapshotCommitment,
  createSnapshotManifest,
  hashPublicProof,
  hashRules,
  sha256HexBytes,
  selectSegmentedWinners,
} from '../src/crypto.ts';
import {
  MAX_TICKET_COUNT,
  parseProof,
  parseSnapshotArchive,
  ProofValidationError,
  SUPPORTED_PROOF_VERSION,
} from '../src/proof-schema.ts';
import { verifyProofIntegrity, verifySnapshotArchive } from '../src/verify.ts';
import { MAX_RFC3161_RECEIPT_BYTES, verifyRfc3161Receipt } from '../src/rfc3161.ts';
import { createOcspRequest, verifyCertificateWithOcsp } from '../src/ocsp.ts';
import { MAX_REVOCATION_CRL_BYTES } from '../src/revocation-config.ts';

const fixture = JSON.parse(readFileSync(new URL('./fixtures/valid-proof.json', import.meta.url), 'utf8')) as Record<string, unknown>;

function cloneFixture(): Record<string, unknown> {
  return JSON.parse(JSON.stringify(fixture)) as Record<string, unknown>;
}

function exactArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function readTsaCertificates(receiptBytes: Uint8Array): [Certificate, Certificate] {
  const decoded = asn1js.fromBER(exactArrayBuffer(receiptBytes));
  assert.equal(decoded.offset, receiptBytes.byteLength);
  const response = new TimeStampResp({ schema: decoded.result });
  assert.ok(response.timeStampToken);
  const signedData = new SignedData({ schema: response.timeStampToken.content });
  const certificates = (signedData.certificates || [])
    .filter((certificate): certificate is Certificate => certificate instanceof Certificate);
  assert.equal(certificates.length, 2);
  return [certificates[0], certificates[1]];
}

function readBase64Fixture(name: string): Uint8Array {
  const encoded = readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8').replace(/\s/g, '');
  return new Uint8Array(Buffer.from(encoded, 'base64'));
}

function rewriteReceipt(
  receiptBytes: Uint8Array,
  mutate: (response: TimeStampResp, signedData: SignedData) => void,
): Uint8Array {
  const decoded = asn1js.fromBER(exactArrayBuffer(receiptBytes));
  assert.equal(decoded.offset, receiptBytes.byteLength);
  const response = new TimeStampResp({ schema: decoded.result });
  const token = response.timeStampToken;
  assert.ok(token);
  const signedData = new SignedData({ schema: token.content });
  mutate(response, signedData);
  token.content = signedData.toSchema();
  return new Uint8Array(response.toSchema().toBER(false));
}

function rewriteTstInfo(
  receiptBytes: Uint8Array,
  mutate: (tstInfo: TSTInfo) => void,
): Uint8Array {
  return rewriteReceipt(receiptBytes, (_response, signedData) => {
    const eContent = signedData.encapContentInfo.eContent;
    assert.ok(eContent);
    const decoded = asn1js.fromBER(exactArrayBuffer(eContent.valueBlock.valueHexView));
    assert.equal(decoded.offset, eContent.valueBlock.valueHexView.byteLength);
    const tstInfo = new TSTInfo({ schema: decoded.result });
    mutate(tstInfo);
    eContent.valueBlock.valueHexView = new Uint8Array(tstInfo.toSchema().toBER(false));
  });
}

function removeTimestampToken(receiptBytes: Uint8Array): Uint8Array {
  const decoded = asn1js.fromBER(exactArrayBuffer(receiptBytes));
  assert.equal(decoded.offset, receiptBytes.byteLength);
  const response = new TimeStampResp({ schema: decoded.result });
  response.timeStampToken = undefined;
  return new Uint8Array(response.toSchema().toBER(false));
}

function appendToTstInfo(receiptBytes: Uint8Array, suffix: Uint8Array): Uint8Array {
  return rewriteReceipt(receiptBytes, (_response, signedData) => {
    const eContent = signedData.encapContentInfo.eContent;
    assert.ok(eContent);
    const current = eContent.valueBlock.valueHexView;
    const updated = new Uint8Array(current.byteLength + suffix.byteLength);
    updated.set(current);
    updated.set(suffix, current.byteLength);
    eContent.valueBlock.valueHexView = updated;
  });
}

function rewriteRawReceipt(
  receiptBytes: Uint8Array,
  mutate: (root: asn1js.Sequence) => void,
): Uint8Array {
  const decoded = asn1js.fromBER(exactArrayBuffer(receiptBytes));
  assert.equal(decoded.offset, receiptBytes.byteLength);
  assert.ok(decoded.result instanceof asn1js.Sequence);
  mutate(decoded.result);
  return new Uint8Array(decoded.result.toBER(false));
}

function findSignerCertificateExtension(root: asn1js.Sequence, oid: string): asn1js.Sequence {
  const token = root.valueBlock.value[1] as asn1js.Sequence;
  const tokenContent = token.valueBlock.value[1] as asn1js.Constructed;
  const signedData = tokenContent.valueBlock.value[0] as asn1js.Sequence;
  const certificates = signedData.valueBlock.value[3] as asn1js.Constructed;
  const signerCertificate = certificates.valueBlock.value[0] as asn1js.Sequence;
  const tbsCertificate = signerCertificate.valueBlock.value[0] as asn1js.Sequence;
  const extensions = (tbsCertificate.valueBlock.value[7] as asn1js.Constructed)
    .valueBlock.value[0] as asn1js.Sequence;
  const extension = extensions.valueBlock.value.find((item) => (
    item instanceof asn1js.Sequence
      && item.valueBlock.value[0] instanceof asn1js.ObjectIdentifier
      && item.valueBlock.value[0].valueBlock.toString() === oid
  ));
  assert.ok(extension instanceof asn1js.Sequence);
  return extension;
}

function replaceExtensionValue(extension: asn1js.Sequence, value: asn1js.BaseBlock): void {
  const extnValue = extension.valueBlock.value.find((item) => item instanceof asn1js.OctetString);
  assert.ok(extnValue instanceof asn1js.OctetString);
  extnValue.valueBlock.valueHexView = new Uint8Array(value.toBER(false));
}

test('verifies the published protocol test vector', async () => {
  const proof = parseProof(fixture);
  const result = await verifyProofIntegrity(proof);

  assert.equal(result.ok, true);
  assert.equal(await hashRules(proof.eligibilityRules), '75d8b35c3268c978bdf75ad781fc7061b1a3e6d2d5b97863722f3bbc149efe4e');
  assert.equal(proof.snapshot.hash, '1750d274ef6faa7cdc0ae069f996ac02d154322025e38e197e6ddffdfbb073ae');
  assert.deepEqual(proof.draw.winners.map((winner) => winner.ticketId), ['ticket-b', 'ticket-c']);
  assert.ok(result.checks.every((check) => check.ok));
});

test('detects a modified proof hash and a snapshot published after the Beacon round', async () => {
  const tampered = cloneFixture();
  tampered.proofHash = 'f'.repeat(64);
  (tampered.snapshot as Record<string, unknown>).publishedAt = '2025-07-01T00:01:00.000Z';
  const result = await verifyProofIntegrity(parseProof(tampered));

  assert.equal(result.ok, false);
  assert.equal(result.checks.find((check) => check.id === 'proof-hash')?.ok, false);
  assert.equal(result.checks.find((check) => check.id === 'timeline')?.ok, false);
});

test('rejects proofs above the ticket count limit before hashing them', () => {
  const tampered = cloneFixture();
  (tampered.snapshot as Record<string, unknown>).ticketIds = Array.from(
    { length: MAX_TICKET_COUNT + 1 },
    (_, index) => `ticket-${index}`,
  );

  assert.throws(() => parseProof(tampered), ProofValidationError);
});

test('requires the production completed status for protocol v2 proofs', () => {
  const tampered = cloneFixture();
  tampered.status = 'completed';

  assert.throws(() => parseProof(tampered), ProofValidationError);
});

test('keeps the manifest newline and sorting rules exact', async () => {
  const manifest = await createSnapshotManifest(['ticket-c', 'ticket-a', 'ticket-b']);
  assert.equal(manifest.manifest, 'ticket-a\nticket-b\nticket-c\n');
  assert.equal(manifest.hash, '1750d274ef6faa7cdc0ae069f996ac02d154322025e38e197e6ddffdfbb073ae');
});

test('detects tampering with the candidate snapshot', async () => {
  const tampered = cloneFixture();
  const snapshot = tampered.snapshot as Record<string, unknown>;
  snapshot.ticketIds = ['ticket-c', 'ticket-a', 'ticket-z'];
  const result = await verifyProofIntegrity(parseProof(tampered));

  assert.equal(result.ok, false);
  assert.equal(result.checks.find((check) => check.id === 'snapshot-hash')?.ok, false);
  assert.equal(result.checks.find((check) => check.id === 'winners')?.ok, false);
});

test('detects a forged draw seed', async () => {
  const tampered = cloneFixture();
  const draw = tampered.draw as Record<string, unknown>;
  draw.drawSeed = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
  const result = await verifyProofIntegrity(parseProof(tampered));

  assert.equal(result.ok, false);
  assert.equal(result.checks.find((check) => check.id === 'draw-seed')?.ok, false);
});

test('rejects proof data containing an email field', () => {
  const tampered = cloneFixture();
  const draw = tampered.draw as Record<string, unknown>;
  const winners = draw.winners as Array<Record<string, unknown>>;
  winners[0].email = 'someone@example.test';

  assert.throws(() => parseProof(tampered), ProofValidationError);
});

test('does not silently verify an unknown proof version', () => {
  const tampered = cloneFixture();
  tampered.proofVersion = '1';

  assert.throws(() => parseProof(tampered), ProofValidationError);
});

test('parses and verifies an archived protocol v2 proof without trusting reserialized JSON', async () => {
  const commitmentBytes = new TextEncoder().encode(`${JSON.stringify(fixture.snapshotCommitment, null, 2)}\n`);
  const receiptBytes = Uint8Array.from([0x30, 0x03, 0x02, 0x01, 0x00]);
  const proofData = cloneFixture();
  proofData.proofVersion = SUPPORTED_PROOF_VERSION;
  proofData.archive = {
    type: 'rfc3161',
    commitmentHash: (fixture.snapshotCommitment as Record<string, unknown>).commitmentHash,
    commitmentJsonSha256: await sha256HexBytes(commitmentBytes),
    timestampReceiptSha256: await sha256HexBytes(receiptBytes),
    archiveUrl: 'https://verifier.example/commitments/summer-2025.json',
    receiptUrl: 'https://verifier.example/commitments/summer-2025.tsr',
    verifierCommit: '1'.repeat(40),
    tsaUrl: 'https://freetsa.org/tsr',
  };
  proofData.proofHash = await hashPublicProof(proofData);

  const proof = parseProof(proofData);
  const archive = parseSnapshotArchive(proof.archive);
  const result = await verifySnapshotArchive(proof, archive, commitmentBytes, receiptBytes);

  assert.equal(result.checks.find((check) => check.id === 'archive-json-sha256')?.ok, true);
  assert.equal(result.checks.find((check) => check.id === 'archive-receipt-sha256')?.ok, true);
  assert.equal(result.checks.find((check) => check.id === 'archive-binding')?.ok, true);
  assert.equal(result.ok, false);
  assert.equal(result.checks.find((check) => check.id === 'rfc3161-structure')?.ok, false);
});

test('verifies the published RFC 3161 receipt with a pinned TSA root and mirrored CRL', async () => {
  const commitmentBytes = new Uint8Array(readFileSync(new URL('../public/commitments/summer-test10.json', import.meta.url)));
  const receiptBytes = new Uint8Array(readFileSync(new URL('../public/commitments/summer-test10.tsr', import.meta.url)));
  const crlBytes = new Uint8Array(readFileSync(new URL('../public/revocation/freetsa-root-ca.crl', import.meta.url)));
  const result = await verifyRfc3161Receipt(
    receiptBytes,
    commitmentBytes,
    'https://freetsa.org/tsr',
    { revocationCrlBytes: crlBytes, revocationCheckDate: new Date('2026-08-28T00:00:00.000Z') },
  );

  assert.equal(result.ok, true);
  assert.equal(result.generatedAt?.toISOString(), '2026-08-28T05:08:18.000Z');
  assert.equal(result.checks.find((check) => check.id === 'rfc3161-message-imprint')?.ok, true);
  assert.equal(result.checks.find((check) => check.id === 'rfc3161-cms-signature')?.ok, true);
  assert.equal(result.checks.find((check) => check.id === 'rfc3161-certificate-chain')?.ok, true);
  assert.equal(result.checks.find((check) => check.id === 'rfc3161-revocation')?.ok, true);
  assert.equal(result.checks.find((check) => check.id === 'rfc3161-revocation')?.warning, undefined);
});

test('applies declared RFC 3161 accuracy as a conservative round-boundary allowance', async () => {
  const commitmentBytes = new Uint8Array(readFileSync(new URL('../public/commitments/summer-test10.json', import.meta.url)));
  const receiptBytes = new Uint8Array(readFileSync(new URL('../public/commitments/summer-test10.tsr', import.meta.url)));
  const receiptWithAccuracy = rewriteTstInfo(receiptBytes, (tstInfo) => {
    tstInfo.accuracy = new Accuracy({ seconds: 1, millis: 250 });
  });

  const result = await verifyRfc3161Receipt(
    receiptWithAccuracy,
    commitmentBytes,
    'https://freetsa.org/tsr',
  );

  assert.deepEqual(result.accuracy, {
    seconds: 1,
    millis: 250,
    micros: 0,
    totalMicros: '1250000',
  });
  assert.equal(result.accuracyMs, 1250);
  assert.equal(result.checks.find((check) => check.id === 'rfc3161-accuracy')?.ok, true);
});

test('uses the RFC 3161 accuracy upper bound for archive timeline checks', async () => {
  const commitmentBytes = new Uint8Array(readFileSync(new URL('../public/commitments/summer-test10.json', import.meta.url)));
  const receiptBytes = new Uint8Array(readFileSync(new URL('../public/commitments/summer-test10.tsr', import.meta.url)));
  const receiptWithAccuracy = rewriteTstInfo(receiptBytes, (tstInfo) => {
    tstInfo.accuracy = new Accuracy({ seconds: 2 });
  });
  const proof = parseProof(cloneFixture());
  proof.drand.targetRoundTime = '2026-08-28T05:08:19.000Z';
  proof.draw.roundTime = proof.drand.targetRoundTime;

  const result = await verifySnapshotArchive(
    proof,
    parseSnapshotArchive(proof.archive),
    commitmentBytes,
    receiptWithAccuracy,
  );

  assert.equal(result.checks.find((check) => check.id === 'rfc3161-accuracy')?.ok, true);
  assert.equal(result.checks.find((check) => check.id === 'rfc3161-timeline')?.ok, false);
});

test('creates a SHA-256 OCSP request and verifies a signed FreeTSA response in the browser path', async () => {
  const receiptBytes = new Uint8Array(readFileSync(new URL('../public/commitments/summer-test10.tsr', import.meta.url)));
  const [tsaCertificate, rootCertificate] = readTsaCertificates(receiptBytes);
  const nonce = Uint8Array.from([
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
    0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x00,
  ]);
  const request = await createOcspRequest(tsaCertificate, rootCertificate, nonce);
  const requestDecoded = asn1js.fromBER(exactArrayBuffer(request.requestBytes));
  assert.equal(requestDecoded.offset, request.requestBytes.byteLength);
  const parsedRequest = new OCSPRequest({ schema: requestDecoded.result });
  assert.equal(parsedRequest.tbsRequest.requestList.length, 1);
  assert.equal(request.certId.hashAlgorithm.algorithmId, '2.16.840.1.101.3.4.2.1');

  const responseBytes = readBase64Fixture('freetsa-ocsp-response.b64');
  const result = await verifyCertificateWithOcsp(
    responseBytes,
    tsaCertificate,
    rootCertificate,
    { expectedNonce: nonce, checkDate: new Date('2026-08-28T07:47:30.000Z') },
  );

  assert.equal(result.ok, true);
  assert.equal(result.status, 'good');
  assert.match(result.detail, /签名、响应者证书链、CertID/);
  assert.equal(result.serial, '00c2e986160da8e9cd');

  const nonceMismatch = await verifyCertificateWithOcsp(
    responseBytes,
    tsaCertificate,
    rootCertificate,
    { expectedNonce: Uint8Array.from([0x01]), checkDate: new Date('2026-08-28T07:47:30.000Z') },
  );
  assert.equal(nonceMismatch.ok, false);
  assert.match(nonceMismatch.detail, /nonce/);
});

test('rejects an old OCSP response that omits nextUpdate', async () => {
  const receiptBytes = new Uint8Array(readFileSync(new URL('../public/commitments/summer-test10.tsr', import.meta.url)));
  const [tsaCertificate, rootCertificate] = readTsaCertificates(receiptBytes);
  const result = await verifyCertificateWithOcsp(
    readBase64Fixture('freetsa-ocsp-response.b64'),
    tsaCertificate,
    rootCertificate,
    { checkDate: new Date('2026-08-30T07:47:30.000Z') },
  );

  assert.equal(result.ok, false);
  assert.equal(result.status, 'good');
  assert.match(result.detail, /最大年龄/);
});

test('uses a valid OCSP response before consulting the CRL fallback', async () => {
  const commitmentBytes = new Uint8Array(readFileSync(new URL('../public/commitments/summer-test10.json', import.meta.url)));
  const receiptBytes = new Uint8Array(readFileSync(new URL('../public/commitments/summer-test10.tsr', import.meta.url)));
  const crlBytes = new Uint8Array(readFileSync(new URL('../public/revocation/freetsa-root-ca.crl', import.meta.url)));
  const responseBytes = readBase64Fixture('freetsa-ocsp-response.b64');
  const nonce = Uint8Array.from([
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
    0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x00,
  ]);
  let fetchCalled = false;
  const result = await verifyRfc3161Receipt(
    receiptBytes,
    commitmentBytes,
    'https://freetsa.org/tsr',
    {
      revocationCrlBytes: crlBytes,
      revocationOcspNonce: nonce,
      revocationCheckDate: new Date('2026-08-28T07:47:30.000Z'),
      revocationOcspFetcher: async (requestBytes, requestNonce) => {
        fetchCalled = true;
        assert.ok(requestBytes.byteLength > 0);
        assert.deepEqual([...requestNonce], [...nonce]);
        return responseBytes;
      },
    },
  );

  const revocation = result.checks.find((check) => check.id === 'rfc3161-revocation');
  assert.equal(fetchCalled, true);
  assert.equal(result.ok, true);
  assert.equal(revocation?.ok, true);
  assert.equal(revocation?.warning, undefined);
  assert.match(revocation?.label || '', /OCSP/);
});

test('falls back to the mirrored CRL when the OCSP proxy response is unavailable', async () => {
  const commitmentBytes = new Uint8Array(readFileSync(new URL('../public/commitments/summer-test10.json', import.meta.url)));
  const receiptBytes = new Uint8Array(readFileSync(new URL('../public/commitments/summer-test10.tsr', import.meta.url)));
  const crlBytes = new Uint8Array(readFileSync(new URL('../public/revocation/freetsa-root-ca.crl', import.meta.url)));
  const result = await verifyRfc3161Receipt(
    receiptBytes,
    commitmentBytes,
    'https://freetsa.org/tsr',
    {
      revocationCrlBytes: crlBytes,
      revocationCheckDate: new Date('2026-08-28T00:00:00.000Z'),
      revocationOcspFetcher: async () => Uint8Array.from([0x30, 0x01, 0x00]),
    },
  );

  const revocation = result.checks.find((check) => check.id === 'rfc3161-revocation');
  assert.equal(result.ok, true);
  assert.equal(revocation?.ok, true);
  assert.equal(revocation?.warning, true);
  assert.match(revocation?.label || '', /CRL 回退/);
  assert.match(revocation?.detail || '', /CRL 镜像回退/);
});

test('fails closed when the browser cannot obtain the mirrored CRL', async () => {
  const commitmentBytes = new Uint8Array(readFileSync(new URL('../public/commitments/summer-test10.json', import.meta.url)));
  const receiptBytes = new Uint8Array(readFileSync(new URL('../public/commitments/summer-test10.tsr', import.meta.url)));
  const result = await verifyRfc3161Receipt(
    receiptBytes,
    commitmentBytes,
    'https://freetsa.org/tsr',
    { revocationError: '请求超时。' },
  );

  assert.equal(result.ok, false);
  assert.equal(result.checks.find((check) => check.id === 'rfc3161-revocation')?.ok, false);
  assert.match(result.checks.find((check) => check.id === 'rfc3161-revocation')?.detail || '', /请求超时/);
});

test('fails closed when the mirrored CRL is stale', async () => {
  const commitmentBytes = new Uint8Array(readFileSync(new URL('../public/commitments/summer-test10.json', import.meta.url)));
  const receiptBytes = new Uint8Array(readFileSync(new URL('../public/commitments/summer-test10.tsr', import.meta.url)));
  const crlBytes = new Uint8Array(readFileSync(new URL('../public/revocation/freetsa-root-ca.crl', import.meta.url)));
  const result = await verifyRfc3161Receipt(
    receiptBytes,
    commitmentBytes,
    'https://freetsa.org/tsr',
    { revocationCrlBytes: crlBytes, revocationCheckDate: new Date('2100-01-01T00:00:00.000Z') },
  );

  assert.equal(result.ok, false);
  assert.equal(result.checks.find((check) => check.id === 'rfc3161-revocation')?.ok, false);
  assert.match(result.checks.find((check) => check.id === 'rfc3161-revocation')?.detail || '', /过期/);
});

test('rejects an oversized mirrored CRL before ASN.1 processing', async () => {
  const commitmentBytes = new Uint8Array(readFileSync(new URL('../public/commitments/summer-test10.json', import.meta.url)));
  const receiptBytes = new Uint8Array(readFileSync(new URL('../public/commitments/summer-test10.tsr', import.meta.url)));
  const result = await verifyRfc3161Receipt(
    receiptBytes,
    commitmentBytes,
    'https://freetsa.org/tsr',
    { revocationCrlBytes: new Uint8Array(MAX_REVOCATION_CRL_BYTES + 1) },
  );

  assert.equal(result.ok, false);
  assert.match(result.checks.find((check) => check.id === 'rfc3161-revocation')?.detail || '', /KiB/);
});

test('rejects a receipt when its TSA endpoint is outside the configured trust profile', async () => {
  const commitmentBytes = new Uint8Array(readFileSync(new URL('../public/commitments/summer-test10.json', import.meta.url)));
  const receiptBytes = new Uint8Array(readFileSync(new URL('../public/commitments/summer-test10.tsr', import.meta.url)));
  const result = await verifyRfc3161Receipt(receiptBytes, commitmentBytes, 'https://tsa.example.test/tsr');

  assert.equal(result.ok, false);
  assert.equal(result.checks.find((check) => check.id === 'rfc3161-tsa-profile')?.ok, false);
});

test('detects a modified CMS signature even when the receipt remains parseable', async () => {
  const commitmentBytes = new Uint8Array(readFileSync(new URL('../public/commitments/summer-test10.json', import.meta.url)));
  const receiptBytes = new Uint8Array(readFileSync(new URL('../public/commitments/summer-test10.tsr', import.meta.url)));
  receiptBytes[receiptBytes.length - 1] ^= 0x01;
  const result = await verifyRfc3161Receipt(receiptBytes, commitmentBytes, 'https://freetsa.org/tsr');

  assert.equal(result.ok, false);
  assert.equal(result.checks.find((check) => check.id === 'rfc3161-cms-signature')?.ok, false);
});

test('rejects a receipt larger than the parser limit before ASN.1 processing', async () => {
  const oversizedReceipt = new Uint8Array(MAX_RFC3161_RECEIPT_BYTES + 1);
  const result = await verifyRfc3161Receipt(oversizedReceipt, new Uint8Array());

  assert.equal(result.ok, false);
  assert.equal(result.checks.find((check) => check.id === 'rfc3161-size')?.ok, false);
  assert.equal(result.checks.some((check) => check.id === 'rfc3161-structure'), false);
});

test('rejects malformed ASN.1 and trailing bytes without throwing', async () => {
  const commitmentBytes = new Uint8Array(readFileSync(new URL('../public/commitments/summer-test10.json', import.meta.url)));
  const receiptBytes = new Uint8Array(readFileSync(new URL('../public/commitments/summer-test10.tsr', import.meta.url)));
  const trailing = new Uint8Array(receiptBytes.byteLength + 1);
  trailing.set(receiptBytes);
  trailing[trailing.length - 1] = 0;

  const trailingResult = await verifyRfc3161Receipt(trailing, commitmentBytes, 'https://freetsa.org/tsr');
  assert.equal(trailingResult.ok, false);
  assert.equal(trailingResult.checks.find((check) => check.id === 'rfc3161-structure')?.ok, false);

  const malformedResult = await verifyRfc3161Receipt(
    Uint8Array.from([0x30, 0x80, 0x00, 0x00]),
    commitmentBytes,
    'https://freetsa.org/tsr',
  );
  assert.equal(malformedResult.ok, false);
  assert.equal(malformedResult.checks.find((check) => check.id === 'rfc3161-structure')?.ok, false);
});

test('rejects a missing token and unsuccessful TSP status', async () => {
  const commitmentBytes = new Uint8Array(readFileSync(new URL('../public/commitments/summer-test10.json', import.meta.url)));
  const receiptBytes = new Uint8Array(readFileSync(new URL('../public/commitments/summer-test10.tsr', import.meta.url)));

  const missingToken = await verifyRfc3161Receipt(removeTimestampToken(receiptBytes), commitmentBytes, 'https://freetsa.org/tsr');
  assert.equal(missingToken.ok, false);
  assert.equal(missingToken.checks.find((check) => check.id === 'rfc3161-token')?.ok, false);

  const rejectedStatus = await verifyRfc3161Receipt(
    rewriteReceipt(receiptBytes, (response) => { response.status.status = 2; }),
    commitmentBytes,
    'https://freetsa.org/tsr',
  );
  assert.equal(rejectedStatus.ok, false);
  assert.equal(rejectedStatus.checks.find((check) => check.id === 'rfc3161-status')?.ok, false);
});

test('rejects a CMS object that is not SignedData or contains multiple signers', async () => {
  const commitmentBytes = new Uint8Array(readFileSync(new URL('../public/commitments/summer-test10.json', import.meta.url)));
  const receiptBytes = new Uint8Array(readFileSync(new URL('../public/commitments/summer-test10.tsr', import.meta.url)));

  const wrongContentType = await verifyRfc3161Receipt(
    rewriteReceipt(receiptBytes, (response) => { response.timeStampToken!.contentType = '1.2.3.4'; }),
    commitmentBytes,
    'https://freetsa.org/tsr',
  );
  assert.equal(wrongContentType.ok, false);
  assert.equal(wrongContentType.checks.find((check) => check.id === 'rfc3161-content-type')?.ok, false);

  const multipleSigners = await verifyRfc3161Receipt(
    rewriteReceipt(receiptBytes, (_response, signedData) => {
      signedData.signerInfos.push(signedData.signerInfos[0]);
    }),
    commitmentBytes,
    'https://freetsa.org/tsr',
  );
  assert.equal(multipleSigners.ok, false);
  assert.equal(multipleSigners.checks.find((check) => check.id === 'rfc3161-signer-count')?.ok, false);
});

test('rejects weak or unknown MessageImprint algorithms', async () => {
  const commitmentBytes = new Uint8Array(readFileSync(new URL('../public/commitments/summer-test10.json', import.meta.url)));
  const receiptBytes = new Uint8Array(readFileSync(new URL('../public/commitments/summer-test10.tsr', import.meta.url)));

  const sha1Receipt = rewriteTstInfo(receiptBytes, (tstInfo) => {
    tstInfo.messageImprint.hashAlgorithm.algorithmId = '1.3.14.3.2.26';
  });
  const sha1Result = await verifyRfc3161Receipt(sha1Receipt, commitmentBytes, 'https://freetsa.org/tsr');
  assert.equal(sha1Result.ok, false);
  assert.equal(sha1Result.checks.find((check) => check.id === 'rfc3161-imprint-algorithm')?.ok, false);
  assert.match(sha1Result.checks.find((check) => check.id === 'rfc3161-imprint-algorithm')?.detail || '', /SHA-1/);

  const unknownReceipt = rewriteTstInfo(receiptBytes, (tstInfo) => {
    tstInfo.messageImprint.hashAlgorithm.algorithmId = '1.2.3.4.999';
  });
  const unknownResult = await verifyRfc3161Receipt(unknownReceipt, commitmentBytes, 'https://freetsa.org/tsr');
  assert.equal(unknownResult.ok, false);
  assert.equal(unknownResult.checks.find((check) => check.id === 'rfc3161-imprint-algorithm')?.ok, false);
  assert.match(unknownResult.checks.find((check) => check.id === 'rfc3161-imprint-algorithm')?.detail || '', /1\.2\.3\.4\.999/);
});

test('rejects a policy mismatch, malformed TSTInfo, and a bad SigningCertificate hash', async () => {
  const commitmentBytes = new Uint8Array(readFileSync(new URL('../public/commitments/summer-test10.json', import.meta.url)));
  const receiptBytes = new Uint8Array(readFileSync(new URL('../public/commitments/summer-test10.tsr', import.meta.url)));

  const policyResult = await verifyRfc3161Receipt(
    rewriteTstInfo(receiptBytes, (tstInfo) => { tstInfo.policy = '1.2.3.4.2'; }),
    commitmentBytes,
    'https://freetsa.org/tsr',
  );
  assert.equal(policyResult.ok, false);
  assert.equal(policyResult.checks.find((check) => check.id === 'rfc3161-policy')?.ok, false);

  const malformedTstResult = await verifyRfc3161Receipt(
    appendToTstInfo(receiptBytes, Uint8Array.from([0x00])),
    commitmentBytes,
    'https://freetsa.org/tsr',
  );
  assert.equal(malformedTstResult.ok, false);
  assert.equal(malformedTstResult.checks.find((check) => check.id === 'rfc3161-tst-structure')?.ok, false);

  const badSigningCertificate = rewriteReceipt(receiptBytes, (_response, signedData) => {
    const attribute = signedData.signerInfos[0].signedAttrs?.attributes.find(
      (item) => item.type === '1.2.840.113549.1.9.16.2.12',
    );
    assert.ok(attribute);
    const certificateHash = attribute.values[0].valueBlock.value[0].valueBlock.value[0].valueBlock.value[0];
    assert.ok(certificateHash instanceof asn1js.OctetString);
    certificateHash.valueBlock.valueHexView[0] ^= 0x01;
  });
  const badSigningCertificateResult = await verifyRfc3161Receipt(
    badSigningCertificate,
    commitmentBytes,
    'https://freetsa.org/tsr',
  );
  assert.equal(badSigningCertificateResult.ok, false);
  assert.equal(badSigningCertificateResult.checks.find((check) => check.id === 'rfc3161-signing-certificate')?.ok, false);
});

test('rejects an invalid TSA certificate usage, validity window, identity, or critical extension', async () => {
  const commitmentBytes = new Uint8Array(readFileSync(new URL('../public/commitments/summer-test10.json', import.meta.url)));
  const receiptBytes = new Uint8Array(readFileSync(new URL('../public/commitments/summer-test10.tsr', import.meta.url)));

  const nonTimestampingEku = rewriteRawReceipt(receiptBytes, (root) => {
    const extension = findSignerCertificateExtension(root, '2.5.29.37');
    replaceExtensionValue(extension, new asn1js.Sequence({
      value: [new asn1js.ObjectIdentifier({ value: '1.3.6.1.5.5.7.3.3' })],
    }));
  });
  const nonTimestampingEkuResult = await verifyRfc3161Receipt(
    nonTimestampingEku,
    commitmentBytes,
    'https://freetsa.org/tsr',
  );
  assert.equal(nonTimestampingEkuResult.ok, false);
  assert.equal(nonTimestampingEkuResult.checks.find((check) => check.id === 'rfc3161-certificate-usage')?.ok, false);

  const nonCriticalEku = rewriteRawReceipt(receiptBytes, (root) => {
    const extension = findSignerCertificateExtension(root, '2.5.29.37');
    const critical = extension.valueBlock.value.find((item) => item instanceof asn1js.Boolean);
    assert.ok(critical instanceof asn1js.Boolean);
    critical.valueBlock.value = false;
  });
  const nonCriticalEkuResult = await verifyRfc3161Receipt(
    nonCriticalEku,
    commitmentBytes,
    'https://freetsa.org/tsr',
  );
  assert.equal(nonCriticalEkuResult.ok, false);
  assert.equal(nonCriticalEkuResult.checks.find((check) => check.id === 'rfc3161-certificate-usage')?.ok, false);

  const invalidGenTime = await verifyRfc3161Receipt(
    rewriteTstInfo(receiptBytes, (tstInfo) => { tstInfo.genTime = new Date('2020-01-01T00:00:00.000Z'); }),
    commitmentBytes,
    'https://freetsa.org/tsr',
  );
  assert.equal(invalidGenTime.ok, false);
  assert.equal(invalidGenTime.checks.find((check) => check.id === 'rfc3161-certificate-chain')?.ok, false);

  const wrongIdentity = await verifyRfc3161Receipt(
    rewriteTstInfo(receiptBytes, (tstInfo) => {
      tstInfo.tsa = new GeneralName({ type: 6, value: 'https://wrong.example/tsa' });
    }),
    commitmentBytes,
    'https://freetsa.org/tsr',
  );
  assert.equal(wrongIdentity.ok, false);
  assert.equal(wrongIdentity.checks.find((check) => check.id === 'rfc3161-tsa-identity')?.ok, false);

  const unknownCriticalExtension = rewriteRawReceipt(receiptBytes, (root) => {
    const extension = findSignerCertificateExtension(root, '1.3.6.1.5.5.7.1.1');
    const critical = new asn1js.Boolean({ value: true });
    extension.valueBlock.value.splice(1, 0, critical);
  });
  const unknownCriticalExtensionResult = await verifyRfc3161Receipt(
    unknownCriticalExtension,
    commitmentBytes,
    'https://freetsa.org/tsr',
  );
  assert.equal(unknownCriticalExtensionResult.ok, false);
  assert.equal(unknownCriticalExtensionResult.checks.find((check) => check.id === 'rfc3161-critical-extensions')?.ok, false);
});

test('detects changes to the original archive JSON or detached receipt bytes', async () => {
  const commitmentBytes = new TextEncoder().encode(JSON.stringify(fixture.snapshotCommitment));
  const receiptBytes = Uint8Array.from([0x30, 0x03, 0x02, 0x01, 0x00]);
  const proofData = cloneFixture();
  proofData.proofVersion = SUPPORTED_PROOF_VERSION;
  proofData.archive = {
    type: 'rfc3161',
    commitmentHash: (fixture.snapshotCommitment as Record<string, unknown>).commitmentHash,
    commitmentJsonSha256: await sha256HexBytes(commitmentBytes),
    timestampReceiptSha256: await sha256HexBytes(receiptBytes),
    archiveUrl: 'https://verifier.example/commitments/summer-2025.json',
    receiptUrl: 'https://verifier.example/commitments/summer-2025.tsr',
    verifierCommit: '1'.repeat(40),
    tsaUrl: 'https://freetsa.org/tsr',
  };
  proofData.proofHash = await hashPublicProof(proofData);
  const proof = parseProof(proofData);
  const archive = parseSnapshotArchive(proof.archive);

  const modifiedJson = new TextEncoder().encode(`${JSON.stringify(fixture.snapshotCommitment)}\n`);
  const modifiedReceipt = new Uint8Array(receiptBytes);
  modifiedReceipt[modifiedReceipt.length - 1] ^= 0x01;
  const result = await verifySnapshotArchive(proof, archive, modifiedJson, modifiedReceipt);

  assert.equal(result.ok, false);
  assert.equal(result.checks.find((check) => check.id === 'archive-json-sha256')?.ok, false);
  assert.equal(result.checks.find((check) => check.id === 'archive-receipt-sha256')?.ok, false);
  assert.equal(result.checks.find((check) => check.id === 'rfc3161-structure')?.ok, false);
});

test('requires protocol v2 archive metadata and rejects unsafe archive URLs', () => {
  const missingArchive = cloneFixture();
  delete missingArchive.archive;
  assert.throws(() => parseProof(missingArchive), /proof\.archive is required/);

  const oldVersion = cloneFixture();
  oldVersion.proofVersion = '1';
  assert.throws(() => parseProof(oldVersion), /unsupported proof version/);

  const unsafe = cloneFixture();
  unsafe.proofVersion = SUPPORTED_PROOF_VERSION;
  unsafe.archive = {
    type: 'rfc3161',
    commitmentHash: (fixture.snapshotCommitment as Record<string, unknown>).commitmentHash,
    commitmentJsonSha256: 'a'.repeat(64),
    timestampReceiptSha256: 'b'.repeat(64),
    archiveUrl: 'https://verifier.example/commitments/summer-2025.json?cache=1',
    receiptUrl: 'https://verifier.example/commitments/summer-2025.tsr',
    verifierCommit: '1'.repeat(40),
    tsaUrl: 'https://freetsa.org/tsr',
  };
  assert.throws(() => parseProof(unsafe), /archiveUrl must be an HTTPS URL/);
});

test('rejects unknown protocol fields instead of excluding them from proofHash', () => {
  const tampered = cloneFixture();
  tampered.unhashedAnnotation = 'changed';

  assert.throws(() => parseProof(tampered), ProofValidationError);
});

test('rejects duplicate ticket IDs during integrity verification', async () => {
  const tampered = cloneFixture();
  const snapshot = tampered.snapshot as Record<string, unknown>;
  snapshot.ticketIds = ['ticket-a', 'ticket-a', 'ticket-c'];
  const result = await verifyProofIntegrity(parseProof(tampered));

  assert.equal(result.ok, false);
  assert.equal(result.checks.find((check) => check.id === 'snapshot-counts')?.ok, false);
});

test('reports an entryCount mismatch explicitly', async () => {
  const tampered = cloneFixture();
  (tampered.snapshot as Record<string, unknown>).entryCount = 2;
  const result = await verifyProofIntegrity(parseProof(tampered));
  const countCheck = result.checks.find((check) => check.id === 'snapshot-counts');

  assert.equal(countCheck?.ok, false);
  assert.match(countCheck?.detail || '', /entryCount/);
});

test('verifies a segmented proof (campaign-drand-segmented-v1 & campaign-snapshot-v2)', async () => {
  const rules = { requireActive: true };
  const rulesHash = await hashRules(rules);
  const entries = [
    { ticketId: 'ticket-free-1', segment: 'free' },
    { ticketId: 'ticket-free-2', segment: 'free' },
    { ticketId: 'ticket-paid-1', segment: 'paid' },
  ];
  const { entries: normalizedEntries, ticketIds, manifest, hash: snapshotHash } = await createSegmentedSnapshotManifest(entries);
  const campaignId = 'segmented-camp-1';
  const publishedAt = '2025-06-01T00:00:00.000Z';
  const freeWinnerCount = 1;
  const paidWinnerCount = 1;
  const winnerCount = freeWinnerCount + paidWinnerCount;
  const drawAlgorithmVersion = 'campaign-drand-segmented-v1';

  const snapshotCommitment = await createSnapshotCommitment({
    campaignId,
    snapshotHash,
    rulesHash,
    entryCount: 3,
    eligibleCount: 3,
    freeCount: 2,
    paidCount: 1,
    publishedAt,
    drawAlgorithmVersion,
    winnerCount,
    freeWinnerCount,
    paidWinnerCount,
  });

  const chainHash = '8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce';
  const round = 1000;
  const randomness = '2b87e0b507d3910c57173b22cf3ffed7f62d19f6a73c155551c6c043e0e7a4e6';

  const drawSeed = await createDrawSeed({
    chainHash,
    round,
    randomness,
    campaignId,
    snapshotHash,
    rulesHash,
    algorithmVersion: drawAlgorithmVersion,
    freeWinnerCount,
    paidWinnerCount,
  });

  const winners = await selectSegmentedWinners(entries, { freeWinnerCount, paidWinnerCount }, drawSeed);

  const proofData: Record<string, unknown> = {
    proofVersion: SUPPORTED_PROOF_VERSION,
    proofHashAlgorithm: 'sha256-stable-json-v1',
    id: campaignId,
    slug: 'segmented-campaign',
    name: 'Segmented Campaign',
    status: 'drawn',
    winnerCount,
    freeWinnerCount,
    paidWinnerCount,
    eligibilityRules: rules,
    drawAlgorithmVersion,
    snapshot: {
      hash: snapshotHash,
      rulesHash,
      publishedAt,
      entryCount: 3,
      eligibleCount: 3,
      freeCount: 2,
      paidCount: 1,
      manifest,
      ticketIds,
      entries: normalizedEntries,
    },
    snapshotCommitment,
    drand: {
      beaconId: 'quicknet',
      chainHash,
      targetRound: round,
      targetRoundTime: '2025-06-01T00:00:30.000Z',
      publicKey: '83cf0ced5d5e6ee38d4f278e6b352845cb4e43d08828694f0ad9e38377e6a13cd5c3ed6e2197802b71364377800b7a69',
      randomness,
      signature: 'a7b8c9d0e1f2030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c',
      beaconPayload: {
        round,
        randomness,
        signature: 'a7b8c9d0e1f2030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c',
      },
    },
    draw: {
      beaconId: 'quicknet',
      chainHash,
      round,
      roundTime: '2025-06-01T00:00:30.000Z',
      randomness,
      signature: 'a7b8c9d0e1f2030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c',
      snapshotHash,
      rulesHash,
      drawSeed,
      algorithmVersion: drawAlgorithmVersion,
      winners,
      completedAt: '2025-06-01T00:01:00.000Z',
      beaconPayload: {
        round,
        randomness,
        signature: 'a7b8c9d0e1f2030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c',
      },
    },
  };
  proofData.archive = {
    type: 'rfc3161',
    commitmentHash: snapshotCommitment.commitmentHash,
    commitmentJsonSha256: 'a'.repeat(64),
    timestampReceiptSha256: 'b'.repeat(64),
    archiveUrl: 'https://verifier.example/commitments/segmented.json',
    receiptUrl: 'https://verifier.example/commitments/segmented.tsr',
    verifierCommit: '1'.repeat(40),
    tsaUrl: 'https://freetsa.org/tsr',
  };
  proofData.proofHash = await hashPublicProof(proofData);

  const parsed = parseProof(proofData);
  const result = await verifyProofIntegrity(parsed);

  assert.equal(result.ok, true);
  assert.equal(parsed.drawAlgorithmVersion, 'campaign-drand-segmented-v1');
  assert.equal(parsed.freeWinnerCount, 1);
  assert.equal(parsed.paidWinnerCount, 1);
  assert.equal(parsed.snapshotCommitment?.commitmentVersion, 'campaign-snapshot-v2');
  assert.ok(result.checks.every((c) => c.ok));
});

test('rejects a segmented proof with mismatched winner quota sum', async () => {
  const proofData: Record<string, unknown> = {
    proofVersion: SUPPORTED_PROOF_VERSION,
    proofHashAlgorithm: 'sha256-stable-json-v1',
    id: 'segmented-bad-quota',
    slug: 'bad-quota',
    name: 'Bad Quota Campaign',
    status: 'drawn',
    winnerCount: 5,
    freeWinnerCount: 2,
    paidWinnerCount: 2,
    eligibilityRules: { requireActive: true },
    drawAlgorithmVersion: 'campaign-drand-segmented-v1',
    snapshot: {
      hash: '1750d274ef6faa7cdc0ae069f996ac02d154322025e38e197e6ddffdfbb073ae',
      rulesHash: '75d8b35c3268c978bdf75ad781fc7061b1a3e6d2d5b97863722f3bbc149efe4e',
      publishedAt: '2025-06-01T00:00:00.000Z',
      entryCount: 4,
      eligibleCount: 4,
      freeCount: 2,
      paidCount: 2,
      ticketIds: ['t1', 't2', 't3', 't4'],
      entries: [
        { ticketId: 't1', segment: 'free' },
        { ticketId: 't2', segment: 'free' },
        { ticketId: 't3', segment: 'paid' },
        { ticketId: 't4', segment: 'paid' },
      ],
    },
    drand: {
      beaconId: 'quicknet',
      chainHash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      targetRound: 1000,
      publicKey: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      randomness: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      signature: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
    },
    draw: {
      beaconId: 'quicknet',
      chainHash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      round: 1000,
      randomness: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      signature: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
      snapshotHash: '1750d274ef6faa7cdc0ae069f996ac02d154322025e38e197e6ddffdfbb073ae',
      rulesHash: '75d8b35c3268c978bdf75ad781fc7061b1a3e6d2d5b97863722f3bbc149efe4e',
      drawSeed: '3e586ceb2335d99f1d9c059a2255f5b2166df538b01377bf05e8d3f0344938c8',
      algorithmVersion: 'campaign-drand-segmented-v1',
      winners: [],
    },
  };
  proofData.archive = {
    type: 'rfc3161',
    commitmentHash: 'a'.repeat(64),
    commitmentJsonSha256: 'b'.repeat(64),
    timestampReceiptSha256: 'c'.repeat(64),
    archiveUrl: 'https://verifier.example/commitments/segmented-bad.json',
    receiptUrl: 'https://verifier.example/commitments/segmented-bad.tsr',
    verifierCommit: '1'.repeat(40),
    tsaUrl: 'https://freetsa.org/tsr',
  };
  proofData.proofHash = await hashPublicProof(proofData);
  assert.throws(() => parseProof(proofData), ProofValidationError);
});
