import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { createSnapshotManifest, hashRules } from '../src/crypto.ts';
import {
  MAX_TICKET_COUNT,
  parseProof,
  parseSnapshotCommitment,
  ProofValidationError,
} from '../src/proof-schema.ts';
import { verifyProofIntegrity } from '../src/verify.ts';

const fixture = JSON.parse(readFileSync(new URL('./fixtures/valid-proof.json', import.meta.url), 'utf8')) as Record<string, unknown>;

function cloneFixture(): Record<string, unknown> {
  return JSON.parse(JSON.stringify(fixture)) as Record<string, unknown>;
}

test('verifies the published protocol test vector', async () => {
  const proof = parseProof(fixture);
  const result = await verifyProofIntegrity(proof);

  assert.equal(result.ok, true);
  assert.equal(await hashRules(proof.eligibilityRules), '75d8b35c3268c978bdf75ad781fc7061b1a3e6d2d5b97863722f3bbc149efe4e');
  assert.equal(proof.snapshot.hash, '1750d274ef6faa7cdc0ae069f996ac02d154322025e38e197e6ddffdfbb073ae');
  assert.deepEqual(proof.draw.winners.map((winner) => winner.ticketId), ['ticket-b', 'ticket-c']);
  assert.ok(result.checks.every((check) => check.ok));
  assert.equal(result.externalCommitmentMatches, false);
  assert.equal(result.checks.find((check) => check.id === 'external-commitment')?.warning, true);
});

test('accepts an independently archived snapshot commitment', async () => {
  const proof = parseProof(fixture);
  const commitment = parseSnapshotCommitment(fixture.snapshotCommitment);
  const result = await verifyProofIntegrity(proof, commitment);

  assert.equal(result.ok, true);
  assert.equal(result.externalCommitmentMatches, true);
  assert.equal(result.checks.find((check) => check.id === 'external-commitment')?.ok, true);
  assert.equal(result.checks.find((check) => check.id === 'external-commitment')?.warning, true);
});

test('rejects an archived commitment that differs from the proof', async () => {
  const proof = parseProof(fixture);
  const commitment = parseSnapshotCommitment(fixture.snapshotCommitment);
  commitment.entryCount += 1;
  const result = await verifyProofIntegrity(proof, commitment);

  assert.equal(result.ok, false);
  assert.equal(result.externalCommitmentMatches, false);
  assert.equal(result.checks.find((check) => check.id === 'external-commitment')?.ok, false);
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

test('requires the production completed status for protocol v1 proofs', () => {
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
  tampered.proofVersion = '2';

  assert.throws(() => parseProof(tampered), ProofValidationError);
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
