import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  createDrawSeed,
  createSegmentedSnapshotManifest,
  createSnapshotCommitment,
  createSnapshotManifest,
  hashPublicProof,
  hashRules,
  selectSegmentedWinners,
} from '../src/crypto.ts';
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
    proofVersion: '1',
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
    proofVersion: '1',
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
  assert.throws(() => parseProof(proofData), ProofValidationError);
});
