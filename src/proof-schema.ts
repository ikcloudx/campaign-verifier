import type {
  CampaignDrawProof,
  CampaignDrandProof,
  CampaignProof,
  CampaignSnapshotArchive,
  CampaignSnapshot,
  CampaignWinner,
  SegmentedSnapshotEntry,
  SnapshotCommitment,
} from './types.ts';
import {
  DRAW_ALGORITHM_VERSION,
  PROOF_HASH_ALGORITHM,
  SEGMENTED_DRAW_ALGORITHM_VERSION,
  SEGMENTED_SNAPSHOT_COMMITMENT_VERSION,
  SNAPSHOT_COMMITMENT_VERSION,
} from './crypto.ts';

const HASH_PATTERN = /^[0-9a-f]{64}$/i;
const HEX_PATTERN = /^[0-9a-f]+$/i;
const EMAIL_PATTERN = /[^\s@]+@[^\s@]+\.[^\s@]+/i;
const SENSITIVE_KEY_PATTERN = /(?:email|user_?id|account_?id|customer_?id|phone|payment_?id|order_?id)/i;
export const SUPPORTED_PROOF_VERSION = '2';
export const COMPLETED_PROOF_STATUS = 'drawn';
export const MAX_PROOF_JSON_BYTES = 16 * 1024 * 1024;
export const MAX_ARCHIVE_JSON_BYTES = 256 * 1024;
export const MAX_ARCHIVE_RECEIPT_BYTES = 2 * 1024 * 1024;
export const MAX_TICKET_COUNT = 250_000;
const MAX_JSON_DEPTH = 64;
const MAX_JSON_NODES = 500_000;

export class ProofValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ProofValidationError';
  }
}

function fail(message: string): never {
  throw new ProofValidationError(message);
}

function record(value: unknown, path: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return fail(`${path} must be an object`);
  }
  return value as Record<string, unknown>;
}

function assertKnownKeys(input: Record<string, unknown>, keys: readonly string[], path: string): void {
  const allowed = new Set(keys);
  const unknown = Object.keys(input).find((key) => !allowed.has(key));
  if (unknown) fail(`${path}.${unknown} is not part of proof protocol v${SUPPORTED_PROOF_VERSION}`);
}

function stringValue(value: unknown, path: string, options: { optional?: boolean } = {}): string {
  if (value === undefined && options.optional) return '';
  if (typeof value !== 'string' || !value) return fail(`${path} must be a non-empty string`);
  return value;
}

function optionalString(value: unknown, path: string): string | null | undefined {
  if (value === undefined || value === null) return value;
  return stringValue(value, path);
}

function hashValue(value: unknown, path: string): string {
  const result = stringValue(value, path);
  if (!HASH_PATTERN.test(result)) return fail(`${path} must be a 64-character hexadecimal hash`);
  return result.toLowerCase();
}

function commitValue(value: unknown, path: string): string {
  const result = stringValue(value, path).toLowerCase();
  if (!/^[0-9a-f]{40,64}$/.test(result)) {
    return fail(`${path} must be a 40- to 64-character hexadecimal commit`);
  }
  return result;
}

function httpsUrlValue(value: unknown, path: string): string {
  const result = stringValue(value, path);
  let parsed: URL;
  try {
    parsed = new URL(result);
  } catch {
    return fail(`${path} must be an HTTPS URL without credentials, query parameters, or a fragment`);
  }
  if (
    parsed.protocol !== 'https:'
    || !parsed.hostname
    || parsed.username
    || parsed.password
    || parsed.search
    || parsed.hash
  ) {
    return fail(`${path} must be an HTTPS URL without credentials, query parameters, or a fragment`);
  }
  return result;
}

function hexValue(value: unknown, path: string, minimumLength = 2): string {
  const result = stringValue(value, path).toLowerCase();
  if (result.length < minimumLength || result.length % 2 !== 0 || !HEX_PATTERN.test(result)) {
    return fail(`${path} must be an even-length hexadecimal value`);
  }
  return result;
}

function positiveInteger(value: unknown, path: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) return fail(`${path} must be a positive integer`);
  return value as number;
}

function nonNegativeInteger(value: unknown, path: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) return fail(`${path} must be a non-negative integer`);
  return value as number;
}

function assertSafeJson(value: unknown, depth = 0, state = { nodes: 0 }): void {
  state.nodes += 1;
  if (state.nodes > MAX_JSON_NODES) fail('public proof contains too many JSON values');
  if (depth > MAX_JSON_DEPTH) fail('public proof JSON is too deeply nested');
  if (Array.isArray(value)) {
    value.forEach((item) => assertSafeJson(item, depth + 1, state));
  } else if (value && typeof value === 'object') {
    Object.entries(value).forEach(([key, child]) => {
      if (key.length > 256) fail('public proof contains an excessively long field name');
      assertSafeJson(child, depth + 1, state);
    });
  }
}

function assertNoSensitiveData(value: unknown, path = '$'): void {
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertNoSensitiveData(item, `${path}[${index}]`));
    return;
  }
  if (!value || typeof value !== 'object') {
    if (typeof value === 'string' && EMAIL_PATTERN.test(value.trim())) {
      fail(`public proof contains an email-like value at ${path}`);
    }
    return;
  }
  for (const [key, child] of Object.entries(value)) {
    // `requireVerifiedEmail` is a public eligibility rule, not an address.
    // Other keys containing email or account identifiers are never allowed in
    // the public proof, including variants such as emailAddress or userId.
    if (SENSITIVE_KEY_PATTERN.test(key) && key.toLowerCase() !== 'requireverifiedemail') {
      fail(`public proof contains a private field at ${path}.${key}`);
    }
    assertNoSensitiveData(child, `${path}.${key}`);
  }
}

function parseSnapshot(value: unknown): CampaignSnapshot {
  const input = record(value, 'snapshot');
  assertKnownKeys(input, [
    'hash', 'rulesHash', 'publishedAt', 'entryCount', 'eligibleCount', 'freeCount', 'paidCount',
    'manifest', 'ticketIds', 'entries',
  ], 'snapshot');
  const ticketIds = input.ticketIds;
  if (!Array.isArray(ticketIds) || ticketIds.some((ticketId) => typeof ticketId !== 'string' || !ticketId)) {
    fail('snapshot.ticketIds must be a non-empty-string array');
  }
  if ((ticketIds as unknown[]).length > MAX_TICKET_COUNT) {
    fail(`snapshot.ticketIds cannot contain more than ${MAX_TICKET_COUNT} tickets`);
  }
  const freeCount = nonNegativeInteger(input.freeCount, 'snapshot.freeCount');
  const paidCount = nonNegativeInteger(input.paidCount, 'snapshot.paidCount');
  const eligibleCount = input.eligibleCount === undefined
    ? freeCount + paidCount
    : nonNegativeInteger(input.eligibleCount, 'snapshot.eligibleCount');
  let entries: SegmentedSnapshotEntry[] | undefined;
  if (input.entries !== undefined) {
    if (!Array.isArray(input.entries)) fail('snapshot.entries must be an array');
    entries = input.entries.map((entry, idx) => {
      const rec = record(entry, `snapshot.entries[${idx}]`);
      assertKnownKeys(rec, ['ticketId', 'segment'], `snapshot.entries[${idx}]`);
      const tId = stringValue(rec.ticketId, `snapshot.entries[${idx}].ticketId`);
      const seg = stringValue(rec.segment, `snapshot.entries[${idx}].segment`);
      if (seg !== 'free' && seg !== 'paid') fail(`snapshot.entries[${idx}].segment must be free or paid`);
      return { ticketId: tId, segment: seg as 'free' | 'paid' };
    });
  }
  return {
    hash: hashValue(input.hash, 'snapshot.hash'),
    rulesHash: hashValue(input.rulesHash, 'snapshot.rulesHash'),
    publishedAt: stringValue(input.publishedAt, 'snapshot.publishedAt'),
    entryCount: nonNegativeInteger(input.entryCount, 'snapshot.entryCount'),
    eligibleCount,
    freeCount,
    paidCount,
    manifest: input.manifest === undefined ? undefined : stringValue(input.manifest, 'snapshot.manifest'),
    ticketIds: ticketIds as string[],
    entries,
  };
}

function parseDrand(value: unknown): CampaignDrandProof {
  const input = record(value, 'drand');
  assertKnownKeys(input, [
    'beaconId', 'chainHash', 'targetRound', 'targetRoundTime', 'verifiedAt', 'publicKey',
    'randomness', 'signature', 'previousSignature', 'beaconPayload',
  ], 'drand');
  return {
    beaconId: stringValue(input.beaconId, 'drand.beaconId'),
    chainHash: hashValue(input.chainHash, 'drand.chainHash'),
    targetRound: positiveInteger(input.targetRound, 'drand.targetRound'),
    targetRoundTime: input.targetRoundTime === undefined || input.targetRoundTime === null
      ? input.targetRoundTime
      : (typeof input.targetRoundTime === 'string' || typeof input.targetRoundTime === 'number'
        ? input.targetRoundTime
        : fail('drand.targetRoundTime must be a string, number, or null')),
    verifiedAt: optionalString(input.verifiedAt, 'drand.verifiedAt'),
    publicKey: hexValue(input.publicKey, 'drand.publicKey', 64),
    randomness: hashValue(input.randomness, 'drand.randomness'),
    signature: hexValue(input.signature, 'drand.signature', 64),
    previousSignature: input.previousSignature === undefined || input.previousSignature === null
      ? input.previousSignature
      : hexValue(input.previousSignature, 'drand.previousSignature', 64),
    beaconPayload: input.beaconPayload === undefined ? undefined : record(input.beaconPayload, 'drand.beaconPayload'),
  };
}

function parseWinner(value: unknown, index: number): CampaignWinner {
  const input = record(value, `draw.winners[${index}]`);
  assertKnownKeys(input, ['ticketId', 'score', 'rank'], `draw.winners[${index}]`);
  return {
    ticketId: stringValue(input.ticketId, `draw.winners[${index}].ticketId`),
    score: hashValue(input.score, `draw.winners[${index}].score`),
    rank: positiveInteger(input.rank, `draw.winners[${index}].rank`),
  };
}

function parseDraw(value: unknown): CampaignDrawProof {
  const input = record(value, 'draw');
  assertKnownKeys(input, [
    'beaconId', 'chainHash', 'round', 'roundTime', 'randomness', 'signature', 'previousSignature',
    'snapshotHash', 'rulesHash', 'drawSeed', 'algorithmVersion', 'beaconPayload', 'winners',
    'completedAt',
  ], 'draw');
  if (!Array.isArray(input.winners)) fail('draw.winners must be an array');
  return {
    beaconId: stringValue(input.beaconId, 'draw.beaconId'),
    chainHash: hashValue(input.chainHash, 'draw.chainHash'),
    round: positiveInteger(input.round, 'draw.round'),
    roundTime: input.roundTime === undefined || input.roundTime === null
      ? input.roundTime
      : (typeof input.roundTime === 'string' || typeof input.roundTime === 'number'
        ? input.roundTime
        : fail('draw.roundTime must be a string, number, or null')),
    randomness: hashValue(input.randomness, 'draw.randomness'),
    signature: hexValue(input.signature, 'draw.signature', 64),
    previousSignature: input.previousSignature === undefined || input.previousSignature === null
      ? input.previousSignature
      : hexValue(input.previousSignature, 'draw.previousSignature', 64),
    snapshotHash: hashValue(input.snapshotHash, 'draw.snapshotHash'),
    rulesHash: hashValue(input.rulesHash, 'draw.rulesHash'),
    drawSeed: hashValue(input.drawSeed, 'draw.drawSeed'),
    algorithmVersion: stringValue(input.algorithmVersion, 'draw.algorithmVersion'),
    beaconPayload: input.beaconPayload === undefined ? undefined : record(input.beaconPayload, 'draw.beaconPayload'),
    winners: input.winners.map(parseWinner),
    completedAt: optionalString(input.completedAt, 'draw.completedAt'),
  };
}

export function parseSnapshotCommitment(value: unknown, path = 'snapshotCommitment'): SnapshotCommitment {
  const input = record(value, path);
  assertKnownKeys(input, [
    'commitmentVersion', 'campaignId', 'snapshotHash', 'rulesHash', 'entryCount', 'eligibleCount',
    'freeCount', 'paidCount', 'publishedAt', 'commitmentHash',
    'drawAlgorithmVersion', 'winnerCount', 'freeWinnerCount', 'paidWinnerCount',
  ], path);
  const commitmentVersion = stringValue(input.commitmentVersion, `${path}.commitmentVersion`);
  if (commitmentVersion !== SNAPSHOT_COMMITMENT_VERSION && commitmentVersion !== SEGMENTED_SNAPSHOT_COMMITMENT_VERSION) {
    fail(`unsupported snapshot commitment version: ${commitmentVersion}`);
  }
  return {
    commitmentVersion,
    campaignId: stringValue(input.campaignId, `${path}.campaignId`),
    snapshotHash: hashValue(input.snapshotHash, `${path}.snapshotHash`),
    rulesHash: hashValue(input.rulesHash, `${path}.rulesHash`),
    entryCount: nonNegativeInteger(input.entryCount, `${path}.entryCount`),
    eligibleCount: nonNegativeInteger(input.eligibleCount, `${path}.eligibleCount`),
    freeCount: nonNegativeInteger(input.freeCount, `${path}.freeCount`),
    paidCount: nonNegativeInteger(input.paidCount, `${path}.paidCount`),
    publishedAt: stringValue(input.publishedAt, `${path}.publishedAt`),
    commitmentHash: hashValue(input.commitmentHash, `${path}.commitmentHash`),
    drawAlgorithmVersion: input.drawAlgorithmVersion === undefined ? undefined : stringValue(input.drawAlgorithmVersion, `${path}.drawAlgorithmVersion`),
    winnerCount: input.winnerCount === undefined ? undefined : positiveInteger(input.winnerCount, `${path}.winnerCount`),
    freeWinnerCount: input.freeWinnerCount === undefined || input.freeWinnerCount === null
      ? (input.freeWinnerCount as null | undefined)
      : nonNegativeInteger(input.freeWinnerCount, `${path}.freeWinnerCount`),
    paidWinnerCount: input.paidWinnerCount === undefined || input.paidWinnerCount === null
      ? (input.paidWinnerCount as null | undefined)
      : nonNegativeInteger(input.paidWinnerCount, `${path}.paidWinnerCount`),
  };
}

export function parseSnapshotArchive(value: unknown, path = 'archive'): CampaignSnapshotArchive {
  const input = record(value, path);
  assertKnownKeys(input, [
    'type', 'commitmentHash', 'commitmentJsonSha256', 'timestampReceiptSha256',
    'archiveUrl', 'receiptUrl', 'verifierCommit', 'tsaUrl',
  ], path);
  const type = stringValue(input.type, `${path}.type`);
  if (type !== 'rfc3161') fail(`${path}.type must be rfc3161`);
  return {
    type: 'rfc3161',
    commitmentHash: hashValue(input.commitmentHash, `${path}.commitmentHash`),
    commitmentJsonSha256: hashValue(input.commitmentJsonSha256, `${path}.commitmentJsonSha256`),
    timestampReceiptSha256: hashValue(input.timestampReceiptSha256, `${path}.timestampReceiptSha256`),
    archiveUrl: httpsUrlValue(input.archiveUrl, `${path}.archiveUrl`),
    receiptUrl: httpsUrlValue(input.receiptUrl, `${path}.receiptUrl`),
    verifierCommit: commitValue(input.verifierCommit, `${path}.verifierCommit`),
    tsaUrl: httpsUrlValue(input.tsaUrl, `${path}.tsaUrl`),
  };
}

export function parseProof(input: unknown): CampaignProof {
  assertSafeJson(input);
  assertNoSensitiveData(input);
  const root = record(input, 'proof');
  const proofVersion = stringValue(root.proofVersion, 'proofVersion');
  if (proofVersion !== SUPPORTED_PROOF_VERSION) {
    fail(`unsupported proof version: ${proofVersion}`);
  }
  assertKnownKeys(root, [
    'proofVersion', 'proofHashAlgorithm', 'proofHash', 'id', 'slug', 'name', 'status', 'startAt',
    'endAt', 'drawAt', 'winnerCount', 'freeWinnerCount', 'paidWinnerCount', 'eligibilityRules',
    'drawAlgorithmVersion', 'snapshot', 'snapshotCommitment', 'archive', 'drand', 'draw',
  ], 'proof');
  const rules = record(root.eligibilityRules, 'eligibilityRules');
  const winnerCount = positiveInteger(root.winnerCount, 'winnerCount');
  if (winnerCount > 1000) fail('winnerCount cannot exceed 1000');
  const freeWinnerCount = root.freeWinnerCount === undefined || root.freeWinnerCount === null
    ? (root.freeWinnerCount as null | undefined)
    : nonNegativeInteger(root.freeWinnerCount, 'freeWinnerCount');
  const paidWinnerCount = root.paidWinnerCount === undefined || root.paidWinnerCount === null
    ? (root.paidWinnerCount as null | undefined)
    : nonNegativeInteger(root.paidWinnerCount, 'paidWinnerCount');
  const proofHash = root.proofHash === undefined ? undefined : hashValue(root.proofHash, 'proofHash');
  const proofHashAlgorithm = root.proofHashAlgorithm === undefined
    ? undefined
    : stringValue(root.proofHashAlgorithm, 'proofHashAlgorithm');
  if (proofHashAlgorithm !== PROOF_HASH_ALGORITHM) {
    fail(`unsupported proof hash algorithm: ${proofHashAlgorithm || 'missing'}`);
  }
  if (!proofHash) fail('proofHash is required for protocol v2');
  const snapshot = parseSnapshot(root.snapshot);
  if (root.snapshotCommitment === undefined) {
    fail(`snapshotCommitment is required for protocol v${SUPPORTED_PROOF_VERSION}`);
  }
  if (root.archive === undefined) {
    fail(`proof.archive is required for protocol v${SUPPORTED_PROOF_VERSION}`);
  }
  const snapshotCommitment = parseSnapshotCommitment(root.snapshotCommitment);
  const archive = parseSnapshotArchive(root.archive);
  const proof: CampaignProof = {
    proofVersion,
    proofHashAlgorithm,
    proofHash,
    id: stringValue(root.id, 'id'),
    slug: stringValue(root.slug, 'slug'),
    name: stringValue(root.name, 'name'),
    status: stringValue(root.status, 'status'),
    startAt: optionalString(root.startAt, 'startAt'),
    endAt: optionalString(root.endAt, 'endAt'),
    drawAt: optionalString(root.drawAt, 'drawAt'),
    winnerCount,
    freeWinnerCount,
    paidWinnerCount,
    eligibilityRules: rules,
    drawAlgorithmVersion: stringValue(root.drawAlgorithmVersion, 'drawAlgorithmVersion'),
    snapshot,
    snapshotCommitment,
    archive,
    drand: parseDrand(root.drand),
    draw: parseDraw(root.draw),
  };
  const validAlgorithms = [DRAW_ALGORITHM_VERSION, SEGMENTED_DRAW_ALGORITHM_VERSION];
  if (!validAlgorithms.includes(proof.drawAlgorithmVersion) || !validAlgorithms.includes(proof.draw.algorithmVersion)) {
    fail('unsupported draw algorithm version');
  }
  if (proof.drawAlgorithmVersion !== proof.draw.algorithmVersion) {
    fail('drawAlgorithmVersion mismatch between proof root and draw object');
  }
  if (proof.drawAlgorithmVersion === SEGMENTED_DRAW_ALGORITHM_VERSION) {
    if (proof.freeWinnerCount == null || proof.paidWinnerCount == null) {
      fail('freeWinnerCount and paidWinnerCount are required for segmented draw algorithm');
    }
    if (proof.freeWinnerCount + proof.paidWinnerCount !== proof.winnerCount) {
      fail('freeWinnerCount + paidWinnerCount must equal winnerCount');
    }
    if (!proof.snapshot.entries) {
      fail('snapshot.entries is required for segmented draw algorithm');
    }
  }
  if (proof.status !== COMPLETED_PROOF_STATUS) {
    fail(`proof status must be ${COMPLETED_PROOF_STATUS}`);
  }
  return proof;
}

export { assertNoSensitiveData };
