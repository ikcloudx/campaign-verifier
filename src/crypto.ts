import type { SnapshotCommitment } from './types.ts';

export const DRAW_ALGORITHM_VERSION = 'campaign-drand-v1';
export const SEGMENTED_DRAW_ALGORITHM_VERSION = 'campaign-drand-segmented-v1';
export const PROOF_HASH_ALGORITHM = 'sha256-stable-json-v1';
export const SNAPSHOT_COMMITMENT_VERSION = 'campaign-snapshot-v1';
export const SEGMENTED_SNAPSHOT_COMMITMENT_VERSION = 'campaign-snapshot-v2';
const SCORE_BATCH_SIZE = 1024;

const encoder = new TextEncoder();

export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    const serialized = JSON.stringify(value);
    // Rules are JSON objects in the public protocol. Treat an unsupported
    // undefined value as null instead of making the browser hash "undefined".
    return serialized === undefined ? 'null' : serialized;
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(',')}]`;
  }
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object).sort().map((key) => (
    `${JSON.stringify(key)}:${stableStringify(object[key])}`
  )).join(',')}}`;
}

export async function sha256Hex(value: string): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', encoder.encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export async function sha256HexBytes(value: Uint8Array): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', value as BufferSource);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export async function hashRules(rules: Record<string, unknown>): Promise<string> {
  return sha256Hex(stableStringify(rules || {}));
}

export async function hashPublicProof(proof: Record<string, unknown>): Promise<string> {
  const input = JSON.parse(JSON.stringify(proof || {})) as Record<string, unknown>;
  delete input.proofHash;
  return sha256Hex(stableStringify(input));
}

export interface SnapshotCommitmentInput {
  campaignId: string;
  snapshotHash: string;
  rulesHash: string;
  entryCount: number;
  eligibleCount: number;
  freeCount: number;
  paidCount: number;
  publishedAt: string;
  drawAlgorithmVersion?: string;
  winnerCount?: number;
  freeWinnerCount?: number | null;
  paidWinnerCount?: number | null;
}

export async function createSnapshotCommitment(input: SnapshotCommitmentInput): Promise<SnapshotCommitment> {
  const segmented = input.freeWinnerCount != null && input.paidWinnerCount != null;
  const payload = {
    commitmentVersion: segmented
      ? SEGMENTED_SNAPSHOT_COMMITMENT_VERSION
      : SNAPSHOT_COMMITMENT_VERSION,
    campaignId: String(input.campaignId),
    snapshotHash: String(input.snapshotHash).toLowerCase(),
    rulesHash: String(input.rulesHash).toLowerCase(),
    entryCount: Number(input.entryCount),
    eligibleCount: Number(input.eligibleCount),
    freeCount: Number(input.freeCount),
    paidCount: Number(input.paidCount),
    ...(!segmented
      ? {}
      : {
          drawAlgorithmVersion: String(input.drawAlgorithmVersion),
          winnerCount: Number(input.winnerCount),
          freeWinnerCount: Number(input.freeWinnerCount),
          paidWinnerCount: Number(input.paidWinnerCount),
        }),
    publishedAt: new Date(input.publishedAt).toISOString(),
  };
  return {
    ...payload,
    commitmentHash: await sha256Hex(stableStringify(payload)),
  };
}

export async function createSnapshotManifest(ticketIds: string[]): Promise<{
  ticketIds: string[];
  manifest: string;
  hash: string;
}> {
  const sorted = [...new Set(ticketIds.map(String))].sort();
  const manifest = `${sorted.join('\n')}${sorted.length ? '\n' : ''}`;
  return { ticketIds: sorted, manifest, hash: await sha256Hex(manifest) };
}

export async function createSegmentedSnapshotManifest(
  entries: Array<{ ticketId: string; segment: string }>,
): Promise<{
  entries: Array<{ ticketId: string; segment: string }>;
  ticketIds: string[];
  manifest: string;
  hash: string;
}> {
  const byTicketId = new Map<string, string>();
  for (const entry of entries) {
    const ticketId = String(entry?.ticketId ?? '');
    const segment = String(entry?.segment ?? '');
    if (!ticketId || (segment !== 'free' && segment !== 'paid')) {
      throw new Error('segmented snapshot entries require a ticketId and free or paid segment');
    }
    const existing = byTicketId.get(ticketId);
    if (existing && existing !== segment) {
      throw new Error('segmented snapshot ticket IDs must have exactly one segment');
    }
    byTicketId.set(ticketId, segment);
  }
  const normalizedEntries = [...byTicketId]
    .map(([ticketId, segment]) => ({ ticketId, segment }))
    .sort((left, right) => (left.ticketId < right.ticketId ? -1 : left.ticketId > right.ticketId ? 1 : 0));
  const manifest = normalizedEntries
    .map((entry) => `${entry.segment}\t${entry.ticketId}\n`)
    .join('');
  return {
    entries: normalizedEntries,
    ticketIds: normalizedEntries.map((entry) => entry.ticketId),
    manifest,
    hash: await sha256Hex(manifest),
  };
}

export async function createDrawSeed(input: {
  chainHash: string;
  round: number;
  randomness: string;
  campaignId: string;
  snapshotHash: string;
  rulesHash: string;
  algorithmVersion?: string;
  freeWinnerCount?: number | null;
  paidWinnerCount?: number | null;
}): Promise<string> {
  const algorithmVersion = input.algorithmVersion || DRAW_ALGORITHM_VERSION;
  const payload = [
    algorithmVersion,
    String(input.chainHash).toLowerCase(),
    String(input.round),
    String(input.randomness).toLowerCase(),
    String(input.campaignId),
    String(input.snapshotHash).toLowerCase(),
    String(input.rulesHash).toLowerCase(),
    ...(algorithmVersion === SEGMENTED_DRAW_ALGORITHM_VERSION
      ? [String(input.freeWinnerCount), String(input.paidWinnerCount)]
      : []),
  ].join('\0');
  return sha256Hex(payload);
}

export async function scoreTicket(drawSeed: string, ticketId: string): Promise<string> {
  return sha256Hex(`${drawSeed}\0${ticketId}`);
}

export async function selectWinners(
  ticketIds: string[],
  winnerCount: number,
  drawSeed: string,
): Promise<Array<{ ticketId: string; score: string; rank: number }>> {
  const scored: Array<{ ticketId: string; score: string }> = [];
  // Bound the number of WebCrypto promises kept in memory at once. This keeps
  // a valid but large public proof from turning winner recomputation into a
  // browser-side promise/memory spike.
  for (let offset = 0; offset < ticketIds.length; offset += SCORE_BATCH_SIZE) {
    const batch = ticketIds.slice(offset, offset + SCORE_BATCH_SIZE);
    scored.push(...await Promise.all(batch.map(async (ticketId) => ({
      ticketId: String(ticketId),
      score: await scoreTicket(drawSeed, String(ticketId)),
    }))));
  }
  return scored
    .sort((left, right) => (
      left.score.localeCompare(right.score, 'en') || left.ticketId.localeCompare(right.ticketId, 'en')
    ))
    .slice(0, winnerCount)
    .map((winner, index) => ({ ...winner, rank: index + 1 }));
}

export async function selectSegmentedWinners(
  entries: Array<{ ticketId: string; segment: string }>,
  quotas: { freeWinnerCount: number; paidWinnerCount: number },
  drawSeed: string,
): Promise<Array<{ ticketId: string; score: string; rank: number }>> {
  const freeTicketIds: string[] = [];
  const paidTicketIds: string[] = [];
  for (const entry of entries) {
    if (entry.segment === 'free') freeTicketIds.push(entry.ticketId);
    else if (entry.segment === 'paid') paidTicketIds.push(entry.ticketId);
  }
  const freeWinners = await selectWinners(freeTicketIds, quotas.freeWinnerCount, drawSeed);
  const paidWinners = await selectWinners(paidTicketIds, quotas.paidWinnerCount, drawSeed);
  const selected = [...freeWinners, ...paidWinners];
  return selected
    .sort((left, right) => (
      left.score.localeCompare(right.score, 'en') || left.ticketId.localeCompare(right.ticketId, 'en')
    ))
    .map((winner, index) => ({ ...winner, rank: index + 1 }));
}
