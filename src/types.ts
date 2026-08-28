export interface SegmentedSnapshotEntry {
  ticketId: string;
  segment: 'free' | 'paid';
}

export interface CampaignSnapshot {
  hash: string;
  rulesHash: string;
  publishedAt: string;
  entryCount: number;
  eligibleCount: number;
  freeCount: number;
  paidCount: number;
  manifest?: string;
  ticketIds: string[];
  entries?: SegmentedSnapshotEntry[];
}

export interface CampaignSnapshotArchive {
  type: 'rfc3161';
  commitmentHash: string;
  commitmentJsonSha256: string;
  timestampReceiptSha256: string;
  archiveUrl: string;
  receiptUrl: string;
  verifierCommit: string;
  tsaUrl: string;
}

export interface SnapshotCommitment {
  commitmentVersion: string;
  campaignId: string;
  snapshotHash: string;
  rulesHash: string;
  entryCount: number;
  eligibleCount: number;
  freeCount: number;
  paidCount: number;
  publishedAt: string;
  commitmentHash: string;
  drawAlgorithmVersion?: string;
  winnerCount?: number;
  freeWinnerCount?: number | null;
  paidWinnerCount?: number | null;
}

export interface CampaignDrandProof {
  beaconId: string;
  chainHash: string;
  targetRound: number;
  targetRoundTime?: string | number | null;
  verifiedAt?: string | null;
  publicKey: string;
  randomness: string;
  signature: string;
  previousSignature?: string | null;
  beaconPayload?: Record<string, unknown>;
}

export interface CampaignWinner {
  ticketId: string;
  score: string;
  rank: number;
}

export interface CampaignDrawProof {
  beaconId: string;
  chainHash: string;
  round: number;
  roundTime?: string | number | null;
  randomness: string;
  signature: string;
  previousSignature?: string | null;
  snapshotHash: string;
  rulesHash: string;
  drawSeed: string;
  algorithmVersion: string;
  beaconPayload?: Record<string, unknown>;
  winners: CampaignWinner[];
  completedAt?: string | null;
}

export interface CampaignProof {
  proofVersion: string;
  proofHashAlgorithm: string;
  proofHash: string;
  id: string;
  slug: string;
  name: string;
  status: string;
  startAt?: string | null;
  endAt?: string | null;
  drawAt?: string | null;
  winnerCount: number;
  freeWinnerCount?: number | null;
  paidWinnerCount?: number | null;
  eligibilityRules: Record<string, unknown>;
  drawAlgorithmVersion: string;
  snapshot: CampaignSnapshot;
  snapshotCommitment: SnapshotCommitment;
  archive: CampaignSnapshotArchive;
  drand: CampaignDrandProof;
  draw: CampaignDrawProof;
}
