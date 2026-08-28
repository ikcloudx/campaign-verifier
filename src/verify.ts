import {
  createDrawSeed,
  createSegmentedSnapshotManifest,
  createSnapshotCommitment,
  createSnapshotManifest,
  hashRules,
  hashPublicProof,
  sha256HexBytes,
  selectSegmentedWinners,
  selectWinners,
  SEGMENTED_DRAW_ALGORITHM_VERSION,
} from './crypto.ts';
import { assertNoSensitiveData, parseSnapshotCommitment } from './proof-schema.ts';
import type { CampaignProof, CampaignSnapshotArchive, SnapshotCommitment } from './types.ts';
import type { Rfc3161VerificationOptions } from './rfc3161.ts';

export interface CheckResult {
  id: string;
  label: string;
  ok: boolean;
  detail: string;
  warning?: boolean;
}

export interface IntegrityVerificationResult {
  checks: CheckResult[];
  ok: boolean;
}

export interface ArchiveVerificationResult {
  checks: CheckResult[];
  ok: boolean;
}

export interface ArchiveVerificationOptions {
  rfc3161?: Rfc3161VerificationOptions;
}

function check(id: string, label: string, ok: boolean, detail: string, warning = false): CheckResult {
  return { id, label, ok, detail, ...(warning ? { warning: true } : {}) };
}

function same(left: string | number | null | undefined, right: string | number | null | undefined): boolean {
  return String(left ?? '').toLowerCase() === String(right ?? '').toLowerCase();
}

function epochMs(value: string | number | null | undefined): number {
  if (typeof value === 'number') {
    return Number.isFinite(value) ? (value < 1e12 ? value * 1000 : value) : Number.NaN;
  }
  if (typeof value !== 'string' || !value) return Number.NaN;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? Number.NaN : parsed;
}

function payloadMatchesBeacon(
  payload: Record<string, unknown> | undefined,
  proof: CampaignProof,
  previousSignature: string | null | undefined,
): boolean {
  if (!payload) return false;
  return Number(payload.round) === proof.draw.round
    && same(payload.randomness as string, proof.draw.randomness)
    && same(payload.signature as string, proof.draw.signature)
    && (payload.previous_signature === undefined
      || same(payload.previous_signature as string, previousSignature));
}

function commitmentFieldsMatch(left: SnapshotCommitment, right: SnapshotCommitment): boolean {
  return left.commitmentVersion === right.commitmentVersion
    && left.campaignId === right.campaignId
    && same(left.snapshotHash, right.snapshotHash)
    && same(left.rulesHash, right.rulesHash)
    && left.entryCount === right.entryCount
    && left.eligibleCount === right.eligibleCount
    && left.freeCount === right.freeCount
    && left.paidCount === right.paidCount
    && left.drawAlgorithmVersion === right.drawAlgorithmVersion
    && left.winnerCount === right.winnerCount
    && left.freeWinnerCount === right.freeWinnerCount
    && left.paidWinnerCount === right.paidWinnerCount
    && left.publishedAt === right.publishedAt
    && same(left.commitmentHash, right.commitmentHash);
}

function decodeUtf8(value: Uint8Array, label: string): string {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(value);
  } catch {
    throw new Error(`${label} 不是有效的 UTF-8 文本。`);
  }
}

export async function verifySnapshotArchive(
  proof: CampaignProof,
  archive: CampaignSnapshotArchive,
  commitmentBytes: Uint8Array,
  receiptBytes: Uint8Array,
  options: ArchiveVerificationOptions = {},
): Promise<ArchiveVerificationResult> {
  const checks: CheckResult[] = [];
  const commitmentJsonSha256 = await sha256HexBytes(commitmentBytes);
  const commitmentJsonHashMatches = same(commitmentJsonSha256, archive.commitmentJsonSha256);
  checks.push(check(
    'archive-json-sha256',
    '归档 JSON 原始字节哈希',
    commitmentJsonHashMatches,
    commitmentJsonHashMatches
      ? `归档 JSON 的 SHA-256 为 ${commitmentJsonSha256}。`
      : `归档 JSON 的 SHA-256 为 ${commitmentJsonSha256}，与 Proof 登记值不一致。`,
  ));

  const receiptSha256 = await sha256HexBytes(receiptBytes);
  const receiptHashMatches = same(receiptSha256, archive.timestampReceiptSha256);
  checks.push(check(
    'archive-receipt-sha256',
    'RFC 3161 receipt 原始字节哈希',
    receiptHashMatches,
    receiptHashMatches
      ? `TSR 的 SHA-256 为 ${receiptSha256}。`
      : `TSR 的 SHA-256 为 ${receiptSha256}，与 Proof 登记值不一致。`,
  ));

  let archivedCommitment: SnapshotCommitment | undefined;
  try {
    const text = decodeUtf8(commitmentBytes, '归档 JSON');
    archivedCommitment = parseSnapshotCommitment(JSON.parse(text), 'archiveCommitment');
  } catch (error) {
    checks.push(check(
      'archive-json-commitment',
      '归档 JSON 承诺内容',
      false,
      error instanceof Error ? error.message : '归档 JSON 无法解析为快照承诺。',
    ));
  }

  if (archivedCommitment) {
    const proofCommitmentMatches = Boolean(proof.snapshotCommitment)
      && commitmentFieldsMatch(archivedCommitment, proof.snapshotCommitment!);
    const metadataCommitmentMatches = same(archivedCommitment.commitmentHash, archive.commitmentHash);
    const bindingMatches = proofCommitmentMatches && metadataCommitmentMatches;
    checks.push(check(
      'archive-json-commitment',
      '归档 JSON 承诺内容',
      proofCommitmentMatches,
      proofCommitmentMatches
        ? '归档 JSON 的快照承诺字段与 Proof 一致。'
        : '归档 JSON 的快照承诺字段与 Proof 不一致。',
    ));
    checks.push(check(
      'archive-binding',
      '归档元数据绑定',
      bindingMatches,
      bindingMatches
        ? '归档登记的 commitmentHash、归档 JSON 和 Proof 三者一致。'
        : '归档登记的 commitmentHash 未同时匹配归档 JSON 和 Proof。',
    ));
  }

  const { verifyRfc3161Receipt } = await import('./rfc3161.ts');
  const rfc3161 = await verifyRfc3161Receipt(
    receiptBytes,
    commitmentBytes,
    archive.tsaUrl,
    options.rfc3161,
  );
  checks.push(...rfc3161.checks);

  const snapshotTime = epochMs(proof.snapshot.publishedAt);
  const targetRoundTime = epochMs(proof.drand.targetRoundTime ?? proof.draw.roundTime);
  const tsaTime = rfc3161.generatedAt?.getTime() ?? Number.NaN;
  const tsaTimelineMatches = Number.isFinite(snapshotTime)
    && Number.isFinite(tsaTime)
    && Number.isFinite(targetRoundTime)
    && snapshotTime < tsaTime
    && tsaTime < targetRoundTime;
  checks.push(check(
    'rfc3161-timeline',
    'TSA 时间顺序',
    tsaTimelineMatches,
    tsaTimelineMatches
      ? `TSA genTime ${rfc3161.generatedAt!.toISOString()} 位于快照发布时间之后、目标 drand round 之前。`
      : 'TSA genTime 必须位于快照发布时间之后、目标 drand round 之前。',
  ));

  return { checks, ok: checks.every((item) => item.ok) };
}

export async function verifyProofIntegrity(proof: CampaignProof): Promise<IntegrityVerificationResult> {
  const checks: CheckResult[] = [];

  try {
    assertNoSensitiveData(proof);
    checks.push(check('privacy', '公开证明不含敏感字段', true, '未发现 email、用户标识或支付标识字段。'));
  } catch (error) {
    checks.push(check('privacy', '公开证明不含敏感字段', false, error instanceof Error ? error.message : '发现敏感字段。'));
  }

  const calculatedProofHash = await hashPublicProof(proof as unknown as Record<string, unknown>);
  const proofHashMatches = same(calculatedProofHash, proof.proofHash);
  checks.push(check(
    'proof-hash',
    '公开 proof 哈希',
    proofHashMatches,
    proofHashMatches
      ? `整份 proof 的 ${proof.proofHashAlgorithm} 哈希一致。`
      : '整份 proof 被修改，或 proofHash 与内容不一致。',
  ));

  const expectedRulesHash = await hashRules(proof.eligibilityRules);
  const rulesMatch = same(expectedRulesHash, proof.snapshot.rulesHash)
    && same(expectedRulesHash, proof.draw.rulesHash);
  checks.push(check(
    'rules-hash',
    '资格规则哈希',
    rulesMatch,
    rulesMatch
      ? `规则哈希 ${expectedRulesHash} 与快照和抽奖记录一致。`
      : `计算值 ${expectedRulesHash} 与公开规则哈希不一致。`,
  ));

  const isSegmented = proof.drawAlgorithmVersion === SEGMENTED_DRAW_ALGORITHM_VERSION;
  const uniqueTicketIds = new Set(proof.snapshot.ticketIds);
  const noDuplicateTickets = uniqueTicketIds.size === proof.snapshot.ticketIds.length;
  const expectedEligibleCount = proof.snapshot.freeCount + proof.snapshot.paidCount;
  const countMatch = expectedEligibleCount === proof.snapshot.eligibleCount
    && proof.snapshot.eligibleCount === proof.snapshot.ticketIds.length;
  const entryCountMatch = proof.snapshot.entryCount >= proof.snapshot.eligibleCount;

  let segmentedCountMatch = true;
  let segmentedCountProblem: string | null = null;
  if (isSegmented && proof.snapshot.entries) {
    const actualFreeCount = proof.snapshot.entries.filter((e) => e.segment === 'free').length;
    const actualPaidCount = proof.snapshot.entries.filter((e) => e.segment === 'paid').length;
    if (actualFreeCount !== proof.snapshot.freeCount || actualPaidCount !== proof.snapshot.paidCount) {
      segmentedCountMatch = false;
      segmentedCountProblem = `entries segment counts (free: ${actualFreeCount}, paid: ${actualPaidCount}) != snapshot counts (free: ${proof.snapshot.freeCount}, paid: ${proof.snapshot.paidCount})`;
    }
  }

  const countProblems = [
    ...(noDuplicateTickets ? [] : ['ticketIds contains duplicates']),
    ...(expectedEligibleCount === proof.snapshot.eligibleCount
      ? []
      : [`freeCount + paidCount (${expectedEligibleCount}) != eligibleCount (${proof.snapshot.eligibleCount})`]),
    ...(proof.snapshot.eligibleCount === proof.snapshot.ticketIds.length
      ? []
      : [`eligibleCount (${proof.snapshot.eligibleCount}) != ticketIds (${proof.snapshot.ticketIds.length})`]),
    ...(entryCountMatch
      ? []
      : [`entryCount (${proof.snapshot.entryCount}) < eligibleCount (${proof.snapshot.eligibleCount})`]),
    ...(segmentedCountProblem ? [segmentedCountProblem] : []),
  ];
  const allCountsMatch = noDuplicateTickets && countMatch && entryCountMatch && segmentedCountMatch;
  checks.push(check(
    'snapshot-counts',
    '快照条目数量',
    allCountsMatch,
    allCountsMatch
      ? `快照包含 ${proof.snapshot.ticketIds.length} 个唯一抽奖票据（总条目 ${proof.snapshot.entryCount}）。`
      : `快照计数不一致：${countProblems.join('；')}`,
  ));

  const manifest = isSegmented && proof.snapshot.entries
    ? await createSegmentedSnapshotManifest(proof.snapshot.entries)
    : await createSnapshotManifest(proof.snapshot.ticketIds);
  const manifestMatches = proof.snapshot.manifest === undefined || proof.snapshot.manifest === manifest.manifest;
  const snapshotHashMatches = same(manifest.hash, proof.snapshot.hash);
  const drawSnapshotHashMatches = same(proof.snapshot.hash, proof.draw.snapshotHash);
  const ticketIdsMatchManifest = manifest.ticketIds.length === uniqueTicketIds.size
    && proof.snapshot.ticketIds.every((id) => manifest.ticketIds.includes(id));
  const snapshotOk = noDuplicateTickets && manifestMatches && snapshotHashMatches && drawSnapshotHashMatches && ticketIdsMatchManifest;
  checks.push(check(
    'snapshot-hash',
    '候选人快照哈希',
    snapshotOk,
    snapshotOk
      ? `快照清单及 SHA-256 ${manifest.hash} 一致。`
      : '快照清单、快照哈希、ticketIds 列表或抽奖记录中的 snapshotHash 不一致。',
  ));

  const expectedCommitment = await createSnapshotCommitment({
    campaignId: proof.id,
    snapshotHash: proof.snapshot.hash,
    rulesHash: proof.snapshot.rulesHash,
    entryCount: proof.snapshot.entryCount,
    eligibleCount: proof.snapshot.eligibleCount,
    freeCount: proof.snapshot.freeCount,
    paidCount: proof.snapshot.paidCount,
    publishedAt: proof.snapshot.publishedAt,
    drawAlgorithmVersion: proof.drawAlgorithmVersion,
    winnerCount: proof.winnerCount,
    freeWinnerCount: proof.freeWinnerCount,
    paidWinnerCount: proof.paidWinnerCount,
  });
  const internalCommitmentMatches = commitmentFieldsMatch(proof.snapshotCommitment, expectedCommitment);
  checks.push(check(
    'snapshot-commitment',
    '快照预承诺',
    internalCommitmentMatches,
    internalCommitmentMatches
      ? `snapshot commitment ${expectedCommitment.commitmentHash} 与快照一致。`
      : 'snapshot commitment 与快照元数据不一致。',
  ));

  const snapshotTime = epochMs(proof.snapshot.publishedAt);
  const targetRoundTime = epochMs(proof.drand.targetRoundTime);
  const drawRoundTime = epochMs(proof.draw.roundTime);
  const hasTargetRoundTime = proof.drand.targetRoundTime !== undefined
    && proof.drand.targetRoundTime !== null;
  const roundTimeFieldsMatch = !hasTargetRoundTime
    || (Number.isFinite(targetRoundTime)
      && Number.isFinite(drawRoundTime)
      && targetRoundTime === drawRoundTime);
  const roundTime = hasTargetRoundTime ? targetRoundTime : drawRoundTime;
  const timelineMatches = Number.isFinite(snapshotTime)
    && Number.isFinite(roundTime)
    && snapshotTime < roundTime
    && roundTimeFieldsMatch;
  checks.push(check(
    'timeline',
    '快照早于随机数公开',
    timelineMatches,
    timelineMatches
      ? '快照发布时间早于目标 drand round，且 draw roundTime 一致。'
      : '快照发布时间必须早于目标 drand round，且时间字段必须一致。',
  ));

  const drandDrawFieldsMatch = proof.drand.beaconId === proof.draw.beaconId
    && same(proof.drand.chainHash, proof.draw.chainHash)
    && proof.drand.targetRound === proof.draw.round
    && same(proof.drand.randomness, proof.draw.randomness)
    && same(proof.drand.signature, proof.draw.signature)
    && same(proof.drand.previousSignature, proof.draw.previousSignature);
  const beaconFieldsMatch = drandDrawFieldsMatch
    && payloadMatchesBeacon(proof.drand.beaconPayload, proof, proof.drand.previousSignature)
    && payloadMatchesBeacon(proof.draw.beaconPayload, proof, proof.draw.previousSignature);
  checks.push(check(
    'beacon-payload',
    'Beacon 字段一致性',
    beaconFieldsMatch,
    beaconFieldsMatch
      ? 'drand、draw 和 beaconPayload 的 chain、round、randomness、signature 一致。'
      : 'drand、draw 或 Beacon payload 的公开字段不一致。',
  ));

  const seed = await createDrawSeed({
    chainHash: proof.draw.chainHash,
    round: proof.draw.round,
    randomness: proof.draw.randomness,
    campaignId: proof.id,
    snapshotHash: proof.draw.snapshotHash,
    rulesHash: proof.draw.rulesHash,
    algorithmVersion: proof.drawAlgorithmVersion,
    freeWinnerCount: proof.freeWinnerCount,
    paidWinnerCount: proof.paidWinnerCount,
  });
  const seedMatches = same(seed, proof.draw.drawSeed);
  checks.push(check(
    'draw-seed',
    '抽奖种子',
    seedMatches,
    seedMatches ? `根据 campaignId、drand 和快照重算得到 ${seed}。` : '重算的抽奖种子与公开 drawSeed 不一致。',
  ));

  let expectedWinners: Array<{ ticketId: string; score: string; rank: number }>;
  if (isSegmented && proof.snapshot.entries && proof.freeWinnerCount != null && proof.paidWinnerCount != null) {
    expectedWinners = await selectSegmentedWinners(
      proof.snapshot.entries,
      { freeWinnerCount: proof.freeWinnerCount, paidWinnerCount: proof.paidWinnerCount },
      seed,
    );
  } else {
    expectedWinners = await selectWinners(proof.snapshot.ticketIds, proof.winnerCount, seed);
  }
  const winnersMatch = expectedWinners.length === proof.draw.winners.length
    && expectedWinners.every((expected, index) => {
      const actual = proof.draw.winners[index];
      return actual
        && actual.rank === expected.rank
        && actual.ticketId === expected.ticketId
        && same(actual.score, expected.score);
    });
  checks.push(check(
    'winners',
    '中奖顺序复算',
    winnersMatch,
    winnersMatch
      ? `按公开算法复算出 ${expectedWinners.length} 名中奖者，顺序和分数一致。`
      : '按公开票据和抽奖种子复算的中奖顺序不一致。',
  ));

  return {
    checks,
    ok: checks.every((item) => item.ok),
  };
}
