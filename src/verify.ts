import {
  createDrawSeed,
  createSegmentedSnapshotManifest,
  createSnapshotCommitment,
  createSnapshotManifest,
  hashRules,
  hashPublicProof,
  selectSegmentedWinners,
  selectWinners,
  SEGMENTED_DRAW_ALGORITHM_VERSION,
} from './crypto.ts';
import { assertNoSensitiveData } from './proof-schema.ts';
import type { CampaignProof, SnapshotCommitment } from './types.ts';

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
  externalCommitmentMatches: boolean;
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

export async function verifyProofIntegrity(
  proof: CampaignProof,
  externalCommitment?: SnapshotCommitment,
): Promise<IntegrityVerificationResult> {
  const checks: CheckResult[] = [];
  let externalCommitmentMatches = false;

  try {
    assertNoSensitiveData(proof);
    checks.push(check('privacy', '公开证明不含敏感字段', true, '未发现 email、用户标识或支付标识字段。'));
  } catch (error) {
    checks.push(check('privacy', '公开证明不含敏感字段', false, error instanceof Error ? error.message : '发现敏感字段。'));
  }

  if (proof.proofHash) {
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
  } else {
    checks.push(check(
      'proof-hash',
      '公开 proof 哈希',
      true,
      'legacy proof 未声明 proofHash；仍会继续验证其内部字段。',
      true,
    ));
  }

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

  if (proof.snapshotCommitment) {
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
    const externalMatches = Boolean(externalCommitment)
      && commitmentFieldsMatch(externalCommitment!, proof.snapshotCommitment);
    externalCommitmentMatches = internalCommitmentMatches && externalMatches;
    checks.push(check(
      'external-commitment',
      '第三方快照承诺',
      externalCommitment ? externalMatches : true,
      externalCommitment
        ? (externalMatches
          ? '外部承诺文档与 proof 的快照承诺一致；本浏览器验证器不解析 RFC 3161 receipt，请按 README 独立验证相邻的 .tsr 文件。'
          : '外部承诺文档与 proof 的快照承诺不一致。')
        : '未提供第三方承诺 URL；当前只能证明 proof 内部一致，不能证明外部预先存档。',
      true,
    ));
  } else {
    checks.push(check(
      'snapshot-commitment',
      '快照预承诺',
      !externalCommitment,
      externalCommitment
        ? '外部承诺已提供，但 proof 本身没有 snapshotCommitment 可供比较。'
        : 'legacy proof 未包含 snapshotCommitment；无法核对独立预承诺。',
      !externalCommitment,
    ));
  }

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
    externalCommitmentMatches,
  };
}
