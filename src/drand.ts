import { fetchBeacon, HttpCachingChain, HttpChainClient } from 'drand-client';
import type { CampaignProof } from './types.ts';
import type { CheckResult } from './verify.ts';

const DRAND_RELAYS = [
  'https://api.drand.sh',
  'https://api2.drand.sh',
  'https://api3.drand.sh',
  'https://drand.cloudflare.com',
];
const DRAND_REQUEST_TIMEOUT_MS = 10_000;

interface VerifiedBeacon {
  relay: string;
  round: number;
  randomness: string;
  signature: string;
  previousSignature?: string;
  expectedRoundTimeMs: number;
}

function normalize(value: unknown): string {
  return String(value ?? '').toLowerCase();
}

async function verifyAtRelay(proof: CampaignProof, relay: string): Promise<VerifiedBeacon> {
  const options = {
    disableBeaconVerification: false,
    noCache: true,
    chainVerificationParams: {
      chainHash: proof.drand.chainHash,
      publicKey: proof.drand.publicKey,
    },
  } as const;
  const chain = new HttpCachingChain(`${relay}/${proof.drand.chainHash}`, options);
  const client = new HttpChainClient(chain, options);
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error('drand request timed out')), DRAND_REQUEST_TIMEOUT_MS);
  });
  try {
    const work = (async () => {
      const chainInfo = await chain.info();
      const chainBeaconId = String(chainInfo.metadata?.beaconID || '');
      if (chainBeaconId !== proof.drand.beaconId
        || String(chainInfo.hash || '').toLowerCase() !== proof.drand.chainHash
        || String(chainInfo.public_key || '').toLowerCase() !== proof.drand.publicKey) {
        throw new Error('drand chain identity does not match the public proof');
      }
      const beacon = await fetchBeacon(client, proof.drand.targetRound);
      return {
        beacon,
        expectedRoundTimeMs: (Number(chainInfo.genesis_time)
          + (proof.drand.targetRound - 1) * Number(chainInfo.period)) * 1000,
      };
    })();
    const { beacon, expectedRoundTimeMs } = await Promise.race([work, timeout]);
    return {
      relay,
      round: beacon.round,
      randomness: beacon.randomness,
      signature: beacon.signature,
      previousSignature: 'previous_signature' in beacon ? beacon.previous_signature : undefined,
      expectedRoundTimeMs,
    };
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export async function verifyDrandBeacon(proof: CampaignProof): Promise<CheckResult> {
  if (proof.drand.chainHash !== proof.draw.chainHash
    || proof.drand.targetRound !== proof.draw.round
    || normalize(proof.drand.randomness) !== normalize(proof.draw.randomness)
    || normalize(proof.drand.signature) !== normalize(proof.draw.signature)
    || normalize(proof.drand.previousSignature) !== normalize(proof.draw.previousSignature)) {
    return {
      id: 'drand',
      label: 'drand Beacon 签名',
      ok: false,
      detail: '证明中的 drand 和抽奖记录字段不一致，已停止网络验证。',
    };
  }

  const attempts = DRAND_RELAYS.map((relay) => verifyAtRelay(proof, relay));
  try {
    const beacon = await Promise.any(attempts);
    const previousSignatureMatches = proof.drand.previousSignature === undefined
      || proof.drand.previousSignature === null
      || normalize(proof.drand.previousSignature) === normalize(beacon.previousSignature);
    const declaredRoundTime = proof.drand.targetRoundTime ?? proof.draw.roundTime;
    const declaredRoundTimeMs = typeof declaredRoundTime === 'number'
      ? (declaredRoundTime < 1e12 ? declaredRoundTime * 1000 : declaredRoundTime)
      : Date.parse(String(declaredRoundTime));
    const roundTimeMatches = Number.isFinite(declaredRoundTimeMs)
      && declaredRoundTimeMs === beacon.expectedRoundTimeMs
      && (!proof.draw.roundTime
        || (typeof proof.draw.roundTime === 'number'
          ? (proof.draw.roundTime < 1e12 ? proof.draw.roundTime * 1000 : proof.draw.roundTime)
          : Date.parse(String(proof.draw.roundTime))) === beacon.expectedRoundTimeMs);
    const payloadMatches = beacon.round === proof.drand.targetRound
      && normalize(beacon.randomness) === normalize(proof.drand.randomness)
      && normalize(beacon.signature) === normalize(proof.drand.signature)
      && previousSignatureMatches
      && roundTimeMatches;
    return {
      id: 'drand',
      label: 'drand Beacon 签名',
      ok: payloadMatches,
      detail: payloadMatches
        ? `官方 drand 客户端已验证第 ${beacon.round} 轮签名和 round 时间（${beacon.relay}）。`
        : '官方 Beacon 签名有效，但公开证明中的 Beacon 或 round 时间字段与网络返回值不一致。',
    };
  } catch {
    return {
      id: 'drand',
      label: 'drand Beacon 签名',
      ok: false,
      detail: '无法从公开 drand relay 获取并验证该轮 Beacon；请稍后重试或检查网络。',
    };
  }
}

export { DRAND_RELAYS };
export { DRAND_REQUEST_TIMEOUT_MS };
