import './style.css';
import { verifyDrandBeacon } from './drand.ts';
import {
  MAX_ARCHIVE_JSON_BYTES,
  MAX_ARCHIVE_RECEIPT_BYTES,
  MAX_PROOF_JSON_BYTES,
  parseProof,
  ProofValidationError,
} from './proof-schema.ts';
import type { CampaignProof } from './types.ts';
import type { ArchiveVerificationResult, CheckResult, IntegrityVerificationResult } from './verify.ts';
import { verifyProofIntegrity, verifySnapshotArchive } from './verify.ts';

const app = document.querySelector<HTMLElement>('#app');
if (!app) throw new Error('Missing application root');

app.innerHTML = `
  <header class="hero">
    <p class="eyebrow">CAMPAIGN VERIFIER</p>
    <h1>公开抽奖验证</h1>
    <p class="lead">把公开 proof JSON 交给浏览器本地复核。这个站点没有登录、后端或邮箱数据。</p>
  </header>
  <section class="panel" aria-labelledby="input-title">
    <h2 id="input-title">载入公开证明</h2>
    <form id="proof-form">
      <label for="proof-url">Proof URL</label>
      <div class="url-row">
        <input id="proof-url" name="proof-url" type="url" inputmode="url" autocomplete="off"
          placeholder="https://主站.example/api/campaigns/summer/proof" />
        <button type="submit" id="verify-button">开始验证</button>
      </div>
      <p class="hint">也可以直接粘贴 proof JSON；所有哈希和中奖排序均在本浏览器执行。</p>
      <p class="hint">验证器只接受包含不可变归档的 protocol v2 proof，会自动读取归档 JSON 和 RFC 3161 <code>.tsr</code>。浏览器会校验原始字节摘要，完整 TSA 签名/证书链仍需独立客户端确认。</p>
      <label for="proof-json">Proof JSON（可选）</label>
      <textarea id="proof-json" name="proof-json" rows="7" spellcheck="false"
        placeholder="{\n  &quot;slug&quot;: &quot;...&quot;\n}"></textarea>
    </form>
    <p id="notice" class="notice" role="status" aria-live="polite"></p>
  </section>
  <section id="result-panel" class="panel results" hidden aria-labelledby="result-title">
    <div class="result-heading">
      <div>
        <p class="eyebrow">VERIFICATION RESULT</p>
        <h2 id="result-title">验证结果</h2>
      </div>
      <span id="overall-badge" class="badge"></span>
    </div>
    <dl id="campaign-summary" class="summary"></dl>
    <div>
      <h3>检查项</h3>
      <ul id="checks" class="checks"></ul>
    </div>
    <div>
      <h3>公开中奖票据</h3>
      <ol id="winners" class="winners"></ol>
      <p id="winner-note" class="hint"></p>
    </div>
  </section>
  <footer class="footer">
    <p>验证器只读取公开证明，不会上传或展示用户邮箱。请同时保存 proof 原文和本次验证时间。</p>
  </footer>
`;

const form = document.querySelector<HTMLFormElement>('#proof-form')!;
const proofUrlInput = document.querySelector<HTMLInputElement>('#proof-url')!;
const proofJsonInput = document.querySelector<HTMLTextAreaElement>('#proof-json')!;
const verifyButton = document.querySelector<HTMLButtonElement>('#verify-button')!;
const notice = document.querySelector<HTMLElement>('#notice')!;
const resultPanel = document.querySelector<HTMLElement>('#result-panel')!;
const overallBadge = document.querySelector<HTMLElement>('#overall-badge')!;
const campaignSummary = document.querySelector<HTMLElement>('#campaign-summary')!;
const checksList = document.querySelector<HTMLElement>('#checks')!;
const winnersList = document.querySelector<HTMLOListElement>('#winners')!;
const winnerNote = document.querySelector<HTMLElement>('#winner-note')!;

if (!form || !proofUrlInput || !proofJsonInput || !verifyButton || !notice || !resultPanel
  || !overallBadge || !campaignSummary || !checksList || !winnersList || !winnerNote) {
  throw new Error('Verifier UI is incomplete');
}

const queryProof = new URLSearchParams(window.location.search).get('proof');
if (queryProof) proofUrlInput.value = queryProof;

function setNotice(message: string, kind: 'info' | 'error' | 'warning' = 'info'): void {
  notice.textContent = message;
  notice.className = `notice ${kind}`;
}

function setLoading(loading: boolean): void {
  verifyButton.disabled = loading;
  verifyButton.textContent = loading ? '验证中…' : '开始验证';
}

function appendSummaryRow(label: string, value: string): void {
  const term = document.createElement('dt');
  term.textContent = label;
  const description = document.createElement('dd');
  description.textContent = value;
  campaignSummary.append(term, description);
}

function renderSummary(proof: CampaignProof): void {
  campaignSummary.replaceChildren();
  appendSummaryRow('活动', `${proof.name}（${proof.slug}）`);
  appendSummaryRow('状态', proof.status);
  appendSummaryRow('候选票据', `${proof.snapshot.ticketIds.length}（免费 ${proof.snapshot.freeCount}，付费 ${proof.snapshot.paidCount}）`);
  appendSummaryRow('目标轮次', `${proof.drand.beaconId} · ${proof.drand.targetRound}`);
  appendSummaryRow('算法', proof.drawAlgorithmVersion);
  appendSummaryRow('快照承诺', proof.snapshotCommitment.commitmentHash);
  appendSummaryRow('归档 JSON', proof.archive.archiveUrl);
  appendSummaryRow('RFC 3161 receipt', proof.archive.receiptUrl);
  appendSummaryRow('协议提示', '归档元数据已纳入 proofHash；浏览器会自动校验 JSON/TSR 原始字节摘要。');
}

function renderChecks(checks: CheckResult[]): void {
  checksList.replaceChildren();
  for (const item of checks) {
    const row = document.createElement('li');
    row.className = item.warning ? 'check warning' : item.ok ? 'check pass' : 'check fail';
    const icon = document.createElement('span');
    icon.className = 'check-icon';
    icon.textContent = item.warning ? '!' : item.ok ? '✓' : '×';
    icon.setAttribute('aria-hidden', 'true');
    const body = document.createElement('span');
    const label = document.createElement('strong');
    label.textContent = item.label;
    const detail = document.createElement('small');
    detail.textContent = item.detail;
    body.append(label, detail);
    row.append(icon, body);
    checksList.append(row);
  }
}

function renderWinners(proof: CampaignProof): void {
  winnersList.replaceChildren();
  for (const winner of proof.draw.winners) {
    const item = document.createElement('li');
    const ticket = document.createElement('code');
    ticket.textContent = winner.ticketId;
    const score = document.createElement('small');
    score.textContent = `score ${winner.score}`;
    item.append(ticket, score);
    winnersList.append(item);
  }
  winnerNote.textContent = proof.draw.winners.length
    ? '这里只显示公开 ticketId；证明中不包含用户邮箱。'
    : '该 proof 没有公开中奖票据。';
}

function renderResult(
  proof: CampaignProof,
  integrity: IntegrityVerificationResult,
  drand: CheckResult,
  archive: ArchiveVerificationResult,
): void {
  const checks = [...integrity.checks, ...archive.checks, drand];
  const ok = checks.every((item) => item.ok);
  const hasWarnings = checks.some((item) => item.warning);
  resultPanel.hidden = false;
  overallBadge.textContent = ok ? (hasWarnings ? '通过（有警告）' : '验证通过') : '验证未通过';
  overallBadge.className = `badge ${ok ? (hasWarnings ? 'warning' : 'pass') : 'fail'}`;
  renderSummary(proof);
  renderChecks(checks);
  renderWinners(proof);
}

function httpUrl(raw: string, label: string): string {
  let parsed: URL;
  try {
    parsed = new URL(raw, window.location.href);
  } catch {
    throw new Error(`${label} 格式无效。`);
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error(`${label} 只能使用 http 或 https。`);
  }
  return parsed.toString();
}

async function readResponseText(response: Response, maxBytes: number, label: string): Promise<string> {
  const declaredLength = Number(response.headers.get('content-length'));
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    throw new Error(`${label} 超过 ${Math.floor(maxBytes / 1024 / 1024)} MB 限制。`);
  }
  if (!response.body) {
    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > maxBytes) {
      throw new Error(`${label} 超过大小限制。`);
    }
    return text;
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const chunks: string[] = [];
  let bytes = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    bytes += value.byteLength;
    if (bytes > maxBytes) {
      await reader.cancel();
      throw new Error(`${label} 超过大小限制。`);
    }
    chunks.push(decoder.decode(value, { stream: true }));
  }
  chunks.push(decoder.decode());
  return chunks.join('');
}

async function readResponseBytes(response: Response, maxBytes: number, label: string): Promise<Uint8Array> {
  const declaredLength = Number(response.headers.get('content-length'));
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    throw new Error(`${label} 超过 ${Math.floor(maxBytes / 1024)} KiB 限制。`);
  }
  if (!response.body) {
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.byteLength > maxBytes) throw new Error(`${label} 超过大小限制。`);
    return bytes;
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let bytesRead = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    bytesRead += value.byteLength;
    if (bytesRead > maxBytes) {
      await reader.cancel();
      throw new Error(`${label} 超过大小限制。`);
    }
    chunks.push(value);
  }
  const result = new Uint8Array(bytesRead);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}

async function fetchJson(url: string, label: string, maxBytes = MAX_PROOF_JSON_BYTES): Promise<unknown> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10_000);
  try {
    const response = await fetch(url, { credentials: 'omit', signal: controller.signal });
    if (!response.ok) throw new Error(`${label} 请求失败（HTTP ${response.status}）。`);
    const text = await readResponseText(response, maxBytes, label);
    try {
      return JSON.parse(text) as unknown;
    } catch {
      throw new Error(`${label} 不是有效的 JSON。`);
    }
  } catch (error) {
    if (error && typeof error === 'object' && 'name' in error && error.name === 'AbortError') {
      throw new Error(`${label} 请求超时。`);
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

async function fetchBytes(url: string, label: string, maxBytes: number): Promise<Uint8Array> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10_000);
  try {
    const response = await fetch(url, { credentials: 'omit', signal: controller.signal });
    if (!response.ok) throw new Error(`${label} 请求失败（HTTP ${response.status}）。`);
    return await readResponseBytes(response, maxBytes, label);
  } catch (error) {
    if (error && typeof error === 'object' && 'name' in error && error.name === 'AbortError') {
      throw new Error(`${label} 请求超时。`);
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

async function readProof(): Promise<unknown> {
  const pasted = proofJsonInput.value.trim();
  if (pasted) {
    if (new TextEncoder().encode(pasted).byteLength > MAX_PROOF_JSON_BYTES) {
      throw new Error(`Proof JSON 超过 ${Math.floor(MAX_PROOF_JSON_BYTES / 1024 / 1024)} MB 限制。`);
    }
    try {
      return JSON.parse(pasted) as unknown;
    } catch {
      throw new Error('Proof JSON 不是有效的 JSON。');
    }
  }
  const rawUrl = proofUrlInput.value.trim();
  if (!rawUrl) throw new Error('请输入 proof URL，或粘贴 proof JSON。');
  return fetchJson(httpUrl(rawUrl, 'Proof URL'), 'Proof');
}

async function readSnapshotArchive(proof: CampaignProof): Promise<{
  commitmentBytes: Uint8Array;
  receiptBytes: Uint8Array;
}> {
  const [commitmentBytes, receiptBytes] = await Promise.all([
    fetchBytes(proof.archive.archiveUrl, '归档 JSON', MAX_ARCHIVE_JSON_BYTES),
    fetchBytes(proof.archive.receiptUrl, 'RFC 3161 receipt', MAX_ARCHIVE_RECEIPT_BYTES),
  ]);
  return { commitmentBytes, receiptBytes };
}

async function verify(): Promise<void> {
  setLoading(true);
  setNotice('正在读取公开证明并在本地复算…');
  try {
    const proof = parseProof(await readProof());
    const integrity = await verifyProofIntegrity(proof);
    const archive = await readSnapshotArchive(proof);
    const archiveVerification = await verifySnapshotArchive(
      proof,
      proof.archive,
      archive.commitmentBytes,
      archive.receiptBytes,
    );
    const drand = await verifyDrandBeacon(proof);
    renderResult(proof, integrity, drand, archiveVerification);
    const checks = [...integrity.checks, ...archiveVerification.checks, drand];
    const ok = checks.every((item) => item.ok);
    const warning = checksHaveWarnings(checks);
    setNotice(ok
      ? (warning
        ? '验证完成：归档 JSON 和 TSR 摘要一致，但 RFC 3161 签名/证书链未在浏览器内解析；请用可信客户端独立确认。'
        : '验证完成：公开证明、候选快照、中奖顺序和 drand Beacon 均一致。')
      : '验证完成：至少有一项检查未通过，请不要把该结果当作可信抽奖结果。', ok ? 'info' : 'error');
  } catch (error) {
    resultPanel.hidden = true;
    const message = error instanceof ProofValidationError || error instanceof Error
      ? error.message
      : '验证失败。';
    setNotice(message, 'error');
  } finally {
    setLoading(false);
  }
}

function checksHaveWarnings(checks: CheckResult[]): boolean {
  return checks.some((item) => item.warning);
}

form.addEventListener('submit', (event) => {
  event.preventDefault();
  void verify();
});
