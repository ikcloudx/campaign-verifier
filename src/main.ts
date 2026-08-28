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
import {
  FREETSA_CRL_MIRROR_PATH,
  FREETSA_OCSP_PROXY_URL,
  FREETSA_TSA_URL,
  MAX_REVOCATION_CRL_BYTES,
  MAX_REVOCATION_OCSP_BYTES,
} from './revocation-config.ts';

const DEPLOYED_COMMIT = import.meta.env.VITE_VERIFIER_COMMIT?.trim() || 'development';
const COMMIT_SHA_PATTERN = /^[0-9a-f]{40,64}$/i;

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
      <p class="hint">验证器只接受包含不可变归档的 protocol v2 proof，会自动读取归档 JSON、RFC 3161 <code>.tsr</code>、配置的 HTTPS OCSP 代理和本站同源镜像的 FreeTSA CRL。浏览器会解析 CMS/ASN.1，验证 TSA 签名、固定信任根、证书用途和 OCSP/CRL 签名、有效期、序列号；MessageImprint 仅接受 SHA-256/384/512。</p>
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
    <p id="version-note" class="version-note" role="status" aria-live="polite" hidden></p>
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
    <span id="build-info" class="build-info">当前部署 commit <code id="build-commit"></code></span>
    <a class="source-link" href="https://github.com/ikcloudx/campaign-verifier" target="_blank" rel="noopener noreferrer" aria-label="打开 Campaign Verifier GitHub 源代码">
      <svg aria-hidden="true" viewBox="0 0 24 24" focusable="false">
        <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.084-.73.084-.73 1.205.085 1.84 1.237 1.84 1.237 1.07 1.835 2.807 1.305 3.492.998.108-.776.418-1.305.762-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.4 3-.405 1.02.005 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.435.375.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12" />
      </svg>
      <span>查看 GitHub 源代码</span>
    </a>
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
const buildCommit = document.querySelector<HTMLElement>('#build-commit')!;
const versionNote = document.querySelector<HTMLElement>('#version-note')!;

if (!form || !proofUrlInput || !proofJsonInput || !verifyButton || !notice || !resultPanel
  || !overallBadge || !campaignSummary || !checksList || !winnersList || !winnerNote || !buildCommit || !versionNote) {
  throw new Error('Verifier UI is incomplete');
}

function renderBuildInfo(): void {
  if (COMMIT_SHA_PATTERN.test(DEPLOYED_COMMIT)) {
    const link = document.createElement('a');
    link.href = `https://github.com/ikcloudx/campaign-verifier/commit/${DEPLOYED_COMMIT}`;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    link.textContent = DEPLOYED_COMMIT.slice(0, 12);
    link.title = `完整 commit：${DEPLOYED_COMMIT}`;
    link.setAttribute('aria-label', `打开当前部署 commit ${DEPLOYED_COMMIT}`);
    buildCommit.replaceChildren(link);
  } else {
    buildCommit.textContent = DEPLOYED_COMMIT;
  }
}

renderBuildInfo();

function verifierVersionStatus(proof: CampaignProof): 'match' | 'mismatch' | 'unknown' {
  if (!COMMIT_SHA_PATTERN.test(DEPLOYED_COMMIT)) return 'unknown';
  return DEPLOYED_COMMIT.toLowerCase() === proof.archive.verifierCommit.toLowerCase()
    ? 'match'
    : 'mismatch';
}

function commitLink(label: string, commit: string): HTMLAnchorElement {
  const link = document.createElement('a');
  link.href = `https://github.com/ikcloudx/campaign-verifier/commit/${commit}`;
  link.target = '_blank';
  link.rel = 'noopener noreferrer';
  link.textContent = `${label} ${commit.slice(0, 12)}`;
  link.title = `完整 commit：${commit}`;
  link.setAttribute('aria-label', `打开 ${label} ${commit}`);
  return link;
}

function renderVersionNote(proof: CampaignProof): void {
  const status = verifierVersionStatus(proof);
  versionNote.replaceChildren();
  versionNote.hidden = false;
  if (status === 'unknown') {
    versionNote.textContent = '版本提示：当前构建未注入部署 commit，无法与 proof 登记的 verifierCommit 进行版本比对；该提示不影响密码学验证。';
    return;
  }
  if (status === 'match') {
    versionNote.hidden = true;
    return;
  }
  versionNote.append(
    document.createTextNode('版本提示：当前部署 commit 与 proof 登记的 verifierCommit 不同；该差异仅用于审计，不影响密码学验证。查看：'),
    commitLink('当前部署', DEPLOYED_COMMIT),
    document.createTextNode('；'),
    commitLink('proof 登记', proof.archive.verifierCommit),
    document.createTextNode('。'),
  );
}

function versionCheck(proof: CampaignProof): CheckResult {
  const status = verifierVersionStatus(proof);
  if (status === 'match') {
    return {
      id: 'verifier-version',
      label: 'Verifier 版本对照',
      ok: true,
      detail: '当前部署 commit 与 proof 登记的 verifierCommit 一致。',
    };
  }
  if (status === 'unknown') {
    return {
      id: 'verifier-version',
      label: 'Verifier 版本对照',
      ok: true,
      warning: true,
      detail: '当前构建未注入部署 commit，无法进行版本对照；这只是审计提示，不影响密码学验证。',
    };
  }
  return {
    id: 'verifier-version',
    label: 'Verifier 版本对照',
    ok: true,
    warning: true,
    detail: '当前部署 commit 与 proof 登记的 verifierCommit 不同；这只是审计提示，不影响密码学验证。',
  };
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
  appendSummaryRow('Proof verifier commit', proof.archive.verifierCommit);
  appendSummaryRow('当前部署 commit', DEPLOYED_COMMIT);
  appendSummaryRow('协议提示', '归档元数据已纳入 proofHash；浏览器会校验 JSON/TSR 原始字节摘要，并在本地解析和验证 RFC 3161 签名、证书链及 OCSP/同源 CRL 吊销状态。');
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

async function copyToClipboard(value: string): Promise<void> {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(value);
      return;
    } catch {
      // Fall back to the selection API when clipboard permission is denied.
    }
  }
  const fallback = document.createElement('textarea');
  fallback.value = value;
  fallback.setAttribute('readonly', '');
  fallback.style.position = 'fixed';
  fallback.style.opacity = '0';
  document.body.append(fallback);
  fallback.focus();
  fallback.select();
  const copied = document.execCommand('copy');
  fallback.remove();
  if (!copied) throw new Error('复制失败。');
}

async function copyTicketId(button: HTMLButtonElement, ticketId: string): Promise<void> {
  const copyLabel = button.querySelector<HTMLElement>('.copy-label');
  try {
    await copyToClipboard(ticketId);
    button.classList.remove('copy-failed');
    button.classList.add('copied');
    button.title = '已复制 ticketId';
    button.setAttribute('aria-label', `已复制 ticketId ${ticketId}`);
    if (copyLabel) copyLabel.textContent = '已复制';
  } catch {
    button.classList.remove('copied');
    button.classList.add('copy-failed');
    button.title = '复制失败，请手动复制 ticketId';
    button.setAttribute('aria-label', `复制失败，请手动复制 ticketId ${ticketId}`);
    if (copyLabel) copyLabel.textContent = '复制失败';
  }
}

function renderWinners(proof: CampaignProof): void {
  winnersList.replaceChildren();
  for (const winner of proof.draw.winners) {
    const item = document.createElement('li');
    const ticket = document.createElement('button');
    ticket.type = 'button';
    ticket.className = 'ticket-copy';
    ticket.title = '点击复制 ticketId';
    ticket.setAttribute('aria-label', `复制 ticketId ${winner.ticketId}`);
    const ticketValue = document.createElement('code');
    ticketValue.textContent = winner.ticketId;
    const copyLabel = document.createElement('span');
    copyLabel.className = 'copy-label';
    copyLabel.textContent = '复制';
    copyLabel.setAttribute('aria-hidden', 'true');
    ticket.append(ticketValue, copyLabel);
    ticket.addEventListener('click', () => {
      void copyTicketId(ticket, winner.ticketId);
    });
    const score = document.createElement('small');
    score.textContent = `score ${winner.score}`;
    item.append(ticket, score);
    winnersList.append(item);
  }
  winnerNote.textContent = proof.draw.winners.length
    ? '这里只显示公开 ticketId；点击 ticketId 可复制，证明中不包含用户邮箱。'
    : '该 proof 没有公开中奖票据。';
}

function renderResult(
  proof: CampaignProof,
  integrity: IntegrityVerificationResult,
  drand: CheckResult,
  archive: ArchiveVerificationResult,
): void {
  const checks = [...integrity.checks, ...archive.checks, drand, versionCheck(proof)];
  const ok = checks.every((item) => item.ok);
  const hasWarnings = checks.some((item) => item.warning);
  resultPanel.hidden = false;
  overallBadge.textContent = ok ? (hasWarnings ? '通过（有警告）' : '验证通过') : '验证未通过';
  overallBadge.className = `badge ${ok ? (hasWarnings ? 'warning' : 'pass') : 'fail'}`;
  renderSummary(proof);
  renderVersionNote(proof);
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

async function fetchBytes(url: string, label: string, maxBytes: number, cache: RequestCache = 'default'): Promise<Uint8Array> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10_000);
  try {
    const response = await fetch(url, { credentials: 'omit', cache, signal: controller.signal });
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

async function fetchOcspResponse(url: string, requestBytes: Uint8Array): Promise<Uint8Array> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10_000);
  try {
    const parsedUrl = new URL(url, document.baseURI);
    if (parsedUrl.protocol !== 'https:' || parsedUrl.username || parsedUrl.password || parsedUrl.search || parsedUrl.hash) {
      throw new Error('OCSP 代理 URL 必须是无凭据、无查询参数和片段的 HTTPS URL。');
    }
    const requestBuffer = requestBytes.buffer.slice(
      requestBytes.byteOffset,
      requestBytes.byteOffset + requestBytes.byteLength,
    ) as ArrayBuffer;
    const response = await fetch(url, {
      method: 'POST',
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      headers: {
        Accept: 'application/ocsp-response',
        'Content-Type': 'application/ocsp-request',
      },
      body: requestBuffer,
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`OCSP 代理请求失败（HTTP ${response.status}）。`);
    return await readResponseBytes(response, MAX_REVOCATION_OCSP_BYTES, 'OCSP 响应');
  } catch (error) {
    if (error && typeof error === 'object' && 'name' in error && error.name === 'AbortError') {
      throw new Error('OCSP 代理请求超时。');
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

async function readRevocationCrl(tsaUrl: string): Promise<Uint8Array | undefined> {
  if (tsaUrl !== FREETSA_TSA_URL) return undefined;
  const url = new URL(FREETSA_CRL_MIRROR_PATH, document.baseURI).toString();
  return fetchBytes(url, 'FreeTSA CRL', MAX_REVOCATION_CRL_BYTES, 'no-cache');
}

async function verify(): Promise<void> {
  setLoading(true);
  setNotice('正在读取公开证明并在本地复算…');
  try {
    const proof = parseProof(await readProof());
    const integrity = await verifyProofIntegrity(proof);
    const archive = await readSnapshotArchive(proof);
    let revocationCrlBytes: Uint8Array | undefined;
    let revocationError: string | undefined;
    try {
      revocationCrlBytes = await readRevocationCrl(proof.archive.tsaUrl);
    } catch (error) {
      revocationError = error instanceof Error ? error.message : 'CRL 请求失败。';
    }
    const archiveVerification = await verifySnapshotArchive(
      proof,
      proof.archive,
      archive.commitmentBytes,
      archive.receiptBytes,
      {
        rfc3161: {
          revocationCrlBytes,
          revocationError,
          revocationOcspFetcher: proof.archive.tsaUrl === FREETSA_TSA_URL && FREETSA_OCSP_PROXY_URL
            ? (requestBytes) => fetchOcspResponse(FREETSA_OCSP_PROXY_URL, requestBytes)
            : undefined,
        },
      },
    );
    const drand = await verifyDrandBeacon(proof);
    renderResult(proof, integrity, drand, archiveVerification);
    const checks = [...integrity.checks, ...archiveVerification.checks, drand, versionCheck(proof)];
    const ok = checks.every((item) => item.ok);
    const warning = checksHaveWarnings(checks);
    setNotice(ok
      ? (warning
        ? '验证完成，但有验证警告；请查看检查项明细。'
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
