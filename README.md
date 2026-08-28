# campaign-verifier

一个完全独立、纯静态的营销活动抽奖公开验证器。它不依赖主站的前端或后端，不需要登录，也不接收用户邮箱；浏览器会在本地读取公开 `proof` JSON，复算候选快照、抽奖种子和中奖顺序，并通过官方 `drand-client` 校验 Beacon 签名。

- 在线验证器：[ikcloudx.github.io/campaign-verifier](https://ikcloudx.github.io/campaign-verifier/)
- 源代码：[github.com/ikcloudx/campaign-verifier](https://github.com/ikcloudx/campaign-verifier)
- 生产 OCSP 代理：[ocsp.kcloudx.com/ocsp](https://ocsp.kcloudx.com/ocsp)

## 能验证什么

- `eligibilityRules` 的稳定 JSON 哈希是否与快照和 draw 记录一致；
- `snapshot.ticketIds` 排序、去重、末尾换行和 SHA-256 快照哈希；
- `campaign-drand-v1` 的 NUL 分隔抽奖种子；
- 每个 ticket 的 SHA-256 分数以及最终中奖顺序；
- drand chain、round、randomness、signature 是否与公开 proof 一致，并由 drand 客户端在浏览器端验证签名；
- proof 中是否出现 email、用户标识、电话、订单或支付标识等敏感字段。
- proof protocol version、整体 `proofHash`、快照计数和 `snapshotCommitment` 是否一致；
- v2 proof 中登记的归档 JSON/TSR URL、原始字节 SHA-256，以及归档承诺与 proof 是否一致；
- 快照发布时间是否早于目标 drand round，以及 drand/draw/beacon payload 的字段是否互相一致。

中奖结果只展示公开的 `ticketId` 和 score，验证器不会展示或上传邮箱地址。

验证器只接受包含不可变归档登记的 `proofVersion: "2"` proof。它使用
`proofHashAlgorithm: "sha256-stable-json-v1"` 和 `snapshotCommitment`，并在
proof 根部携带 `archive`；其中的 JSON/TSR URL 和原始字节 SHA-256 都纳入
`proofHash`。缺少归档或声明旧/未知版本的 proof 会直接停止，避免把不完整
的证明误当成当前协议验证。

## 使用

直接打开部署后的站点，输入主站公开 proof 地址，例如：

```text
https://主站.example/api/campaigns/summer-2025/proof
```

也可以通过 `?proof=<URL-encoded-proof-url>` 预填地址，或粘贴完整 JSON。验证过程不会把 proof 发到本验证器的服务器；浏览器只向输入的 proof、公开 drand relay、proof 登记的归档 URL、生产 OCSP 代理，以及本站同源 CRL 镜像发起请求。

### 浏览器验证流程

验证器在浏览器中按以下顺序完成检查：

1. 读取 proof，并校验 proof、快照和归档文件的摘要与结构；
2. 解析 RFC 3161 TSR，在本地验证 MessageImprint、CMS/TSA 签名、证书链、用途和时间顺序；
3. 优先通过 `https://ocsp.kcloudx.com/ocsp` 获取原始 OCSP 响应，并由 PKI.js 在浏览器内验证签名、响应者证书链、CertID、nonce 和时效；
4. OCSP 不可达或返回 `unknown` 时，回退到仓库同源的 FreeTSA CRL，并显示回退警告；
5. 验证 drand Beacon 签名、抽奖种子、票据分数和最终中奖顺序。

OCSP 返回 `revoked`、签名错误、证书链不可信或关键摘要不一致时，验证直接失败，不会把异常状态当作“未吊销”。

### 独立快照承诺

Freeze 返回 `snapshot_committed` 后，主站提供不含邮箱和用户标识的
`GET /api/campaigns/<slug>/commitment`。运营方应先将返回的完整 JSON 原样
保存到独立托管位置，并为这些原始字节取得 RFC 3161 时间戳 receipt（`.tsr`），
再调用主站管理员 API 登记归档；服务端在同一数据库事务中检查该登记后才会安排
drand target round。不要在 JSON 和 receipt 都验证完成并登记前点击管理后台的
**Schedule Beacon**。

登记接口为 `POST /api/admin/campaigns/<campaign-id>/archive`，请求体记录
`commitmentHash`、JSON 与 `.tsr` 的 SHA-256、两个公开 URL、verifier Git 提交和
TSA URL。登记记录按 campaign 唯一且不可更新/删除；重复提交完全相同的数据是幂等的，
不同数据会被拒绝。主站不会把 `.tsr` 内容复制到数据库，参与者仍应从公开 URL 下载并
使用受信 CA bundle 独立验证回执。

目标 drand round 公开前，
将返回的完整 JSON 原样保存到独立托管位置，例如另一个 Git 仓库的提交、
不可变对象存储，或与 RFC 3161 `.tsr` receipt 一起发布在 GitHub Pages。抽奖完成后，
本页只需填写 proof URL；验证器会自动读取 Proof 中登记的 JSON 和 TSR URL。验证器会检查：

1. proof 内部重新计算出的 `snapshotCommitment`；
2. proof 中的 commitment 与第三方归档 JSON 的字段和 `commitmentHash`；
3. 归档 JSON 和 TSR 的原始字节 SHA-256 与登记值一致；
4. snapshot publication time 早于 drand 目标 round。

主站当前 commitment URL 不再作为验证器输入；只有在活动处于
`snapshot_committed` 时完成归档登记，Proof 才会携带可自动读取的归档地址。归档站点必须允许浏览器
跨域读取 JSON（CORS），并且不应在归档文件中加入未经协议定义的敏感字段。

浏览器验证器会自动校验 v2 proof 所指向的归档 JSON/TSR 原始字节摘要，并在浏览器内
解析 RFC 3161 的 CMS/ASN.1 receipt，验证 MessageImprint、CMS/TSA 签名、
SigningCertificate、TSA 证书链、timeStamping EKU、TSA 身份、关键证书扩展、时间顺序，
以及本站同源镜像的 FreeTSA CRL。生产环境已配置 HTTPS OCSP 代理
`https://ocsp.kcloudx.com/ocsp`；浏览器使用现有 PKI.js 生成 SHA-256 CertID 和 nonce 请求，
验证原始 BasicOCSPResponse 的签名、委托响应者证书链、OCSP Signing EKU、CertID、nonce
和时效。OCSP 返回 `revoked` 时直接失败，OCSP 不可达或 `unknown` 时回退 CRL，并明确显示
回退警告。浏览器不使用系统证书库，而是使用 verifier 内置、固定 SHA-256 指纹的 FreeTSA
根证书；TSR 内嵌的证书只能作为链材料，不能自动成为信任锚。
CRL 的原始 PEM/DER 会在浏览器中解析，使用固定根证书验证签名，检查 `thisUpdate`/
`nextUpdate`，再按 TSA 签名证书序列号查吊销列表。CRL 缺失、签名错误或过期时，验证项
会失败（不会把“无法检查”当作“未吊销”）。

FreeTSA 的公开吊销地址不是适合 HTTPS 静态页面直接读取的 CORS 端点，因此仓库保留了
`public/revocation/freetsa-root-ca.crl` 的同源副本。`.github/workflows/refresh-freetsa-crl.yml`
每周一 03:00 UTC 下载官方 CRL，先用固定指纹的根证书验证 CRL 签名和有效期，再在有变化时
提交更新；提交完成后 Pages 工作流会重新构建发布。也可以在 Actions 页面手动触发刷新。
每周刷新意味着吊销信息最多可能滞后约 7 天；高安全场景应把 cron 调整为每日或每 6 小时。

生产环境已启用 OCSP 代理，代码位于 `workers/ocsp-proxy/`，配置值为
`src/revocation-config.ts` 中的 `FREETSA_OCSP_PROXY_URL = 'https://ocsp.kcloudx.com/ocsp'`。
代理只允许 `POST /ocsp` 和 CORS 预检，固定转发到 FreeTSA，限制请求/响应大小、超时、重定向
和来源，并由 Cloudflare 原生 Rate Limiting binding 限制为每个客户端地址每 60 秒 30 个有效请求；
超限返回 429，限流服务异常则返回 503。代理不会解析 OCSP，也不会返回可信的吊销结论。
Worker 部署、自定义域名、CORS、日志和故障排查见
[`workers/ocsp-proxy/README.md`](workers/ocsp-proxy/README.md)。修改代理地址或代码后，需要重新构建并发布 Pages。

MessageImprint 只接受 SHA-256、SHA-384 或 SHA-512；SHA-1 会被拒绝。这里不影响
ESSCertID v1 使用 SHA-1 标识签名证书，因为证书标识摘要与被加时间戳的数据摘要是
两个不同的字段。RFC 3161 receipt 的浏览器解析上限为 2 MiB，超过上限会在 ASN.1
解析前拒绝。

```bash
curl --fail --location --output summer-test1.json \
  https://ikcloudx.github.io/campaign-verifier/commitments/summer-test1.json
curl --fail --location --output summer-test1.tsr \
  https://ikcloudx.github.io/campaign-verifier/commitments/summer-test1.tsr
openssl ts -verify \
  -data summer-test1.json \
  -in summer-test1.tsr \
  -CAfile ./.secrets/freetsa-cacert.pem \
  -untrusted ./.secrets/freetsa-tsa.crt
```

浏览器当前固定的 FreeTSA 根证书指纹为
`a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc`；根证书来源为
[FreeTSA 官方 cacert.pem](https://freetsa.org/files/cacert.pem)。若改用其他 TSA，
必须在 verifier 中增加该 TSA 的独立信任 profile（根证书、指纹和可接受的 policy OID），
不能仅把 TSR 中附带的证书加入信任列表。

当前归档脚本默认使用 FreeTSA：
`https://freetsa.org/tsr`、`./.secrets/freetsa-cacert.pem` 和
`./.secrets/freetsa-tsa.crt`。当这些默认值生效时，脚本会自动创建
`.secrets`，在文件缺失或指纹不匹配时通过 HTTPS 下载 FreeTSA 的根 CA 与 TSA
证书，并将文件 SHA-256 与脚本内置的官方指纹比对；已预置且指纹匹配的文件不会
重复下载。指纹来源是 FreeTSA 的
[Certification Practice Statement](https://www.freetsa.org/freetsa_cps.html)，
脚本不会从同一站点再下载一个“指纹文件”来形成循环信任。审计或离线环境仍可通过
独立信任渠道预置并核对文件。如果改用其他 TSA，请替换为该提供方的 `-CAfile`
和 `-untrusted` 文件；自定义 TSA 不会触发 FreeTSA 的自动下载。

如果配置了 `CAMPAIGN_TSA_POLICY`，还应追加 `-policy <OID>`。

`openssl ts -verify` 必须报告 `Verification: OK`，并且 receipt 中的时间必须早于
目标 drand round。TSA CA bundle 必须通过独立渠道固定；不要从待验证的 Pages
站点下载它。

若要让 Git 提交具备长期证据价值，应在 verifier 仓库启用分支保护、禁止强制推送，
并限制可写入该分支的账号；脚本的路径检查不能替代这些仓库策略。
首次启用前，请先提交本仓库的 `.gitattributes`，确保 JSON 不做换行转换、`.tsr`
按二进制文件保存；归档脚本要求运行前工作区保持 clean。clean 状态只保护归档输入，
不替代对 verifier 代码版本的审查或固定。

对于旧版本脚本已经提交的 JSON，只要活动仍处于 `snapshot_committed`，归档脚本会验证
其原始字节后以新的提交补上 `.tsr`，不会重写原 JSON。

归档脚本会在验证完成后、提交前再次读取活动状态，作为并发调度的乐观保护；设置
`CAMPAIGN_ARCHIVE_API_KEY` 并使用 `--push` 时，脚本会在 verifier 提交推送后
自动登记归档。未设置 API key 时，脚本仍可生成和推送文件，但必须由管理员手动调用登记 API；
没有登记记录，`Schedule Beacon` 会被主站和数据库触发器共同拒绝。

验证器的输入上限是 proof JSON 16 MiB、250,000 个 ticket、JSON 深度 64 层和
500,000 个节点；归档 JSON 上限为 256 KiB，RFC 3161
receipt 上限为 2 MiB。proof 和 archive 请求均有 10 秒超时，并以
流式方式限制响应大小。

主站目前使用受限 CORS。要让浏览器跨域读取 proof，需要把验证器正式域名加入主站的 `ALLOWED_ORIGINS`（或为只读 proof 路由配置等价的公开 CORS）。这不会改变 proof 的内容，也不会授予验证器管理员权限。

本目录自身是独立 Git 仓库。主站仓库只保留部署说明，不把 verifier 作为子目录提交；发布前请在本目录提交并推送到单独的公开仓库，再启用 Pages 或其他静态托管。

从工作区根目录准备发布时，可执行：

```bash
git -C campaign-verifier status
git -C campaign-verifier add .
git -C campaign-verifier commit
git -C campaign-verifier remote add origin <public-repository-url>
git -C campaign-verifier push -u origin main
```

请把 `<public-repository-url>` 替换成组织实际创建的公开仓库地址；本项目不会假设
组织或托管平台名称。

## 本地开发

需要 Node.js 22 或更高版本：

```bash
npm install
npm test
npm run typecheck
npm run build
npm run dev
```

生产构建输出在 `dist/`，不需要 Node.js 服务器即可托管。

## 部署

`.github/workflows/pages.yml` 会在 `main` 分支变更、手动触发或 CRL 刷新工作流完成后运行测试、类型检查和构建，并部署到 GitHub Pages。构建会注入已检出的 Git commit SHA，页面底部和验证结果中会同时显示当前部署 commit 与 proof 登记的 `verifierCommit`。仓库 Settings → Pages 中选择 **GitHub Actions** 作为发布来源。

该站点也可以部署到 Cloudflare Pages：构建命令为 `npm run build`，输出目录为 `dist`，Node.js 版本使用 22。为显示真实部署版本，请在构建环境设置 `VITE_VERIFIER_COMMIT` 为该次发布对应的 Git SHA；未设置时页面会显示 `development`。部署平台只托管静态文件，不会获得 proof 中的任何额外权限。

OCSP 代理是独立的 Cloudflare Worker，不会随 Pages 自动部署。生产环境的代理地址为
`https://ocsp.kcloudx.com/ocsp`；如需重新部署或更换域名，请按
[`workers/ocsp-proxy/README.md`](workers/ocsp-proxy/README.md) 完成 Worker、HTTPS 自定义域名、CORS
和真实 DER 请求检查，再更新 `FREETSA_OCSP_PROXY_URL` 并重新发布 Pages。

`.github/workflows/dependency-audit.yml` 会在提交、Pull Request、每周定时任务和手动触发时执行
`npm ci --ignore-scripts` 与高危级别的 `npm audit`；`.github/dependabot.yml` 每周检查 npm 依赖
和 GitHub Actions 更新。Pages 与 CRL 工作流中的 Action 均固定到完整 commit SHA，避免可变标签
在后续运行中指向未经审查的代码。

## 验证协议

抽奖种子按以下顺序拼接并以 NUL（`\0`）分隔后做 SHA-256：

```text
campaign-drand-v1
lower(chainHash)
round
lower(randomness)
campaignId
lower(snapshotHash)
lower(rulesHash)
```

候选票据先按 ASCII/英文 locale 排序并以 `\n` 连接，非空清单追加一个末尾换行后计算快照哈希。每个票据的 score 为：

```text
SHA-256(drawSeed + NUL + ticketId)
```

score 升序（再按 ticketId）就是中奖顺序。验证器刻意独立实现了这些规则，并使用固定测试向量防止与主站共享实现错误。

`snapshotCommitment.commitmentHash` 是以下字段按 UTF-8 稳定 JSON（对象键按
字典序排序、数组顺序不变、无额外空白）计算的 SHA-256：

```json
{
  "commitmentVersion": "campaign-snapshot-v1",
  "campaignId": "…",
  "snapshotHash": "…",
  "rulesHash": "…",
  "entryCount": 0,
  "eligibleCount": 0,
  "freeCount": 0,
  "paidCount": 0,
  "publishedAt": "2026-01-01T00:00:00.000Z"
}
```

`proofHash` 使用相同的稳定 JSON 规则对整个 proof 计算 SHA-256，但先移除
自身的 `proofHash` 字段。固定协议对象拒绝未知字段；未知 `proofVersion` 或
`proofHashAlgorithm` 会停止验证，而不是静默降级。

协议 v2 的 `archive` 字段格式如下；所有 URL 必须为不含凭据、查询参数或片段的
HTTPS URL，摘要对应发布到 Pages 的原始字节：

```json
{
  "type": "rfc3161",
  "commitmentHash": "…",
  "commitmentJsonSha256": "…",
  "timestampReceiptSha256": "…",
  "archiveUrl": "https://…/commitments/summer.json",
  "receiptUrl": "https://…/commitments/summer.tsr",
  "verifierCommit": "…",
  "tsaUrl": "https://freetsa.org/tsr"
}
```

## 信任边界

验证器可以证明公开 proof 与指定 drand Beacon、指定快照和公开算法一致，并在 v2 中自动证明归档 JSON/TSR 原始字节与不可变登记值一致；它不能仅凭一个 URL 证明外部副本的历史发布时间。

- 浏览器不使用操作系统证书库；只信任 verifier 内置、固定 SHA-256 指纹的 FreeTSA 根证书。TSR 内嵌证书只能作为链材料，不能自动成为信任锚。
- 浏览器会验证 RFC 3161 的 CMS/ASN.1、签名、证书链和时间顺序，并验证 OCSP 原始响应或同源镜像 CRL；OCSP Worker 只是受限转发器，本身不是信任锚，也不返回可信的吊销布尔值。
- CRL 是定期快照，不等同于实时 OCSP；每周刷新时，吊销信息最多可能滞后约 7 天。高安全场景应缩短刷新周期，或使用受信客户端独立检查最新 CRL/OCSP。
- 验证器不能证明主站在快照发布前没有漏记或错误筛选用户；参与者仍应确认 TSA 时间早于目标 drand round，并保留 proof、归档文件和验证时间。
- drand relay 暂时不可用时，快照和中奖顺序仍可本地复算，但整体结果会标记为未完成验证。

相关协议文档：

- [drand HTTP API](https://docs.drand.love/developer/API-v2/drand-http-api/)
- [drand clients](https://docs.drand.love/developer/clients/)
- [GitHub Pages custom workflows](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-for-github-pages)
- [Cloudflare Pages static deployments](https://developers.cloudflare.com/pages/framework-guides/deploy-anything/)
- [RFC 3161 Time-Stamp Protocol](https://www.rfc-editor.org/rfc/rfc3161.html)
- [RFC 8785 JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785.html)（本项目使用版本化的项目内稳定 JSON 规则）
- [OpenTimestamps](https://opentimestamps.org/)（可选的外部时间戳归档方案）
