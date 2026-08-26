# campaign-verifier

一个完全独立、纯静态的营销活动抽奖公开验证器。它不依赖主站的前端或后端，不需要登录，也不接收用户邮箱；浏览器会在本地读取公开 `proof` JSON，复算候选快照、抽奖种子和中奖顺序，并通过官方 `drand-client` 校验 Beacon 签名。

## 能验证什么

- `eligibilityRules` 的稳定 JSON 哈希是否与快照和 draw 记录一致；
- `snapshot.ticketIds` 排序、去重、末尾换行和 SHA-256 快照哈希；
- `campaign-drand-v1` 的 NUL 分隔抽奖种子；
- 每个 ticket 的 SHA-256 分数以及最终中奖顺序；
- drand chain、round、randomness、signature 是否与公开 proof 一致，并由 drand 客户端在浏览器端验证签名；
- proof 中是否出现 email、用户标识、电话、订单或支付标识等敏感字段。
- proof protocol version、整体 `proofHash`、快照计数和 `snapshotCommitment` 是否一致；
- 快照发布时间是否早于目标 drand round，以及 drand/draw/beacon payload 的字段是否互相一致。

中奖结果只展示公开的 `ticketId` 和 score，验证器不会展示或上传邮箱地址。

当前主站生成的新 proof 声明 `proofVersion: "1"`、
`proofHashAlgorithm: "sha256-stable-json-v1"` 和 `snapshotCommitment`。
验证器仍兼容旧的 legacy proof，但会把缺少整体哈希或独立承诺标记为警告。
若 proof 声明版本，当前只接受 `proofVersion: "1"`，未知版本会直接停止，避免把新协议误当成旧协议验证。

## 使用

直接打开部署后的站点，输入主站公开 proof 地址，例如：

```text
https://主站.example/api/campaigns/summer-2025/proof
```

也可以通过 `?proof=<URL-encoded-proof-url>` 预填地址，或粘贴完整 JSON。验证过程不会把 proof 发到本验证器的服务器；URL 模式下浏览器只向输入的 proof 地址和公开 drand relay 发起请求。

### 独立快照承诺

Freeze 返回 `snapshot_committed` 后，主站提供不含邮箱和用户标识的
`GET /api/campaigns/<slug>/commitment`。运营方应先将返回的完整 JSON 原样
保存到独立托管位置，再安排 drand target round；不要在存档完成前点击管理后台
的 **Archive and schedule Beacon**。

目标 drand round 公开前，
将返回的完整 JSON 原样保存到独立托管位置，例如另一个 Git 仓库的提交、
不可变对象存储，或带可信时间戳的公开归档。抽奖完成后，在本页同时填写
proof URL 和该归档 URL；验证器会检查：

1. proof 内部重新计算出的 `snapshotCommitment`；
2. proof 中的 commitment 与第三方归档 JSON 的字段和 `commitmentHash`；
3. snapshot publication time 早于 drand 目标 round。

只填写主站当前的 commitment URL，或填写任何内容一致但没有可验证历史时间的 URL，
会得到“内容一致”结果，但会保留警告；当前响应本身不能证明它在抽奖前已经独立存档。
第三方站点必须允许浏览器
跨域读取 JSON（CORS），并且不应在归档文件中加入未经协议定义的敏感字段。

验证器的输入上限是 proof JSON 16 MiB、250,000 个 ticket、JSON 深度 64 层和
500,000 个节点；第三方 commitment 上限为 256 KiB。proof/commitment 请求分别
有 10 秒超时，并以流式方式限制响应大小。

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

`.github/workflows/pages.yml` 会在 `main` 分支变更后运行测试、类型检查和构建，并部署到 GitHub Pages。仓库 Settings → Pages 中选择 **GitHub Actions** 作为发布来源。

该站点也可以部署到 Cloudflare Pages：构建命令为 `npm run build`，输出目录为 `dist`，Node.js 版本使用 22。部署平台只托管静态文件，不会获得 proof 中的任何额外权限。

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

## 信任边界

验证器能证明“公开 proof 与指定 drand Beacon、指定快照和公开算法一致”，以及输入的外部副本内容一致；它不能仅凭一个 URL 证明外部副本的历史发布时间，也不能证明主站在快照发布前没有漏记或错误筛选用户。运营方应公开保存 proof 原文、发布时间、活动规则和可验证的存档凭据；参与者应自行保存验证结果。drand relay 暂时不可用时，快照和中奖顺序仍可本地复算，但整体结果会标记为未完成验证。

相关协议文档：

- [drand HTTP API](https://docs.drand.love/developer/API-v2/drand-http-api/)
- [drand clients](https://docs.drand.love/developer/clients/)
- [GitHub Pages custom workflows](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-for-github-pages)
- [Cloudflare Pages static deployments](https://developers.cloudflare.com/pages/framework-guides/deploy-anything/)
- [RFC 8785 JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785.html)（本项目使用版本化的项目内稳定 JSON 规则）
- [OpenTimestamps](https://opentimestamps.org/)（可选的外部时间戳归档方案）
