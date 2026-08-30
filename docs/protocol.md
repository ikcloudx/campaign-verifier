# 验证协议

## 普通抽奖

候选 `ticketId` 按英文 locale 排序，以 `\n` 连接；非空清单追加末尾换行，再计算 SHA-256 快照哈希。

抽奖种子由以下字段按顺序以 NUL（`\0`）分隔，再计算 SHA-256：

```text
campaign-drand-v1
lower(chainHash)
round
lower(randomness)
campaignId
lower(snapshotHash)
lower(rulesHash)
```

每张票据的 score 为：

```text
SHA-256(drawSeed + NUL + ticketId)
```

按 score 升序排列，并以 `ticketId` 作为平局键，即得到中奖顺序。

## 分段抽奖

分段活动使用 `campaign-drand-segmented-v1`。`snapshot.entries` 按 ticket ID 使用英文 locale 排序，每行编码为 `<segment>\t<ticketId>\n`。`free` 和 `paid` 的数量必须与快照计数一致，排序后的 ID 也必须与 `snapshot.ticketIds` 完全一致。

抽奖种子在 `rulesHash` 后追加有效的 `freeWinnerCount` 和 `paidWinnerCount`。验证器分别选出两个分段中 score 最低的指定数量票据，再按 score 和 ticket ID 合并、编号。

## Commitment 与 proofHash

`snapshotCommitment.commitmentHash` 对以下字段执行 UTF-8 稳定 JSON 序列化后计算 SHA-256。对象键按字典序排序，数组顺序不变，不添加空白：

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

`proofHash` 使用相同规则计算整个 proof，但计算前移除 `proofHash` 字段。固定协议对象拒绝未知字段；未知 `proofVersion`、`proofHashAlgorithm` 或 draw algorithm 不会静默降级。

Protocol v2 必须同时包含不可变 `archive` 和 `snapshotCommitment`。普通抽奖可继续使用
`campaign-snapshot-v1` commitment；分段抽奖使用 `campaign-snapshot-v2`。归档对象绑定
commitment hash、归档 JSON 摘要、RFC 3161 回执摘要、资源 URL、验证器 commit 和 TSA URL。

验证器独立实现上述算法，并通过固定测试向量防止与主站共享实现错误。

## 参考资料

- [drand HTTP API](https://docs.drand.love/developer/API-v2/drand-http-api/)
- [drand clients](https://docs.drand.love/developer/clients/)
- [RFC 8785 JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785.html)（本项目使用版本化的项目内稳定 JSON 规则）

[快照承诺与归档](archival.md) · [返回 README](../README.md)
