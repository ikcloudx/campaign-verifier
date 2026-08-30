# 快照承诺与归档

## 操作流程

1. Freeze 返回 `snapshot_committed` 后，从 `GET /api/campaigns/<slug>/commitment` 获取不含邮箱和用户标识的快照承诺（commitment）JSON。
2. 在安排 drand 目标轮次前，将完整 JSON 原样保存到独立托管位置，例如独立 Git 仓库、不可变对象存储或可信时间戳归档。
3. 确认存档完成后，再执行管理后台的 **Archive and schedule Beacon**。
4. 抽奖完成后，将公开证明（proof）URL 输入验证器。Protocol v2 中的 `archive.archiveUrl` 和 `archive.receiptUrl` 会被自动读取。

归档通过 `POST /api/admin/campaigns/<campaign-id>/archive` 登记，内容包括 `commitmentHash`、归档 JSON 与 `.tsr` 的 SHA-256、两个公开 URL、验证器 Git 提交和 TSA URL。登记按 campaign 唯一且不可更新或删除；相同数据可幂等重试，不同数据会被拒绝。只有完成登记后，服务端才允许安排 drand 目标轮次。

主站不会将 `.tsr` 内容复制到数据库，归档 JSON 和回执仍需发布到允许跨域读取的独立位置。归档脚本可生成、验证并推送文件；设置 `CAMPAIGN_ARCHIVE_API_KEY` 后可在推送完成后自动登记，否则需要管理员调用登记 API。

归档仓库应启用分支保护并禁止强制推送。提交前还应保留 `.gitattributes`，确保 JSON 不转换换行、`.tsr` 按二进制文件保存。脚本要求工作区 clean，但这不能替代代码审查和仓库权限控制。

## 验证内容

验证器会检查：

1. proof 内部重新计算的 `snapshotCommitment`；
2. `archive.archiveUrl` 指向的归档 JSON 与 proof 的字段及 `commitmentHash`；
3. 归档 JSON 和 RFC 3161 回执原始字节的 SHA-256 摘要；
4. RFC 3161 CMS/ASN.1、TSA 签名、固定信任根、证书用途及 OCSP/CRL 吊销状态；
5. snapshot publication time 与 `genTime + accuracy`（若 receipt 声明 accuracy）的时间顺序。

归档和回执站点必须允许跨域读取（CORS），且归档文件不应包含协议未定义的敏感字段。receipt
省略可选的 `accuracy` 时，浏览器会保留 `genTime` 检查并显示警告；严格的离线时间证明应
根据 TSA 独立 policy 使用 [RFC 3161 CLI](rfc3161.md) 提供 `--max-accuracy-ms`。

## 输入限制

- 公开 proof JSON：最大 16 MiB、250,000 个 ticket、JSON 深度 64 层、500,000 个节点；
- 归档 commitment：最大 256 KiB，RFC 3161 receipt：最大 2 MiB；
- proof、commitment 和 receipt 请求：10 秒超时，并在流式读取时限制大小。

[验证结果说明](results.md) · [RFC 3161 验证](rfc3161.md) · [返回 README](../README.md)
