# 贡献指南

## 开始前

使用 Node.js 24，并从独立分支提交改动。测试数据不得包含真实邮箱、电话、订单号、支付标识或其他用户数据。

## 本地检查

```bash
npm install
npm run check:docs
npm test
npm run typecheck
npm run build
```

提交前请确认只包含本次任务相关文件，并检查构建产物中没有敏感数据。

## 修改验证协议

协议变更需要同时完成：

1. 更新 schema、类型和完整性验证实现；
2. 为正常、边界和篡改场景补充固定测试向量；
3. 更新[协议文档](docs/protocol.md)及相关专题文档；
4. 在主项目运行 `campaign-verifier-contract.test.js`，覆盖 v2 legacy 算法、分段、未归档拒绝和已归档公开证明；
5. 确认未知版本、算法和字段仍然显式失败，不会静默降级。

本仓库应保持验证逻辑独立，不直接复用主站的协议计算实现，以便跨仓库契约测试发现共同假设或字段漂移。

## 文档约定

首次出现的核心术语使用“中文（英文）”，后续优先使用中文；协议字段、JSON 键和代码标识保留原文并使用反引号。固定术语如下：

| 英文 | 中文 |
| --- | --- |
| proof | 公开证明 |
| snapshot | 候选快照 |
| commitment | 快照承诺 |
| receipt | 时间戳回执 |
| round | drand 轮次 |
| score | 票据分数 |

新增 Markdown 文件后，应将其加入 README 导航，并运行 `npm run check:docs` 检查格式、本地链接和 README 中引用的 npm 命令。

[返回 README](README.md)
