# campaign-verifier

独立、纯静态的营销活动抽奖公开验证器。浏览器在本地读取公开证明（proof），复算候选快照、抽奖种子和中奖顺序，并验证 drand 信标、RFC 3161 时间戳及证书吊销状态。无需登录，也不会读取或上传用户邮箱。

- [在线验证器](https://ikcloudx.github.io/campaign-verifier/)
- [源代码](https://github.com/ikcloudx/campaign-verifier)

## 使用

打开在线验证器，输入主站公开证明地址，或直接粘贴完整 JSON：

```text
https://主站.example/api/campaigns/summer-2025/proof
```

也可以使用 `?proof=<URL-encoded-proof-url>` 预填地址。浏览器只会请求公开证明、证明登记的归档资源、drand relay、生产 OCSP 代理及本站同源 CRL 镜像。

## 验证内容

- 公开证明、规则、候选快照、归档文件和快照承诺的完整性；
- 抽奖种子、票据分数和最终中奖顺序；
- drand chain、轮次、randomness 和信标签名；
- RFC 3161 MessageImprint、TSA 签名链、时间顺序及 OCSP/CRL 吊销状态；
- 公开证明是否包含邮箱、电话、订单或支付标识等敏感字段。

当前仅接受包含不可变归档登记的 `proofVersion: "2"` 证明。缺少归档或使用旧版、未知协议及算法时，验证会直接停止。

## 信任边界

验证器能证明公开材料、算法、时间戳和 drand 信标相互一致，但不能证明主站在生成候选快照前没有漏记或错误筛选用户。CRL 是定期快照，实时性弱于 OCSP；外部服务不可用时也不会降级为完整通过。状态含义见[验证结果说明](docs/results.md)，完整安全边界见[吊销检查](docs/revocation.md)和[归档说明](docs/archival.md)。

## 本地开发

使用 Node.js 24：

```bash
npm install
npm test
npm run build
npm run dev
```

生产构建输出到 `dist/`，可部署到 GitHub Pages、Cloudflare Pages 或其他静态托管平台。跨域读取公开证明和归档资源需要配置 CORS，详见[部署文档](docs/deployment.md)。

## 文档

- [验证结果说明](docs/results.md)
- [验证协议](docs/protocol.md)
- [快照承诺与归档](docs/archival.md)
- [RFC 3161 验证](docs/rfc3161.md)
- [OCSP 与 CRL 吊销检查](docs/revocation.md)
- [部署](docs/deployment.md)
- [贡献指南](CONTRIBUTING.md)
