# OCSP 与 CRL 吊销检查

浏览器不使用操作系统证书库，而是使用验证器内置、固定 SHA-256 指纹的 FreeTSA 根证书。TSR 内嵌证书只能作为证书链材料，不能自动成为信任锚。

## 检查顺序

1. 浏览器优先向 `https://ocsp.kcloudx.com/ocsp` 请求原始 OCSP 响应；
2. PKI.js 在本地验证响应签名、响应者证书链、OCSP Signing EKU、CertID、nonce 和时效；
3. OCSP 不可达或返回 `unknown` 时，回退到 `public/revocation/freetsa-root-ca.crl` 的同源副本并显示警告；
4. CRL 会使用固定根证书验证签名和有效期，再按 TSA 签名证书序列号查询吊销状态。

OCSP 返回 `revoked`，或出现签名错误、证书链不可信、CRL 缺失及过期等情况时，验证直接失败，不会将“无法检查”解释为“未吊销”。

## CRL 更新

`.github/workflows/refresh-freetsa-crl.yml` 每周一 03:00 UTC 下载官方 CRL，验证根证书指纹、CRL 签名和有效期，并仅在内容变化时提交更新。也可以从 Actions 页面手动触发。

每周更新意味着吊销信息最多可能滞后约 7 天。高安全场景应缩短刷新周期，或使用受信客户端独立查询最新 CRL/OCSP。

## OCSP 代理

生产代理是一个受限 Cloudflare Worker，只转发原始 OCSP 数据，不解析响应或提供可信布尔结论。它仅允许 `POST /ocsp` 和 CORS 预检，并限制来源、请求大小、响应大小、超时、重定向及请求频率。

部署、自定义域名和故障排查见 [Worker 文档](../workers/ocsp-proxy/README.md)。修改代理地址后，需要同步更新 `src/revocation-config.ts` 中的 `FREETSA_OCSP_PROXY_URL` 并重新发布静态站点。

[RFC 3161 验证](rfc3161.md) · [返回 README](../README.md)
