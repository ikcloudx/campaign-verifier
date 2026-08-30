# 部署

## GitHub Pages

`.github/workflows/pages.yml` 在 `main` 分支变更后运行测试和构建，并部署到 GitHub Pages。`npm run build` 已包含类型检查；从其他分支手动运行 workflow 时只构建、不部署。

首次部署前，在仓库 **Settings → Pages** 中将 **Build and deployment → Source** 设为 **GitHub Actions**。Pages 未启用时，`deploy-pages` 创建部署可能返回 `404 Not Found`。

## Cloudflare Pages

- 构建命令：`npm run build`
- 输出目录：`dist`
- Node.js：24

验证器是纯静态站点，部署平台不会获得公开 proof 之外的权限。

## CORS

浏览器需要跨域读取公开 proof、归档 JSON 和时间戳回执（receipt）。主站使用受限 CORS 时，应将验证器的正式域名加入 `ALLOWED_ORIGINS`，或对只读 proof 路由配置等价的公开 CORS。归档与回执托管位置也必须允许验证器域名读取。

该配置只允许读取公开资源，不会改变 proof 内容或授予管理员权限。

## 参考资料

- [GitHub Pages custom workflows](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages)
- [Cloudflare Pages static deployments](https://developers.cloudflare.com/pages/framework-guides/deploy-anything/)

[返回 README](../README.md)
