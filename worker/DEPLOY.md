# Cloudflare Worker 部署指南

## 前置条件

1. 注册 [Cloudflare 账号](https://dash.cloudflare.com/sign-up)
2. 安装 [Node.js](https://nodejs.org/)
3. 安装 Wrangler CLI：
   ```bash
   npm install -g wrangler
   ```

## 部署步骤

### 1. 登录 Cloudflare

```bash
wrangler login
```

### 2. 创建 KV 命名空间

```bash
wrangler kv:namespace create "CACHE"
wrangler kv:namespace create "CACHE" --preview
```

复制输出的 `id` 和 `preview_id`，填入 `wrangler.toml` 中对应的位置。

### 3. 配置 GitHub Token

编辑 `wrangler.toml`，将 `GITHUB_TOKEN` 设置为你的 GitHub Personal Access Token。

或者使用 secret 方式（推荐）：
```bash
wrangler secret put GITHUB_TOKEN
```

### 4. 部署 Worker

```bash
cd worker
wrangler deploy
```

### 5. 获取 Worker URL

部署成功后会输出类似：
```
https://hust-hub-proxy.YOUR_SUBDOMAIN.workers.dev
```

### 6. 更新前端配置

在 `index.html` 中，将 `WORKER_URL` 替换为你的 Worker URL：
```js
const WORKER_URL = 'https://hust-hub-proxy.YOUR_SUBDOMAIN.workers.dev';
```

## 架构说明

```
前端 SPA (GitHub Pages)
    │
    ├── GET /api/issues → Worker (读缓存 KV)
    ├── GET /api/issue/:id → Worker (读缓存 KV)
    ├── GET /api/comments/:id → Worker (读缓存 KV)
    ├── POST/PATCH/DELETE → Worker → GitHub API (写操作)
    │                          └→ 清除 KV 缓存
    │                          └→ WebSocket 广播刷新
    │
    └── WebSocket /ws → Worker (实时通知)
```

## 回退方案

如果 Worker 出问题，前端会自动回退：
- WebSocket 断开 → 恢复 5 秒轮询
- Worker 不可用 → 设置 `USE_WORKER = false` 切回直连 GitHub

## 免费额度预估

以华科日常使用场景（日均 100 活跃用户）：

| 资源 | 用量估算 | 免费额度 | 够用？ |
|---|---|---|---|
| Workers 请求 | ~5000/天 | 10万/天 | ✅ |
| KV 读取 | ~5000/天 | 10万/天 | ✅ |
| KV 写入 | ~100/天 | 1000/天 | ✅ |
| Durable Objects 请求 | ~200/天 | 100万/月 | ✅ |
