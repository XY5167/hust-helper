# hust-helper 迁移到 Netlify 的方案（设计稿，未执行）

> 状态：**方案文档 + 脚手架草案**，未部署、未切换 DNS、未改动线上。
> 关联计划：`cosmic-pulse-darwin.md` 第三部分 C。

## 1. 为什么考虑迁移

| 现状 | 痛点 |
|---|---|
| 前端 GitHub Pages + 后端腾讯云 SCF 代理 | SCF 每次需进控制台「上传 zip → 部署」，且**腾讯云会缓存上次 zip**，只点部署不换码（已踩坑多次） |
| 域名 | 需另买 + 备案才像样 |
| 密钥 | GITHUB_TOKEN 等存 SCF 环境变量（已正确，无前端硬编码）✅ |

竞品「饭小科」用 **Netlify 纯静态托管**（响应头 `Server: Netlify`），零构建、自动 HTTPS、免费自定义域名，部署体验远优于 SCF 手动传包。

## 2. 目标架构

```
浏览器 → Netlify 静态站(index.html) → /api/*、/gh/* → Netlify Function(proxy)
                                                    │ GITHUB_TOKEN 等密钥存 Netlify 环境变量(服务端)
                                                    └→ GitHub Issues(数据库，不变)
```

- 前端 `index.html` 直接作为 Netlify 静态资源（无需改构建）。
- 用 **Netlify Functions** 实现原 SCF 的全部路由（`/api/*` 业务 + `/gh/*` 透传），逻辑、脱敏规则、P0/P1 修复全部复用。
- 密钥：把 SCF 里的环境变量（GITHUB_TOKEN、IMGBB_API_KEY、HUNYUAN_SECRET_ID/KEY、SESSION_SECRET、ADMIN_STUDENT_ID 等）原样迁入 Netlify 后台，前端仍零硬编码。

## 3. 具体步骤

1. **加 `netlify.toml`**（见下方脚手架）：`publish="."`、`functions="netlify/functions"`、把 `/api/*` 与 `/gh/*` 重写到 `/.netlify/functions/proxy`。
2. **写 `netlify/functions/proxy.js`**：`exports.handler = async (event) => {...}`，把 Netlify 的 `event`（httpMethod / path / headers / body）适配成原 SCF 的 `req/res` 形态，复用 `worker/scf/index.js` 里 L369 起的路由主体。
3. **迁环境变量**：Netlify 后台 → Site settings → Environment variables，逐项填入（命名保持一致，前端 `PROXY_BASE` 改为 Netlify Function 路径即可）。
4. **前端改 `PROXY_BASE`**：从 SCF 地址改为 `/api`、`/gh` 同域代理路径（或 Function URL）。
5. **绑域名 + DNS**：Netlify 后台填自定义域名 → 按提示加 CNAME → 自动签发 HTTPS。
6. **灰度切流**：上线后保留 GitHub Pages + SCF 一段时间作回退；用 curl 对比两端 `/api/health`、`/api/user/check` 等响应一致后再把主域名 DNS 切到 Netlify。

## 4. 收益与风险

- 收益：单仓库单流水线、免手动传包、免费域名 + 自动 HTTPS、密钥仍在服务端。
- 风险：Functions 冷启动延迟（首请偏慢，可加 `--http` 或定时预热）；需重测 429 限流与 AI 配额；属较大变动，**务必先在独立分支验证、保留 SCF 回退**。

## 5. 验证清单（上线前）

```bash
# 代理健康
curl <NETLIFY>/api/health        # 应回显新版本号
# 隐私越权仍生效（沿用 P0 修复）
curl -i <NETLIFY>/gh/repos/.../issues?labels=user        # 匿名应 401
curl -i -H "Authorization: Bearer <token>" <NETLIFY>/api/user/<他人学号>  # 非本人应 403
# 前端冒烟：首页/任务大厅/发布/登录/支付码 正常
```

## 6. 交付物（本方案附带）

- `NETLIFY_MIGRATION.md`（本文件）
- `netlify.toml` — 站点配置
- `netlify/functions/proxy.js` — 适配器脚手架（含 `/api/health`、`/gh/*` 透传示例，其余 handler 标注「从 worker/scf/index.js 复制」）

> 注意：`netlify/functions/proxy.js` 是**草案**，未部署。真正执行时再决定：方案 A 抽取 SCF 路由主体为可复用模块，方案 B 直接在 proxy.js 内重排。建议方案 A（避免两份逻辑分叉）。
