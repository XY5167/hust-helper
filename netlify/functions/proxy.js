// ============================================================
// hust-helper-proxy —— Netlify Functions 适配器（草案，未部署）
// 目标：复用 worker/scf/index.js 的路由主体，仅替换入口形态。
//
// 执行迁移时的两种落地方式（本脚手架默认展示方式 B 的结构，
// 推荐改成方式 A：把 worker/scf/index.js 中 L369 起的路由主体
// 抽成独立函数/模块，这里直接 require 并调用，避免两份逻辑分叉）：
//   A) const { handleRequest } = require('../../worker/scf/core'); exports.handler = ...
//   B) 在下方 route() 内直接重写/复制各 handler（本草案示范）
// ============================================================

// ---- 环境变量（与 SCF 完全一致，迁入 Netlify 后台即可）----
const GITHUB_API = 'https://api.github.com';
const REPO = process.env.GITHUB_REPO || 'XY5167/hust-helper-backend';
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || '';
const ALLOW_ORIGINS = (process.env.ALLOW_ORIGINS || 'https://xy5167.github.io')
  .split(',').map(s => s.trim()).filter(Boolean);
const CACHE_TTL = (parseInt(process.env.CACHE_TTL || '30', 10)) * 1000;
const IMGBB_API_KEY = process.env.IMGBB_API_KEY || '';
const SESSION_SECRET = process.env.SESSION_SECRET || 'CHANGE_ME_IN_NETLIFY_ENV';
const ADMIN_STUDENT_ID = process.env.ADMIN_STUDENT_ID || 'U202512533';
const HUNYUAN_SECRET_ID = process.env.HUNYUAN_SECRET_ID || '';
const HUNYUAN_SECRET_KEY = process.env.HUNYUAN_SECRET_KEY || '';
const HUNYUAN_MODEL = process.env.HUNYUAN_MODEL || 'hunyuan-lite';
const VERSION = 'netlify-draft';

// ---- 工具：把 Netlify event 适配成 SCF 的 (req,res) 形态 ----
function buildReqRes(event) {
  const req = {
    method: (event.httpMethod || 'GET').toUpperCase(),
    url: event.path || '/',
    headers: event.headers || {},
    body: event.body || '',
  };
  const chunks = [];
  const res = {
    statusCode: 200,
    headers: {},
    setHeader(k, v) { this.headers[k] = v; },
    getHeader(k) { return this.headers[k]; },
    write(chunk) { chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk))); },
    end(chunk) {
      if (chunk) this.write(chunk);
      this._body = Buffer.concat(chunks).toString('utf8');
    },
    _body: '',
  };
  return { req, res };
}

// ---- 路由主体（草案：health + /gh 透传已可实现；其余 handler 从 worker/scf/index.js 复制）----
async function route(event) {
  const { req, res } = buildReqRes(event);
  const sendJSON = (code, obj, extra) => {
    res.statusCode = code;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(obj));
    return toResponse(res);
  };

  // CORS
  const origin = req.headers.origin || '';
  if (ALLOW_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  }
  if (req.method === 'OPTIONS') { res.statusCode = 204; res.end(''); return toResponse(res); }

  const url = new URL(req.url, 'http://localhost');
  const path = url.pathname;

  // /api/health —— 健康检查
  if (path === '/api/health') {
    return sendJSON(200, { ok: true, version: VERSION, repo: REPO });
  }

  // /gh/* —— 透传 GitHub Issues（剥离 /gh 前缀并注入 Token）
  // 注意：沿用 worker/scf/index.js 的隐私约束（P0）——labels=user|admin 或单条 user issue 强制登录并强脱敏
  if (path.startsWith('/gh/')) {
    const ghPath = '/' + path.slice('/gh/'.length);
    // TODO: 复制 worker/scf/index.js 中 ghProxy() 与 desensitizeIssuePrivate() 逻辑
    try {
      const target = GITHUB_API + ghPath;
      const r = await fetch(target, {
        method: req.method,
        headers: { Authorization: 'Bearer ' + GITHUB_TOKEN, 'User-Agent': 'hust-helper-proxy', 'Content-Type': 'application/json' },
        body: req.method !== 'GET' ? req.body : undefined,
      });
      const data = await r.text();
      res.statusCode = r.status;
      res.setHeader('Content-Type', 'application/json');
      res.end(data);
      return toResponse(res);
    } catch (e) {
      return sendJSON(502, { error: e.message });
    }
  }

  // /api/* —— 业务路由（login/register/me/user/:sid/ai/chat/imgbb/admin/stats ...）
  // TODO: 复制 worker/scf/index.js L369 起 createServer 回调中的全部 handler 分支
  return sendJSON(404, { error: 'NOT_IMPLEMENTED_IN_DRAFT', hint: 'port handlers from worker/scf/index.js' });
}

function toResponse(res) {
  return {
    statusCode: res.statusCode,
    headers: res.headers,
    body: res._body || '',
  };
}

export const handler = async (event) => {
  try {
    return await route(event);
  } catch (e) {
    return { statusCode: 500, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ error: e.message }) };
  }
};

// 本地联调：node netlify/functions/proxy.js 时用以下桩
if (import.meta.url === `file://${process.argv[1]}`) {
  const ev = { httpMethod: 'GET', path: '/api/health', headers: {} };
  handler(ev).then(r => console.log(r.statusCode, r.body));
}
