// ============================================================
// hust-helper-proxy — 腾讯云 SCF Web 函数（纯 Node.js，零依赖）
// 核心：GitHub Token 留在服务端环境变量，前端不再暴露任何密钥。
// 前端两类请求：
//   1) ghApi() 语义路由 -> <PROXY>/api/*  （本函数实现分页/缓存）
//   2) 裸 fetch 透传     -> <PROXY>/gh/*   （本函数剥离 /gh 前缀并注入 Token）
// ============================================================

const http = require('http');

const GITHUB_API = 'https://api.github.com';
const REPO = process.env.GITHUB_REPO || 'XY5167/hust-helper-backend';
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || '';
const ALLOW_ORIGINS = (process.env.ALLOW_ORIGINS || 'https://xy5167.github.io')
  .split(',').map(s => s.trim()).filter(Boolean);
const CACHE_TTL = (parseInt(process.env.CACHE_TTL || '5', 10)) * 1000;

// 白名单：仅放行本仓库的 issues（含子路径 /comments），拒绝其它仓库/敏感路径
const REPO_ESC = REPO.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const GH_WHITELIST = new RegExp('^/repos/' + REPO_ESC + '/issues(/|\\?|$)');

// ---- 简易内存缓存（单实例有效，多实例各自缓存，不影响正确性）----
const memCache = new Map();
function getCache(key) {
  const e = memCache.get(key);
  if (e && Date.now() - e.ts < CACHE_TTL) return e.data;
  memCache.delete(key);
  return null;
}
function setCache(key, data) { memCache.set(key, { data, ts: Date.now() }); }
function clearCache() { memCache.clear(); }

// ---- CORS：仅允许白名单来源，不用 * ----
function corsHeaders(origin) {
  const allow = ALLOW_ORIGINS.includes(origin) ? origin : (ALLOW_ORIGINS[0] || '');
  return {
    'Access-Control-Allow-Origin': allow,
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
  };
}

// ---- 转发到 GitHub（Token 由服务端注入）----
async function ghProxy(ghPath, method, body) {
  const opts = {
    method,
    headers: {
      'Authorization': 'Bearer ' + GITHUB_TOKEN,
      'Accept': 'application/vnd.github+json',
      'User-Agent': 'hust-helper-proxy',
    },
  };
  if (body && method !== 'GET') {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(GITHUB_API + ghPath, opts);
  const data = res.status === 204 ? null : await res.json().catch(() => null);
  return { status: res.status, data };
}

// 分页拉全量 issues
async function ghIssuesAll(label, state) {
  let all = [];
  let page = 1;
  while (true) {
    const { status, data } = await ghProxy(
      `/repos/${REPO}/issues?labels=${encodeURIComponent(label)}&state=${state}&per_page=100&page=${page}`, 'GET', null);
    if (status !== 200 || !data || data.length === 0) break;
    all = all.concat(data);
    if (data.length < 100) break;
    page++;
  }
  return all;
}
// 分页拉全量 comments
async function ghCommentsAll(num) {
  let all = [];
  let page = 1;
  while (true) {
    const { status, data } = await ghProxy(
      `/repos/${REPO}/issues/${num}/comments?per_page=100&page=${page}`, 'GET', null);
    if (status !== 200 || !data || data.length === 0) break;
    all = all.concat(data);
    if (data.length < 100) break;
    page++;
  }
  return all;
}

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', () => resolve(''));
  });
}

function sendJSON(res, status, data, extra) {
  res.writeHead(status, Object.assign({ 'Content-Type': 'application/json' }, extra || {}));
  res.end(data === null || data === undefined ? '' : JSON.stringify(data));
}

const server = http.createServer(async (req, res) => {
  const origin = req.headers.origin || '';
  const headers = corsHeaders(origin);
  const url = new URL(req.url, 'http://localhost');
  const path = url.pathname;
  const method = req.method;

  // 预检
  if (method === 'OPTIONS') {
    res.writeHead(204, headers);
    return res.end();
  }

  // 健康检查（无需 token，供前端/运维探测）
  if (path === '/health') {
    return sendJSON(res, 200, { status: 'ok', hasToken: !!GITHUB_TOKEN, ts: Date.now() }, headers);
  }

  // ---- /api/* 语义路由（带缓存、分页）----
  if (path.startsWith('/api/')) {
    try {
      if (method === 'GET') {
        const issuesMatch = path.match(/^\/api\/issues$/);
        const issueMatch = path.match(/^\/api\/issue\/(\d+)$/);
        const commentsMatch = path.match(/^\/api\/comments\/(\d+)$/);
        if (issuesMatch) {
          const label = url.searchParams.get('label') || 'order';
          const state = url.searchParams.get('state') || 'open';
          const ck = `issues:${label}:${state}`;
          const cached = getCache(ck);
          if (cached) return sendJSON(res, 200, cached, Object.assign({}, headers, { 'x-cache': 'HIT' }));
          const data = await ghIssuesAll(label, state);
          setCache(ck, data);
          return sendJSON(res, 200, data, Object.assign({}, headers, { 'x-cache': 'MISS' }));
        }
        if (issueMatch) {
          const num = issueMatch[1];
          const ck = `issue:${num}`;
          const cached = getCache(ck);
          if (cached) return sendJSON(res, 200, cached, Object.assign({}, headers, { 'x-cache': 'HIT' }));
          const { status, data } = await ghProxy(`/repos/${REPO}/issues/${num}`, 'GET', null);
          if (status === 200) setCache(ck, data);
          return sendJSON(res, status, data, headers);
        }
        if (commentsMatch) {
          const num = commentsMatch[1];
          const ck = `comments:${num}`;
          const cached = getCache(ck);
          if (cached) return sendJSON(res, 200, cached, Object.assign({}, headers, { 'x-cache': 'HIT' }));
          const data = await ghCommentsAll(num);
          setCache(ck, data);
          return sendJSON(res, 200, data, Object.assign({}, headers, { 'x-cache': 'MISS' }));
        }
        return sendJSON(res, 404, { error: 'Unknown API route' }, headers);
      }

      if (['POST', 'PATCH', 'DELETE'].includes(method)) {
        const raw = await readBody(req);
        let ghBody = undefined;
        if (raw) { try { ghBody = JSON.parse(raw); } catch (e) { ghBody = undefined; } }

        let ghPath = '';
        if (method === 'POST' && path === '/api/issues') {
          ghPath = `/repos/${REPO}/issues`;
        } else if (method === 'POST' && /^\/api\/comments\/\d+$/.test(path)) {
          const num = path.split('/api/comments/')[1];
          ghPath = `/repos/${REPO}/issues/${num}/comments`;
        } else if (method === 'PATCH' && /^\/api\/issue\/\d+$/.test(path)) {
          const num = path.split('/api/issue/')[1];
          ghPath = `/repos/${REPO}/issues/${num}`;
        } else if (method === 'DELETE' && /^\/api\/issue\/\d+\/comments\/\d+$/.test(path)) {
          const parts = path.split('/api/issue/')[1].split('/');
          ghPath = `/repos/${REPO}/issues/comments/${parts[1]}`;
        } else {
          return sendJSON(res, 404, { error: 'Unknown API endpoint' }, headers);
        }

        const { status, data } = await ghProxy(ghPath, method, ghBody);
        if (status >= 200 && status < 300) clearCache();
        return sendJSON(res, status, data || { ok: true }, headers);
      }

      return sendJSON(res, 405, { error: 'Method not allowed' }, headers);
    } catch (e) {
      return sendJSON(res, 502, { error: e.message }, headers);
    }
  }

  // ---- /gh/* 白名单透传：承接前端 36 处裸 fetch 的 /repos/... 拼接 ----
  if (path.startsWith('/gh/')) {
    const ghPath = req.url.replace(/^\/gh/, ''); // 保留 query string
    if (!GH_WHITELIST.test(ghPath) || ghPath.includes('..')) {
      return sendJSON(res, 403, { error: 'Forbidden path' }, headers);
    }

    let body;
    if (method !== 'GET' && method !== 'DELETE') {
      const raw = await readBody(req);
      try { body = raw ? JSON.parse(raw) : undefined; } catch (e) { body = undefined; }
    }

    const cacheKey = method + ' ' + ghPath;
    if (method === 'GET' && CACHE_TTL > 0) {
      const cached = getCache(cacheKey);
      if (cached) return sendJSON(res, 200, cached, Object.assign({}, headers, { 'x-cache': 'HIT' }));
    }

    try {
      const { status, data } = await ghProxy(ghPath, method, body);
      if (method !== 'GET' && status >= 200 && status < 300) clearCache();
      if (method === 'GET' && status === 200 && CACHE_TTL > 0) setCache(cacheKey, data);
      return sendJSON(res, status, data, headers);
    } catch (e) {
      return sendJSON(res, 502, { error: e.message }, headers);
    }
  }

  sendJSON(res, 404, { error: 'Not found' }, headers);
});

const PORT = process.env.PORT || 9000;
server.listen(PORT, () => console.log('hust-helper-proxy listening on ' + PORT));
