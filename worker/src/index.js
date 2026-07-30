// ============================================================
// HUST Hub Proxy - Cloudflare Worker (简化版)
// 功能：
//   1. 缓存 GitHub Issues 读操作到内存，减少 API 消耗
//   2. 透传写操作（创建/更新/删除）到 GitHub
//   3. 轮询模式：前端定时拉取（比直连 GitHub 更省额度）
// ============================================================

const GITHUB_API = 'https://api.github.com';
const REPO = 'XY5167/hust-helper-backend';

// 内存缓存（单 Worker 实例内有效）
const memCache = new Map();
const CACHE_TTL = 5000; // 5 秒（默认值，可被环境变量覆盖）

function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': origin || '*',
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
  };
}

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...extra },
  });
}

// 内存缓存
function getCache(key) {
  const entry = memCache.get(key);
  if (entry && Date.now() - entry.ts < CACHE_TTL) return entry.data;
  memCache.delete(key);
  return null;
}

function setCache(key, data) {
  memCache.set(key, { data, ts: Date.now() });
}

function clearCache(prefix) {
  for (const key of memCache.keys()) {
    if (key.startsWith(prefix)) memCache.delete(key);
  }
}

// 代理 GitHub API
async function ghProxy(path, method, body, token) {
  const opts = {
    method,
    headers: {
      'Authorization': 'Bearer ' + token,
      'Accept': 'application/vnd.github+json',
      'User-Agent': 'hust-hub-proxy',
    },
  };
  if (body && method !== 'GET') {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }

  const res = await fetch(GITHUB_API + path, opts);
  const remaining = res.headers.get('x-ratelimit-remaining');
  const data = res.status === 204 ? null : await res.json().catch(() => null);

  return {
    status: res.status,
    data,
    rateRemaining: remaining,
  };
}

// 分页拉取全部 Issues
async function ghIssuesAll(label, state, token) {
  let all = [];
  let page = 1;
  while (true) {
    const path = `/repos/${REPO}/issues?labels=${label}&state=${state}&per_page=100&page=${page}`;
    const { status, data } = await ghProxy(path, 'GET', null, token);
    if (status !== 200 || !data || data.length === 0) break;
    all = all.concat(data);
    if (data.length < 100) break;
    page++;
  }
  return all;
}

// 分页拉取全部评论
async function ghCommentsAll(issueNum, token) {
  let all = [];
  let page = 1;
  while (true) {
    const path = `/repos/${REPO}/issues/${issueNum}/comments?per_page=100&page=${page}`;
    const { status, data } = await ghProxy(path, 'GET', null, token);
    if (status !== 200 || !data || data.length === 0) break;
    all = all.concat(data);
    if (data.length < 100) break;
    page++;
  }
  return all;
}

// ============ 请求处理 ============
async function handleRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;
  const origin = request.headers.get('Origin') || '*';
  const headers = corsHeaders(origin);

  if (method === 'OPTIONS') {
    return new Response(null, { status: 204, headers });
  }

  // 必须从请求头传入 Token（由前端代码拼接后传入）
  const authHeader = request.headers.get('Authorization');
  let token = '';
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7);
  }
  if (!token) {
    return json({ error: 'Missing GitHub token' }, 401, headers);
  }

  // ---- GET: 读操作（带缓存） ----
  if (method === 'GET') {
    // Issues 列表
    if (path === '/api/issues') {
      const label = url.searchParams.get('label') || 'order';
      const state = url.searchParams.get('state') || 'open';
      const cacheKey = `issues:${label}:${state}`;
      const cached = getCache(cacheKey);
      if (cached) {
        return json(cached, 200, { ...headers, 'x-cache': 'HIT' });
      }
      const data = await ghIssuesAll(label, state, token);
      setCache(cacheKey, data);
      return json(data, 200, { ...headers, 'x-cache': 'MISS' });
    }

    // 单个 Issue
    const issueMatch = path.match(/^\/api\/issue\/(\d+)$/);
    if (issueMatch) {
      const num = issueMatch[1];
      const cacheKey = `issue:${num}`;
      const cached = getCache(cacheKey);
      if (cached) return json(cached, 200, { ...headers, 'x-cache': 'HIT' });
      const { status, data } = await ghProxy(`/repos/${REPO}/issues/${num}`, 'GET', null, token);
      if (status === 200) setCache(cacheKey, data);
      return json(data, status, headers);
    }

    // 评论列表
    const commentsMatch = path.match(/^\/api\/comments\/(\d+)$/);
    if (commentsMatch) {
      const num = commentsMatch[1];
      const cacheKey = `comments:${num}`;
      const cached = getCache(cacheKey);
      if (cached) return json(cached, 200, { ...headers, 'x-cache': 'HIT' });
      const data = await ghCommentsAll(num, token);
      setCache(cacheKey, data);
      return json(data, 200, { ...headers, 'x-cache': 'MISS' });
    }
  }

  // ---- POST/PATCH/DELETE: 写操作（透传 + 清缓存） ----
  if (['POST', 'PATCH', 'DELETE'].includes(method)) {
    let ghPath = '';
    let ghBody = null;

    try {
      if (method === 'POST' && path === '/api/issues') {
        const body = await request.json();
        ghPath = `/repos/${REPO}/issues`;
        ghBody = body;
      } else if (method === 'POST' && path.startsWith('/api/comments/')) {
        const num = path.split('/api/comments/')[1];
        const body = await request.json();
        ghPath = `/repos/${REPO}/issues/${num}/comments`;
        ghBody = body;
      } else if (method === 'PATCH' && path.startsWith('/api/issue/')) {
        const parts = path.split('/api/issue/')[1].split('/');
        const num = parts[0];
        const body = await request.json();
        ghPath = `/repos/${REPO}/issues/${num}`;
        ghBody = body;
      } else if (method === 'DELETE' && path.startsWith('/api/issue/')) {
        const parts = path.split('/api/issue/')[1].split('/');
        const commentId = parts[1];
        if (commentId) {
          ghPath = `/repos/${REPO}/issues/comments/${commentId}`;
        }
      }

      if (!ghPath) return json({ error: 'Unknown endpoint' }, 404, headers);

      const { status, data } = await ghProxy(ghPath, method, ghBody, token);

      // 写操作成功后清缓存
      if (status >= 200 && status < 300) {
        clearCache('issues:');
        clearCache('issue:');
        clearCache('comments:');
      }

      return json(data || { ok: true }, status, headers);
    } catch (e) {
      return json({ error: e.message }, 500, headers);
    }
  }

  // 健康检查
  if (path === '/health') {
    return json({ status: 'ok', ts: Date.now() }, 200, headers);
  }

  return json({ error: 'Not found' }, 404, headers);
}

export default {
  async fetch(request, env) {
    return handleRequest(request, env);
  },
};
