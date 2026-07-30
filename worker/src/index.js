// ============================================================
// HUST Hub Proxy - Cloudflare Worker
// 功能：
//   1. 缓存 GitHub Issues 读操作到 KV，减少 API 消耗
//   2. 透传写操作（创建/更新/删除）到 GitHub
//   3. WebSocket 实时通知：写操作后广播 "refresh" 事件
// ============================================================

const GITHUB_API = 'https://api.github.com';
const REPO = 'XY5167/hust-helper-backend';

// ============ 工具函数 ============
function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': origin || '*',
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
    'Access-Control-Max-Age': '86400',
  };
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...extraHeaders },
  });
}

// ============ KV 缓存 ============
async function getCached(key, env) {
  try {
    const raw = await env.CACHE.get(key);
    if (raw) {
      const { data, ts } = JSON.parse(raw);
      const ttl = parseInt(env.CACHE_TTL || '5') * 1000;
      if (Date.now() - ts < ttl) return data;
    }
  } catch (e) { /* ignore */ }
  return null;
}

async function setCache(key, data, env) {
  try {
    await env.CACHE.put(key, JSON.stringify({ data, ts: Date.now() }), { expirationTtl: 60 });
  } catch (e) { /* ignore */ }
}

async function invalidateCache(env) {
  // 写操作后删除所有列表缓存
  try {
    const keys = await env.CACHE.list({ prefix: 'list:' });
    for (const k of keys.keys) {
      await env.CACHE.delete(k.name);
    }
  } catch (e) { /* ignore */ }
}

// ============ GitHub API 代理 ============
async function proxyGitHub(path, method, body, token) {
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

  const url = GITHUB_API + path;
  const res = await fetch(url, opts);

  // 处理速率限制
  const remaining = res.headers.get('x-ratelimit-remaining');
  const reset = res.headers.get('x-ratelimit-reset');

  const result = {
    status: res.status,
    headers: {
      'x-ratelimit-remaining': remaining || '?',
      'x-ratelimit-reset': reset || '?',
    },
  };

  if (res.status === 204) {
    result.data = null;
  } else {
    try {
      result.data = await res.json();
    } catch (e) {
      result.data = null;
    }
  }

  return result;
}

// 代理 GET 请求（走缓存）
async function proxyGet(cacheKey, ghPath, token, env) {
  // 尝试缓存
  const cached = await getCached(cacheKey, env);
  if (cached) {
    return json(cached, 200, {
      'x-cache': 'HIT',
      'x-cache-key': cacheKey,
    });
  }

  // 从 GitHub 拉取
  const result = await proxyGitHub(ghPath, 'GET', null, token);
  if (result.status === 200 && result.data) {
    await setCache(cacheKey, result.data, env);
    return json(result.data, 200, {
      'x-cache': 'MISS',
      'x-ratelimit-remaining': result.headers['x-ratelimit-remaining'],
    });
  }

  return json({ error: 'GitHub API error', status: result.status }, result.status);
}

// ============ 请求路由 ============
async function handleRequest(request, env, ctx) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // CORS 预检
  if (method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders(request.headers.get('Origin')) });
  }

  const origin = request.headers.get('Origin') || '*';
  const headers = corsHeaders(origin);

  // 从请求中获取 GitHub Token（前端传入，不存储在 Worker 中）
  const authHeader = request.headers.get('Authorization');
  let token = '';
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7);
  }
  if (!token) {
    return json({ error: 'Missing GitHub token' }, 401, headers);
  }

  // ---- WebSocket 升级 ----
  if (path === '/ws') {
    const upgradeHeader = request.headers.get('Upgrade');
    if (upgradeHeader && upgradeHeader === 'websocket') {
      const roomId = env.WS_ROOM.idFromName('global');
      const room = env.WS_ROOM.get(roomId);
      return room.fetch(request);
    }
    return json({ error: 'Expected WebSocket' }, 400, headers);
  }

  // ---- 读操作（带缓存） ----
  if (method === 'GET') {
    // 获取 Issues 列表（核心高频接口）
    if (path === '/api/issues') {
      const label = url.searchParams.get('label') || 'order';
      const state = url.searchParams.get('state') || 'open';
      const cacheKey = `list:issues:${label}:${state}`;
      const ghPath = `/repos/${REPO}/issues?labels=${label}&state=${state}&per_page=100`;
      return proxyGet(cacheKey, ghPath, token, env);
    }

    // 获取单个 Issue
    if (path.startsWith('/api/issue/')) {
      const issueNum = path.split('/api/issue/')[1];
      if (issueNum && /^\d+$/.test(issueNum)) {
        const cacheKey = `issue:${issueNum}`;
        const ghPath = `/repos/${REPO}/issues/${issueNum}`;
        return proxyGet(cacheKey, ghPath, token, env);
      }
    }

    // 获取评论
    if (path.startsWith('/api/comments/')) {
      const issueNum = path.split('/api/comments/')[1];
      if (issueNum && /^\d+$/.test(issueNum)) {
        const cacheKey = `comments:${issueNum}`;
        const ghPath = `/repos/${REPO}/issues/${issueNum}/comments?per_page=100`;
        return proxyGet(cacheKey, ghPath, token, env);
      }
    }
  }

  // ---- 写操作（透传 + 广播刷新） ----
  const isWrite = ['POST', 'PATCH', 'DELETE'].includes(method);

  if (isWrite) {
    let ghPath = '';
    let ghBody = null;

    try {
      if (method === 'POST' && path === '/api/issues') {
        const body = await request.json();
        ghPath = `/repos/${REPO}/issues`;
        ghBody = body;
      } else if (method === 'POST' && path.startsWith('/api/comments/')) {
        const issueNum = path.split('/api/comments/')[1];
        const body = await request.json();
        ghPath = `/repos/${REPO}/issues/${issueNum}/comments`;
        ghBody = body;
      } else if ((method === 'PATCH' || method === 'DELETE') && path.startsWith('/api/issue/')) {
        const parts = path.split('/api/issue/')[1].split('/');
        const issueNum = parts[0];
        if (method === 'PATCH') {
          const body = await request.json();
          ghPath = `/repos/${REPO}/issues/${issueNum}`;
          ghBody = body;
        } else {
          // DELETE 评论
          const commentId = parts[1];
          if (commentId) {
            ghPath = `/repos/${REPO}/issues/comments/${commentId}`;
          }
        }
      }

      if (!ghPath) {
        return json({ error: 'Unknown endpoint' }, 404, headers);
      }

      const result = await proxyGitHub(ghPath, method, ghBody, token);

      // 写操作成功后：清除缓存 + 广播 WebSocket 刷新通知
      if (result.status >= 200 && result.status < 300) {
        ctx.waitUntil(invalidateCache(env));
        ctx.waitUntil(broadcastRefresh(env, path));
      }

      return json(result.data || { ok: true }, result.status, headers);
    } catch (e) {
      return json({ error: e.message }, 500, headers);
    }
  }

  return json({ error: 'Not found', path }, 404, headers);
}

// ============ WebSocket 广播 ============
async function broadcastRefresh(env, sourcePath) {
  try {
    const roomId = env.WS_ROOM.idFromName('global');
    const room = env.WS_ROOM.get(roomId);
    // 通过 HTTP 调用 Durable Object 的 broadcast 方法
    await room.fetch(new Request('https://dummy/broadcast', {
      method: 'POST',
      body: JSON.stringify({ type: 'refresh', source: sourcePath, ts: Date.now() }),
    }));
  } catch (e) { /* ignore */ }
}

// ============ Durable Object - WebSocket 房间 ============
class WSRoom {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.sessions = [];
  }

  async fetch(request) {
    const url = new URL(request.url);

    // broadcast 内部调用
    if (url.pathname === '/broadcast' && request.method === 'POST') {
      const msg = await request.json();
      this.sessions = this.sessions.filter(ws => {
        try {
          ws.send(JSON.stringify(msg));
          return true;
        } catch (e) { return false; }
      });
      return new Response('ok');
    }

    // WebSocket 升级
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);

    server.accept();
    this.sessions.push(server);

    // 心跳
    const heartbeat = setInterval(() => {
      try { server.send(JSON.stringify({ type: 'ping' })); }
      catch (e) { clearInterval(heartbeat); }
    }, 30000);

    server.addEventListener('close', () => {
      clearInterval(heartbeat);
      this.sessions = this.sessions.filter(s => s !== server);
    });

    server.addEventListener('message', (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === 'ping') {
          server.send(JSON.stringify({ type: 'pong' }));
        }
      } catch (e) { /* ignore */ }
    });

    return new Response(null, { status: 101, webSocket: client });
  }
}

// ============ 入口 ============
export default {
  async fetch(request, env, ctx) {
    return handleRequest(request, env, ctx);
  },
};

export { WSRoom };
