// ============================================================
// hust-helper-proxy — 腾讯云 SCF Web 函数（纯 Node.js，零依赖）
// 核心：GitHub Token 留在服务端环境变量，前端不再暴露任何密钥。
// 前端两类请求：
//   1) ghApi() 语义路由 -> <PROXY>/api/*  （本函数实现分页/缓存）
//   2) 裸 fetch 透传     -> <PROXY>/gh/*   （本函数剥离 /gh 前缀并注入 Token）
//
// v1.14.0 新增：
//   - 密码后端真修：/api/login（服务端 scrypt 校验 + 明文迁移 + HMAC Token）、
//     /api/register（服务端哈希后建 Issue）、/api/me、/api/user/:sid、
//     /api/user/check、/api/admin/users、/api/stats
//   - 用户数据脱敏：所有 label=user 的响应（含 /gh/* 直读）一律剥离 password*
//   - 写保护：PATCH 用户 Issue 时服务端合并保留 password_hash，杜绝整对象写回锁号
//   - ImgBB key 移入服务端：/api/imgbb 注入 IMGBB_API_KEY
//   - CACHE_TTL 默认 30 秒
// ============================================================

const http = require('http');
const crypto = require('crypto');

const GITHUB_API = 'https://api.github.com';
const REPO = process.env.GITHUB_REPO || 'XY5167/hust-helper-backend';
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || '';
const ALLOW_ORIGINS = (process.env.ALLOW_ORIGINS || 'https://xy5167.github.io')
  .split(',').map(s => s.trim()).filter(Boolean);
const CACHE_TTL = (parseInt(process.env.CACHE_TTL || '30', 10)) * 1000;
const IMGBB_API_KEY = process.env.IMGBB_API_KEY || '';
const SESSION_SECRET = process.env.SESSION_SECRET || 'CHANGE_ME_IN_SCF_ENV';
const ADMIN_STUDENT_ID = process.env.ADMIN_STUDENT_ID || 'U202512533';
const VERSION = '1.14.1';

// 白名单：仅放行本仓库的 issues（含子路径 /comments），拒绝其它仓库/敏感路径
const REPO_ESC = REPO.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const GH_WHITELIST = new RegExp('^/repos/' + REPO_ESC + '/issues(/|\\?|$)');
const TOKEN_TTL = 12 * 3600 * 1000; // 12 小时
const RATE_LIMIT = 10;               // 每 IP 每分钟最多 10 次登录/查重
const RATE_WINDOW = 60 * 1000;

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

// ---- 速率限制（登录/查重）----
const rateMap = new Map();
function rateLimited(ip) {
  const now = Date.now();
  const arr = (rateMap.get(ip) || []).filter(t => now - t < RATE_WINDOW);
  if (arr.length >= RATE_LIMIT) { rateMap.set(ip, arr); return true; }
  arr.push(now);
  rateMap.set(ip, arr);
  return false;
}

// ---- Token（HMAC-SHA256 无状态）----
function b64url(buf) { return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function b64urlDecode(s) { s = s.replace(/-/g, '+').replace(/_/g, '/'); return Buffer.from(s, 'base64'); }
function signToken(payload) {
  const body = b64url(JSON.stringify(payload));
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return body + '.' + sig;
}
function verifyToken(token) {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [body, sig] = parts;
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  if (sig.length !== expected.length) return null;
  try { if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null; }
  catch (e) { return null; }
  try {
    const payload = JSON.parse(b64urlDecode(body).toString('utf8'));
    if (payload.exp && Date.now() > payload.exp) return null; // 过期拒绝
    return payload;
  } catch (e) { return null; }
}
function roleOf(sid) { return sid === ADMIN_STUDENT_ID ? 'admin' : 'user'; }

// ---- 密码哈希（scrypt）----
async function hashPw(pw) {
  const salt = crypto.randomBytes(16);
  return new Promise((resolve, reject) => {
    crypto.scrypt(pw, salt, 64, (err, derived) => {
      if (err) return reject(err);
      resolve('scrypt$16384$' + salt.toString('hex') + '$' + derived.toString('hex'));
    });
  });
}
async function verifyPw(pw, stored) {
  if (!stored) return false;
  if (typeof stored === 'string' && stored.startsWith('scrypt$')) {
    const parts = stored.split('$');
    const salt = Buffer.from(parts[2], 'hex');
    const expected = Buffer.from(parts[3], 'hex');
    return new Promise((resolve) => {
      crypto.scrypt(pw, salt, 64, (err, derived) => {
        if (err) return resolve(false);
        if (derived.length !== expected.length) return resolve(false);
        try { resolve(crypto.timingSafeEqual(derived, expected)); } catch (e) { resolve(false); }
      });
    });
  }
  // 兼容未迁移的明文
  return pw === stored;
}

// ---- 脱敏：剥离 password / password_hash ----
function desensitizeUser(u) {
  if (!u || typeof u !== 'object') return u;
  const c = Object.assign({}, u);
  delete c.password;
  delete c.password_hash;
  return c;
}
function issueHasUserLabel(data) {
  return data && data.labels && Array.isArray(data.labels) &&
    data.labels.some(l => (l && (l.name || l)) === 'user');
}
function desensitizeIssue(data) {
  if (Array.isArray(data)) return data.map(desensitizeIssue);
  if (issueHasUserLabel(data)) {
    try {
      const body = JSON.parse(data.body);
      return Object.assign({}, data, { body: JSON.stringify(desensitizeUser(body)) });
    } catch (e) { /* 解析失败原样返回 */ }
  }
  return data;
}
// 写用户 Issue 时合并保留服务端的 password_hash（防整对象写回锁号）
function protectPasswordField(newBodyStr, curBodyStr) {
  try {
    const cur = JSON.parse(curBodyStr);
    if (!cur.password_hash && !cur.password) return newBodyStr; // 当前无密码字段，无需保护
    const neu = JSON.parse(newBodyStr);
    if (cur.password_hash && !neu.password_hash) neu.password_hash = cur.password_hash;
    if (cur.password && !neu.password) neu.password = cur.password;
    return JSON.stringify(neu);
  } catch (e) { return newBodyStr; }
}

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

function bearerPayload(req) {
  const h = req.headers['authorization'] || '';
  if (!h.startsWith('Bearer ')) return null;
  return verifyToken(h.slice(7).trim());
}
function clientIp(req) {
  const xff = req.headers['x-forwarded-for'] || '';
  return (xff.split(',')[0] || req.socket.remoteAddress || 'unknown').trim();
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

// 分页拉全量 issues（原始数据，含 password_hash）
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
  }
  return all;
}
function findUserBySid(all, sid) {
  return all.find(i => {
    try { return JSON.parse(i.body).student_id === sid; } catch (e) { return false; }
  });
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
function sendText(res, status, text, extra) {
  res.writeHead(status, Object.assign({ 'Content-Type': 'text/plain' }, extra || {}));
  res.end(text);
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
    return sendJSON(res, 200, { status: 'ok', version: VERSION, hasToken: !!GITHUB_TOKEN, ts: Date.now() }, headers);
  }

  // ---- /api/* 语义路由（带缓存、分页）----
  if (path.startsWith('/api/')) {
    try {
      if (method === 'GET') {
        const issuesMatch = path.match(/^\/api\/issues$/);
        const issueMatch = path.match(/^\/api\/issue\/(\d+)$/);
        const commentsMatch = path.match(/^\/api\/comments\/(\d+)$/);
        const meMatch = path.match(/^\/api\/me$/);
        const userMatch = path.match(/^\/api\/user\/([^/]+)$/);
        const checkMatch = path.match(/^\/api\/user\/check$/);
        const adminMatch = path.match(/^\/api\/admin\/users$/);
        const statsMatch = path.match(/^\/api\/stats$/);

        if (meMatch) {
          const tk = bearerPayload(req);
          if (!tk) return sendJSON(res, 401, { error: 'UNAUTHORIZED' }, headers);
          const { status, data } = await ghProxy(`/repos/${REPO}/issues/${tk.num}`, 'GET', null);
          if (status !== 200 || !data) return sendJSON(res, 401, { error: 'UNAUTHORIZED' }, headers);
          const u = desensitizeUser(JSON.parse(data.body));
          u._issue_number = tk.num;
          return sendJSON(res, 200, u, headers);
        }
        if (checkMatch) {
          const sid = url.searchParams.get('sid');
          if (rateLimited(clientIp(req))) return sendJSON(res, 429, { error: 'RATE_LIMITED' }, headers);
          if (!sid) return sendJSON(res, 400, { error: 'INVALID_INPUT' }, headers);
          const all = await ghIssuesAll('user', 'all');
          const issue = findUserBySid(all, sid);
          return sendJSON(res, 200, { exists: !!issue, state: issue ? issue.state : null }, headers);
        }
        if (userMatch) {
          const tk = bearerPayload(req);
          if (!tk) return sendJSON(res, 401, { error: 'UNAUTHORIZED' }, headers);
          const all = await ghIssuesAll('user', 'all');
          const issue = findUserBySid(all, decodeURIComponent(userMatch[1]));
          if (!issue) return sendJSON(res, 404, { error: 'NOT_FOUND' }, headers);
          const u = desensitizeUser(JSON.parse(issue.body));
          u._issue_number = issue.number;
          return sendJSON(res, 200, u, headers);
        }
        if (adminMatch) {
          const tk = bearerPayload(req);
          if (!tk) return sendJSON(res, 401, { error: 'UNAUTHORIZED' }, headers);
          if (tk.role !== 'admin') return sendJSON(res, 403, { error: 'FORBIDDEN' }, headers);
          const all = await ghIssuesAll('user', 'all');
          const list = all.map(i => { const u = desensitizeUser(JSON.parse(i.body)); u._issue_number = i.number; return u; });
          return sendJSON(res, 200, list, headers);
        }
        if (statsMatch) {
          const ck = 'stats';
          const cached = getCache(ck);
          if (cached) return sendJSON(res, 200, cached, Object.assign({}, headers, { 'x-cache': 'HIT' }));
          const [users, orders] = await Promise.all([ghIssuesAll('user', 'all'), ghIssuesAll('order', 'open')]);
          const orderList = orders.map(i => { try { return JSON.parse(i.body); } catch (e) { return null; } }).filter(Boolean);
          const orderCnt = orderList.filter(o => o.status !== 'completed' && o.status !== 'cancelled' && o.type !== 'chat').length;
          const out = { users: users.length, orders: orderCnt };
          setCache(ck, out);
          return sendJSON(res, 200, out, Object.assign({}, headers, { 'x-cache': 'MISS' }));
        }
        if (issuesMatch) {
          const label = url.searchParams.get('label') || 'order';
          const state = url.searchParams.get('state') || 'open';
          const ck = `issues:${label}:${state}`;
          const cached = getCache(ck);
          if (cached) return sendJSON(res, 200, cached, Object.assign({}, headers, { 'x-cache': 'HIT' }));
          const data = await ghIssuesAll(label, state);
          const safe = (label === 'user') ? data.map(desensitizeIssue) : data;
          setCache(ck, safe);
          return sendJSON(res, 200, safe, Object.assign({}, headers, { 'x-cache': 'MISS' }));
        }
        if (issueMatch) {
          const num = issueMatch[1];
          const ck = `issue:${num}`;
          const cached = getCache(ck);
          if (cached) return sendJSON(res, 200, cached, Object.assign({}, headers, { 'x-cache': 'HIT' }));
          const { status, data } = await ghProxy(`/repos/${REPO}/issues/${num}`, 'GET', null);
          if (status === 200) setCache(ck, desensitizeIssue(data));
          return sendJSON(res, status, desensitizeIssue(data), headers);
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

        // ---- 注册：服务端哈希密码后建 Issue ----
        if (method === 'POST' && path === '/api/register') {
          const userData = ghBody && ghBody.userData;
          const password = ghBody && ghBody.password;
          if (!userData || !password) return sendJSON(res, 400, { error: 'INVALID_INPUT' }, headers);
          const all = await ghIssuesAll('user', 'all');
          if (findUserBySid(all, userData.student_id)) return sendJSON(res, 409, { error: 'DUPLICATE' }, headers);
          const hash = await hashPw(password);
          const ud = Object.assign({}, userData);
          delete ud.password;
          ud.password_hash = hash;
          const { status, data } = await ghProxy(`/repos/${REPO}/issues`, 'POST',
            { title: userData.student_id, body: JSON.stringify(ud), labels: ['user'] });
          if (status !== 201) return sendJSON(res, status || 500, data || { error: 'CREATE_FAILED' }, headers);
          const safe = desensitizeUser(ud);
          safe._issue_number = data.number;
          let token = null;
          if (ud.status === 'approved') {
            token = signToken({ sid: ud.student_id, role: roleOf(ud.student_id), num: data.number, iat: Date.now(), exp: Date.now() + TOKEN_TTL, pv: 1 });
          }
          return sendJSON(res, 200, { token, user: safe, status: ud.status }, headers);
        }

        // ---- 登录：服务端校验 + 明文迁移 + 签发 Token ----
        if (method === 'POST' && path === '/api/login') {
          const student_id = ghBody && ghBody.student_id;
          const password = ghBody && ghBody.password;
          if (!student_id || !password) return sendJSON(res, 400, { error: 'INVALID_INPUT' }, headers);
          if (rateLimited(clientIp(req))) return sendJSON(res, 429, { error: 'RATE_LIMITED' }, headers);
          const all = await ghIssuesAll('user', 'all');
          const issue = findUserBySid(all, student_id);
          if (!issue) return sendJSON(res, 401, { error: 'BAD_CREDENTIALS' }, headers);
          const u = JSON.parse(issue.body);
          const ok = await verifyPw(password, u.password_hash || u.password);
          if (!ok) return sendJSON(res, 401, { error: 'BAD_CREDENTIALS' }, headers);
          // 明文迁移
          if (u.password && !u.password_hash) {
            try {
              const h = await hashPw(password);
              const nu = Object.assign({}, u, { password_hash: h });
              delete nu.password;
              await ghProxy(`/repos/${REPO}/issues/${issue.number}`, 'PATCH', { body: JSON.stringify(nu) });
            } catch (e) { /* 迁移失败不阻断登录 */ }
          }
          if (issue.state !== 'open') {
            try { await ghProxy(`/repos/${REPO}/issues/${issue.number}`, 'PATCH', { state: 'open' }); } catch (e) {}
          }
          if (u.status === 'pending') return sendJSON(res, 403, { error: 'PENDING' }, headers);
          if (u.status === 'rejected') return sendJSON(res, 403, { error: 'REJECTED' }, headers);
          if ((u.credit_score != null ? u.credit_score : 100) < 25) return sendJSON(res, 403, { error: 'CREDIT_BLOCKED' }, headers);
          const safe = desensitizeUser(u);
          safe._issue_number = issue.number;
          const token = signToken({ sid: u.student_id, role: roleOf(u.student_id), num: issue.number, iat: Date.now(), exp: Date.now() + TOKEN_TTL, pv: 1 });
          return sendJSON(res, 200, { token, exp: Date.now() + TOKEN_TTL, user: safe }, headers);
        }

        // ---- ImgBB 图床：服务端注入 key ----
        if (method === 'POST' && path === '/api/imgbb') {
          const image = ghBody && ghBody.image;
          if (!image) return sendJSON(res, 400, { error: 'INVALID_INPUT' }, headers);
          if (!IMGBB_API_KEY) return sendJSON(res, 500, { error: 'IMGBB_NOT_CONFIGURED' }, headers);
          try {
            const form = new URLSearchParams();
            form.append('key', IMGBB_API_KEY);
            form.append('image', image);
            const r = await fetch('https://api.imgbb.com/1/upload', {
              method: 'POST',
              headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
              body: form.toString()
            });
            const j = await r.json();
            if (!j.success) return sendJSON(res, 502, { error: j.error && j.error.message || 'UPLOAD_FAILED' }, headers);
            return sendJSON(res, 200, { url: j.data.display_url || j.data.url }, headers);
          } catch (e) { return sendJSON(res, 502, { error: e.message }, headers); }
        }

        let ghPath = '';
        if (method === 'POST' && path === '/api/issues') {
          ghPath = `/repos/${REPO}/issues`;
        } else if (method === 'POST' && /^\/api\/comments\/\d+$/.test(path)) {
          const num = path.split('/api/comments/')[1];
          ghPath = `/repos/${REPO}/issues/${num}/comments`;
        } else if (method === 'PATCH' && /^\/api\/issue\/(\d+)$/.test(path)) {
          const num = path.split('/api/issue/')[1];
          ghPath = `/repos/${REPO}/issues/${num}`;
          // 写保护：合并保留 password_hash
          if (ghBody && ghBody.body) {
            const cur = await ghProxy(ghPath, 'GET', null);
            if (cur.status === 200 && issueHasUserLabel(cur.data)) {
              ghBody = Object.assign({}, ghBody, { body: protectPasswordField(ghBody.body, cur.data.body) });
            }
          }
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

  // ---- /gh/* 白名单透传：承接前端裸 fetch 的 /repos/... 拼接 ----
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

    // 写保护：PATCH 用户 Issue 合并保留 password_hash
    if (method === 'PATCH' && body && body.body) {
      const cur = await ghProxy(ghPath, 'GET', null);
      if (cur.status === 200 && issueHasUserLabel(cur.data)) {
        body = Object.assign({}, body, { body: protectPasswordField(body.body, cur.data.body) });
      }
    }

    try {
      const { status, data } = await ghProxy(ghPath, method, body);
      if (method !== 'GET' && status >= 200 && status < 300) clearCache();
      if (method === 'GET' && status === 200 && CACHE_TTL > 0) setCache(cacheKey, data);
      // 脱敏：任何含 user label 的响应都剥离 password*
      return sendJSON(res, status, desensitizeIssue(data), headers);
    } catch (e) {
      return sendJSON(res, 502, { error: e.message }, headers);
    }
  }

  sendJSON(res, 404, { error: 'Not found' }, headers);
});

const PORT = process.env.PORT || 9000;
server.listen(PORT, () => console.log('hust-helper-proxy listening on ' + PORT));
