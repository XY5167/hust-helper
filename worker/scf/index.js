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
//
// v1.15.0 新增（ai+opc 项目主题）：
//   - 腾讯混元大模型接入：TC3-HMAC-SHA256 签名（零依赖），密钥读 HUNYUAN_SECRET_ID/KEY 环境变量
//   - /api/ai/chat：承接前端互助助手对话，转发混元 ChatCompletions
//   - /api/ai/polish：承接前端「AI 帮我写」，返回结构化 JSON（title/desc/type/subtype/price）
//
// v1.16.0 新增（AI 识图）：
//   - TC3 签名重构为通用 tc3Request()（参数化 service/host/action/version）
//   - /api/ai/ocr：腾讯云 GeneralBasicOCR 识别图片文字 + 混元提取搜索关键词（两段式）
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
const HUNYUAN_SECRET_ID = process.env.HUNYUAN_SECRET_ID || '';
const HUNYUAN_SECRET_KEY = process.env.HUNYUAN_SECRET_KEY || '';
const HUNYUAN_MODEL = process.env.HUNYUAN_MODEL || 'hunyuan-lite';
const AI_RATE_LIMIT = parseInt(process.env.AI_RATE_LIMIT || '20', 10); // 每 IP 每分钟最多 20 次 AI 调用
const OCR_RATE_LIMIT = parseInt(process.env.OCR_RATE_LIMIT || '10', 10); // 每 IP 每分钟最多 10 次 OCR（额度保护）
const VERSION = '1.17.2';

// 白名单：仅放行本仓库的 issues（含子路径 /comments），拒绝其它仓库/敏感路径
const REPO_ESC = REPO.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const GH_WHITELIST = new RegExp('^/repos/' + REPO_ESC + '/issues(/|\\?|$)');
const TOKEN_TTL = 4 * 3600 * 1000; // 4 小时（缩短泄露窗口，P1 安全修复）
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
function rateLimited(ip, limit) {
  const cap = limit || RATE_LIMIT;
  const now = Date.now();
  const arr = (rateMap.get(ip) || []).filter(t => now - t < RATE_WINDOW);
  if (arr.length >= cap) { rateMap.set(ip, arr); return true; }
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
// 强脱敏：user 类 issue 剥离真实身份字段（学号/姓名/手机号/宿舍/邮箱等），纵深防御
const PRIVATE_FIELDS = ['student_id', 'name', 'phone', 'dorm', 'email', 'real_name', 'wechat', 'qq'];
function desensitizeIssuePrivate(data) {
  if (Array.isArray(data)) return data.map(desensitizeIssuePrivate);
  if (issueHasUserLabel(data)) {
    try {
      const body = JSON.parse(data.body);
      const c = Object.assign({}, body);
      PRIVATE_FIELDS.forEach(f => delete c[f]);
      return Object.assign({}, data, { body: JSON.stringify(c) });
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

// ---- 腾讯云 TC3-HMAC-SHA256 通用签名请求（零依赖，参数化 service/host/action/version）----
async function tc3Request(opts) {
  // opts: { service, host, action, version, region, payloadObj, timeoutMs }
  if (!HUNYUAN_SECRET_ID || !HUNYUAN_SECRET_KEY) throw new Error('TENCENT_NOT_CONFIGURED');
  const host = opts.host;
  const service = opts.service;
  const payload = JSON.stringify(opts.payloadObj || {});
  const timestamp = Math.floor(Date.now() / 1000);
  const date = new Date(timestamp * 1000).toISOString().slice(0, 10); // UTC YYYY-MM-DD

  const hashedPayload = crypto.createHash('sha256').update(payload).digest('hex');
  const canonicalHeaders = 'content-type:application/json; charset=utf-8\nhost:' + host + '\n';
  const signedHeaders = 'content-type;host';
  const canonicalRequest = 'POST\n/\n\n' + canonicalHeaders + '\n' + signedHeaders + '\n' + hashedPayload;

  const credentialScope = date + '/' + service + '/tc3_request';
  const hashedCanonicalRequest = crypto.createHash('sha256').update(canonicalRequest).digest('hex');
  const stringToSign = 'TC3-HMAC-SHA256\n' + timestamp + '\n' + credentialScope + '\n' + hashedCanonicalRequest;

  function hmac(key, msg) { return crypto.createHmac('sha256', key).update(msg).digest(); }
  const secretDate = hmac('TC3' + HUNYUAN_SECRET_KEY, date);
  const secretService = hmac(secretDate, service);
  const secretSigning = hmac(secretService, 'tc3_request');
  const signature = hmac(secretSigning, stringToSign).toString('hex');

  const authorization = 'TC3-HMAC-SHA256 Credential=' + HUNYUAN_SECRET_ID + '/' + credentialScope +
    ', SignedHeaders=' + signedHeaders + ', Signature=' + signature;

  const headers = {
    'Authorization': authorization,
    'Content-Type': 'application/json; charset=utf-8',
    'Host': host,
    'X-TC-Action': opts.action,
    'X-TC-Version': opts.version,
    'X-TC-Timestamp': String(timestamp)
  };
  if (opts.region) headers['X-TC-Region'] = opts.region; // OCR 为全局服务可不传，region 不参与签名
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), opts.timeoutMs || 20000);
  try {
    const r = await fetch('https://' + host + '/', { method: 'POST', headers, body: payload, signal: ctl.signal });
    return await r.json();
  } finally { clearTimeout(timer); }
}

// ---- 腾讯混元大模型（薄封装：复用 tc3Request）----
async function callHunyuan(messages) {
  if (!HUNYUAN_SECRET_ID || !HUNYUAN_SECRET_KEY) throw new Error('HUNYUAN_NOT_CONFIGURED');
  const json = await tc3Request({
    service: 'hunyuan',
    host: 'hunyuan.tencentcloudapi.com',
    action: 'ChatCompletions',
    version: '2023-09-01',
    region: 'ap-guangzhou',
    payloadObj: {
      Model: HUNYUAN_MODEL,
      Stream: false,
      Messages: messages.map(m => ({
        Role: (m.role === 'system') ? 'system'
          : (m.role === 'assistant' || m.role === 'bot') ? 'assistant'
          : 'user',
        Content: String(m.content || '')
      }))
    }
  });
  if (json.Response && json.Response.Error) throw new Error(json.Response.Error.Message || 'HUNYUAN_ERROR');
  if (!json.Response || !json.Response.Choices || !json.Response.Choices[0]) throw new Error('HUNYUAN_EMPTY');
  return json.Response.Choices[0].Message.Content;
}

// ---- 腾讯云 OCR 通用文字识别（GeneralBasicOCR，免费 1000 次/月）----
async function callOcrBasic(imageBase64) {
  const json = await tc3Request({
    service: 'ocr',
    host: 'ocr.tencentcloudapi.com',
    action: 'GeneralBasicOCR',
    version: '2018-11-19',
    region: '', // OCR 为全局服务，不传 X-TC-Region
    payloadObj: { ImageBase64: imageBase64 },
    timeoutMs: 15000
  });
  if (json.Response && json.Response.Error) {
    const code = json.Response.Error.Code || '';
    throw new Error(code === 'FailedOperation.Arrears' || /Limit|Quota/i.test(code)
      ? 'OCR_QUOTA_EXCEEDED' : (json.Response.Error.Message || 'OCR_ERROR'));
  }
  const dets = (json.Response && json.Response.TextDetections) || [];
  return dets.map(d => String(d.DetectedText || '').trim()).filter(Boolean).join('\n');
}

// 抽取 JSON（容错：忽略前后多余文本、markdown 代码块）
function extractJson(text) {
  if (!text) return null;
  try { return JSON.parse(text); } catch (e) {}
  const m = text.match(/\{[\s\S]*\}/);
  if (m) { try { return JSON.parse(m[0]); } catch (e) {} }
  return null;
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
          const sid = decodeURIComponent(userMatch[1]);
          // 越权防护：仅本人或管理员可读取他人用户资料
          if (tk.role !== 'admin' && tk.sid !== sid) {
            return sendJSON(res, 403, { error: 'FORBIDDEN' }, headers);
          }
          const all = await ghIssuesAll('user', 'all');
          const issue = findUserBySid(all, sid);
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
          const [users, orders] = await Promise.all([ghIssuesAll('user', 'open'), ghIssuesAll('order', 'open')]);
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

        // ---- 管理员发布站内公告 ----
        if (method === 'POST' && path === '/api/announce') {
          const tk = bearerPayload(req);
          if (!tk) return sendJSON(res, 401, { error: 'UNAUTHORIZED' }, headers);
          if (tk.role !== 'admin') return sendJSON(res, 403, { error: 'FORBIDDEN' }, headers);
          const title = (ghBody && ghBody.title || '').trim();
          const content = (ghBody && ghBody.content || '').trim();
          if (!title || !content) return sendJSON(res, 400, { error: 'INVALID_INPUT' }, headers);
          const { status, data } = await ghProxy(`/repos/${REPO}/issues`, 'POST', {
            title: '[公告] ' + title,
            body: JSON.stringify({ title, content, author: tk.sid, created: Date.now() }),
            labels: ['announcement']
          });
          if (status !== 201) return sendJSON(res, status || 500, data || { error: 'CREATE_FAILED' }, headers);
          clearCache();
          return sendJSON(res, 200, { ok: true, number: data.number }, headers);
        }

        // ---- 管理员撤回/删除公告（关闭 issue）----
        if (method === 'POST' && path === '/api/announce/delete') {
          const tk = bearerPayload(req);
          if (!tk) return sendJSON(res, 401, { error: 'UNAUTHORIZED' }, headers);
          if (tk.role !== 'admin') return sendJSON(res, 403, { error: 'FORBIDDEN' }, headers);
          const num = ghBody && ghBody.number;
          if (!num) return sendJSON(res, 400, { error: 'INVALID_INPUT' }, headers);
          const { status, data } = await ghProxy(`/repos/${REPO}/issues/${num}`, 'PATCH', { state: 'closed' });
          if (status !== 200) return sendJSON(res, status || 500, data || { error: 'DELETE_FAILED' }, headers);
          clearCache();
          return sendJSON(res, 200, { ok: true }, headers);
        }

        // ---- AI 互助小助手：聊天 ----
        if (method === 'POST' && path === '/api/ai/chat') {
          if (rateLimited(clientIp(req), AI_RATE_LIMIT)) return sendJSON(res, 429, { error: 'RATE_LIMITED' }, headers);
          const msgs = ghBody && ghBody.messages;
          if (!msgs || !Array.isArray(msgs) || msgs.length === 0) return sendJSON(res, 400, { error: 'INVALID_INPUT' }, headers);
          try {
            const reply = await callHunyuan(msgs);
            return sendJSON(res, 200, { ok: true, reply }, headers);
          } catch (e) { return sendJSON(res, 502, { error: e.message }, headers); }
        }

        // ---- AI 互助小助手：发布润色 ----
        if (method === 'POST' && path === '/api/ai/polish') {
          if (rateLimited(clientIp(req), AI_RATE_LIMIT)) return sendJSON(res, 429, { error: 'RATE_LIMITED' }, headers);
          const text = ghBody && ghBody.text;
          if (!text || typeof text !== 'string') return sendJSON(res, 400, { error: 'INVALID_INPUT' }, headers);
          const sysPrompt = '你是华中科技大学(HUST)校园互助平台的发布助手。用户会用大白话描述一个互助需求，请把它改写成规范、友好、信息完整的发布内容。必须只返回一个 JSON 对象（不要 markdown 代码块、不要任何解释文字），字段：title（不超过 20 字的中文标题）、desc（通顺的需求描述，80-150 字，语气礼貌友好，主动提示必要信息如具体地点/楼栋、期望时间、报酬金额与线下支付方式，结尾加一句"如有疑问可平台私信联系"）、type（从 task/secondhand/qa/find 中严格选一个）、subtype（对应子分类：task 用 express/food/buydeliver/print/repair/other；secondhand 用 other；qa 用 exercise/course/exam/life/job/other；find 用 other）、price（建议报酬，整数元，仅 type 为 task/secondhand/find 时给出，qa 给 0）。注意：不要在内容中留微信号、QQ号或手机号，统一引导用平台私信。';
          try {
            const content = await callHunyuan([
              { role: 'system', content: sysPrompt },
              { role: 'user', content: '需求：' + text }
            ]);
            const parsed = extractJson(content);
            if (!parsed || !parsed.title) return sendJSON(res, 502, { error: 'PARSE_FAILED' }, headers);
            if (!['task', 'secondhand', 'qa', 'find'].includes(parsed.type)) parsed.type = 'task';
            parsed.price = parseInt(parsed.price, 10) || 0;
            parsed.desc = (parsed.desc || text).toString();
            return sendJSON(res, 200, parsed, headers);
          } catch (e) { return sendJSON(res, 502, { error: e.message }, headers); }
        }

        // ---- AI 识图：OCR 识别 + 混元提取关键词（两段式，一次请求返回）----
        if (method === 'POST' && path === '/api/ai/ocr') {
          if (rateLimited(clientIp(req), OCR_RATE_LIMIT)) return sendJSON(res, 429, { error: 'RATE_LIMITED' }, headers);
          const image = ghBody && ghBody.image;
          if (!image || typeof image !== 'string' || image.length < 100) return sendJSON(res, 400, { error: 'INVALID_INPUT' }, headers);
          if (image.length > 7 * 1024 * 1024) return sendJSON(res, 400, { error: 'IMAGE_TOO_LARGE' }, headers);
          try {
            const text = await callOcrBasic(image);          // 第一段：OCR
            if (!text) return sendJSON(res, 200, { ok: true, text: '', keywords: [] }, headers); // 图中无文字属正常
            const clip = text.slice(0, 1500);                // 防混元超长
            let keywords = [];
            try {                                             // 第二段：混元提取关键词（失败不阻断，仅 keywords 为空）
              const sys = '你是二手交易/校园互助平台的图片关键词提取器。输入是照片 OCR 识别出的文字（可能杂乱）。' +
                '请提取最有助于买家搜索的关键词：商品名、书名/课程名、品牌、型号、成色描述等。' +
                '必须只返回一个 JSON 对象 {"keywords":["..."]}：最多 8 个，每个 2-10 个字，去掉价格/纯数字/' +
                '微信号/QQ/手机号等联系方式和乱码，不要编造 OCR 文字中没有的商品信息。';
              const content = await callHunyuan([
                { role: 'system', content: sys },
                { role: 'user', content: 'OCR 文字：\n' + clip }
              ]);
              const parsed = extractJson(content);
              if (parsed && Array.isArray(parsed.keywords)) {
                keywords = parsed.keywords.map(k => String(k).trim().slice(0, 10)).filter(k => k.length >= 2).slice(0, 8);
              }
            } catch (e) { /* 关键词提取失败，降级返回纯文本 */ }
            return sendJSON(res, 200, { ok: true, text: clip, keywords }, headers);
          } catch (e) { return sendJSON(res, 502, { error: e.message }, headers); }
        }

        // ---- AI 投诉预审：根据投诉内容判定成立/不成立/需人工，附置信度与建议 ----
        if (method === 'POST' && path === '/api/ai/review') {
          if (rateLimited(clientIp(req), AI_RATE_LIMIT)) return sendJSON(res, 429, { error: 'RATE_LIMITED' }, headers);
          const reason = (ghBody && ghBody.reason || '').toString().trim();
          const description = (ghBody && ghBody.description || '').toString().trim();
          const orderTitle = (ghBody && ghBody.order_title || '').toString().trim();
          const targetName = (ghBody && ghBody.target_name || '').toString().trim();
          const reporterName = (ghBody && ghBody.reporter_name || '').toString().trim();
          if (!description) return sendJSON(res, 400, { error: 'INVALID_INPUT' }, headers);
          const sysPrompt = '你是校园互助平台的投诉仲裁助手，负责对用户投诉做第一轮预审，减轻人工审核压力。' +
            '投诉可能涉及：付款金额不对、付款后失联、未完成约定任务、态度恶劣、虚假信息、其他。' +
            '判断规则：' +
            '1) 描述具体、有明确事实（涉及金额、时间、聊天过程、具体承诺未兑现等）→ 倾向 valid（投诉成立）；' +
            '2) 描述模糊、只有情绪宣泄、无具体事实、双方说法待核实 → review（需人工复核）；' +
            '3) 明显恶意攻击、侮辱谩骂、与订单无关、或描述显示是投诉人自己的问题 → invalid（投诉不成立）；' +
            '必须只返回一个 JSON 对象（不要 markdown 代码块、不要任何解释文字）：' +
            '{"verdict":"valid|invalid|review","confidence":0-100的整数,"reason":"一句话理由（20字内）","suggested_action":"建议处理方式（如：扣被投诉方信用分10分/驳回/双方协商）"}。' +
            'confidence 表示你对判断的把握程度：只有事实非常清楚、几乎没有争议时才给 90 以上；把握不足一律 80 以下并选 review。';
          try {
            const content = await callHunyuan([
              { role: 'system', content: sysPrompt },
              { role: 'user', content: '投诉原因：' + (reason || '未选择') +
                '\n详细说明：' + description +
                (orderTitle ? '\n相关订单：' + orderTitle : '') +
                (targetName ? '\n被投诉人：' + targetName : '') +
                (reporterName ? '\n投诉人：' + reporterName : '') }
            ]);
            const parsed = extractJson(content);
            if (!parsed || !parsed.verdict || !['valid', 'invalid', 'review'].includes(parsed.verdict)) {
              return sendJSON(res, 200, { ok: true, verdict: 'review', confidence: 50, reason: 'AI 未能理解投诉内容，转人工复核', suggested_action: '人工复核' });
            }
            const conf = Math.max(0, Math.min(100, parseInt(parsed.confidence, 10) || 50));
            return sendJSON(res, 200, {
              ok: true,
              verdict: parsed.verdict,
              confidence: conf,
              reason: (parsed.reason || '').toString().slice(0, 80),
              suggested_action: (parsed.suggested_action || '').toString().slice(0, 80)
            });
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

    // 防护：announcement 标签仅管理员可创建，防止普通用户伪造公告
    if (method !== 'GET' && method !== 'DELETE' && body && Array.isArray(body.labels) && body.labels.includes('announcement')) {
      const tk = bearerPayload(req);
      if (!tk || tk.role !== 'admin') return sendJSON(res, 403, { error: 'FORBIDDEN' }, headers);
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
      if (method !== 'GET') {
        // 写操作：仅剥离 password*
        return sendJSON(res, status, desensitizeIssue(data), headers);
      }
      // ---- GET：隐私约束 ----
      const isUserList = /[?&]labels=(user|admin)\b/.test(ghPath);
      const singleMatch = ghPath.match(/\/issues\/\d+(?:\?.*)?$/);
      if (isUserList || singleMatch) {
        // 敏感用户数据不进公共缓存，避免越权缓存侧信道
        const tk = bearerPayload(req);
        if (!tk) return sendJSON(res, 401, { error: 'UNAUTHORIZED' }, headers);
        if (singleMatch) {
          // 单条 issue：user/admin 类且非管理员则强脱敏，杜绝泄露他人手机/姓名
          if (issueHasUserLabel(data)) {
            if (tk.role === 'admin') return sendJSON(res, status, desensitizeIssue(data), headers);
            return sendJSON(res, status, desensitizeIssuePrivate(data), headers);
          }
          return sendJSON(res, status, desensitizeIssue(data), headers);
        }
        // user/admin 列表：一律强脱敏（管理员查全量请走 /api/admin/users）
        return sendJSON(res, status, desensitizeIssuePrivate(data), headers);
      }
      // 公开数据（订单/问答/二手等）：仅剥离 password*，可安全缓存
      const safe = desensitizeIssue(data);
      if (status === 200 && CACHE_TTL > 0) setCache(cacheKey, safe);
      return sendJSON(res, status, safe, headers);
    } catch (e) {
      return sendJSON(res, 502, { error: e.message }, headers);
    }
  }

  sendJSON(res, 404, { error: 'Not found' }, headers);
});

const PORT = process.env.PORT || 9000;
server.listen(PORT, () => console.log('hust-helper-proxy listening on ' + PORT));
