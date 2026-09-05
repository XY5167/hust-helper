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
// 2026-09 腾讯混元旧版模型下线，AI 对话/润色/审核/仲裁统一迁移至 TokenHub（OpenAI 兼容接口）
const TOKENHUB_API_KEY = process.env.TOKENHUB_API_KEY || '';
const TOKENHUB_BASE_URL = (process.env.TOKENHUB_BASE_URL || 'https://tokenhub.tencentmaas.com/v1').replace(/\/$/, '');
const TOKENHUB_MODEL = process.env.TOKENHUB_MODEL || 'hy3';
const AI_RATE_LIMIT = parseInt(process.env.AI_RATE_LIMIT || '20', 10); // 每 IP 每分钟最多 20 次 AI 调用
const OCR_RATE_LIMIT = parseInt(process.env.OCR_RATE_LIMIT || '10', 10); // 每 IP 每分钟最多 10 次 OCR（额度保护）
const VERSION = '1.40.0';

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

// ---- 通用大模型（OpenAI 兼容接口：腾讯 TokenHub / 智谱 GLM / 其他）----
// 支持多供应商切换：仅需在 SCF 环境变量配 TOKENHUB_API_KEY / TOKENHUB_MODEL / TOKENHUB_BASE_URL。
// 例：智谱 GLM-4.7-Flash（免费）= https://open.bigmodel.cn/api/paas/v4 + glm-4.7-flash
async function callHunyuan(messages) {
  if (!TOKENHUB_API_KEY) throw new Error('TOKENHUB_NOT_CONFIGURED');
  const buildBody = () => JSON.stringify({
    model: TOKENHUB_MODEL,
    messages: messages.map(m => ({
      role: (m.role === 'system') ? 'system'
        : (m.role === 'assistant' || m.role === 'bot') ? 'assistant'
        : 'user',
      content: String(m.content || '')
    })),
    temperature: 0.7
  });
  const sleep = ms => new Promise(res => setTimeout(res, ms));
  // 免费模型（如 GLM-4.7-Flash）偶发 429 限流：重试 1 次，退避 1s
  // 注意：单请求总预算必须 < SCF 平台执行超时（约30s）：12s×2 + 1s ≈ 25s
  const MAX_ATTEMPTS = 2;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), 12000);
    try {
      const r = await fetch(TOKENHUB_BASE_URL + '/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer ' + TOKENHUB_API_KEY,
          'Content-Type': 'application/json'
        },
        body: buildBody(),
        signal: ctl.signal
      });
      const json = await r.json().catch(() => ({}));
      if (!r.ok) {
        // 429 / 1305 = 限流，退避后重试
        if (r.status === 429 || (json.error && (json.error.code === '1305' || String(json.error.code || '').indexOf('429') >= 0))) {
          if (attempt < MAX_ATTEMPTS) { await sleep(1000); continue; }
        }
        throw new Error((json.error && json.error.message) || 'LLM_ERROR');
      }
      if (!json.choices || !json.choices[0] || !json.choices[0].message) throw new Error('LLM_EMPTY');
      const msg = json.choices[0].message;
      // 部分思考模型 content 为空时，退回 reasoning_content（首次请求一般不会发生）
      if (msg.content && String(msg.content).trim()) return String(msg.content);
      if (msg.reasoning_content && String(msg.reasoning_content).trim()) return String(msg.reasoning_content);
      throw new Error('LLM_EMPTY');
    } finally { clearTimeout(timer); }
  }
  throw new Error('LLM_RETRY_EXHAUSTED');
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

// ---- 失物招领 AI 智能匹配 ----
// v1.40.0：物品归一化字典（20 类高频校园失物）
const LOST_ITEM_DICT = [
  { key:'card',      label:'校园卡/学生证', kws:['校园卡','学生证','一卡通','饭卡','身份证'] },
  { key:'umbrella',  label:'雨伞',         kws:['雨伞','伞','折叠伞'] },
  { key:'book',      label:'书本',         kws:['书','教材','课本','习题册','高数','线代','马原'] },
  { key:'notebook',  label:'笔记本电脑',   kws:['笔记本','电脑','macbook','thinkpad','联想','戴尔','华为','小米笔记本'] },
  { key:'phone',     label:'手机',         kws:['手机','iphone','华为','小米','oppo','vivo','荣耀','安卓'] },
  { key:'key',       label:'钥匙',         kws:['钥匙','钥匙扣','车钥匙','宿舍钥匙'] },
  { key:'bottle',    label:'水杯/水瓶',    kws:['水杯','水瓶','保温杯','杯子'] },
  { key:'glasses',   label:'眼镜',         kws:['眼镜','墨镜','近视镜','太阳镜','镜框'] },
  { key:'wallet',    label:'钱包',         kws:['钱包','卡包','皮夹'] },
  { key:'headphone', label:'耳机',         kws:['耳机','蓝牙耳机','airpods','有线耳机','头戴'] },
  { key:'charger',   label:'充电器/充电宝',kws:['充电器','充电宝','数据线','充电头','移动电源'] },
  { key:'coat',      label:'外套/衣物',    kws:['外套','衣服','上衣','夹克','卫衣','羽绒服','毛衣'] },
  { key:'pen',       label:'文具',         kws:['笔','文具','钢笔','中性笔','签字笔','文具盒'] },
  { key:'calculator',label:'计算器',       kws:['计算器','卡西欧','计算器科学'] },
  { key:'card_other',label:'其他卡类',     kws:['银行卡','公交卡','会员卡','健身卡','水卡'] },
  { key:'usb',       label:'U盘/硬盘',     kws:['u盘','优盘','移动硬盘','硬盘'] },
  { key:'watch',     label:'手表',         kws:['手表','腕表','电子表','智能手环','手环'] },
  { key:'bag',       label:'书包/背包',    kws:['书包','背包','双肩包','斜挎包','手提包','电脑包'] },
  { key:'bicycle',   label:'自行车',       kws:['自行车','单车','山地车','小电驴','电动车'] },
  { key:'other',     label:'其他',         kws:[] }
];

// 抽取物品归一化 key
function classifyLostItem(text) {
  if (!text) return 'other';
  const s = String(text);
  for (const cat of LOST_ITEM_DICT) {
    for (const kw of cat.kws) { if (s.includes(kw)) return cat.key; }
  }
  return 'other';
}

// 校区归一化（前后端约定：main/tongji/wangan/junshan/empty）
function normalizeCampus(c) {
  const s = String(c || '').trim().toLowerCase();
  if (['main','tongji','wangan','junshan'].includes(s)) return s;
  return 'main';
}

// 字符串相似度（Jaccard，按字）
function jaccardStr(a, b) {
  if (!a || !b) return 0;
  const sa = new Set(String(a).replace(/\s+/g,'').split(''));
  const sb = new Set(String(b).replace(/\s+/g,'').split(''));
  let inter = 0;
  for (const x of sa) if (sb.has(x)) inter++;
  const uni = sa.size + sb.size - inter;
  return uni > 0 ? inter / uni : 0;
}

// 最长公共子串（≥5 字符视作相近）
function longestCommonSubstr(a, b, minLen) {
  if (!a || !b) return 0;
  const sa = String(a), sb = String(b);
  const m = sa.length, n = sb.length;
  if (m === 0 || n === 0) return 0;
  let best = 0;
  const dp = Array.from({length:m+1}, () => new Array(n+1).fill(0));
  for (let i=1;i<=m;i++) for (let j=1;j<=n;j++) {
    if (sa[i-1] === sb[j-1]) { dp[i][j] = dp[i-1][j-1] + 1; if (dp[i][j] > best) best = dp[i][j]; }
    else dp[i][j] = 0;
  }
  return best;
}

// 计算两个失物帖的匹配分数（4 维度满分 100）
//   campus 35 + item 30 + time 20 + location 15
function scoreLostMatch(self, other) {
  const reasons = [];
  let score = 0;

  // 校区 35
  const cSelf = normalizeCampus(self.campus);
  const cOther = normalizeCampus(other.campus);
  if (cSelf === cOther) { score += 35; reasons.push('📍 同校区'); }

  // 物品 30（归一化字典相同 +30；关键词重叠度最高 +15）
  const itemSelf = classifyLostItem((self.item || '') + ' ' + (self.title || '') + ' ' + (self.content || ''));
  const itemOther = classifyLostItem((other.item || '') + ' ' + (other.title || '') + ' ' + (other.content || ''));
  if (itemSelf === itemOther && itemSelf !== 'other') { score += 30; reasons.push('🎒 物品类型相似'); }
  else if (itemSelf !== 'other' && itemOther !== 'other') { score += 15; }

  // 时间 20（丢帖早于捡帖且 ≤30d +20；±6h 强互补额外 +10）
  const t1 = Date.parse(self.time_bucket || '') || 0;
  const t2 = Date.parse(other.time_bucket || '') || 0;
  if (t1 && t2) {
    const diffH = Math.abs(t1 - t2) / 3600000;
    const days = diffH / 24;
    if (days <= 30) { score += 20; if (diffH <= 6) { score += 10; reasons.push('⏰ 时间互补'); } }
  }

  // 地点 15（最长公共子串≥5 或 Jaccard>0.5）
  const locSelf = String(self.location || '');
  const locOther = String(other.location || '');
  const lcs = longestCommonSubstr(locSelf, locOther, 5);
  const jc = jaccardStr(locSelf, locOther);
  if (lcs >= 5 || jc > 0.5) { score += 15; reasons.push('🧭 地点相近'); }

  return { score, reasons };
}

// 从已发布 Issues 列表中找反向失物帖（lost_type 不同），算 Top3
function matchLostItems(extract, lostType, recentIssues) {
  try {
    const myType = String(lostType || 'lost'); // lost | found
    const reverseType = myType === 'lost' ? 'found' : 'lost';
    const cSelf = normalizeCampus(extract.campus);
    const scored = [];
    for (const it of (recentIssues || [])) {
      if (!it) continue;
      if (String(it.cat || '') !== 'lost') continue;
      const itsType = String(it.lost_type || (myType === 'lost' ? 'found' : 'lost'));
      if (itsType !== reverseType) continue;
      // 校区过滤：同校区优先（跨校区暂不算）
      const cOther = normalizeCampus(it.campus);
      if (cSelf !== cOther) continue;
      const r = scoreLostMatch({
        item: extract.item, location: extract.location, time_bucket: extract.time_bucket, campus: cSelf,
        title: extract.title, content: extract.content
      }, {
        item: it.ai_extract && it.ai_extract.item || '', location: it.ai_extract && it.ai_extract.location || '',
        time_bucket: it.ai_extract && it.ai_extract.time_bucket || '', campus: cOther,
        title: it.title || '', content: it.body_text || ''
      });
      if (r.score >= 50) scored.push({ id: it.number, score: r.score, reasons: r.reasons });
    }
    scored.sort((a, b) => b.score - a.score);
    return scored.slice(0, 3);
  } catch (e) {
    return [];
  }
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

        // ---- AI 内容安全审核：发帖/发布前预检，识别广告引流/站外交易/诈骗/违禁品/人身攻击 ----
        if (method === 'POST' && path === '/api/ai/moderate') {
          if (rateLimited(clientIp(req), AI_RATE_LIMIT)) return sendJSON(res, 429, { error: 'RATE_LIMITED' }, headers);
          const title = (ghBody && ghBody.title || '').toString().trim();
          const content = (ghBody && ghBody.content || '').toString().trim();
          const kind = (ghBody && ghBody.type || 'post').toString().trim();
          if (!content && !title) return sendJSON(res, 400, { error: 'INVALID_INPUT' }, headers);
          const sysPrompt = '你是华中科技大学(HUST)校园互助平台的发帖内容安全审核助手，负责在内容发布前做第一轮风险识别，维护校园互助环境。' +
            '需要识别的违规类型：' +
            '1) 广告引流：引导到淘宝/拼多多/抖音/闲鱼/校外商家等平台，或为他人店铺拉客；' +
            '2) 站外私下交易：诱导用微信/QQ/支付宝/银行卡等脱离平台担保进行私下转账、先款后货；' +
            '3) 诈骗话术：刷单返利、垫付、押金、中奖、裸聊、色情、赌博、非法贷款、培训贷、医美贷、套现、洗钱；' +
            '4) 违禁品/违规服务：烟酒、管制刀具、药品、办证/假证/刻章、学历造假、代写论文/代考、成绩修改/改分、代注册、走私、虚拟币交易；' +
            '5) 人身攻击/仇恨言论/侮辱谩骂。' +
            '判断规则：' +
            'A) 明显且确凿的违规（如直接售假证、明码标价诈骗、违禁品交易）→ verdict="block"（置信度 85-99），前端将直接拦截；' +
            'B) 疑似但不确定（如模糊的引流话术、疑似站外交易引导、风险偏高但未明确违规）→ verdict="warn"（置信度 60-84），前端将提醒用户确认；' +
            'C) 正常互助内容（代取快递、二手转让、问路、课程求助等）→ verdict="safe"（置信度 85-99）。' +
            '必须只返回一个 JSON 对象（不要 markdown 代码块、不要任何解释文字）：' +
            '{"verdict":"safe|warn|block","confidence":0-100的整数,"reason":"一句话理由（20字内）","suggestion":"给发布者的改写建议（如：请勿引导站外私下交易，使用平台担保）"}。' +
            'confidence 表示把握程度：只有事实非常清楚才给 85 以上；把握不足一律给 80 以下并选 warn 或 safe。';
          try {
            const text = '标题：' + (title || '（无）') + '\n内容：' + (content || '（无）') + (kind ? '\n类型：' + kind : '');
            const c = await callHunyuan([
              { role: 'system', content: sysPrompt },
              { role: 'user', content: text }
            ]);
            const parsed = extractJson(c);
            if (!parsed || !parsed.verdict || !['safe', 'warn', 'block'].includes(parsed.verdict)) {
              return sendJSON(res, 200, { ok: true, verdict: 'safe', confidence: 50, reason: 'AI 未能判定，按安全放行', suggestion: '' });
            }
            const conf = Math.max(0, Math.min(100, parseInt(parsed.confidence, 10) || 50));
            return sendJSON(res, 200, {
              ok: true,
              verdict: parsed.verdict,
              confidence: conf,
              reason: (parsed.reason || '').toString().slice(0, 80),
              suggestion: (parsed.suggestion || '').toString().slice(0, 120)
            });
          } catch (e) { return sendJSON(res, 502, { error: e.message }, headers); }
        }

        // v1.40.0: 失物招领 AI 抽取 + 匹配（GLM 抽结构化 + 4 维度规则打分）
        if (method === 'POST' && path === '/api/ai/extract-lost') {
          if (rateLimited(clientIp(req), AI_RATE_LIMIT)) return sendJSON(res, 429, { error: 'RATE_LIMITED' }, headers);
          const { title, content, campus, lost_type, recent_issues } = ghBody || {};
          const sysPrompt = '你是校园失物招领信息抽取助手。从用户发布的中文文本中抽取 4 个字段，返回严格 JSON：' +
            '{"item":"物品归一化类别（短词，如：校园卡/雨伞/手机/书本/钥匙/钱包 等）","location":"地点短语（如：东九楼 3 楼、西一食堂二楼、韵苑路口）","time_bucket":"事件时间（YYYY-MM-DD HH，缺失则填 unknown）","campus":"main/tongji/wangan/junshan/empty（华科主校区/同济/网安/军山/空）"}' +
            '。要求：只输出 JSON，不要任何解释、不要 markdown 代码块、不要多余文字。';
          let aiExtract = null;
          try {
            const text = '标题：' + (title || '（无）') + '\n内容：' + (content || '（无）');
            const c = await callHunyuan([
              { role: 'system', content: sysPrompt },
              { role: 'user', content: text }
            ]);
            const parsed = extractJson(c);
            if (parsed && parsed.item) aiExtract = {
              item: String(parsed.item || '').slice(0, 30),
              location: String(parsed.location || '').slice(0, 60),
              time_bucket: /^\d{4}-\d{2}-\d{2} \d{2}$/.test(parsed.time_bucket || '') ? parsed.time_bucket : 'unknown',
              campus: normalizeCampus(parsed.campus || campus || '')
            };
          } catch (e) { /* fail-open：LLM 失败时 aiExtract=null，降级到正则 */ }

          // LLM 失败/无效时降级到正则抽取
          if (!aiExtract) {
            const allTxt = String(title || '') + ' ' + String(content || '');
            aiExtract = {
              item: LOST_ITEM_DICT.find(cat => cat.kws.some(kw => allTxt.includes(kw)))?.label || '其他',
              location: 'unknown',
              time_bucket: 'unknown',
              campus: normalizeCampus(campus || '')
            };
          }

          // 算匹配（传 recent_issues 数组）
          let matches = [];
          try {
            const norm = (Array.isArray(recent_issues) ? recent_issues : []).map(it => ({
              number: it.number, cat: it.cat, lost_type: it.lost_type,
              ai_extract: it.ai_extract, title: it.title, body_text: it.body_text, campus: it.campus
            }));
            matches = matchLostItems(aiExtract, lost_type, norm);
          } catch (e) { matches = []; }

          return sendJSON(res, 200, { ok: true, ai_extract: aiExtract, matches });
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
