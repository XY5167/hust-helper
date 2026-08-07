// ============================================================
// HUST Hub API Proxy - Vercel Serverless Function
// 所有 /api/* 请求转发到 GitHub API，token 从环境变量读取
// ============================================================

const GITHUB_API = 'https://api.github.com';

const memCache = new Map();
const CACHE_TTL = 5000;

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

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Max-Age', '86400');

  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  const TOKEN = process.env.GITHUB_TOKEN;
  if (!TOKEN) {
    return res.status(500).json({ error: 'Server misconfigured: GITHUB_TOKEN not set' });
  }

  if (req.url === '/api/health' || req.url === '/api/health/') {
    return res.status(200).json({ status: 'ok', ts: Date.now() });
  }

  const path = req.url.replace(/^\/api/, '');
  const ghUrl = GITHUB_API + path;

  const opts = {
    method: req.method,
    headers: {
      'Authorization': 'Bearer ' + TOKEN,
      'Accept': 'application/vnd.github+json',
      'User-Agent': 'hust-hub-proxy',
    },
  };

  if (req.body && req.method !== 'GET') {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
  }

  try {
    if (req.method === 'GET') {
      const cacheKey = path;
      const cached = getCache(cacheKey);
      if (cached) {
        res.setHeader('X-Cache', 'HIT');
        return res.status(200).json(cached);
      }

      const ghRes = await fetch(ghUrl, opts);
      const data = ghRes.status === 204 ? null : await ghRes.json().catch(() => null);

      if (ghRes.status === 200 && data) {
        setCache(cacheKey, data);
      }

      res.setHeader('X-Cache', 'MISS');
      return res.status(ghRes.status).json(data);
    }

    const ghRes = await fetch(ghUrl, opts);
    const data = ghRes.status === 204 ? null : await ghRes.json().catch(() => null);

    if (ghRes.status >= 200 && ghRes.status < 300) {
      clearCache('');
    }

    return res.status(ghRes.status).json(data);

  } catch (e) {
    return res.status(502).json({ error: 'GitHub API request failed: ' + e.message });
  }
}
