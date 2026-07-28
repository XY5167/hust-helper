import express from 'express';
import nodemailer from 'nodemailer';
import cors from 'cors';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// 静态文件目录：Railway 上在根目录，本地开发在 ../hust-hub/static
const STATIC_DIR = process.env.STATIC_DIR || path.resolve(__dirname);

const app = express();
app.use(cors());
app.use(express.json());

// ============ 配置 ============
// QQ邮箱SMTP配置（通过环境变量或直接填写）
const SMTP_HOST = process.env.SMTP_HOST || 'smtp.qq.com';
const SMTP_PORT = parseInt(process.env.SMTP_PORT || '465');
const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASS = process.env.SMTP_PASS || ''; // QQ邮箱授权码

// ============ 验证码存储 ============
// Map<email, { code, expires, attempts }>
const codeStore = new Map();
const CODE_EXPIRE = 5 * 60 * 1000; // 5分钟过期
const MAX_ATTEMPTS = 5; // 最多尝试次数

// 定期清理过期验证码（每30秒）
setInterval(() => {
  const now = Date.now();
  for (const [key, val] of codeStore) {
    if (now > val.expires) codeStore.delete(key);
  }
}, 30000);

// ============ 邮件模板 ============
function buildEmailHTML(code) {
  return `
<div style="max-width:480px;margin:0 auto;padding:30px;font-family:Arial,sans-serif;background:#f8fafc;border-radius:12px">
  <div style="text-align:center;margin-bottom:24px">
    <h1 style="color:#1a73e8;margin:0;font-size:22px">HUST 校园互助</h1>
    <p style="color:#64748b;margin:4px 0 0">邮箱验证码</p>
  </div>
  <div style="background:#fff;border-radius:8px;padding:24px;text-align:center">
    <p style="color:#1e293b;margin:0 0 8px">你的验证码是：</p>
    <div style="font-size:32px;font-weight:800;letter-spacing:6px;color:#1a73e8;padding:12px 0;background:#e8f0fe;border-radius:8px;margin:12px 0">${code}</div>
    <p style="color:#94a3b8;font-size:13px;margin:8px 0 0">验证码 5 分钟内有效，请勿泄露给他人。</p>
    <p style="color:#94a3b8;font-size:13px">如非本人操作，请忽略此邮件。</p>
  </div>
</div>`;
}

// ============ 创建邮件发送器 ============
let transporter = null;

function getTransporter() {
  if (!SMTP_USER || !SMTP_PASS) return null;
  if (transporter) return transporter;
  transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: true,
    auth: { user: SMTP_USER, pass: SMTP_PASS }
  });
  return transporter;
}

// ============ API ============

// 健康检查
app.get('/api/health', (req, res) => {
  const configured = !!(SMTP_USER && SMTP_PASS);
  res.json({ ok: true, configured, smtp_user: SMTP_USER ? SMTP_USER.substring(0,3) + '***' : '(not set)' });
});

// 发送验证码
app.post('/api/send-code', async (req, res) => {
  const { email } = req.body;
  
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: '请输入有效的邮箱地址' });
  }

  const tp = getTransporter();
  if (!tp) {
    return res.status(500).json({ error: '邮件服务未配置，请联系管理员设置SMTP' });
  }

  // 检查是否过于频繁（60秒内只能发一次）
  const existing = codeStore.get(email);
  if (existing && (Date.now() - existing.createdAt < 60000)) {
    return res.status(429).json({ error: '发送过于频繁，请60秒后再试', retryAfter: Math.ceil((60000 - (Date.now() - existing.createdAt)) / 1000) });
  }

  // 生成6位数字验证码
  const code = String(Math.floor(100000 + Math.random() * 900000));
  
  try {
    await tp.sendMail({
      from: `"HUST校园互助" <${SMTP_USER}>`,
      to: email,
      subject: '【HUST校园互助】邮箱验证码 ' + code,
      html: buildEmailHTML(code)
    });

    codeStore.set(email, {
      code,
      expires: Date.now() + CODE_EXPIRE,
      attempts: 0,
      createdAt: Date.now()
    });

    console.log(`📧 验证码已发送至 ${email}: ${code}`);
    res.json({ ok: true, message: '验证码已发送，请查收邮件' });
  } catch (err) {
    console.error('发送邮件失败:', err.message);
    res.status(500).json({ error: '邮件发送失败: ' + err.message });
  }
});

// 校验验证码
app.post('/api/verify-code', (req, res) => {
  const { email, code } = req.body;

  if (!email || !code) {
    return res.status(400).json({ error: '参数不完整' });
  }

  const entry = codeStore.get(email);
  if (!entry) {
    return res.status(400).json({ error: '验证码不存在或已过期，请重新发送' });
  }

  if (Date.now() > entry.expires) {
    codeStore.delete(email);
    return res.status(400).json({ error: '验证码已过期，请重新发送' });
  }

  entry.attempts++;
  if (entry.attempts > MAX_ATTEMPTS) {
    codeStore.delete(email);
    return res.status(400).json({ error: '尝试次数过多，请重新发送验证码' });
  }

  if (entry.code !== String(code).trim()) {
    return res.status(400).json({ error: `验证码错误，还剩 ${MAX_ATTEMPTS - entry.attempts} 次机会` });
  }

  // 验证成功，删除验证码
  codeStore.delete(email);
  res.json({ ok: true, message: '验证成功' });
});

// ============ 启动 ============
const PORT = process.env.PORT || 3456;

// 静态文件服务（前端页面）
app.use(express.static(STATIC_DIR));
// SPA fallback
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) return; // API 路由已在上面处理，这里只是兜底
  res.sendFile(path.join(STATIC_DIR, 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`📮 HUST 邮件服务已启动: http://0.0.0.0:${PORT}`);
  console.log(`   健康检查: http://localhost:${PORT}/api/health`);
  if (!SMTP_USER || !SMTP_PASS) {
    console.warn('⚠️  未配置 SMTP，请设置 SMTP_USER 和 SMTP_PASS 环境变量');
    console.warn('   示例: SMTP_USER=your@qq.com SMTP_PASS=授权码 node server.js');
  }
});
