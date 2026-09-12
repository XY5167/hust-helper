const fs = require('fs');
const vm = require('vm');

const html = fs.readFileSync('index.html', 'utf8');
// 提取所有内联 <script>（排除带 src 的外部脚本）
const re = /<script([^>]*)>([\s\S]*?)<\/script>/gi;
let m, idx = 0, errors = 0, skipped = 0;

while ((m = re.exec(html))) {
  const attrs = m[1] || '';
  const code = m[2];
  idx++;
  if (/\bsrc\s*=/.test(attrs)) continue;                 // 外链脚本跳过
  if (/type\s*=\s*["']application\/(ld\+json|json)["']/i.test(attrs)) { skipped++; continue; } // JSON 块跳过
  if (!code.trim()) continue;
  try {
    new vm.Script(code, { filename: 'inline-' + idx + '.js' });
  } catch (e) {
    errors++;
    const line = e.stack && e.stack.match(/inline-\d+\.js:(\d+)/);
    console.log(`❌ SCRIPT #${idx} SYNTAX ERROR @附近行 ${line ? line[1] : '?'}: ${e.message}`);
    if (line) {
      const n = parseInt(line[1], 10);
      const lines = code.split('\n');
      console.log('   >>> ' + (lines[n - 1] || '').trim().slice(0, 160));
    }
  }
}

console.log(`\n共扫描 ${idx} 个 <script>，跳过 ${skipped} 个 JSON-LD 块`);
console.log(errors === 0 ? '✅ ALL_INLINE_SCRIPTS_OK — 无 JS 语法错误' : `❌ FOUND ${errors} ERROR(S)`);
process.exit(errors === 0 ? 0 : 1);
