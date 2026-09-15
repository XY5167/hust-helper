// v1.55.0 语义搜索：前后端一致性 + 量化往返 端到端测试
// 关键点：从两个源文件里「抽取真实函数体」再执行，避免测的代码和跑的代码不是同一份。
const fs = require('fs');

function extract(src, header) {
  const i = src.indexOf(header);
  if (i < 0) throw new Error('未找到函数: ' + header);
  let j = src.indexOf('{', i + header.length - 1);
  let depth = 0, k = j;
  for (; k < src.length; k++) {
    if (src[k] === '{') depth++;
    else if (src[k] === '}') { depth--; if (depth === 0) break; }
  }
  return src.slice(i, k + 1);
}

const fe = fs.readFileSync('index.html', 'utf8');
const be = fs.readFileSync('worker/scf/index.js', 'utf8');

const code = [
  extract(fe, 'function genPostVectorText(o)'),
  extract(be, 'function postVectorText(o)'),
  extract(be, 'function quantizeVec(vec)'),
  extract(fe, 'function decodeVec(b64)'),
  extract(fe, 'function cosVec(a, b)')
].join('\n');
eval(code);

let pass = 0, fail = 0;
function ok(cond, msg) { if (cond) { pass++; } else { fail++; console.log('  ❌ ' + msg); } }

// ---------- 1. 前后端「向量化文本」必须逐字一致 ----------
console.log('\n[1] 前后端 postVectorText / genPostVectorText 一致性');
const samples = [
  { name: '完整订单', o: { title: '帮带饭到韵苑', description: '在百景园带个饭', search_keywords: ['带饭', '外卖'], category: 'food', ai_book_meta: { subject: '高数', book_title: '微积分', grade: '大一' } } },
  { name: '无 search_keywords', o: { title: '代取快递', description: '菜鸟驿站', category: 'express' } },
  { name: 'search_keywords 为字符串', o: { title: 'A', description: 'B', search_keywords: '吃饭 带饭' } },
  { name: '无 description', o: { title: '只剩标题', category: 'other' } },
  { name: '含多余空白/换行', o: { title: '求  组队', description: '一起\n\n打车  去机场', search_keywords: ['拼车'] } },
  { name: 'ai_book_meta 字段残缺', o: { title: '出教材', description: '九成新', ai_book_meta: { subject: '', book_title: '线性代数', grade: null } } },
  { name: '空对象', o: {} }
];
for (const s of samples) {
  const a = genPostVectorText(s.o), b = postVectorText(s.o);
  ok(a === b, s.name + ' 不一致\n     前端=' + JSON.stringify(a) + '\n     后端=' + JSON.stringify(b));
  if (a === b) console.log('  ✅ ' + s.name + ' → ' + JSON.stringify(a).slice(0, 70));
}
ok(genPostVectorText({ title: 'x'.repeat(900) }).length === 600, '超长文本应截断到 600 字');

// ---------- 2. 量化往返精度 ----------
console.log('\n[2] quantizeVec → decodeVec 往返');
function rndVec(n, seed) {
  let s = seed;
  const r = () => { s = (s * 1103515245 + 12345) & 0x7fffffff; return s / 0x7fffffff - 0.5; };
  const v = [];
  for (let i = 0; i < n; i++) v.push(r());
  return v;
}
let minCos = 1, maxErr = 0;
for (let t = 0; t < 200; t++) {
  const v = rndVec(256, t + 1);
  const back = decodeVec(quantizeVec(v));
  ok(back && back.length === 256, '第' + t + '组 反量化维度错');
  const c = cosVec(v, back);
  if (c < minCos) minCos = c;
  maxErr = Math.max(maxErr, Math.abs(c - 1));
}
console.log('  ✅ 200 组 256 维往返：最低余弦 ' + minCos.toFixed(5) + '，最大误差 ' + maxErr.toFixed(5));
ok(minCos > 0.999, '往返余弦过低: ' + minCos);

const q = quantizeVec(rndVec(256, 7));
ok(q.length === 344, '256 维 base64 应为 344 字符，实际 ' + q.length);
console.log('  ✅ 单帖向量体积 ' + q.length + ' 字符');

// ---------- 3. 量化后排序是否与原向量排序一致 ----------
// 注意：真实的 embedding 向量有强语义结构（同主题余弦 0.7+、异主题 0.4 上下），
// 梯度远大于量化误差；而「均匀随机向量」彼此余弦都挤在 0 附近，用它会得出
// 虚高的翻转率、并不能代表真实数据。故这里用「语义簇」模型（中心 + 噪声）模拟。
console.log('\n[3] 量化对排序的影响（语义簇模型）');
function unit(v) { const n = Math.sqrt(v.reduce((s, x) => s + x * x, 0)) || 1; return v.map(x => x / n); }
const noiseOf = (seed, amp) => rndVec(256, seed).map(x => x * amp);

let top1Hit = 0, top1Total = 0, sameCluster = 0, clusterTotal = 0;
let keptBig = 0, bigTotal = 0, flippedTie = 0, tieTotal = 0, pairErr = 0, missGap = 0;
for (let t = 0; t < 60; t++) {
  // 3 个语义中心（模拟 3 类帖子：跑腿/二手/问答）
  const centers = [unit(rndVec(256, 900 + t * 9)), unit(rndVec(256, 901 + t * 9)), unit(rndVec(256, 902 + t * 9))];
  const pool = [], truth = [];
  for (let i = 0; i < 20; i++) {
    const c = centers[i % 3];
    const nz = noiseOf(7000 + t * 20 + i, 0.30);
    pool.push(c.map((x, k) => x + nz[k]));
    truth.push(i % 3);
  }
  const qv = centers[0].slice();                       // 查询向量 = 第 0 类中心
  const qqv = decodeVec(quantizeVec(qv));
  const rawS = pool.map((p, i) => ({ i, c: cosVec(qv, p) })).sort((a, b) => b.c - a.c);
  const quaS = pool.map((p, i) => ({ i, c: cosVec(qqv, decodeVec(quantizeVec(p))) })).sort((a, b) => b.c - a.c);

  // 指标 A：top-1 是否一致；若不一致，记录原始第 1、2 名的分数差（用于判断是否本就是平局）
  top1Total++;
  if (rawS[0].i === quaS[0].i) top1Hit++;
  else { const g = rawS[0].c - rawS[1].c; if (g > missGap) missGap = g; }
  // 指标 B：量化后 top-5 是否都来自查询所属的语义簇（用户真正能感知的正确性）
  clusterTotal++; if (quaS.slice(0, 5).every(x => truth[x.i] === 0)) sameCluster++;
  // 指标 C：原始分数差距明显的相邻对，量化后是否保持顺序（差距 < 0.002 视为平局，不计入）
  for (let i = 0; i < rawS.length - 1; i++) {
    const gap = rawS[i].c - rawS[i + 1].c;
    const posA = quaS.findIndex(x => x.i === rawS[i].i);
    const posB = quaS.findIndex(x => x.i === rawS[i + 1].i);
    if (gap >= 0.02) { bigTotal++; if (posA < posB) keptBig++; }
    else if (gap < 0.002) { tieTotal++; if (posA > posB) flippedTie++; }
  }
  // 逐对相似度误差
  for (let i = 0; i < 5; i++) pairErr = Math.max(pairErr, Math.abs(cosVec(qv, pool[i]) - cosVec(qqv, decodeVec(quantizeVec(pool[i])))));
}
console.log('  ✅ top-1 一致：' + top1Hit + '/' + top1Total
  + '；top-5 同簇：' + sameCluster + '/' + clusterTotal
  + '；明显差距（≥0.02）的相邻对保持顺序：' + keptBig + '/' + bigTotal);
console.log('  ℹ️ 平局对（差距<0.002）有 ' + flippedTie + '/' + tieTotal + ' 被换位 —— 属预期：这类名次对用户无意义；'
  + '逐对相似度最大误差 ' + pairErr.toFixed(5));
ok(top1Hit / top1Total > 0.9, 'top-1 一致率过低: ' + top1Hit + '/' + top1Total);
// top-1 发生变化的那些组，原始前两名的分数差必须小到「本就分不出来」，否则才是真错误
console.log('  ℹ️ top-1 未保持一致的组，其原始第 1/2 名分数差最大仅 ' + missGap.toFixed(4)
  + '（< 量化误差 ' + pairErr.toFixed(4) + ' → 本就是平局，谁在前都合理）');
ok(missGap <= pairErr + 1e-3, 'top-1 翻转发生在分数差异明显的组: gap=' + missGap);
ok(sameCluster / clusterTotal > 0.98, 'top-5 同簇率过低: ' + sameCluster + '/' + clusterTotal);
ok(keptBig === bigTotal, '明显差距的排序被量化打乱: ' + keptBig + '/' + bigTotal);
// int8 量化的相似度误差应远小于我设的语义计分步长（SEM_WEIGHT）
const scoreJitter = pairErr * 80;
ok(pairErr < 0.01, '相关性打分误差过大: ' + pairErr);
console.log('  ℹ️ 该误差折算到搜索分数是 ±' + scoreJitter.toFixed(2) + ' 分（SEM_WEIGHT=80），'
  + '而一次关键词命中 = 6 分 → 噪声相当于其 ' + (scoreJitter / 6 * 100).toFixed(0) + '%');

// 对照：真实语义间距应远大于量化误差，这是「量化不影响排序」的根本原因
const cA2 = unit(rndVec(256, 42)), cB2 = unit(rndVec(256, 43));
const sameTopic = cosVec(cA2, cA2.map((x, k) => x + noiseOf(77, 0.30)[k]));
const crossTopic = cosVec(cA2, cB2);
console.log('  ℹ️ 同主题余弦 ' + sameTopic.toFixed(3) + ' vs 跨主题 ' + crossTopic.toFixed(3)
  + ' → 语义间距 ' + (sameTopic - crossTopic).toFixed(3) + '，是量化误差的 '
  + Math.round((sameTopic - crossTopic) / Math.max(pairErr, 1e-6)) + ' 倍');
ok(sameTopic - crossTopic > pairErr * 10, '语义间距未显著大于量化误差');

// ---------- 4. 边界与健壮性 ----------
console.log('\n[4] 边界情况');
ok(decodeVec(null) === null, 'null 应返回 null');
ok(decodeVec('') === null, '空串应返回 null');
ok(decodeVec('!!!not-base64!!!') === null || decodeVec('!!!not-base64!!!').length >= 0, '非法 base64 不应抛异常');
ok(cosVec([1, 0], [1, 0]) === 1, '同向余弦应为 1');
ok(Math.abs(cosVec([1, 0], [0, 1])) < 1e-9, '正交余弦应为 0');
ok(cosVec([1, 0], [1, 0, 0]) === -1, '维度不一致应返回 -1');
ok(cosVec(null, [1]) === -1, 'null 输入应返回 -1');
console.log('  ✅ 边界全部安全（不抛异常、维度不符返回 -1）');

// ---------- 5. 语义门槛常量合理性 ----------
console.log('\n[5] 语义参数自检');
const feSrc = fs.readFileSync('index.html', 'utf8');
const mFloor = feSrc.match(/const SEM_COS_FLOOR\s*=\s*([\d.]+)/);
const mWeight = feSrc.match(/const SEM_WEIGHT\s*=\s*([\d.]+)/);
const mKeep = feSrc.match(/const SEM_KEEP\s*=\s*([\d.]+)/);
ok(mFloor && mWeight && mKeep, '三个语义常量应齐全');
if (mFloor && mWeight && mKeep) {
  const floor = +mFloor[1], weight = +mWeight[1], keep = +mKeep[1];
  ok(keep > floor, 'SEM_KEEP 应大于 SEM_COS_FLOOR（否则召回分低于计分线，白召回）');
  ok(floor > 0.3 && floor < 0.8, 'SEM_COS_FLOOR 应在合理区间');
  console.log('  ✅ FLOOR=' + floor + ' WEIGHT=' + weight + ' KEEP=' + keep
    + ' → cos=0.75 得 ' + Math.max(0, 0.75 - floor) * weight + ' 分');
}

console.log('\n' + '='.repeat(46));
console.log(fail === 0 ? '🎉 全部通过 ' + pass + '/' + (pass + fail) : '⚠️ ' + fail + ' 项失败 / 共 ' + (pass + fail));
process.exit(fail === 0 ? 0 : 1);
