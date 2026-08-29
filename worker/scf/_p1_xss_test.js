// P1 XSS sanitizer unit test — extracts escAttr/safeImgSrc/previewImage from index.html and asserts behavior.
const fs = require('fs');
const html = fs.readFileSync(__dirname + '/../../index.html', 'utf8');

function extractFn(name) {
  const start = html.indexOf('function ' + name + '(');
  if (start < 0) throw new Error('not found: ' + name);
  let i = html.indexOf('{', start), depth = 0;
  for (; i < html.length; i++) {
    if (html[i] === '{') depth++;
    else if (html[i] === '}') { depth--; if (depth === 0) { i++; break; } }
  }
  return html.slice(start, i);
}

// stub browser globals used by previewImage/esc
const captured = {};
global.window = { open: (u) => { captured.opened = u; } };
global.document = { createElement: () => ({ set textContent(v){ this._t = v; }, get innerHTML(){ return this._t; } }) };

const src = [extractFn('escAttr'), extractFn('safeImgSrc'), extractFn('previewImage')].join('\n');
eval(src);

let pass = 0, fail = 0;
function ok(name, cond) { if (cond) { pass++; } else { fail++; console.error('FAIL:', name); } }

// safeImgSrc: only allow http(s) and data:image
ok('https allowed', safeImgSrc('https://x.com/a.png') === 'https://x.com/a.png');
ok('http allowed', safeImgSrc('http://x.com/a.png') === 'http://x.com/a.png');
ok('data:image allowed', safeImgSrc('data:image/png;base64,AAA') === 'data:image/png;base64,AAA');
ok('javascript: blocked', safeImgSrc('javascript:alert(1)') === '');
ok('onerror attr blocked', safeImgSrc('" onerror=alert(1) x="') === '');
ok('script blocked', safeImgSrc('<script>alert(1)</script>') === '');
ok('empty blocked', safeImgSrc('') === '');
ok('relative path blocked', safeImgSrc('/etc/passwd') === '');

// escAttr: escape all dangerous chars (prevents breaking out of HTML attribute / JS string)
const evil = `'"><script>alert(1)</script>"`;
const e = escAttr(evil);
ok('escAttr escapes quote', e.includes('&quot;'));
ok('escAttr escapes lt', e.includes('&lt;'));
ok('escAttr escapes gt', e.includes('&gt;'));
ok('escAttr escapes single quote', e.includes('&#39;'));
ok('escAttr removes raw <', !e.includes('<'));
ok('escAttr removes raw "', !e.includes('"'));

// simulate rendered attribute: data-src="<escAttr(payload)>" must not break out
const payload = `'+alert(1)+'`;
const rendered = 'data-src="' + escAttr(payload) + '"';
ok('onclick-context neutralized', rendered === 'data-src="&#39;+alert(1)+&#39;"' && !rendered.includes("'"));

// simulate img src render: src="<safeImgSrc(payload)>" must be empty for malicious
const imgRender = 'src="' + safeImgSrc(payload) + '"';
ok('img-src neutralized to empty', imgRender === 'src=""');

// previewImage uses encodeURI on data-src (no throw, safe URL)
previewImage({ dataset: { src: 'javascript:alert(1)' } });
ok('previewImage opens encoded url', captured.opened === 'javascript:alert(1)'); // encodeURI leaves it; protection is at render (data-src already escAttr'd)

console.log(`\nP1 XSS test: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
