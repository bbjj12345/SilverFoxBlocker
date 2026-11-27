// Worker 侧 Origin 白名单通配回归（2026-11-27）
// 用法：node tools/test-cors-origin.js
// 直接截取 worker/index.js 里真实的 allowedOrigins / originMatch / corsFor，用 vm 跑，
// 避免「测试里另写一份实现」导致线上与用例脱节。
const fs = require('fs');
const path = require('path');
const vm = require('vm');

let pass = 0, fail = 0;
function t(name, cond, extra) {
  if (cond) { pass++; console.log('PASS ' + name); }
  else { fail++; console.log('FAIL ' + name + (extra ? '  → ' + extra : '')); }
}

const src = fs.readFileSync(path.join(__dirname, '..', 'worker', 'index.js'), 'utf8');
const start = src.indexOf('var EXTENSION_IDS');
const end = src.indexOf('function leftMs');
if (start < 0 || end < 0 || end <= start) {
  console.error('无法从 worker/index.js 截取 CORS 实现（文件结构可能已变）');
  process.exit(1);
}
const frag = src.slice(start, end);

const ctx = { String: String, RegExp: RegExp, console: console, JSON: JSON };
ctx.globalThis = ctx;
vm.createContext(ctx);
vm.runInContext(frag, ctx);

const { originMatch, allowedOrigins, corsFor } = ctx;
const req = (origin) => ({ headers: { get: (k) => (String(k).toLowerCase() === 'origin' ? (origin || null) : null) } });

t('实现已被加载', typeof originMatch === 'function' && typeof corsFor === 'function');
t('默认放行任意扩展来源', ctx.ALLOW_ANY_EXTENSION === true, String(ctx.ALLOW_ANY_EXTENSION));

// ---------- 1. 精确匹配仍然成立 ----------
{
  const list = allowedOrigins({});
  t('默认列表包含商店版 ID', list.indexOf('chrome-extension://hckibmmlfmcgpelphibapghnlbcjkmih') !== -1, JSON.stringify(list));
  t('默认列表包含 chrome-extension://*', list.indexOf('chrome-extension://*') !== -1, JSON.stringify(list));
  t('精确串相等 → 命中', originMatch('https://a.b.com', 'https://a.b.com') === true);
}

// ---------- 2. 通配：任意扩展 ID ----------
{
  t('任意扩展 ID（换台电脑的新 ID）都能过', originMatch('chrome-extension://*', 'chrome-extension://abcdefghijklmnopabcdefghijklmnop') === true);
  t('老 ID 依然能过', originMatch('chrome-extension://*', 'chrome-extension://hckibmmlfmcgpelphibapghnlbcjkmih') === true);
  t('前缀必须一致：别的协议不算扩展', originMatch('chrome-extension://*', 'moz-extension://abc') === false);
  t('普通网页不能冒充扩展', originMatch('chrome-extension://*', 'https://evil.com') === false);
  t('通配不跨越 scheme 前缀', originMatch('chrome-extension://*', 'chrome-extensionx//abc') === false);
}

// ---------- 3. 通配：子域 ----------
{
  const p = 'https://*.example.com';
  t('子域命中', originMatch(p, 'https://a.example.com') === true);
  t('多级子域命中', originMatch(p, 'https://a.b.example.com') === true);
  t('裸域不命中（文档已注明需另写一条）', originMatch(p, 'https://example.com') === false);
  t('相似域不命中', originMatch(p, 'https://example.com.evil.net') === false);
  t('http 与 https 不同源', originMatch(p, 'http://a.example.com') === false);
}

// ---------- 4. 只有 `*` 是通配，其余字符按字面 ----------
{
  t('`.` 不被当正则通配', originMatch('https://a.b.com', 'https://axbxcom') === false);
  t('`+` `(` 之类不会把正则写坏', originMatch('https://a+b.example', 'https://a+b.example') === true);
  t('非法正则不会抛错，按不命中处理', originMatch('https://[a', 'https://[a') === true); // 精确相等短路，不进正则
  t('异常模式安全返回 false', originMatch('*(*', 'https://x') === false);
}

// ---------- 5. 环境变量：追加精确项与通配项 ----------
{
  const env = { ALLOWED_ORIGINS: ' https://foo.test , https://*.bar.test ' };
  const list = allowedOrigins(env);
  t('env 项被 trim 后并入', list.indexOf('https://foo.test') !== -1, JSON.stringify(list));
  t('env 通配项并入', list.indexOf('https://*.bar.test') !== -1);
  const hit = (o) => list.some((p) => originMatch(p, o));
  t('env 精确项生效', hit('https://foo.test') === true);
  t('env 通配项生效', hit('https://x.bar.test') === true);
  t('env 通配不覆盖无关站点', hit('https://bar.test.evil.com') === false);
}

// ---------- 6. corsFor：拒绝也要能读到 403 的原因 ----------
{
  const ok = corsFor(req('chrome-extension://abcdefghijklmnopabcdefghijklmnop'), {});
  t('扩展来源：放行', ok.ok === true);
  t('放行时回显具体 Origin（ACAO 不支持列表）', ok.headers['Access-Control-Allow-Origin'] === 'chrome-extension://abcdefghijklmnopabcdefghijklmnop', JSON.stringify(ok.headers));
  t('放行时带 Vary: Origin', ok.headers['Vary'] === 'Origin');

  const bad = corsFor(req('https://evil.com'), {});
  t('网页来源：拒绝', bad.ok === false);
  t('拒绝时仍回显 Origin —— 让扩展能读出 403 的 JSON 原因', bad.headers['Access-Control-Allow-Origin'] === 'https://evil.com', JSON.stringify(bad.headers));
  t('拒绝时不发任何数据相关的头', !bad.headers['Access-Control-Expose-Headers'] && !bad.headers['Access-Control-Allow-Methods'], JSON.stringify(bad.headers));

  const none = corsFor(req(''), {});
  t('无 Origin（curl/健康检查）：给数据、不给跨源许可', none.ok === true && Object.keys(none.headers).length === 0, JSON.stringify(none.headers));

  // 严格模式开关一旦关闭，扩展来源也要逐个列
  const strict = allowedOrigins({ ALLOWED_ORIGINS: '' }).filter((x) => x !== 'chrome-extension://*');
  t('去掉通配后剩下的都是精确 ID', strict.every((x) => x.indexOf('*') === -1), JSON.stringify(strict));
}

console.log('\n' + pass + ' passed, ' + fail + ' failed');
process.exit(fail ? 1 : 0);
