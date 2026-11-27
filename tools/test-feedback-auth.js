// 反馈接口签名鉴权回归（2026-11-27）
// 用法：node tools/test-feedback-auth.js
// 三份真实代码互相验证，避免「测试里另写一份实现」：
//   ① worker/index.js 的 verifyFeedbackSignature（服务端）
//   ② ui/options.js 的 sfbSignHeaders（扩展端）
//   ③ ui/feedback-config.js 的 secretCodes（两端共享的密钥）
// 只要有一处改动没同步（换了算法、换了分隔符、换了密钥），这里立刻红。
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const nodeCrypto = require('crypto');
const { webcrypto } = nodeCrypto;
const enc = new TextEncoder();

let pass = 0, fail = 0;
function t(name, cond, extra) {
  if (cond) { pass++; console.log('PASS ' + name); }
  else { fail++; console.log('FAIL ' + name + (extra ? '  → ' + extra : '')); }
}

// ---------- ① 服务端 ----------
const wSrc = fs.readFileSync(path.join(__dirname, '..', 'worker', 'index.js'), 'utf8');
const wStart = wSrc.indexOf('var FEEDBACK_TS_SKEW_MS');
const wEnd = wSrc.indexOf('function leftMs');
if (wStart < 0 || wEnd < 0 || wEnd <= wStart) {
  console.error('无法从 worker/index.js 截取签名实现（文件结构可能已变）');
  process.exit(1);
}
const wCtx = { crypto: webcrypto, TextEncoder: TextEncoder, URL: URL, Number: Number,
  String: String, Date: Date, isFinite: isFinite, console: console };
wCtx.globalThis = wCtx;
vm.createContext(wCtx);
vm.runInContext(wSrc.slice(wStart, wEnd), wCtx);

const verify = wCtx.verifyFeedbackSignature;
const signString = wCtx.feedbackSignString;
const tSkew = wCtx.FEEDBACK_TS_SKEW_MS;

const TEST_SECRET = 'unit-test-secret-0123456789';
const URL_SEND = 'https://api.example.org/send';

function mkReq(url, headers) {
  const map = {};
  Object.keys(headers || {}).forEach((k) => { map[k.toLowerCase()] = String(headers[k]); });
  return { url: url, headers: { get: (k) => (map[String(k).toLowerCase()] === undefined ? null : map[String(k).toLowerCase()]) } };
}
function hmac(secret, msg) {
  return nodeCrypto.createHmac('sha256', secret).update(msg).digest('hex');
}
function signed(url, body, opts) {
  const o = opts || {};
  const secret = o.secret === undefined ? TEST_SECRET : o.secret;
  const ts = String(o.ts === undefined ? Date.now() : o.ts);
  const p = new URL(url).pathname;
  return {
    headers: { 'X-SF-Ts': ts, 'X-SF-Sig': o.sig || hmac(secret, signString(p, ts, body)) },
  };
}

t('服务端实现已被加载', typeof verify === 'function' && typeof signString === 'function');
t('时间窗口 5 分钟', tSkew === 5 * 60 * 1000, String(tSkew));
t('待签名串是「路径 \\n 时间戳 \\n 正文」', signString('/send', '123', 'B') === '/send\n123\nB', JSON.stringify(signString('/send', '123', 'B')));
t('反馈路径判定：/list 与 /health 之外都算反馈', wCtx.isFeedbackPath('/send') && wCtx.isFeedbackPath('/') && !wCtx.isFeedbackPath('/list') && !wCtx.isFeedbackPath('/health'));

(async function () {
  const body = JSON.stringify({ message: '你好', contact: '' });

  // ---------- 密钥配置 ----------
  {
    const r = await verify(mkReq(URL_SEND, {}), body, {});
    t('未配置 SECRET_DATA → 503 关闭接口', r.ok === false && r.status === 503 && r.error === 'FEEDBACK_DISABLED', JSON.stringify(r));
    const r2 = await verify(mkReq(URL_SEND, {}), body, { SECRET_DATA: 'short' });
    t('密钥过短（<16）视为未配置', r2.ok === false && r2.status === 503, JSON.stringify(r2));
  }

  // ---------- 头部缺失 / 格式 ----------
  {
    const r = await verify(mkReq(URL_SEND, {}), body, { SECRET_DATA: TEST_SECRET });
    t('缺签名头 → 401 SIGNATURE_REQUIRED', r.status === 401 && r.error === 'SIGNATURE_REQUIRED', JSON.stringify(r));
    const onlyTs = await verify(mkReq(URL_SEND, { 'X-SF-Ts': String(Date.now()) }), body, { SECRET_DATA: TEST_SECRET });
    t('只有时间戳 → 仍要求签名', onlyTs.error === 'SIGNATURE_REQUIRED', JSON.stringify(onlyTs));
    const bad = await verify(mkReq(URL_SEND, signed(URL_SEND, body, { ts: 'abc' }).headers), body, { SECRET_DATA: TEST_SECRET });
    t('时间戳不是数字 → 401 TIMESTAMP_INVALID', bad.status === 401 && bad.error === 'TIMESTAMP_INVALID', JSON.stringify(bad));
  }

  // ---------- 时间窗（防重放） ----------
  {
    const old = await verify(mkReq(URL_SEND, signed(URL_SEND, body, { ts: Date.now() - 10 * 60 * 1000 }).headers), body, { SECRET_DATA: TEST_SECRET });
    t('10 分钟前的签名 → 401 TIMESTAMP_EXPIRED', old.status === 401 && old.error === 'TIMESTAMP_EXPIRED', JSON.stringify(old));
    const future = await verify(mkReq(URL_SEND, signed(URL_SEND, body, { ts: Date.now() + 10 * 60 * 1000 }).headers), body, { SECRET_DATA: TEST_SECRET });
    t('未来 10 分钟的时间戳同样拒绝', future.error === 'TIMESTAMP_EXPIRED', JSON.stringify(future));
    const edge = await verify(mkReq(URL_SEND, signed(URL_SEND, body, { ts: Date.now() - 4 * 60 * 1000 }).headers), body, { SECRET_DATA: TEST_SECRET });
    t('4 分钟内仍然放行（不过度敏感）', edge.ok === true, JSON.stringify(edge));
  }

  // ---------- 签名本身 ----------
  {
    const ok = await verify(mkReq(URL_SEND, signed(URL_SEND, body).headers), body, { SECRET_DATA: TEST_SECRET });
    t('正确签名 → 通过', ok.ok === true, JSON.stringify(ok));
    const upper = signed(URL_SEND, body);
    upper.headers['X-SF-Sig'] = upper.headers['X-SF-Sig'].toUpperCase();
    const okUpper = await verify(mkReq(URL_SEND, upper.headers), body, { SECRET_DATA: TEST_SECRET });
    t('大写 hex 也认（比较前统一小写）', okUpper.ok === true, JSON.stringify(okUpper));
    const wrongKey = await verify(mkReq(URL_SEND, signed(URL_SEND, body, { secret: 'another-secret-0123456789' }).headers), body, { SECRET_DATA: TEST_SECRET });
    t('密钥不一致 → 401 BAD_SIGNATURE', wrongKey.status === 401 && wrongKey.error === 'BAD_SIGNATURE', JSON.stringify(wrongKey));
    const tampered = await verify(mkReq(URL_SEND, signed(URL_SEND, body).headers), body + ' ', { SECRET_DATA: TEST_SECRET });
    t('请求体被改动 → 401 BAD_SIGNATURE', tampered.error === 'BAD_SIGNATURE', JSON.stringify(tampered));
    const greedy = await verify(mkReq(URL_SEND, signed(URL_SEND, body).headers), body + '{"x":1}', { SECRET_DATA: TEST_SECRET });
    t('追加内容同样不通过', greedy.error === 'BAD_SIGNATURE', JSON.stringify(greedy));
  }

  // ---------- 路径绑定：别把别处的签名搬过来 ----------
  {
    const forList = hmac(TEST_SECRET, signString('/list', '1', body));
    const r = await verify(mkReq(URL_SEND, { 'X-SF-Ts': '1', 'X-SF-Sig': forList }), body, { SECRET_DATA: TEST_SECRET });
    t('用 /list 的签名打 /send → 拒绝（路径参与签名）', r.ok === false, JSON.stringify(r));
  }

  // ---------- ② 扩展端 + ③ 真实密钥 端到端 ----------
  // 载入真实 feedback-config.js，取它内置的 secretCodes 解出来的密钥
  const cfgCtx = { window: {}, String: String, Array: Array };
  cfgCtx.globalThis = cfgCtx;
  vm.createContext(cfgCtx);
  vm.runInContext(fs.readFileSync(path.join(__dirname, '..', 'ui', 'feedback-config.js'), 'utf8'), cfgCtx);
  const REAL_ENDPOINT = cfgCtx.window.SFB_FEEDBACK.decode(cfgCtx.window.SFB_FEEDBACK.endpointCodes);
  const REAL_SECRET = cfgCtx.window.SFB_FEEDBACK.decode(cfgCtx.window.SFB_FEEDBACK.secretCodes);
  t('feedback-config：能解出反馈端点', /^https:\/\/[^\s]+$/.test(REAL_ENDPOINT), REAL_ENDPOINT);
  t('feedback-config：能解出共享密钥', typeof REAL_SECRET === 'string' && REAL_SECRET.length >= 16, REAL_SECRET ? REAL_SECRET.length + ' 字符' : '(空)');
  t('feedback-config：密钥不含空白/引号（避免复制粘贴带进隐形字符）', !/[\s'"]/.test(REAL_SECRET || ''), JSON.stringify(REAL_SECRET));

  // 载入真实 options.js 的签名实现（含 sfbSignHeaders / sfbPostFeedback）
  const oSrc = fs.readFileSync(path.join(__dirname, '..', 'ui', 'options.js'), 'utf8');
  const oStart = oSrc.indexOf('var SFB_MAIL_HTTP_HINT');
  const oEnd = oSrc.indexOf('const RESCUE_DOWNLOAD_URL');
  const oCtx = {
    URL: URL, JSON: JSON, String: String, Error: Error, RegExp: RegExp, console: console,
    crypto: webcrypto, TextEncoder: TextEncoder,
    setTimeout: setTimeout, clearTimeout: clearTimeout,
    navigator: { onLine: true }, fetch: null,
    window: cfgCtx.window,
  };
  oCtx.globalThis = oCtx;
  vm.createContext(oCtx);
  vm.runInContext(oSrc.slice(oStart, oEnd), oCtx);

  const payload = { message: '来自扩展的端到端测试', contact: 'n/a' };
  const bodyText = JSON.stringify(payload);
  const signHeaders = await oCtx.sfbSignHeaders(REAL_ENDPOINT, bodyText);
  t('扩展端：生成了时间戳与签名', /^\d{13}$/.test(signHeaders['X-SF-Ts']) && /^[0-9a-f]{64}$/.test(signHeaders['X-SF-Sig']), JSON.stringify(signHeaders));

  // 用「真实密钥」配置的服务端去验「真实扩展端」算出的签名
  const real = await verify(mkReq(REAL_ENDPOINT, signHeaders), bodyText, { SECRET_DATA: REAL_SECRET });
  t('端到端：服务端接受扩展端签名（两端公式与密钥一致）', real.ok === true, JSON.stringify(real));

  // 反证：服务端换成别的密钥就必须拒绝，证明「不是随便什么都放行」
  const wrong = await verify(mkReq(REAL_ENDPOINT, signHeaders), bodyText, { SECRET_DATA: REAL_SECRET + 'x' });
  t('端到端：密钥不同即拒绝', wrong.ok === false && wrong.error === 'BAD_SIGNATURE', JSON.stringify(wrong));

  // 反证：直接把浏览器里的请求改成「无签名」，必被拒
  const bare = await verify(mkReq(REAL_ENDPOINT, { 'Content-Type': 'application/json' }), bodyText, { SECRET_DATA: REAL_SECRET });
  t('端到端：无签名的裸请求被拒绝（这就是拦住外部刷接口的那道闸门）', bare.status === 401, JSON.stringify(bare));

  console.log('\n' + pass + ' passed, ' + fail + ' failed');
  process.exit(fail ? 1 : 0);
})();
