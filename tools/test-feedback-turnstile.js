// 反馈接口人机验证（Turnstile）回归（2026-11-27）
// 用法：node tools/test-feedback-turnstile.js
//
// 两份真实代码互相咬合，测试里不另写实现：
//   ① worker/index.js 的 verifyTurnstile / turnstileChallengeHtml（服务端）
//   ② ui/options.js  的 sfbTurnstileWait / sfbSendFeedback（扩展端）
// 关键约束（任何一条被改坏，线上都是「反馈发不出去」）：
//   · 服务端只在配了 TURNSTILE_SECRET_KEY 时才要求验证，未配则完全透明；
//   · 缺 token → 403 TURNSTILE_REQUIRED（扩展据此弹验证框），不是 401、不是 500；
//   · 默认 soft：验不过只降配额（3 次/天）不挡人；strict 才硬拒。两条路径都要测；
//   · token 单次有效：重复/超时 → TURNSTILE_EXPIRED，扩展提示「重新验证」；
//   · 挑战页绝不吐 secret；site key 缺失时明确报错，不静默放行；
//   · 扩展端只采信「同源 + 同一张 iframe + 带 sfb-challenge 标记」的消息。
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const nodeCrypto = require('crypto');
const { webcrypto } = nodeCrypto;

let pass = 0, fail = 0;
function t(name, cond, extra) {
  if (cond) { pass++; console.log('PASS ' + name); }
  else { fail++; console.log('FAIL ' + name + (extra ? '  → ' + extra : '')); }
}

// ============================================================================
// ① 服务端：截取 worker/index.js 里的 Turnstile 段（var TURNSTILE_VERIFY_URL → function leftMs）
// ============================================================================
const wSrc = fs.readFileSync(path.join(__dirname, '..', 'worker', 'index.js'), 'utf8');
const wStart = wSrc.indexOf('var TURNSTILE_VERIFY_URL');
const wEnd = wSrc.indexOf('function leftMs');
if (wStart < 0 || wEnd < 0 || wEnd <= wStart) {
  console.error('无法从 worker/index.js 截取 Turnstile 实现（文件结构可能已变）');
  process.exit(1);
}

// fetch 由每条用例替换：记录请求，回放预设响应
let calls = [];
let responder = async () => ({ json: async () => ({ success: true }) });
const wCtx = {
  String: String, Number: Number, URL: URL, URLSearchParams: URLSearchParams,
  AbortController: AbortController, JSON: JSON, console: console, isFinite: isFinite,
  setTimeout: setTimeout, clearTimeout: clearTimeout, Promise: Promise,
  fetch: async (url, opts) => { calls.push({ url: url, opts: opts }); return responder(url, opts); },
};
wCtx.globalThis = wCtx;
vm.createContext(wCtx);
vm.runInContext(wSrc.slice(wStart, wEnd), wCtx);

const SECRET = 'turnstile-test-secret-0123456789';
const SITEKEY = '0x4AAAAAAA_test_site_key';
const ENV_ON = { TURNSTILE_SECRET_KEY: SECRET, TURNSTILE_SITE_KEY: SITEKEY };
// v1.13.14 起默认 soft；要测「硬拦截」的老语义必须显式写 strict
const ENV_STRICT = Object.assign({}, ENV_ON, { TURNSTILE_ENFORCE: 'strict' });

t('服务端实现已被加载', typeof wCtx.verifyTurnstile === 'function' && typeof wCtx.turnstileChallengeHtml === 'function');
t('开关判定：只承认 secret', wCtx.turnstileEnabled(ENV_ON) === true && wCtx.turnstileEnabled({ TURNSTILE_SITE_KEY: SITEKEY }) === false);
t('开关判定：secret 长度太短，视为没有配置', wCtx.turnstileEnabled({ TURNSTILE_SECRET_KEY: 'short' }) === false);

(async function () {
  // ---------- 未配置：透明跳过 ----------
  {
    calls = [];
    const r = await wCtx.verifyTurnstile('', '1.2.3.4', {});
    t('未配置 secret → 直接放行（mode=off）', r.ok === true && r.mode === 'off', JSON.stringify(r));
    t('未配置 secret → 不发送子请求', calls.length === 0);
  }

  // ---------- 缺 token ----------
  {
    calls = [];
    responder = async () => ({ json: async () => ({ success: true }) });
    const r = await wCtx.verifyTurnstile('', '1.2.3.4', ENV_ON);
    t('缺少 token → 403 TURNSTILE_REQUIRED（扩展据此弹出验证）', r.ok === false && r.status === 403 && r.error === 'TURNSTILE_REQUIRED', JSON.stringify(r));
    t('缺少 token → 不向 Cloudflare 发送请求', calls.length === 0);
  }

  // ---------- 正向：siteverify ----------
  {
    calls = [];
    responder = async () => ({ json: async () => ({ success: true, 'error-codes': [] }) });
    const r = await wCtx.verifyTurnstile('TOKEN-OK', '1.2.3.4', ENV_ON);
    t('验证通过 → ok / mode=pass', r.ok === true && r.mode === 'pass', JSON.stringify(r));
    t('调用的是 siteverify', calls.length === 1 && calls[0].url === wCtx.TURNSTILE_VERIFY_URL, JSON.stringify(calls.map((c) => c.url)));
    const body = calls[0].opts.body;
    t('把 secret 放进请求体', body.get('secret') === SECRET);
    t('把 token 放进请求体', body.get('response') === 'TOKEN-OK');
    t('带上客户端 IP（绑定 token）', body.get('remoteip') === '1.2.3.4');
    t('IP 为 unknown 时不带 remoteip', (await (async () => {
      calls = [];
      await wCtx.verifyTurnstile('TOKEN-OK', 'unknown', ENV_ON);
      return calls[0].opts.body.get('remoteip') === null;
    })()) === true);
  }

  // ---------- 各类失败码（strict：硬拒，v1.13.12 的老语义）----------
  {
    responder = async () => ({ json: async () => ({ success: false, 'error-codes': ['timeout-or-duplicate'] }) });
    const r = await wCtx.verifyTurnstile('TOKEN-USED', '1.2.3.4', ENV_STRICT);
    t('重复/过期 → 403 TURNSTILE_EXPIRED', r.ok === false && r.status === 403 && r.error === 'TURNSTILE_EXPIRED', JSON.stringify(r));

    responder = async () => ({ json: async () => ({ success: false, 'error-codes': ['invalid-input-response'] }) });
    const r2 = await wCtx.verifyTurnstile('TOKEN-BAD', '1.2.3.4', ENV_STRICT);
    t('token 无效 → 403 TURNSTILE_FAILED', r2.ok === false && r2.status === 403 && r2.error === 'TURNSTILE_FAILED', JSON.stringify(r2));

    responder = async () => ({ json: async () => ({ success: false, 'error-codes': ['invalid-input-secret'] }) });
    const r3 = await wCtx.verifyTurnstile('TOKEN-OK', '1.2.3.4', ENV_STRICT);
    t('密钥配置错误 → 503 TURNSTILE_MISCONFIGURED（这不是 401，不需要检查签名）', r3.ok === false && r3.status === 503 && r3.error === 'TURNSTILE_MISCONFIGURED', JSON.stringify(r3));

    responder = async () => { throw new Error('network down'); };
    const r4 = await wCtx.verifyTurnstile('TOKEN-OK', '1.2.3.4', ENV_STRICT);
    t('siteverify 无法访问 → 503 TURNSTILE_UNREACHABLE', r4.ok === false && r4.status === 503 && r4.error === 'TURNSTILE_UNREACHABLE', JSON.stringify(r4));

    responder = async () => ({ json: async () => ({ success: false }) });
    const r5 = await wCtx.verifyTurnstile('TOKEN-OK', '1.2.3.4', ENV_STRICT);
    t('无 error-codes 时也失败（默认拒绝）', r5.ok === false && r5.error === 'TURNSTILE_FAILED', JSON.stringify(r5));
  }

  // ---------- 超长 token ----------
  {
    calls = [];
    const r = await wCtx.verifyTurnstile('x'.repeat(wCtx.TURNSTILE_MAX_TOKEN + 1), '1.2.3.4', ENV_ON);
    t('超长 token → 400 TURNSTILE_BAD_TOKEN', r.ok === false && r.status === 400 && r.error === 'TURNSTILE_BAD_TOKEN', JSON.stringify(r));
    t('超长 token 不消耗 siteverify 配额', calls.length === 0);
  }

  // ---------- 策略开关：soft 是默认，且配置写错不能变成「全放」或「全拒」----------
  {
    t('策略：默认 soft', wCtx.turnstileEnforce({}) === 'soft' && wCtx.turnstileEnforce(ENV_ON) === 'soft');
    t('策略：显式 strict 生效（大小写/空格不敏感）', wCtx.turnstileEnforce({ TURNSTILE_ENFORCE: ' STRICT ' }) === 'strict');
    t('策略：非法值回落 soft', wCtx.turnstileEnforce({ TURNSTILE_ENFORCE: 'yolo' }) === 'soft');
    t('降级配额：默认 3', wCtx.turnstileSoftQuota({}) === 3);
    t('降级配额：可配', wCtx.turnstileSoftQuota({ TURNSTILE_SOFT_QUOTA: '5' }) === 5);
    t('降级配额：不超过正常配额 60', wCtx.turnstileSoftQuota({ TURNSTILE_SOFT_QUOTA: '999' }) === 60);
    t('降级配额：非法值回落 3', wCtx.turnstileSoftQuota({ TURNSTILE_SOFT_QUOTA: 'abc' }) === 3);
  }

  // ---------- soft：无 token 仍要弹框（否则等于没开）----------
  {
    const r = await wCtx.verifyTurnstile('', '1.2.3.4', ENV_ON, false);
    t('soft：无 token 且无 fallback → 仍然 REQUIRED（要弹框）', r.ok === false && r.error === 'TURNSTILE_REQUIRED', JSON.stringify(r));
    const r2 = await wCtx.verifyTurnstile('', '1.2.3.4', ENV_ON, true);
    t('soft：无 token + fallback → 放行且配额降到 3', r2.ok === true && r2.mode === 'soft-degraded' && r2.quota === 3, JSON.stringify(r2));
    const r3 = await wCtx.verifyTurnstile('', '1.2.3.4', ENV_STRICT, true);
    t('strict：fallback 标记无效，照样 REQUIRED', r3.ok === false && r3.error === 'TURNSTILE_REQUIRED', JSON.stringify(r3));
  }

  // ---------- soft：各种「验不过」都放行，但只给降级配额 ----------
  {
    responder = async () => ({ json: async () => ({ success: false, 'error-codes': ['timeout-or-duplicate'] }) });
    const a = await wCtx.verifyTurnstile('T', '1.2.3.4', ENV_ON);
    t('soft：凭据过期 → 放行，标记 expired', a.ok === true && a.quota === 3 && /expired/.test(String(a.degraded)), JSON.stringify(a));

    responder = async () => { throw new Error('down'); };
    const b = await wCtx.verifyTurnstile('T', '1.2.3.4', ENV_ON);
    t('soft：siteverify 连不上 → 放行，标记 unreachable', b.ok === true && /unreachable/.test(String(b.degraded)), JSON.stringify(b));

    responder = async () => ({ json: async () => ({ success: false, 'error-codes': ['invalid-input-secret'] }) });
    const c = await wCtx.verifyTurnstile('T', '1.2.3.4', ENV_ON);
    t('soft：服务端密钥错 → 放行（不替作者的配置背锅）', c.ok === true && /misconfigured/.test(String(c.degraded)), JSON.stringify(c));

    responder = async () => ({ json: async () => ({ success: false, 'error-codes': ['invalid-input-response'] }) });
    const f = await wCtx.verifyTurnstile('T', '1.2.3.4', ENV_ON);
    t('soft：token 无效 → 放行，但标记 failed（便于统计）', f.ok === true && /failed:/.test(String(f.degraded)), JSON.stringify(f));

    const d = await wCtx.verifyTurnstile('x'.repeat(wCtx.TURNSTILE_MAX_TOKEN + 1), '1.2.3.4', ENV_ON);
    t('soft：超长 token 仍然 400（明显伪造不奖励）', d.ok === false && d.status === 400, JSON.stringify(d));

    responder = async () => ({ json: async () => ({ success: true }) });
    const e = await wCtx.verifyTurnstile('T', '1.2.3.4', ENV_ON);
    t('soft：通过验证 → 满配额 60', e.ok === true && e.quota === 60 && e.mode === 'pass', JSON.stringify(e));
  }

  // ---------- 限流接线（handler 依赖 env 不好单跑，改用源码顺序断言）----------
  {
    const iT = wSrc.indexOf('const turnstile = await verifyTurnstile');
    const iQ = wSrc.indexOf('const quota = turnstile.quota');
    const iL = wSrc.indexOf('currentCount >= FEEDBACK_DAILY_QUOTA');
    t('顺序：验人机 → 取配额 → 限流（否则 soft 配额无从得知）', iT > 0 && iQ > iT && iL > iQ, JSON.stringify({ iT, iQ, iL }));
    t('降级通道独立计数（rate_limit_soft_）', wSrc.indexOf('rate_limit_soft_') > 0);
    t('降级额度用尽有专门错误码', wSrc.indexOf('DEGRADED_QUOTA_EXCEEDED') > 0);
    t('降级也累加主计数（防 60+3 后门）', /RATE_LIMIT_KV\.put\(kvKey/.test(wSrc));
  }

  // ---------- 挑战页 ----------
  {
    const html = wCtx.turnstileChallengeHtml(ENV_ON, { theme: 'dark' });
    t('挑战页：内嵌 site key', html.indexOf(SITEKEY) !== -1);
    t('挑战页：绝不泄露 secret', html.indexOf(SECRET) === -1);
    t('挑战页：加载 Cloudflare 官方脚本（render=explicit + onload 回调）',
      html.indexOf('api.js?render=explicit&onload=sfbTsOnload') !== -1);
    t('挑战页：主题参数生效', html.indexOf('theme:"dark"') !== -1);
    t('挑战页：postMessage 带 sfb-challenge 标记', html.indexOf("m.source='sfb-challenge'") !== -1);
    t('挑战页：声明 viewport（手机上也放得下）', html.indexOf('name="viewport"') !== -1);

    const off = wCtx.turnstileChallengeHtml({}, {});
    t('未打开验证时页面返回 mode:"off"（扩展照常发送）', off.indexOf('mode:"off"') !== -1);

    const mis = wCtx.turnstileChallengeHtml({ TURNSTILE_SECRET_KEY: SECRET }, {});
    t('只配置 secret 但未配置 site key → mode:"error" + no-sitekey', mis.indexOf('mode:"error"') !== -1 && mis.indexOf('no-sitekey') !== -1);
    t('配置错误时也不泄漏 secret', mis.indexOf(SECRET) === -1);

    const light = wCtx.turnstileChallengeHtml(ENV_ON, { theme: 'light' });
    t('非法 theme 归一为 auto', wCtx.turnstileChallengeHtml(ENV_ON, { theme: 'pink' }).indexOf('theme:"auto"') !== -1);
    t('light 主题生效', light.indexOf('theme:"light"') !== -1);
  }

  await testExtension();
  testCopy();
  console.log('\n' + pass + ' passed, ' + fail + ' failed');
  process.exit(fail ? 1 : 0);
})();

// ============================================================================
// ② 扩展端：从 ui/options.js 里按函数名切出真实实现，喂一个最小 DOM / window
// ============================================================================
// fromEnd：同名函数在「旧实现」注释块里也出现过时（sfbDescribeMailFailure 就是），
//   取最后一次出现的那份，否则切到的是注释里的残骸。
function sliceFn(src, name, fromEnd) {
  const key = 'function ' + name + '(';
  const at = fromEnd ? src.lastIndexOf(key) : src.indexOf(key);
  if (at < 0) throw new Error('找不到函数 ' + name);
  let depth = 0, i = src.indexOf('{', at);
  for (; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}') { depth--; if (depth === 0) break; }
  }
  return src.slice(at, i + 1);
}

async function testExtension() {
  const oSrc = fs.readFileSync(path.join(__dirname, '..', 'ui', 'options.js'), 'utf8');
  const names = ['sfbSignError', 'sfbFeedbackSecret', 'sfbBytesToHex', 'sfbHmacHex', 'sfbSignHeaders',
    'sfbPostFeedback', 'sfbTsError', 'sfbChallengeUrl', 'sfbTurnstileWait', 'sfbTsReasonText', 'sfbSendFeedback'];
  // 常量也要从源码里取（它是模块级 var，不在任何函数体内）
  const constLine = (oSrc.match(/var SFB_TS_TIMEOUT_MS = [^;]+;/) || [''])[0];
  const code = constLine + '\n' + names.map((n) => sliceFn(oSrc, n)).join('\n');

  const EP = 'https://api.example.org';
  const SECRET2 = 'unit-test-secret-0123456789';

  // ---- 最小 DOM ----
  const frames = [];
  const msgHandlers = [];
  function makeEl(tag) {
    const el = {
      tagName: tag, hidden: true, parentNode: null, children: [], attrs: {}, style: {},
      set src(v) { this._src = v; this.attrs.src = v; },
      get src() { return this._src; },
      setAttribute(k, v) { this.attrs[k] = v; },
      appendChild(c) { this.children.push(c); c.parentNode = this; return c; },
      removeChild(c) { this.children = this.children.filter((x) => x !== c); c.parentNode = null; return c; },
      set innerHTML(v) { if (!v) this.children = []; },
      get innerHTML() { return ''; },
    };
    if (tag === 'iframe') el.contentWindow = { __id: frames.length };
    return el;
  }
  const ctx = {
    URL: URL, JSON: JSON, String: String, Error: Error, Promise: Promise, Object: Object,
    setTimeout: setTimeout, clearTimeout: clearTimeout, AbortController: AbortController,
    crypto: webcrypto, TextEncoder: TextEncoder, console: { warn() {}, log() {} },
    document: {
      documentElement: { classList: { contains: () => false } },
      createElement: (tag) => { const el = makeEl(tag); if (tag === 'iframe') frames.push(el); return el; },
    },
    window: {
      addEventListener: (type, fn) => { if (type === 'message') msgHandlers.push(fn); },
      removeEventListener: (type, fn) => {
        if (type !== 'message') return;
        const i = msgHandlers.indexOf(fn); if (i >= 0) msgHandlers.splice(i, 1);
      },
    },
  };
  ctx.window.SFB_FEEDBACK = {
    decode: (a) => a.map((c) => String.fromCharCode(c)).join(''),
    secretCodes: Array.from(SECRET2).map((c) => c.charCodeAt(0)),
  };
  ctx.globalThis = ctx;
  vm.createContext(ctx);
  vm.runInContext(code, ctx);

  const tick = (ms) => new Promise((r) => setTimeout(r, ms || 15));

  // ---- 请求模拟：第一次 403 TURNSTILE_REQUIRED，之后成功 ----
  let seen = [];
  ctx.fetch = async (url, opts) => {
    seen.push({ url: url, opts: opts });
    const nth = seen.length;
    if (nth === 1) {
      return {
        ok: false, status: 403,
        text: async () => JSON.stringify({ error: 'TURNSTILE_REQUIRED', detail: '需要人机验证' }),
      };
    }
    return { ok: true, status: 200, text: async () => '{"success":true}' };
  };

  const mount = makeEl('div');
  const p = ctx.sfbSendFeedback(EP, { message: '你好', contact: '' }, { mount: mount });
  let settled = null;
  p.then((r) => { settled = { ok: true, r: r }; }, (e) => { settled = { ok: false, e: e }; });

  await tick(30);
  t('首次发送不带 turnstileToken', seen.length === 1 && String(seen[0].opts.body).indexOf('turnstileToken') === -1, seen[0] && seen[0].opts.body);
  t('收到 TURNSTILE_REQUIRED 后插入一张 iframe', frames.length === 1, String(frames.length));
  t('iframe 指向 /challenge（与接口同源）', /^https:\/\/api\.example\.org\/challenge\?/.test(frames[0].src), frames[0] && frames[0].src);
  t('iframe 带主题参数', /theme=dark/.test(frames[0].src || ''));
  t('mount 被显示', mount.hidden === false && mount.children.length === 1);
  t('此时还没有结论（等待用户勾选）', settled === null);

  // 伪造消息：来源不对 / 窗口不对 / 没有标记，都必须被忽略
  const frameWin = frames[0].contentWindow;
  msgHandlers.slice().forEach((h) => h({ origin: 'https://evil.example', source: frameWin, data: { source: 'sfb-challenge', type: 'token', token: 'EVIL' } }));
  msgHandlers.slice().forEach((h) => h({ origin: 'https://api.example.org', source: { __id: 999 }, data: { source: 'sfb-challenge', type: 'token', token: 'EVIL' } }));
  msgHandlers.slice().forEach((h) => h({ origin: 'https://api.example.org', source: frameWin, data: { type: 'token', token: 'EVIL' } }));
  await tick(10);
  t('来源不对的消息被忽略', seen.length === 1 && settled === null);
  t('窗口不对的消息被忽略', settled === null);
  t('没有 sfb-challenge 标记的消息被忽略', settled === null);

  // 正常回话
  msgHandlers.slice().forEach((h) => h({ origin: 'https://api.example.org', source: frameWin, data: { source: 'sfb-challenge', type: 'token', token: 'TOKEN-XYZ' } }));
  await tick(30);
  t('拿到 token 后自动重发', seen.length === 2, String(seen.length));
  const body2 = JSON.parse(seen[1].opts.body);
  t('重发时请求体带上 turnstileToken', body2.turnstileToken === 'TOKEN-XYZ', seen[1].opts.body);
  t('正文没有被改动', body2.message === '你好' && body2.contact === '');
  const expectSig = nodeCrypto.createHmac('sha256', SECRET2)
    .update('/' + '\n' + seen[1].opts.headers['X-SF-Ts'] + '\n' + seen[1].opts.body).digest('hex');
  t('签名覆盖了含 token 的最终请求体（不能被掉包）', seen[1].opts.headers['X-SF-Sig'] === expectSig);
  t('发送成功后收尾：iframe 被移除、mount 再次隐藏', frames[0].parentNode === null && mount.hidden === true, JSON.stringify({ p: frames[0].parentNode, h: mount.hidden }));
  t('最终 resolve', settled && settled.ok === true);
  t('message 监听已解绑（不留悬挂回调）', msgHandlers.length === 0, String(msgHandlers.length));

  // ---- 服务端没开验证：回 off → 不带 token 直接重发 ----
  {
    seen = []; settled = null; frames.length = 0;
    let n = 0;
    ctx.fetch = async (url, opts) => {
      seen.push({ url, opts }); n++;
      if (n === 1) return { ok: false, status: 403, text: async () => JSON.stringify({ error: 'TURNSTILE_REQUIRED' }) };
      return { ok: true, status: 200, text: async () => '{"success":true}' };
    };
    const m2 = makeEl('div');
    const p2 = ctx.sfbSendFeedback(EP, { message: 'x', contact: '' }, { mount: m2 });
    p2.then(() => { settled = { ok: true }; }, () => { settled = { ok: false }; });
    await tick(30);
    msgHandlers.slice().forEach((h) => h({ origin: 'https://api.example.org', source: frames[0].contentWindow, data: { source: 'sfb-challenge', type: 'off' } }));
    await tick(30);
    t('挑战页回 off → 仍会重发', seen.length === 2, String(seen.length));
    t('off 时请求体不带 turnstileToken', String(seen[1].opts.body).indexOf('turnstileToken') === -1);
    t('off 分支也能 resolve', settled && settled.ok === true);
  }

  // ---- 验证页报错：soft 下改为「带 fallback 标记降级重发」，而不是直接失败 ----
  {
    seen = []; settled = null; frames.length = 0;
    let n = 0;
    ctx.fetch = async (url, opts) => {
      seen.push({ url, opts }); n++;
      if (n === 1) return { ok: false, status: 403, text: async () => JSON.stringify({ error: 'TURNSTILE_REQUIRED' }) };
      // 第二次：服务端看到 fallback 标记，按 soft 放行
      return { ok: true, status: 200, text: async () => '{"success":true,"degraded":true}' };
    };
    let fellBack = null;
    const m3 = makeEl('div');
    const p3 = ctx.sfbSendFeedback(EP, { message: 'x', contact: '' }, {
      mount: m3,
      onFallback: function (e) { fellBack = e; },
    });
    p3.then(() => { settled = { ok: true }; }, (e) => { settled = { ok: false, e: e }; });
    await tick(30);
    msgHandlers.slice().forEach((h) => h({ origin: 'https://api.example.org', source: frames[0].contentWindow, data: { source: 'sfb-challenge', type: 'error', reason: 'no-sitekey' } }));
    await tick(30);
    t('验证页报错 → 触发降级重发（不再直接失败）', seen.length === 2, String(seen.length));
    const body3 = JSON.parse(seen[1].opts.body);
    t('降级请求带 turnstileFallback:true', body3.turnstileFallback === true, seen[1].opts.body);
    t('降级请求不带 token（没有就是没有）', body3.turnstileToken === undefined, seen[1].opts.body);
    t('降级请求照样签名（fallback 也在签名覆盖范围内，改不了）', (function () {
      const want = nodeCrypto.createHmac('sha256', SECRET2)
        .update('/' + '\n' + seen[1].opts.headers['X-SF-Ts'] + '\n' + seen[1].opts.body).digest('hex');
      return seen[1].opts.headers['X-SF-Sig'] === want;
    })());
    t('onFallback 回调拿到 turnstile 阶段错误（供 UI 提示限额）', !!fellBack && fellBack.sfbStage === 'turnstile', fellBack && fellBack.sfbStage);
    t('服务端放行后 resolve', settled && settled.ok === true);
  }

  // ---- strict 模式：降级重发仍被拒 → 上抛 REQUIRED，且只试两次 ----
  {
    seen = []; settled = null; frames.length = 0;
    ctx.fetch = async (url, opts) => {
      seen.push({ url, opts });
      return { ok: false, status: 403, text: async () => JSON.stringify({ error: 'TURNSTILE_REQUIRED', detail: '需要人机验证' }) };
    };
    const m3b = makeEl('div');
    const p3b = ctx.sfbSendFeedback(EP, { message: 'x', contact: '' }, { mount: m3b });
    p3b.then(() => { settled = { ok: true }; }, (e) => { settled = { ok: false, e: e }; });
    await tick(30);
    msgHandlers.slice().forEach((h) => h({ origin: 'https://api.example.org', source: frames[0].contentWindow, data: { source: 'sfb-challenge', type: 'error', reason: 'timeout' } }));
    await tick(30);
    t('strict：降级重发被 403 拒绝后上抛', settled && settled.ok === false && settled.e.sfbCode === 'TURNSTILE_REQUIRED', settled && JSON.stringify({ c: settled.e && settled.e.sfbCode }));
    t('strict：只发两次，不无限重试', seen.length === 2, String(seen.length));
  }

  // ---- 没有挂载点：没地方放验证框 → 直接走降级通道（别静默失败） ----
  {
    seen = []; settled = null; frames.length = 0;
    let n = 0;
    ctx.fetch = async (url, opts) => {
      seen.push({ url, opts }); n++;
      if (n === 1) return { ok: false, status: 403, text: async () => JSON.stringify({ error: 'TURNSTILE_REQUIRED' }) };
      return { ok: true, status: 200, text: async () => '{"success":true,"degraded":true}' };
    };
    const p4 = ctx.sfbSendFeedback(EP, { message: 'x', contact: '' }, {});
    p4.then(() => { settled = { ok: true }; }, (e) => { settled = { ok: false, e: e }; });
    await tick(30);
    t('没有挂载点 → 不插 iframe', frames.length === 0, String(frames.length));
    t('没有挂载点 → 走降级重发', seen.length === 2 && JSON.parse(seen[1].opts.body).turnstileFallback === true, String(seen.length));
    t('没有挂载点 → soft 放行后 resolve', settled && settled.ok === true);
  }

  // ---- 非人机验证的失败必须原样抛给上层（不能被这里吞掉） ----
  {
    settled = null; frames.length = 0;
    ctx.fetch = async () => ({ ok: false, status: 401, text: async () => JSON.stringify({ error: 'BAD_SIGNATURE', detail: '签名校验失败' }) });
    const p5 = ctx.sfbSendFeedback(EP, { message: 'x', contact: '' }, { mount: makeEl('div') });
    p5.then(() => { settled = { ok: true }; }, (e) => { settled = { ok: false, e: e }; });
    await tick(30);
    t('401 不触发人机验证，直接上抛', settled && settled.ok === false && settled.e.sfbStage === 'http' && settled.e.sfbStatus === 401);
    t('401 时没有插 iframe', frames.length === 0);
  }
}

// ============================================================================
// ③ 失败文案：人机验证的几个错误码必须各说各的，不能被 403 的通用解释盖掉
// ============================================================================
function testCopy() {
  const oSrc = fs.readFileSync(path.join(__dirname, '..', 'ui', 'options.js'), 'utf8');
  const hintLine = (oSrc.match(/var SFB_MAIL_HTTP_HINT = \{[\s\S]*?\n\};/) || [''])[0];
  const describe = sliceFn(oSrc, 'sfbDescribeMailFailure', true);
  if (!hintLine || !describe) { t('文案：能从源码里取到实现', false); return; }

  const ctx = {
    String: String, URL: URL, Error: Error, RegExp: RegExp,
    SFB_DIAG: { offline: 'offline' },
    sfbIsNetError: () => false,
    sfbMailNetText: (h) => h,
    sfbIsOffline: () => false,
    sfbExtId: () => '',
  };
  ctx.globalThis = ctx;
  vm.createContext(ctx);
  vm.runInContext(hintLine + '\n' + describe, ctx);

  const mk = (st, code) => ({ sfbStage: 'http', sfbStatus: st, sfbCode: code, sfbDetail: '' });
  const r1 = ctx.sfbDescribeMailFailure(mk(403, 'TURNSTILE_EXPIRED'), 'https://x/');
  // 断言只卡语义（「只能用一次」），不卡整句 —— 否则文案每微调一个字就误红
  t('403 TURNSTILE_EXPIRED → 明确说「凭据只能用一次」', /只能用一次/.test(r1), r1);
  t('403 TURNSTILE_EXPIRED → 不泄露内部错误码', r1.indexOf('TURNSTILE_') === -1, r1);
  const r2 = ctx.sfbDescribeMailFailure(mk(403, 'TURNSTILE_FAILED'), 'https://x/');
  t('403 TURNSTILE_FAILED → 让用户重新勾选', /重新勾选/.test(r2), r2);
  const r3 = ctx.sfbDescribeMailFailure(mk(503, 'TURNSTILE_MISCONFIGURED'), 'https://x/');
  t('503 配置错误 → 说清「不是你网络的问题」', /不是你的网络|非网络故障/.test(r3), r3);
  const r4 = ctx.sfbDescribeMailFailure({ sfbStage: 'turnstile', sfbReason: 'timeout', sfbDetail: '验证组件未能渲染' }, 'https://x/');
  t('验证页加载失败 → 说「人机验证没有完成」并给替代通道', /人机验证没有完成/.test(r4) && /GitHub/.test(r4), r4);
  // no-sitekey = 服务端漏配 site key（2026-11-27 真实踩到）。绝不能叫用户去查自己的网络。
  const r6 = ctx.sfbDescribeMailFailure({ sfbStage: 'turnstile', sfbReason: 'no-sitekey',
    sfbDetail: '服务端只配了 TURNSTILE_SECRET_KEY，没配 TURNSTILE_SITE_KEY，人机验证无法显示' }, 'https://x/');
  t('no-sitekey → 明说「与你的网络无关」', /与你的网络无关/.test(r6), r6);
  t('no-sitekey → 不再叫人去查 challenges.cloudflare.com', r6.indexOf('challenges.cloudflare.com') === -1, r6);
  t('no-sitekey → 给出可用的替代通道', /GitHub Issue/.test(r6), r6);
  // script / timeout 才是「你这边网络或代理拦了」，这两类要保留换网络的建议
  const r7 = ctx.sfbDescribeMailFailure({ sfbStage: 'turnstile', sfbReason: 'timeout', sfbDetail: '验证组件 12 秒内没有渲染出来' }, 'https://x/');
  t('timeout → 保留「换网络再试」的建议', /换网络/.test(r7), r7);
  const r5 = ctx.sfbDescribeMailFailure(mk(403, ''), 'https://x/');
  t('普通 403（无错误码）仍走通用解释', /被服务端拒绝/.test(r5), r5);
  // soft 模式带来的两个新文案：降级额度用尽、strict 下必验
  const r8 = ctx.sfbDescribeMailFailure(mk(429, 'DEGRADED_QUOTA_EXCEEDED'), 'https://x/');
  t('429 降级额度用尽 → 点明「免验证通道」有小限额', /免验证|免人机验证/.test(r8), r8);
  t('429 降级额度用尽 → 给替代通道', /GitHub Issue/.test(r8), r8);
  const r9 = ctx.sfbDescribeMailFailure(mk(403, 'TURNSTILE_REQUIRED'), 'https://x/');
  t('403 REQUIRED → 提示可能是「严格模式」', /严格模式/.test(r9), r9);
}
