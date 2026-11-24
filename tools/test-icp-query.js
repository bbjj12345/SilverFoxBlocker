// ICP 权威核验解析回归（background.js 的 queryIcp / ICP_PROVIDERS）
// 用法：node tools/test-icp-query.js
// 背景：2026-11-24 uapis 改版，「无备案」从 200 + "查询失败" 文案改成
//   HTTP 404 + {"code":"NOT_FOUND"}。旧 queryIcp 对非 2xx 直接换源，第二源 apihz 又有
//   10 次/分钟的令牌桶，超限后整次查询返回 {queried:false} —— 直接后果是
//   「盗用他人备案号」（需 queried:true + hasIcp:false）整条静默失效。
// 本测试用 vm 载入真实 background.js（桩掉 chrome / fetch），只锁解析与换源行为。
const fs = require('fs');
const path = require('path');
const vm = require('vm');

let pass = 0, fail = 0;
function t(name, cond, extra) {
  if (cond) { pass++; console.log('PASS ' + name); }
  else { fail++; console.log('FAIL ' + name + (extra ? '  → ' + extra : '')); }
}

const src = fs.readFileSync(path.join(__dirname, '..', 'background.js'), 'utf8');
// chrome 全量桩：任何属性/调用都返回"万能函数"，避免顶层监听器与 storage 调用炸掉
function anyFn() {
  const f = function () { return anyFn(); };
  return new Proxy(f, {
    get: (o, p) => (p === 'then' || p === Symbol.toPrimitive || p === 'toString' ? undefined : anyFn()),
    apply: () => anyFn(),
  });
}
const chromeStub = new Proxy(function () {}, { get: () => anyFn(), apply: () => anyFn() });
const ctx = {
  console, setTimeout, clearTimeout, Promise, AbortController, TextEncoder, TextDecoder,
  URL, JSON, Date, Math, setInterval, clearInterval, atob, btoa,
  fetch: null, chrome: chromeStub, importScripts: () => {},
};
ctx.self = ctx;
const context = vm.createContext(ctx);
vm.runInContext(src + '\n;globalThis.__q = queryIcp;', context, { filename: 'background.js' });

let calls = [];
const resp = (status, body) => () => Promise.resolve({
  ok: status >= 200 && status < 300, status,
  text: () => Promise.resolve(typeof body === 'string' ? body : JSON.stringify(body)),
});
function setFetch(map) {
  ctx.fetch = async (url, opt) => {
    calls.push(url);
    const k = Object.keys(map).find((x) => url.indexOf(x) !== -1);
    return map[k](opt && opt.signal);
  };
  calls = [];
}
// 「首源不响应」桩：只在 abort 时 reject，用来验证单源超时是否把预算让给第二源
function hang() {
  return (signal) => new Promise((resolve, reject) => {
    const t = setTimeout(() => resolve({ ok: true, status: 200, text: () => Promise.resolve('{}') }), 30000);
    if (signal) signal.addEventListener('abort', () => {
      clearTimeout(t);
      const e = new Error('aborted'); e.name = 'AbortError'; reject(e);
    });
  });
}

(async () => {
  // 1) uapis 404 + 明确的"无记录"正文 → 必须当成「已查询且无记录」，且不再打第二源
  setFetch({
    uapis: resp(404, { code: 'NOT_FOUND', message: 'No ICP record found for this domain.' }),
    apihz: resp(200, { code: 400, msg: '查询失败或没有备案。' }),
  });
  let r = await ctx.__q('ai.deekseep-e.com.cn');
  t('404 + NOT_FOUND 视为「已查询且无记录」', r.queried === true && r.hasIcp === false, JSON.stringify(r));
  t('命中首源后不再请求第二源（省 apihz 令牌）', calls.length === 1 && /uapis/.test(calls[0]), calls.join(','));

  // 2) 404 但正文不是「无记录」（参数错误）→ 不能当无备案，必须换源由第二源定夺
  setFetch({
    uapis: resp(404, { code: 'INVALID_PARAM', message: 'domain required' }),
    apihz: resp(200, { code: 400, msg: '查询失败或没有备案。' }),
  });
  r = await ctx.__q('some-other.cn');
  t('404 + 参数错误 → 换源（不臆断无备案）', r.service === 'apihz' && r.queried === true, JSON.stringify(r));
  t('404 + 参数错误 确实打了两个源', calls.length === 2, calls.join(','));

  // 3) 200 + 真实备案号 → hasIcp:true（联动跳过仿冒判定）
  setFetch({ uapis: resp(200, { code: 200, serviceLicence: '京ICP备2024000001号', unitName: '某公司' }) });
  r = await ctx.__q('gov.example.cn');
  t('200 + 备案号 → hasIcp:true', r.queried === true && r.hasIcp === true && r.icpNumber === '京ICP备2024000001号', JSON.stringify(r));

  // 4) 两源都异常（5xx / 非 JSON）→ queried:false（引擎回退页面文本，绝不冤枉）
  setFetch({ uapis: resp(500, 'oops'), apihz: resp(502, '<html>502</html>') });
  r = await ctx.__q('fail.example.cn');
  t('两源都失败 → queried:false', r.queried === false && r.hasIcp === false, JSON.stringify(r));

  // 5) 404 无记录的结果要进 24h 成功缓存（再次查询不再发请求）
  setFetch({ uapis: resp(404, { code: 'NOT_FOUND', message: 'No ICP record found for this domain.' }) });
  const first = await ctx.__q('cached.example.cn');
  const before = calls.length;
  const second = await ctx.__q('cached.example.cn');
  t('无记录结果被缓存（第二次不再请求）', calls.length === before && JSON.stringify(first) === JSON.stringify(second),
    'calls=' + before + '→' + calls.length);

  // 6) apihz 被限流（HTTP 200 + code 400 + "调用频次过快"）**不能**当成「无记录」
  //    旧 parse 把所有 code≠200 都判 hasIcp:false，等于把"我刚被限流"当成"权威确认无备案"，
  //    配合页面备案号就是 55 分「盗用他人备案号」，会砸到真正备过案的正规站。
  setFetch({
    uapis: resp(500, 'oops'),
    apihz: resp(200, { code: 400, s: 19, max: 329, now: 344, msg: '调用频次过快，请19秒后再试，或购买钻石会员！' }),
  });
  r = await ctx.__q('ratelimited.example.cn');
  t('apihz 限流 → 不是无记录（must queried:false）', r.queried === false && r.hasIcp === false, JSON.stringify(r));

  // 7) apihz 明确的「查询失败或没有备案」才算无记录
  setFetch({ uapis: resp(500, 'oops'), apihz: resp(200, { code: 400, msg: '查询失败或没有备案。' }) });
  r = await ctx.__q('norecord.example.cn');
  t('apihz 明确无记录 → hasIcp:false + service=apihz', r.queried === true && r.hasIcp === false && r.service === 'apihz', JSON.stringify(r));

  // 8) uapis 200 但正文结构不认识（既没备案号也没"查询失败"）→ 换源，不臆断
  setFetch({
    uapis: resp(200, { code: 200, data: null }),
    apihz: resp(200, { code: 400, msg: '查询失败或没有备案。' }),
  });
  r = await ctx.__q('weird.example.cn');
  t('uapis 未预期结构 → 换源', r.service === 'apihz', JSON.stringify(r));

  // 9) 首源挂住不响应（实测 uapis 会 6s 都不返回）：单源 1.5s 超时后必须让第二源拿到预算。
  //    旧实现单源 3s，会独吞内容脚本留给 ICP 的 ~2.2s，第二源根本轮不到 → queried:false → 55 分消失。
  setFetch({ uapis: hang(), apihz: resp(200, { code: 400, msg: '查询失败或没有备案。' }) });
  const t0 = Date.now();
  r = await ctx.__q('slow.example.cn');
  const dt = Date.now() - t0;
  t('首源挂住时 2s 内仍由第二源给出结论', r.service === 'apihz' && r.hasIcp === false && dt < 2000, dt + 'ms ' + JSON.stringify(r));

  // 10) 对冲（hedge）：uapis 已给出确定结论时，推迟 400ms 的 apihz **连请求都不该发**。
  //     否则每个「有备案的正常站」都会把域名多披露给一个第三方，还白耗它 10 次/分钟的额度。
  setFetch({ uapis: resp(200, { code: 200, serviceLicence: '京ICP备2024000002号', unitName: '某公司' }) });
  r = await ctx.__q('hedge.example.cn');
  await new Promise((res) => setTimeout(res, 600));
  t('对冲：首源已定案时第二源不发请求', r.hasIcp === true && calls.length === 1, calls.length + ' 次 ' + calls.join(','));

  // 11) apihz 的第二种「无记录」应答形状：HTTP 200 + code:200 + type/icp 都是「查询失败」
  //    （实测同一域名两次请求，一次回 code:400，一次回这个），旧 parse 只认 400 → 整次查询失败。
  setFetch({
    uapis: hang(),
    apihz: resp(200, { code: 200, td: '2-1', type: '查询失败', icp: '查询失败', unit: '查询失败', domain: '查询失败', time: '查询失败' }),
  });
  r = await ctx.__q('sentinel.example.cn');
  t('apihz 200 + type/icp 均「查询失败」→ 无记录', r.queried === true && r.hasIcp === false && r.service === 'apihz', JSON.stringify(r));

  // 12) uapis 慢但最终回 404（实测 8~10s，这里用 1.2s 模拟）：apihz 被限流时**不能**提前放弃。
  //    旧实现单源 1.5s 超时会把这条 8~10s 的 404 掐断，这正是「无记录」永远拿不到的根因。
  const slow = (ms, status, body) => () => new Promise((res) => setTimeout(() => res({
    ok: status >= 200 && status < 300, status,
    text: () => Promise.resolve(JSON.stringify(body)),
  }), ms));
  setFetch({
    uapis: slow(1200, 404, { code: 'NOT_FOUND', message: 'No ICP record found for this domain.' }),
    apihz: resp(200, { code: 400, msg: '调用频次过快，请19秒后再试，或购买钻石会员！' }),
  });
  const t1 = Date.now();
  r = await ctx.__q('slow404.example.cn');
  const dt1 = Date.now() - t1;
  t('慢 404 仍能定案（不被 1.5s 那一版掐断）', r.queried === true && r.hasIcp === false && r.service === 'uapis', dt1 + 'ms ' + JSON.stringify(r));
  t('慢 404 不会把 apihz 的「限流」当结论（结论来源必须是 uapis）', dt1 >= 1000, dt1 + 'ms');

  console.log('\n' + pass + ' passed, ' + fail + ' failed');
  process.exit(fail ? 1 : 0);
})();
