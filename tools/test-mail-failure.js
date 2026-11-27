// 邮件反馈失败诊断回归（2026-11-27，文案改为固定版式后的第二版）
// 用法：node tools/test-mail-failure.js
// 直接截取 ui/options.js 里的真实实现（跨文件复制会失真），用 vm 注入桩后逐场景断言。
// 覆盖：
//   ① 网络层：四行固定版式（抬头 / 常见原因 / 本机扩展 ID / 诊断）
//   ② HTTP 层：两行固定版式（发送失败：HTTP xxx / 该码解释），必要时补服务端原话
//   ③ 「诊断」行有证据：可达 → 跨域；不通 + DoH 查无此域 → DNS；不通 + DoH 能解析 → 防火墙；无证据 → 不写
//   ④ 不再出现「任何失败都只说发送失败，请稍后重试」的退化
const fs = require('fs');
const path = require('path');
const vm = require('vm');

let pass = 0, fail = 0;
function t(name, cond, extra) {
  if (cond) { pass++; console.log('PASS ' + name); }
  else { fail++; console.log('FAIL ' + name + (extra ? '  → ' + extra : '')); }
}

const src = fs.readFileSync(path.join(__dirname, '..', 'ui', 'options.js'), 'utf8');
const start = src.indexOf('var SFB_MAIL_HTTP_HINT');
const end = src.indexOf('const RESCUE_DOWNLOAD_URL');
if (start < 0 || end < 0 || end <= start) {
  console.error('无法从 options.js 截取诊断实现（文件结构可能已变）');
  process.exit(1);
}
const frag = src.slice(start, end);

const ctx = {
  URL: URL,
  setTimeout: setTimeout,
  clearTimeout: clearTimeout,
  AbortController: typeof AbortController !== 'undefined' ? AbortController : undefined,
  JSON: JSON, String: String, Error: Error, RegExp: RegExp, console: console,
  navigator: { onLine: true },
  fetch: null,
};
ctx.globalThis = ctx;
vm.createContext(ctx);
vm.runInContext(frag, ctx);

const describe = ctx.sfbDescribeMailFailure;
const post = ctx.sfbPostFeedback;
const EP = 'https://api.example-feedback.org/send';
const HOST = 'api.example-feedback.org';

const NET_REASONS = '常见原因：网络故障 / DNS 解析失败 / 使用代理或VPN / 被防火墙拦截 / 跨域被拒（扩展 ID 不在服务端白名单）';
const lines = (s) => String(s).split('\n');

t('实现已被加载（核心函数都在）',
  typeof describe === 'function' && typeof post === 'function'
  && typeof ctx.sfbReportMailFailure === 'function' && typeof ctx.sfbDnsVerdict === 'function');

// ---------- 1. 网络层：四行固定版式 ----------
{
  const s = describe(new TypeError('Failed to fetch'), EP);
  const L = lines(s);
  t('网络层：第 1 行是「无法连接反馈服务器（原文）」', L[0] === '发送失败：无法连接反馈服务器（Failed to fetch）', L[0]);
  t('网络层：第 2 行是完整「常见原因」（五种一次列全）', L[1] === NET_REASONS, L[1]);
  t('网络层：点出 DNS/代理/防火墙/跨域', /DNS/.test(s) && /代理/.test(s) && /防火墙/.test(s) && /跨域/.test(s), s);
  t('网络层：不再只有「请稍后重试」', s.indexOf('请稍后重试') === -1, s);
  t('网络层：无扩展 ID 上下文时不出现空 ID 行', s.indexOf('本机扩展 ID') === -1, s);
  t('网络层：不再把接口主机名塞进提示里（改由控制台/服务端日志看）', s.indexOf('接口：') === -1, s);
}
{
  const e = new Error('The user aborted a request.');
  e.name = 'AbortError';
  const s = describe(e, EP);
  t('超时：标明 15 秒无响应', s.indexOf('15 秒') !== -1, s);
  t('超时：与「连不上」措辞不同', s.indexOf('无法连接') === -1, s);
  t('超时：同样给出常见原因行', s.indexOf(NET_REASONS) !== -1, s);
}
{
  const s = describe(new TypeError('Failed to fetch'), EP);
  // 已知离线时当场给「诊断」，不等探测
  ctx.navigator = { onLine: false };
  const off = describe(new TypeError('Failed to fetch'), EP);
  ctx.navigator = { onLine: true };
  t('离线：当场补「诊断：网络故障…」', /诊断：网络故障，您似乎没有连接到互联网/.test(off), off);
  t('离线：「诊断」是最后一行', lines(off)[lines(off).length - 1].indexOf('诊断：') === 0);
  t('在线：不预写「诊断」行（等探测结论）', s.indexOf('诊断：') === -1, s);
}
{
  const s = describe(new Error('boom'), '');
  t('未知错误：原样带出 message', s.indexOf('boom') !== -1, s);
}

// ---------- 2. HTTP 层：两行固定版式 ----------
{
  const e = new Error('HTTP 429');
  e.sfbStage = 'http'; e.sfbStatus = 429;
  e.sfbDetail = '您今天的提交次数已达上限，请明天再试。';
  const L = lines(describe(e, EP));
  t('HTTP 429：第 1 行只有「发送失败：HTTP 429」', L[0] === '发送失败：HTTP 429', L[0]);
  t('HTTP 429：第 2 行是文档里的解释', L[1] === '提交过于频繁：已触发服务端限流，或达到当日发送上限', L[1]);
  t('HTTP 429：服务端原话另起一行照登', /服务端说明：您今天的提交次数已达上限/.test(L[2] || ''), L[2]);
}
{
  // 服务端原话与通用解释相同时不重复
  const e = new Error('HTTP 429');
  e.sfbStage = 'http'; e.sfbStatus = 429;
  e.sfbDetail = '提交过于频繁：已触发服务端限流，或达到当日发送上限';
  const L = lines(describe(e, EP));
  t('HTTP 429：解释与通用文案重复时不叠加「服务端说明」', L.length === 2, JSON.stringify(L));
}
{
  const e = new Error('HTTP 404');
  e.sfbStage = 'http'; e.sfbStatus = 404; e.sfbDetail = '';
  const L = lines(describe(e, EP));
  t('HTTP 404：给出「接口地址不存在」的定位', L[1] && L[1].indexOf('不存在') !== -1, L[1]);
}
{
  const e = new Error('HTTP 502');
  e.sfbStage = 'http'; e.sfbStatus = 502; e.sfbDetail = '';
  t('HTTP 502：归为网关错误', /网关|上游/.test(describe(e, EP)));
}
{
  const e = new Error('HTTP 599');
  e.sfbStage = 'http'; e.sfbStatus = 599; e.sfbDetail = '';
  const s = describe(e, EP);
  t('未知状态码：仍显示原始状态码', s.indexOf('599') !== -1, s);
  t('未知状态码：给出兜底解释而不是空行', lines(s)[1] && lines(s)[1].length > 0, s);
}

// ---------- 3. sfbPostFeedback 的两层分流 ----------
function resp(status, bodyText, okFlag) {
  return {
    ok: okFlag === undefined ? (status >= 200 && status < 300) : okFlag,
    status: status,
    text: function () { return Promise.resolve(bodyText); },
    json: function () { return Promise.resolve(JSON.parse(bodyText)); },
  };
}
function jsonResp(obj) {
  return {
    ok: true, status: 200,
    text: function () { return Promise.resolve(JSON.stringify(obj)); },
    json: function () { return Promise.resolve(obj); },
  };
}
function setFetch(fn) { ctx.fetch = fn; }

(async function () {
  // 3.1 成功直接返回
  setFetch(function () { return Promise.resolve(resp(200, '{"success":true}')); });
  let res = await post(EP, { message: 'x', contact: '' });
  t('2xx：原样返回 Response（走成功分支）', res && res.status === 200);

  // 3.2 429 带 Worker 的中文 error
  setFetch(function () { return Promise.resolve(resp(429, JSON.stringify({ error: '您今天的提交次数已达上限，请明天再试。' }))); });
  let err = null;
  try { await post(EP, { message: 'x' }); } catch (e) { err = e; }
  t('非 2xx：抛出带阶段的错误', err && err.sfbStage === 'http', err && err.sfbStage);
  t('非 2xx：保留状态码', err && err.sfbStatus === 429, err && err.sfbStatus);
  t('非 2xx：抽到 body 里的 error 字段', err && /今天的提交次数已达上限/.test(err.sfbDetail), err && err.sfbDetail);
  t('非 2xx 端到端文案可读', err && describe(err, EP).indexOf('HTTP 429') !== -1);

  // 3.3 404 返回 HTML（Worker 路由不存在时的典型形态）
  setFetch(function () { return Promise.resolve(resp(404, '<html><body><h1>Not Found</h1></body></html>')); });
  err = null;
  try { await post(EP, { message: 'x' }); } catch (e) { err = e; }
  t('非 JSON 正文：剥标签后仍能给出说明', err && /Not Found/.test(err.sfbDetail), err && err.sfbDetail);

  // 3.4 网络层 reject 原样上抛（由 describe 归类）
  setFetch(function () { return Promise.reject(new TypeError('Failed to fetch')); });
  err = null;
  try { await post(EP, { message: 'x' }); } catch (e) { err = e; }
  t('网络层 reject：不带 sfbStage（交给网络分支解释）', err && !err.sfbStage, err && err.sfbStage);
  t('网络层 reject：文案走「无法连接」', err && describe(err, EP).indexOf('无法连接') !== -1);

  // 3.5 读 body 本身失败
  setFetch(function () {
    return Promise.resolve({ ok: false, status: 500, text: function () { return Promise.reject(new Error('stream error')); } });
  });
  err = null;
  try { await post(EP, { message: 'x' }); } catch (e) { err = e; }
  t('body 读取失败：仍按 HTTP 500 归类', err && err.sfbStage === 'http' && err.sfbStatus === 500, err && err.sfbStatus);

  // ---------- 4. 可达性探测 / DoH 判定 ----------
  const probe = ctx.sfbProbeReachability;
  const report = ctx.sfbReportMailFailure;
  const verdict = ctx.sfbDnsVerdict;
  const tick = () => new Promise((r) => setTimeout(r, 30));
  const isDoh = (u) => /alidns|cloudflare-dns/.test(String(u));

  setFetch(function () { return Promise.resolve({}); });   // opaque response：CORS 不校验
  t('探测：no-cors 拿到 opaque 响应 → reachable', (await probe(EP)) === 'reachable');

  setFetch(function () { return Promise.reject(new TypeError('Failed to fetch')); });
  t('探测：网络层失败 → unreachable', (await probe(EP)) === 'unreachable');

  setFetch(function (u) { return Promise.resolve(isDoh(u) ? jsonResp({ Status: 0, Answer: [{ data: '1.2.3.4' }] }) : {}); });
  t('DoH：有 Answer → resolved', (await verdict(HOST)) === 'resolved');

  setFetch(function (u) { return Promise.resolve(isDoh(u) ? jsonResp({ Status: 3 }) : {}); });
  t('DoH：NXDOMAIN → nxdomain', (await verdict(HOST)) === 'nxdomain');

  setFetch(function (u) { return Promise.resolve(isDoh(u) ? jsonResp({ Status: 2 }) : {}); });
  t('DoH：SERVFAIL → unknown（不猜）', (await verdict(HOST)) === 'unknown');

  setFetch(function () { return Promise.reject(new TypeError('Failed to fetch')); });
  t('DoH：全部通道失败 → unknown', (await verdict(HOST)) === 'unknown');

  // ---------- 5. 失败出口：「诊断」行只写命中的那一条 ----------
  {
    const seen = [];
    setFetch(function () { return Promise.reject(new TypeError('Failed to fetch')); });
    report(new TypeError('Failed to fetch'), EP, function (x) { seen.push(x); });
    t('失败出口：立刻给出原因，不让用户干等', seen.length === 1 && seen[0].indexOf('无法连接') !== -1, JSON.stringify(seen));
    await tick();
    t('网络真不通且查不到证据：不追加「诊断」误诊', seen.length === 1 && seen[0].indexOf('诊断：') === -1, JSON.stringify(seen));
  }
  {
    const seen = [];
    setFetch(function (u) { return Promise.resolve(isDoh(u) ? jsonResp({ Status: 0, Answer: [] }) : {}); });
    report(new TypeError('Failed to fetch'), EP, function (x) { seen.push(x); });
    await tick();
    t('探测可达：追加「诊断：跨域被拒…」', seen.length === 2 && /诊断：跨域被拒/.test(seen[1]), JSON.stringify(seen));
    t('追加后仍是四行版式（不丢常见原因/扩展 ID 结构）', seen.length === 2 && seen[1].indexOf(NET_REASONS) !== -1);
  }
  {
    const seen = [];
    // 探测不通 + DoH 说域名不存在
    setFetch(function (u) {
      if (isDoh(u)) return Promise.resolve(jsonResp({ Status: 3 }));
      return Promise.reject(new TypeError('Failed to fetch'));
    });
    report(new TypeError('Failed to fetch'), EP, function (x) { seen.push(x); });
    await tick(); await tick();
    t('不通 + 域名查无：诊断为 DNS 解析失败', seen.length === 2 && /诊断：DNS 解析失败/.test(seen[1]), JSON.stringify(seen));
  }
  {
    const seen = [];
    // 探测不通 + DoH 能解析 → 出网与解析都正常，只有这条连接被拦
    setFetch(function (u) {
      if (isDoh(u)) return Promise.resolve(jsonResp({ Status: 0, Answer: [{ data: '1.2.3.4' }] }));
      return Promise.reject(new TypeError('Failed to fetch'));
    });
    report(new TypeError('Failed to fetch'), EP, function (x) { seen.push(x); });
    await tick(); await tick();
    t('不通 + 能解析：诊断为被防火墙拦截', seen.length === 2 && /诊断：被防火墙拦截/.test(seen[1]), JSON.stringify(seen));
  }
  {
    const seen = [];
    const e = new Error('HTTP 500');
    e.sfbStage = 'http'; e.sfbStatus = 500; e.sfbDetail = '';
    let probed = false, doh = false;
    setFetch(function (u) { if (isDoh(u)) doh = true; else probed = true; return Promise.resolve({}); });
    report(e, EP, function (x) { seen.push(x); });
    await tick();
    t('HTTP 层：只输出一次，不做多余探测', seen.length === 1 && probed === false && doh === false);
  }
  {
    const seen = [];
    setFetch(function () { return Promise.resolve({}); });
    ctx.navigator = { onLine: false };
    report(new TypeError('Failed to fetch'), EP, function (x) { seen.push(x); });
    ctx.navigator = { onLine: true };
    await tick();
    t('已离线：首屏就带「诊断：网络故障」，不再探测', seen.length === 1 && /诊断：网络故障/.test(seen[0]), JSON.stringify(seen));
  }

  // ---------- 6. 本机扩展 ID（新电脑失败的高频原因） ----------
  {
    ctx.chrome = { runtime: { id: 'abcdefghijklmnopabcdefghijklmnop' } };
    const L = lines(describe(new TypeError('Failed to fetch'), EP));
    const idLine = L.filter((x) => x.indexOf('本机扩展 ID：') === 0);
    t('网络失败时显示本机扩展 ID', idLine.length === 1 && idLine[0].indexOf('abcdefghijklmnopabcdefghijklmnop') !== -1, JSON.stringify(L));
    t('扩展 ID 行在「常见原因」之后', L.indexOf(idLine[0]) === 2, L.indexOf(idLine[0]) + '');
    ctx.chrome = undefined;
    t('无 chrome 上下文时不输出空 ID 行', describe(new TypeError('Failed to fetch'), EP).indexOf('本机扩展 ID') === -1);
  }

  console.log('\n' + pass + ' passed, ' + fail + ' failed');
  process.exit(fail ? 1 : 0);
})();
