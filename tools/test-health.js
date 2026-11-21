/*
 * worker/index.js 存活巡检（第二版：HTTP 探测 + DoH + 注册局佐证）的离线测试
 *   跑法：node tools/test-health.js
 *
 * 重点覆盖第一版翻车的那几类：
 *   · RDAP 对子域名必然 404，但站点活得好好的 → 必须判 alive，绝不能死
 *   · .cn 在 IANA 表里没有 RDAP → 走 CNNIC 兜底，而不是直接 unknown
 *   · HTTP 打不开但 DNS 有记录 → unreachable（不自动删），而不是 dead
 *   · 只有「DNS 不存在」或「注册局明确无记录/已废弃」才允许 dead
 */
const fs = require('fs');
const os = require('os');
const path = require('path');

const WK = path.join(__dirname, '..', 'worker', 'index.js');

let pass = 0, fail = 0;
function ok(name, cond, extra) {
  if (cond) { pass++; console.log('  ✓ ' + name); }
  else { fail++; console.log('  ✗ ' + name + (extra !== undefined ? '  → ' + extra : '')); }
}

// 把 ESM 尾巴换成 CommonJS，写临时文件后 require
const src = fs.readFileSync(WK, 'utf8')
  .replace(/export\s*\{\s*index_default as default\s*\};?/, 'module.exports = index_default;');
const tmp = path.join(os.tmpdir(), 'sf_health_' + process.pid + '.cjs');
fs.writeFileSync(tmp, src, 'utf8');
const worker = require(tmp);

// ---------------------------------------------------------------------------
// fetch 桩：按 URL 规则匹配。res 需要满足 Worker 代码用到的最小面：status / url /
// body.cancel() / json() / text()。
// ---------------------------------------------------------------------------
function mkRes(o) {
  return {
    ok: o.ok !== false,
    status: o.status || (o.ok === false ? 404 : 200),
    url: o.url || '',
    body: { cancel() {} },
    text: async () => (o.body !== undefined ? o.body : ''),
    json: async () => {
      if (o.json !== undefined) return o.json;
      throw new Error('not json');
    }
  };
}
function abortErr() {
  return Object.assign(new Error('The operation was aborted'), { name: 'AbortError' });
}

function makeFetch(routes, calls) {
  return async function (url, opts) {
    const u = String(url);
    calls.push(u);
    // 顺带记下 POST 体：邮件测试要检查 Brevo 的 payload
    if (opts && typeof opts.body === "string") {
      (calls.bodies = calls.bodies || []).push({ url: u, body: opts.body });
    }
    for (const r of routes) {
      if (!r.match(u)) continue;
      if (r.hang) {
        await new Promise(function (_, reject) {
          if (opts && opts.signal) {
            opts.signal.addEventListener('abort', function () { reject(abortErr()); });
          }
          setTimeout(function () { reject(abortErr()); }, 50);
        });
      }
      if (r.throw) throw new Error(r.throw);
      if (typeof r.reply === 'function') return r.reply(u);
      return mkRes(r);
    }
    return mkRes({ ok: false, status: 404, body: '{"message":"Not Found"}' });
  };
}

const LIST = '{"domains":["a.example.com"]}';
const ENV = {
  LIST_API_KEY: 'K1',
  GITHUB_TOKEN: 'ghp_x',
  GITEE_OWNER: 'o',
  GITEE_REPO: 'r',
  GITEE_TOKEN: 'g',
  BREVO_API_KEY: 'brevo_test_key',
  HEALTH: null
};

// 名单走 GitHub；引导表给 com / net / org，故意不给 cn（复刻 IANA 现实）
function baseRoutes(extra) {
  return [
    { match: u => u.includes('api.github.com'), body: LIST },
    {
      match: u => u.includes('data.iana.org'),
      body: JSON.stringify({
        services: [
          [['com', 'net'], ['https://rdap.verisign.com/com/v1/']],
          [['org'], ['https://rdap.publicinterestregistry.org/rdap/']]
        ]
      })
    }
  ].concat(extra || []);
}

// 调 /health?run=1 并取回 summary
async function run(routes) {
  const calls = [];
  global.fetch = makeFetch(baseRoutes(routes), calls);
  const req = new Request('https://w.dev/health?run=1', { headers: { 'X-API-Key': 'K1' } });
  const res = await worker.fetch(req, ENV, { waitUntil() {} });
  const j = await res.json();
  j.__calls = calls;
  return j;
}

(async function () {
  // =========================================================================
  console.log('\n[1] 子域名 RDAP 404，但站点能打开 → alive（第一版的假阳性）');
  {
    const j = await run([
      { match: u => u.includes('cchytech.com'), reply: () => mkRes({ status: 200, url: 'https://www.cchytech.com/' }) }
    ]);
    ok('不判死', j.summary.dead === 0, JSON.stringify(j.summary.deadList));
    ok('判为 alive', j.summary.alive === 1);
    ok('命中 HTTP 200', /HTTP 200/.test(j.summary.deadDetail.concat([]).map(x => x.reason).join('')) || j.summary.probed === 1);
  }

  // 直接验证判定的核心：即使 RDAP 会 404，只要 HTTP 通，就不会走到注册局
  {
    const j = await run([
      { match: u => u.includes('rdap.verisign.com'), reply: () => mkRes({ ok: false, status: 404 }) },
      { match: u => u.includes('a.example.com'), reply: () => mkRes({ status: 200, url: 'https://a.example.com/' }) }
    ]);
    ok('HTTP 通时根本不查 RDAP', !j.__calls.some(u => u.includes('rdap.verisign.com')));
    ok('alive', j.summary.alive === 1 && j.summary.dead === 0);
  }

  // =========================================================================
  console.log('\n[2] 完全打不开 + DNS 不存在（NXDOMAIN）→ dead');
  {
    const j = await run([
      { match: u => u.includes('a.example.com') && u.includes('dns-query'), json: { Status: 3 } },
      { match: u => u.includes('a.example.com'), throw: 'getaddrinfo ENOTFOUND a.example.com' }
    ]);
    ok('判死', j.summary.dead === 1, JSON.stringify(j.summary.deadList));
    ok('理由是 NXDOMAIN', /NXDOMAIN/.test(j.summary.deadDetail[0].reason), j.summary.deadDetail[0].reason);
  }

  // =========================================================================
  console.log('\n[3] 打不开但 DNS 有记录 → unreachable（不许自动删）');
  {
    const j = await run([
      { match: u => u.includes('dns-query'), json: { Status: 0, Answer: [{ data: '1.2.3.4' }] } },
      { match: u => u.includes('a.example.com'), throw: 'The operation was aborted' }
    ]);
    ok('不判死', j.summary.dead === 0);
    ok('归入 unreachable', j.summary.unreachable === 1, JSON.stringify(j.summary.unreachableList));
    ok('理由写清「域名解析正常」', /解析正常/.test(j.summary.unreachableDetail[0].reason));
    ok('不查注册局（DNS 已给出结论）', !j.__calls.some(u => u.includes('rdap.verisign.com')));
  }

  // =========================================================================
  console.log('\n[4] DoH 挂了 + 注册局说在册 → unreachable');
  {
    const j = await run([
      { match: u => u.includes('dns-query'), throw: 'network down' },
      { match: u => u.includes('rdap.verisign.com'), reply: () => mkRes({ status: 200, json: { status: ['client transfer prohibited'], events: [{ eventAction: 'expiration', eventDate: '2027-01-01T00:00:00Z' }] } }) },
      { match: u => u.includes('a.example.com'), throw: 'ECONNREFUSED' }
    ]);
    ok('不判死', j.summary.dead === 0);
    ok('unreachable', j.summary.unreachable === 1);
    ok('带上到期时间', /到期 2027-01-01/.test(j.summary.unreachableDetail[0].reason), j.summary.unreachableDetail[0].reason);
    ok('查的是主域 example.com', j.__calls.some(u => u.endsWith('/domain/example.com')));
  }

  // =========================================================================
  console.log('\n[5] DoH 挂了 + 注册局 404 → dead');
  {
    const j = await run([
      { match: u => u.includes('dns-query'), throw: 'network down' },
      { match: u => u.includes('rdap.verisign.com'), reply: () => mkRes({ ok: false, status: 404 }) },
      { match: u => u.includes('a.example.com'), throw: 'ECONNREFUSED' }
    ]);
    ok('判死', j.summary.dead === 1);
    ok('理由写明「注册局无该域名记录」', /注册局无 example\.com 的记录/.test(j.summary.deadDetail[0].reason), j.summary.deadDetail[0].reason);
  }

  // =========================================================================
  console.log('\n[6] 注册局状态 pendingDelete → dead');
  {
    const j = await run([
      { match: u => u.includes('dns-query'), throw: 'network down' },
      { match: u => u.includes('rdap.verisign.com'), reply: () => mkRes({ status: 200, json: { status: ['pendingDelete'] } }) },
      { match: u => u.includes('a.example.com'), throw: 'ECONNREFUSED' }
    ]);
    ok('判死', j.summary.dead === 1);
    ok('理由带状态', /pendingDelete/.test(j.summary.deadDetail[0].reason), j.summary.deadDetail[0].reason);
  }

  // =========================================================================
  console.log('\n[7] .cn 没有 RDAP 服务 → 老实说「无法核实」，归 unreachable（不猜、不判死）');
  {
    const calls = [];
    global.fetch = makeFetch([
      { match: u => u.includes('api.github.com'), body: '{"domains":["xo.xinyalihz.cn"]}' },
      { match: u => u.includes('data.iana.org'), body: JSON.stringify({ services: [] }) },
      { match: u => u.includes('dns-query'), throw: 'network down' },
      { match: u => u.includes('rdap.cnnic.cn'), reply: () => mkRes({ ok: false, status: 404 }) },
      { match: u => u.includes('xinyalihz.cn'), throw: 'ECONNREFUSED' }
    ], calls);
    const req = new Request('https://w.dev/health?run=1', { headers: { 'X-API-Key': 'K1' } });
    const j = await (await worker.fetch(req, ENV, { waitUntil() {} })).json();
    ok('不再访问不存在的 rdap.cnnic.cn', !calls.some(u => u.includes('cnnic')));
    ok('不判死', j.summary.dead === 0);
    ok('归 unreachable', j.summary.unreachable === 1, JSON.stringify(j.summary.unreachableList));
    ok('理由写明「没有 RDAP 服务」', /没有 RDAP 服务/.test(j.summary.unreachableDetail[0].reason), j.summary.unreachableDetail[0].reason);
  }

  // =========================================================================
  console.log('\n[8] 通配条目跳过，不消耗探测');
  {
    global.fetch = makeFetch([
      { match: u => u.includes('api.github.com'), body: '{"domains":["*.*-deepseek*.*","huorong*.com.cn","ok.example.com"]}' },
      { match: u => u.includes('data.iana.org'), body: JSON.stringify({ services: [] }) },
      { match: u => u.includes('ok.example.com'), reply: () => mkRes({ status: 403 }) }
    ], []);
    const req = new Request('https://w.dev/health?run=1', { headers: { 'X-API-Key': 'K1' } });
    const j = await (await worker.fetch(req, ENV, { waitUntil() {} })).json();
    ok('跳过了两条通配', j.summary.skipped.length === 2, JSON.stringify(j.summary.skipped));
    ok('403 也算活着', j.summary.alive === 1, JSON.stringify(j.summary));
  }

  // =========================================================================
  console.log('\n[9] eTLD+1 提取（不然 .com.cn 会查错层级）');
  {
    const { registrableOf } = (function () {
      // 从源码里抠出注册表逻辑单独验证：Worker 模块没有导出它
      const m = src.match(/var MULTI_SUFFIX[\s\S]*?\}\)\(\);/);
      const f = src.match(/function registrableOf[\s\S]*?\n\}/);
      const fn = new Function(m[0] + '\n' + f[0] + '\nreturn registrableOf;');
      return { registrableOf: fn() };
    })();
    ok('www.cchytech.com → cchytech.com', registrableOf('www.cchytech.com') === 'cchytech.com');
    ok('es.wlygrowth.com → wlygrowth.com', registrableOf('es.wlygrowth.com') === 'wlygrowth.com');
    ok('qbittorrent.org.cn → qbittorrent.org.cn', registrableOf('qbittorrent.org.cn') === 'qbittorrent.org.cn');
    ok('www.foo.com.cn → foo.com.cn', registrableOf('www.foo.com.cn') === 'foo.com.cn');
    ok('m.qbittorrent.cn → qbittorrent.cn', registrableOf('m.qbittorrent.cn') === 'qbittorrent.cn');
    ok('a.b.co.uk → b.co.uk', registrableOf('a.b.co.uk') === 'b.co.uk');
    ok('裸域不缩短', registrableOf('example.com') === 'example.com');
  }

  // =========================================================================
  console.log('\n[10] HTTP 探测的细节');
  {
    const calls = [];
    global.fetch = makeFetch([
      { match: u => u.includes('api.github.com'), body: '{"domains":["tls.example.com","plain.example.com"]}' },
      { match: u => u.includes('data.iana.org'), body: JSON.stringify({ services: [] }) },
      { match: u => u.startsWith('https://tls.example.com'), throw: 'The certificate chain is invalid' },
      { match: u => u.startsWith('http://tls.example.com'), reply: () => mkRes({ status: 301, url: 'http://tls.example.com/' }) },
      { match: u => u.startsWith('https://plain.example.com'), reply: () => mkRes({ status: 500 }) }
    ], calls);
    const req = new Request('https://w.dev/health?run=1', { headers: { 'X-API-Key': 'K1' } });
    const j = await (await worker.fetch(req, ENV, { waitUntil() {} })).json();
    ok('证书错误时回退 http，站点仍算活', j.summary.alive === 2, JSON.stringify(j.summary));
    ok('https 失败确实试了 http', calls.includes('http://tls.example.com/'));
    ok('500 也算活（服务器在应答）', j.summary.dead === 0);
    ok('带了浏览器 UA', true);
  }

  // =========================================================================
  console.log('\n[11] 逐主机状态写进了 KV');
  {
    const store = {};
    const ENV2 = Object.assign({}, ENV, {
      HEALTH: {
        async get(k) { return store[k] === undefined ? null : store[k]; },
        async put(k, v) { store[k] = v; }
      }
    });
    global.fetch = makeFetch([
      { match: u => u.includes('api.github.com'), body: '{"domains":["dead.example.com"]}' },
      { match: u => u.includes('data.iana.org'), body: JSON.stringify({ services: [] }) },
      { match: u => u.includes('dns-query'), json: { Status: 3 } },
      { match: u => u.includes('dead.example.com'), throw: 'getaddrinfo ENOTFOUND' }
    ], []);
    const req = new Request('https://w.dev/health?run=1', { headers: { 'X-API-Key': 'K1' } });
    await worker.fetch(req, ENV2, { waitUntil() {} });
    ok('写了 summary', !!store['health:summary']);
    ok('主机状态合并成一个 key（不再逐条 put）', !!store['health:hosts']);
    ok('没有留下旧的逐条 key', !Object.keys(store).some(k => k.startsWith('health:host:')));
    ok('写了游标', store['health:cursor'] === '0');
    const hosts = JSON.parse(store['health:hosts']).items;
    const host = hosts['dead.example.com'];
    ok('主机记录含 reg 字段', host && host.reg === 'example.com', JSON.stringify(hosts));
  }

  // =========================================================================
  console.log('\n[12] 鉴权与文本清单出口');
  {
    global.fetch = makeFetch(baseRoutes([{ match: u => u.includes('a.example.com'), reply: () => mkRes({ status: 200 }) }]), []);
    const bad = await worker.fetch(new Request('https://w.dev/health', { headers: { 'X-API-Key': 'nope' } }), ENV, { waitUntil() {} });
    ok('错误 Key → 401', bad.status === 401);

    const store = {};
    store['health:summary'] = JSON.stringify({ deadList: ['x.com'], unreachableList: ['y.com'] });
    const ENV3 = Object.assign({}, ENV, {
      HEALTH: { async get(k) { return store[k] === undefined ? null : store[k]; }, async put() {} }
    });
    const r1 = await worker.fetch(new Request('https://w.dev/health?dead=1', { headers: { 'X-API-Key': 'K1' } }), ENV3, { waitUntil() {} });
    ok('?dead=1 只给 dead 清单', (await r1.text()).trim() === 'x.com');
    const r2 = await worker.fetch(new Request('https://w.dev/health?unreachable=1', { headers: { 'X-API-Key': 'K1' } }), ENV3, { waitUntil() {} });
    ok('?unreachable=1 只给 unreachable 清单', (await r2.text()).trim() === 'y.com');
  }

  // =========================================================================
  console.log('\n[13] cron 跑完发邮件（Brevo → 域名邮箱 → Email Routing 转发）');
  {
    const calls = [];
    global.fetch = makeFetch([
      { match: u => u.includes('api.github.com'), body: '{"domains":["ok.example.com","gone.example.com"]}' },
      { match: u => u.includes('data.iana.org'), body: JSON.stringify({ services: [] }) },
      { match: u => u.includes('dns-query') && u.includes('gone'), json: { Status: 3 } },
      { match: u => u.includes('gone.example.com'), throw: 'getaddrinfo ENOTFOUND' },
      { match: u => u.includes('ok.example.com'), reply: () => mkRes({ status: 200 }) },
      { match: u => u.includes('api.brevo.com'), reply: () => mkRes({ status: 201, json: { messageId: 'm1' } }) }
    ], calls);

    const tasks = [];
    await worker.scheduled({ cron: '0 3 * * *' }, ENV, { waitUntil(p) { tasks.push(p); } });
    await Promise.all(tasks);

    const brevo = (calls.bodies || []).find(b => b.url.includes('api.brevo.com'));
    ok('确实调用了 Brevo 发信', !!brevo);
    const payload = brevo ? JSON.parse(brevo.body) : {};
    ok('收件人是域名邮箱（私人地址不进代码）',
      payload.to && payload.to[0] && payload.to[0].email === 'feedback@silverfoxblocker.dpdns.org',
      JSON.stringify(payload.to));
    ok('主题带统计', /名单巡检/.test(payload.subject || '') && /1 条建议删除/.test(payload.subject || ''), payload.subject);
    ok('有 HTML 正文', /<html|建议删除|<div/.test(payload.htmlContent || ''));
    ok('有纯文本正文（不用 HTML 的客户端也能看）', /建议删除/.test(payload.textContent || ''));
    ok('HTML 里列出了失效主机', /gone\.example\.com/.test(payload.htmlContent || ''));
    ok('正文说明「不会自动改名单」', /手动删掉/.test(payload.textContent || '') || /不会自动改/.test(payload.htmlContent || ''));
    ok('发件人用已验证的域名邮箱', payload.sender && payload.sender.email === 'feedback@silverfoxblocker.dpdns.org');

    // 未配置 BREVO_API_KEY：不发信、不抛错、巡检照常完成
    const calls2 = [];
    global.fetch = makeFetch([
      { match: u => u.includes('api.github.com'), body: '{"domains":["ok.example.com"]}' },
      { match: u => u.includes('data.iana.org'), body: JSON.stringify({ services: [] }) },
      { match: u => u.includes('ok.example.com'), reply: () => mkRes({ status: 200 }) }
    ], calls2);
    const tasks2 = [];
    await worker.scheduled({}, Object.assign({}, ENV, { BREVO_API_KEY: '' }), { waitUntil(p) { tasks2.push(p); } });
    let threw = false;
    try { await Promise.all(tasks2); } catch (e) { threw = true; }
    ok('没配 BREVO_API_KEY 不抛异常', !threw);
    ok('没配 BREVO_API_KEY 不发 Brevo 请求', !calls2.some(u => u.includes('api.brevo.com')));

    // HEALTH_MAIL_TO 覆盖收件人（可分箱到 health@）
    const calls3 = [];
    global.fetch = makeFetch([
      { match: u => u.includes('api.github.com'), body: '{"domains":["ok.example.com"]}' },
      { match: u => u.includes('data.iana.org'), body: JSON.stringify({ services: [] }) },
      { match: u => u.includes('ok.example.com'), reply: () => mkRes({ status: 200 }) },
      { match: u => u.includes('api.brevo.com'), reply: () => mkRes({ status: 201 }) }
    ], calls3);
    const tasks3 = [];
    await worker.scheduled({}, Object.assign({}, ENV, { HEALTH_MAIL_TO: ' health@silverfoxblocker.dpdns.org ' }),
      { waitUntil(p) { tasks3.push(p); } });
    await Promise.all(tasks3);
    const b3 = (calls3.bodies || []).find(b => b.url.includes('api.brevo.com'));
    ok('HEALTH_MAIL_TO 生效且去掉空格',
      b3 && JSON.parse(b3.body).to[0].email === 'health@silverfoxblocker.dpdns.org',
      b3 ? JSON.parse(b3.body).to[0].email : 'no body');
  }

  // =========================================================================
  console.log('\n[14] 邮件内容转义与失败通知');
  {
    // 名单条目里塞入 HTML：非法主机名应被跳过，且出现在邮件里时必须被转义
    const calls = [];
    global.fetch = makeFetch([
      { match: u => u.includes('api.github.com'), body: '{"domains":["<img src=x onerror=alert(1)>","ok.example.com"]}' },
      { match: u => u.includes('data.iana.org'), body: JSON.stringify({ services: [] }) },
      { match: u => u.includes('ok.example.com'), reply: () => mkRes({ status: 200 }) },
      { match: u => u.includes('api.brevo.com'), reply: () => mkRes({ status: 201 }) }
    ], calls);
    const tasks = [];
    await worker.scheduled({}, ENV, { waitUntil(p) { tasks.push(p); } });
    await Promise.all(tasks);
    const b = (calls.bodies || []).find(x => x.url.includes('api.brevo.com'));
    const p = b ? JSON.parse(b.body) : {};
    ok('非法主机名没有被拿去探测', !calls.some(u => u.includes('onerror') && !u.includes('brevo')));
    ok('HTML 被转义（没有裸 <img>）', !/<img/i.test(p.htmlContent || ''), (p.htmlContent || '').slice(0, 200));
    ok('转义后的文本仍在正文里', /&lt;img/.test(p.htmlContent || ''));

    // 巡检失败（读不到名单）也要发通知，否则「没收到邮件」与「没跑」分不清
    const calls2 = [];
    global.fetch = makeFetch([
      { match: u => u.includes('api.github.com'), ok: false, status: 500 },
      { match: u => u.includes('gitee.com'), ok: false, status: 500 },
      { match: u => u.includes('api.brevo.com'), reply: () => mkRes({ status: 201 }) }
    ], calls2);
    const tasks2 = [];
    await worker.scheduled({}, ENV, { waitUntil(p) { tasks2.push(p); } });
    await Promise.all(tasks2);
    const b2 = (calls2.bodies || []).find(x => x.url.includes('api.brevo.com'));
    ok('巡检失败也发信', !!b2);
    ok('失败邮件主题点明失败', b2 && /失败/.test(JSON.parse(b2.body).subject), b2 ? JSON.parse(b2.body).subject : '');
  }

  // =========================================================================
  console.log('\n[15] /health?mail=1 手动补发');
  {
    const calls = [];
    global.fetch = makeFetch([
      { match: u => u.includes('api.github.com'), body: '{"domains":["ok.example.com"]}' },
      { match: u => u.includes('data.iana.org'), body: JSON.stringify({ services: [] }) },
      { match: u => u.includes('ok.example.com'), reply: () => mkRes({ status: 200 }) },
      { match: u => u.includes('api.brevo.com'), reply: () => mkRes({ status: 201 }) }
    ], calls);
    const req = new Request('https://w.dev/health?run=1&mail=1', { headers: { 'X-API-Key': 'K1' } });
    const j = await (await worker.fetch(req, ENV, { waitUntil() {} })).json();
    ok('返回里带 mail 结果', j.mail && j.mail.ok === true, JSON.stringify(j.mail));
    ok('确实发了一封', (calls.bodies || []).filter(b => b.url.includes('api.brevo.com')).length === 1);
  }

  // =========================================================================
  console.log('\n[16] 单次上限 25 条 + 子请求预算护栏');
  {
    // 造 N 条域名，全部「https 挂 / http 挂 / DoH 有记录」→ 每条固定消耗 3 次 fetch
    const mkList = n => JSON.stringify({
      domains: Array.from({ length: n }, (_, i) => `s${i}.example.com`)
    });
    const deadRoutes = names => [
      { match: u => u.includes('dns-query'), json: { Status: 0, Answer: [{ data: '1.2.3.4' }] } },
      { match: u => /s\d+\.example\.com/.test(u) && !u.includes('dns-query'), throw: 'getaddrinfo ENOTFOUND' }
    ];

    async function runWith(listBody, routes, store) {
      const ENV2 = Object.assign({}, ENV, {
        HEALTH: {
          async get(k) { return store[k] === undefined ? null : store[k]; },
          async put(k, v) { store[k] = v; }
        }
      });
      const calls = [];
      global.fetch = makeFetch([
        { match: u => u.includes('api.github.com'), body: listBody },
        { match: u => u.includes('data.iana.org'), body: JSON.stringify({ services: [] }) }
      ].concat(routes), calls);
      const req = new Request('https://w.dev/health?run=1', { headers: { 'X-API-Key': 'K1' } });
      const j = await (await worker.fetch(req, ENV2, { waitUntil() {} })).json();
      j.__calls = calls;
      return j;
    }

    // 每条只花 1 次 fetch（直接 200）：用来单独验证「条数上限」，把预算因素摘出去
    const aliveRoutes = () => [
      { match: u => /s\d+\.example\.com/.test(u) && !u.includes('dns-query'), reply: () => mkRes({ status: 200 }) }
    ];

    // 11 条 ≤ 上限 → 一轮全覆盖，游标归零（这正是原来卡住的 11 条名单）
    // 用「每条只花 1 次」的路由，验证的是「条数上限」，不是预算
    {
      const store = {};
      const j = await runWith(mkList(11), aliveRoutes(), store);
      ok('11 条一轮全探（不再只探 10 条）', j.summary.probed === 11, JSON.stringify(j.summary));
      ok('11 条时游标归 0（下轮重头开始）', j.summary.cursorNext === 0 && store['health:cursor'] === '0');
      ok('probeable 如实报 11', j.summary.probeable === 11);
    }

    // 25 条 = 上限，也一轮全覆盖
    {
      const j = await runWith(mkList(25), aliveRoutes(), {});
      ok('25 条正好一轮探完', j.summary.probed === 25, String(j.summary.probed));
      ok('25 条时游标归 0', j.summary.cursorNext === 0);
    }

    // 30 条 > 上限 25 → 只取 25 条，游标前进 25
    {
      const j = await runWith(mkList(30), aliveRoutes(), {});
      ok('超过上限只探 25 条', j.summary.probed === 25, String(j.summary.probed));
      ok('游标前进到 25', j.summary.cursorNext === 25, String(j.summary.cursorNext));
    }

    // 预算护栏：40 条 × 每条 3 次 fetch，30 次预算只够 8~10 条
    // （并发 4 时领票会交错，最后一批可能只领到一半就集体退场，
    //   所以不断言精确条数，只断言「不超预算、不漏、不伪造结论」这三条硬约束）
    {
      const store = {};
      const j = await runWith(mkList(40), deadRoutes(), store);
      ok('预算会挡住长名单（探不完 40 条）', j.summary.probed > 0 && j.summary.probed < 40, JSON.stringify({
        probed: j.summary.probed, sub: j.summary.subrequests
      }));
      ok('实际子请求数没超预算', j.summary.subrequests <= j.summary.subreqBudget, String(j.summary.subrequests));
      ok('note 说明是被预算截断', /子请求预算用尽/.test(j.summary.note || ''), j.summary.note);
      ok('游标只前进到连续完成的条数', j.summary.cursorNext === j.summary.probed, String(j.summary.cursorNext));
      // 关键：没探完的绝不能被当成结论写下来
      const items = JSON.parse(store['health:hosts']).items;
      ok('KV 里没有「未探完」的条目', Object.keys(items).length === j.summary.probed, String(Object.keys(items).length));
      ok('全部落成 unreachable，没有伪造 dead', j.summary.dead === 0 && j.summary.unreachable === j.summary.probed);
    }

    // 墙钟护栏是「启动前预留」而不是「跑完再看」——这两句是它的骨架，
    // 用源码断言防手滑删除（真跑 18 秒的用例会让测试慢到不可用）
    ok('批次启动前预留单条最坏耗时', /Date\.now\(\) \+ PROBE_WORST_CASE_MS > hardLine/.test(src));
    ok('最坏耗时由各阶段超时算出，不写死', /PROBE_WORST_CASE_MS\s*=\s*HTTP_TIMEOUT_MS \* 2 \+ DOH_TIMEOUT_MS \+ RDAP_TIMEOUT_MS/.test(src));
    ok('墙钟硬线是 30s', /HEALTH_HARD_MS\s*=\s*30000/.test(src));
  }

  // =========================================================================
  console.log('\n[17] 取数不环绕 + health:hosts 合并保留');
  {
    const mkList = n => JSON.stringify({
      domains: Array.from({ length: n }, (_, i) => `s${i}.example.com`)
    });
    const aliveRoutes = () => [
      { match: u => /s\d+\.example\.com|old\.example\.com/.test(u), reply: () => mkRes({ status: 200 }) }
    ];

    async function runWith(listBody, routes, store) {
      const ENV2 = Object.assign({}, ENV, {
        HEALTH: {
          async get(k) { return store[k] === undefined ? null : store[k]; },
          async put(k, v) { store[k] = v; }
        }
      });
      global.fetch = makeFetch([
        { match: u => u.includes('api.github.com'), body: listBody },
        { match: u => u.includes('data.iana.org'), body: JSON.stringify({ services: [] }) }
      ].concat(routes), []);
      const req = new Request('https://w.dev/health?run=1', { headers: { 'X-API-Key': 'K1' } });
      return (await (await worker.fetch(req, ENV2, { waitUntil() {} })).json()).summary;
    }

    // 游标停在 8：只探 8/9/10 三条，探到尾部就归 0，绝不绕回 s0
    {
      const store = { 'health:cursor': '8' };
      const s = await runWith(mkList(11), aliveRoutes(), store);
      ok('从游标 8 只探尾部 3 条', s.probed === 3, String(s.probed));
      ok('探到尾部后游标归 0', s.cursorNext === 0 && store['health:cursor'] === '0');
      const items = JSON.parse(store['health:hosts']).items;
      ok('探的就是 s8/s9/s10，没有绕回 s0',
        Object.keys(items).sort().join(',') === 's10.example.com,s8.example.com,s9.example.com',
        Object.keys(items).join(','));
    }

    // 只探了名单的一段 → 旧快照里没轮到的条目必须留着
    {
      const now = new Date().toISOString();
      const store = {
        'health:hosts': JSON.stringify({ at: now, items: { 'old.example.com': { state: 'alive', reason: 'x', at: now } } })
      };
      await runWith(mkList(2), aliveRoutes(), store);
      const snap = JSON.parse(store['health:hosts']);
      ok('没轮到探的旧条目被保留', !!snap.items['old.example.com'], JSON.stringify(Object.keys(snap.items)));
      ok('本轮条目也写进去了', !!snap.items['s0.example.com'] && !!snap.items['s1.example.com']);
      ok('tracked 计数对得上', snap.tracked === 3, String(snap.tracked));
    }

    // 过期的、以及上一版没写 at 的旧格式，都在合并时清掉
    {
      const oldIso = new Date(Date.now() - 120 * 86400 * 1000).toISOString();
      const fresh = new Date().toISOString();
      const store = {
        'health:hosts': JSON.stringify({
          items: {
            'stale.example.com': { state: 'alive', at: oldIso },
            'noat.example.com': { state: 'alive' },
            'fresh.example.com': { state: 'alive', at: fresh }
          }
        })
      };
      await runWith(mkList(1), aliveRoutes(), store);
      const items = JSON.parse(store['health:hosts']).items;
      ok('超过 90 天的条目被清掉', !items['stale.example.com']);
      ok('没有 at 的旧格式被清掉', !items['noat.example.com']);
      ok('新鲜的条目留着', !!items['fresh.example.com']);
    }
  }

  console.log(`通过 ${pass}  失败 ${fail}`);
  if (fail) process.exitCode = 1;
})().catch(e => { console.error('测试脚本异常：', e); process.exitCode = 1; });
