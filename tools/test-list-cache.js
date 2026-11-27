/**
 * /list 的 5 分钟缓存（v1.13.15）回归测试
 *
 * 做法：把 worker/index.js 原样拷成 .mjs 直接 import，然后拿真实的 Request 打
 *   `mod.default.fetch(request, env, ctx)` —— 不是把逻辑切片重写一遍，而是跑真代码。
 *   上游 fetch 用桩替换（按 host 分流），KV 用内存 Map 模拟。
 *
 * 覆盖：
 *   ① 未命中 → 打上游一次；② 命中 → 一个上游请求都不发；③ 5 分钟后重新回源；
 *   ④ 上游全挂但有旧副本 → 发旧的（X-Data-Stale）；⑤ 没有旧副本 → 502；
 *   ⑥ nocache / diag / force 穿透缓存；⑦ 并发击穿合并；⑧ 黑白名单分开缓存；
 *   ⑨ 鉴权在缓存之前；⑩ 没绑 KV 时自动降级（行为同旧版）；⑪ 响应头如实标注。
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { pathToFileURL } = require('url');

let pass = 0, fail = 0;
function t(name, cond, extra) {
  if (cond) { pass++; return; }
  fail++;
  console.log('FAIL ' + name + (extra === undefined ? '' : '  ← ' + String(extra).slice(0, 300)));
}

const SRC = path.join(__dirname, '..', 'worker', 'index.js');

// ---------------------------------------------------------------- 内存 KV
function makeKv(store) {
  return {
    _store: store || new Map(),
    _gets: 0,
    _puts: 0,
    async get(k) {
      this._gets++;
      const v = this._store.get(k);
      return v === undefined ? null : v;
    },
    async put(k, v, opts) {
      this._puts++;
      this._store.set(k, v);
      return null;
    },
    dump() { return this._store; },
  };
}

// ---------------------------------------------------------------- 上游桩
function makeUpstream() {
  const calls = [];
  let mode = 'ok';   // ok | fail | slowfail
  const handler = async (url) => {
    calls.push(String(url));
    const host = new URL(String(url)).host;
    if (mode === 'fail') return { ok: false, status: 500, text: async () => 'boom' };
    if (mode === 'slowfail') {
      await new Promise((r) => setTimeout(r, 30));
      return { ok: false, status: 502, text: async () => 'bad gateway' };
    }
    if (mode === 'slowok') {
      await new Promise((r) => setTimeout(r, 30));
      return { ok: true, status: 200, text: async () => JSON.stringify({ domains: ['slow-a.com'] }) };
    }
    if (host === 'api.github.com') {
      return { ok: true, status: 200, text: async () => JSON.stringify({ domains: ['gh-a.com', 'gh-b.com'] }) };
    }
    if (host === 'gitee.com') {
      return { ok: true, status: 200, text: async () => JSON.stringify({ domains: ['gt-a.com'] }) };
    }
    return { ok: false, status: 404, text: async () => 'nope' };
  };
  return {
    handler,
    calls,
    setMode(m) { mode = m; },
    count(host) { return calls.filter((u) => new URL(u).host === host).length; },
    reset() { calls.length = 0; },
  };
}

async function main() {
  // import 真模块（.mjs 只是为了让 Node 按 ESM 解析）
  const tmp = path.join(os.tmpdir(), 'sfb-worker-' + process.pid + '.mjs');
  fs.copyFileSync(SRC, tmp);
  const mod = await import(pathToFileURL(tmp).href);
  const worker = mod.default;
  t('模块可加载：导出 fetch 入口', worker && typeof worker.fetch === 'function');

  const up = makeUpstream();
  const realFetch = globalThis.fetch;
  globalThis.fetch = up.handler;

  const ctx = { waitUntil(p) { if (p && p.catch) p.catch(() => {}); } };
  const req = (qs, key) => new Request('https://api.example.org/list' + (qs || ''), {
    method: 'GET',
    headers: Object.assign({ Origin: 'chrome-extension://testtesttesttesttesttesttesttest' },
      key === false ? {} : { 'X-API-Key': key || 'k-test' }),
  });
  const call = async (qs, key) => {
    const res = await worker.fetch(req(qs, key), env(), ctx);
    return { status: res.status, h: res.headers, body: await res.text() };
  };

  let kv = makeKv();
  function env(extra) {
    return Object.assign({
      LIST_API_KEY: 'k-test',
      GITHUB_TOKEN: 'gh-token',
      GITEE_OWNER: 'owner', GITEE_REPO: 'repo', GITEE_TOKEN: 'gt-token',
      HEALTH: kv,
    }, extra || {});
  }

  // ------------------------------------------------------------ ① 未命中 → 回源
  up.reset();
  let r1 = await call('');
  t('① 冷启动：HTTP 200', r1.status === 200, r1.status);
  t('① 冷启动：X-Cache=MISS', r1.h.text === undefined || r1.h.get('X-Cache') === 'MISS', r1.h.get('X-Cache'));
  t('① 冷启动：真的打了上游一次', up.count('api.github.com') === 1, up.calls);
  t('① 冷启动：返回的是 GitHub 的正文', r1.body.indexOf('gh-a.com') > -1, r1.body);
  t('① 冷启动：标明数据来源', r1.h.get('X-Data-Source') === 'GitHub', r1.h.get('X-Data-Source'));
  t('① 冷启动：不许浏览器再缓存一层', r1.h.get('Cache-Control') === 'no-store', r1.h.get('Cache-Control'));

  // ------------------------------------------------------------ ② 命中 → 零上游
  up.reset();
  let r2 = await call('');
  t('② 命中：HTTP 200', r2.status === 200);
  t('② 命中：X-Cache=HIT', r2.h.get('X-Cache') === 'HIT', r2.h.get('X-Cache'));
  t('② 命中：上游一次都没打', up.calls.length === 0, up.calls);
  t('② 命中：正文与首次完全一致', r2.body === r1.body, r2.body);
  t('② 命中：带 X-Cache-Age', /^\d+$/.test(r2.h.get('X-Cache-Age') || ''), r2.h.get('X-Cache-Age'));

  // 再打 20 次，仍然一次上游都不发
  up.reset();
  for (let i = 0; i < 20; i++) await call('');
  t('② 连打 20 次仍零上游', up.calls.length === 0, up.calls.length);

  // ------------------------------------------------------------ ③ 5 分钟后过期
  const key = 'list_cache_v1:blacklist_json';
  const rec = JSON.parse(kv.dump().get(key));
  t('③ 缓存键名符合预期', !!rec, [...kv.dump().keys()].join(','));
  rec.ts = Date.now() - 6 * 60 * 1000;   // 6 分钟前
  kv.dump().set(key, JSON.stringify(rec));
  up.reset();
  const r3 = await call('');
  t('③ 过期后重新回源', up.count('api.github.com') === 1, up.calls);
  t('③ 过期回源标 MISS（不是 STALE）', r3.h.get('X-Cache') === 'MISS', r3.h.get('X-Cache'));

  // ------------------------------------------------------------ ④ 上游全挂 → 发旧副本
  //   先把缓存戳成「已过期」（正常请求会读它但不认它新鲜），再让上游全挂
  {
    const k2 = 'list_cache_v1:blacklist_json';
    const staleRec = JSON.parse(kv.dump().get(k2));
    staleRec.ts = Date.now() - 30 * 60 * 1000;   // 半小时前，早已过期
    kv.dump().set(k2, JSON.stringify(staleRec));
  }
  up.setMode('fail');
  up.reset();
  const r4 = await call('');
  up.setMode('ok');
  t('④ 上游全挂但有旧副本：仍 200', r4.status === 200, r4.status);
  t('④ 兜底数据标 X-Cache=STALE', r4.h.get('X-Cache') === 'STALE', r4.h.get('X-Cache'));
  t('④ 明确标出这是旧数据', r4.h.get('X-Data-Stale') === '1', r4.h.get('X-Data-Stale'));
  t('④ 兜底内容不是错误 JSON', r4.body.indexOf('domains') > -1, r4.body.slice(0, 80));
  t('④ 兜底时确实尝试过两个源', up.count('api.github.com') > 0 && up.count('gitee.com') > 0, up.calls.length);

  // ------------------------------------------------------------ ⑤ 无缓存 + 上游全挂 → 502
  const kv2 = makeKv();
  up.setMode('fail');
  const savedKv = kv;
  kv = kv2;
  up.reset();
  const r5 = await call('');
  up.setMode('ok');
  kv = savedKv;
  t('⑤ 没有旧副本：502', r5.status === 502, r5.status);
  t('⑤ 502 仍带结构化原因', /github/.test(r5.body), r5.body.slice(0, 120));

  // ------------------------------------------------------------ ⑥ 穿透参数
  up.reset();
  const r6a = await call('?nocache=1');
  t('⑥ nocache=1：真回源', up.count('api.github.com') === 1, up.calls);
  t('⑥ nocache=1：X-Cache=REFRESH（不读但顺手刷新缓存）', r6a.h.get('X-Cache') === 'REFRESH', r6a.h.get('X-Cache'));

  // nocache 是「绕过缓存的公开参数」，必须给它加最短刷新间隔，否则它自己就成了刷上游的通道
  up.reset();
  const r6a2 = await call('?nocache=1');
  t('⑥ nocache 在 60 秒内：直接发缓存，零上游', up.calls.length === 0 && r6a2.h.get('X-Cache') === 'HIT',
    up.calls.length + '/' + r6a2.h.get('X-Cache'));
  // 把缓存戳老到 61 秒前，nocache 才允许真的回源
  {
    const k3 = 'list_cache_v1:blacklist_json';
    const r3rec = JSON.parse(kv.dump().get(k3));
    r3rec.ts = Date.now() - 61 * 1000;
    kv.dump().set(k3, JSON.stringify(r3rec));
  }
  up.reset();
  const r6a3 = await call('?nocache=1');
  t('⑥ nocache 超过 60 秒：才真的回源', up.count('api.github.com') === 1, up.calls);
  t('⑥ nocache 回源后标 REFRESH', r6a3.h.get('X-Cache') === 'REFRESH', r6a3.h.get('X-Cache'));

  up.reset();
  const r6b = await call('?diag=1');
  t('⑥ diag=1：回源', up.count('api.github.com') === 1, up.calls);
  t('⑥ diag=1：回诊断 JSON', /"elapsedMs"/.test(r6b.body), r6b.body.slice(0, 80));

  up.reset();
  const r6c = await call('?force=gitee');
  t('⑥ force=gitee：跳过 GitHub', up.count('api.github.com') === 0, up.calls);
  t('⑥ force=gitee：打了 Gitee', up.count('gitee.com') === 1, up.calls);
  t('⑥ force=gitee：数据源标 Gitee', r6c.h.get('X-Data-Source') === 'Gitee', r6c.h.get('X-Data-Source'));
  // force 的结果不能污染正常缓存（回到默认请求仍应命中 GitHub 缓存）
  up.reset();
  const r6d = await call('');
  t('⑥ force 请求不写缓存：默认请求仍命中旧缓存', up.calls.length === 0 && r6d.h.get('X-Cache') === 'HIT',
    up.calls.length + '/' + r6d.h.get('X-Cache'));

  // ------------------------------------------------------------ ⑦ 并发击穿合并
  const kv3 = makeKv();
  kv = kv3;
  up.setMode('slowok');   // 拉长上游耗时，让并发真的重叠（成功路径只打第一个目录，计数干净）
  up.reset();
  await Promise.all([call(''), call(''), call(''), call(''), call('')]);
  up.setMode('ok');
  t('⑦ 5 个并发未命中：GitHub 只被打 1 次', up.count('api.github.com') === 1, up.count('api.github.com'));
  kv = savedKv;

  // ------------------------------------------------------------ ⑧ 黑白名单分开缓存
  kv = makeKv();
  up.reset();
  await call('?type=white');
  await call('?type=black');
  const keys = [...kv.dump().keys()].sort();
  t('⑧ 黑白名单各一份缓存键', keys.length === 2 && /white/.test(keys.join(',')) && /black/.test(keys.join(',')), keys.join(','));
  up.reset();
  await call('?type=white');
  t('⑧ 白名单命中自己的缓存', up.calls.length === 0, up.calls);

  // ------------------------------------------------------------ ⑨ 鉴权先于缓存
  up.reset();
  const r9 = await call('', false);
  t('⑨ 无 Key：401', r9.status === 401, r9.status);
  t('⑨ 无 Key：不读缓存也不回源', up.calls.length === 0, up.calls);
  const r9b = await call('', 'wrong-key');
  t('⑨ 错 Key：401', r9b.status === 401, r9b.status);
  t('⑨ 错 Key：不泄露任何名单内容', r9b.body.indexOf('domains') === -1, r9b.body);

  // ------------------------------------------------------------ ⑩ 没绑 KV 时降级
  kv = savedKv;
  up.reset();
  const envNoKv = { LIST_API_KEY: 'k-test', GITHUB_TOKEN: 'gh-token', GITEE_OWNER: 'owner', GITEE_REPO: 'repo', GITEE_TOKEN: 'gt-token' };
  const r10a = await worker.fetch(req('', 'k-test'), envNoKv, ctx);
  const b10a = await r10a.text();
  t('⑩ 无 KV：请求照常成功', r10a.status === 200, r10a.status);
  t('⑩ 无 KV：如实标 BYPASS（没缓存）', r10a.headers.get('X-Cache') === 'BYPASS', r10a.headers.get('X-Cache'));
  up.reset();
  await worker.fetch(req('', 'k-test'), envNoKv, ctx);
  t('⑩ 无 KV：每次都回源（与旧版一致）', up.count('api.github.com') === 1, up.calls);

  // ------------------------------------------------------------ ⑪ 缓存层自身异常不能弄挂主流程
  const kvBad = {
    async get() { throw new Error('KV read boom'); },
    async put() { throw new Error('KV write boom'); },
  };
  kv = kvBad;
  up.reset();
  const r11 = await call('?nocache=1');
  t('⑪ KV 抛异常：读/写都不影响返回', r11.status === 200, r11.status);
  t('⑪ KV 抛异常：仍然拿到真实数据', r11.body.indexOf('domains') > -1, r11.body.slice(0, 60));
  kv = savedKv;

  globalThis.fetch = realFetch;
  try { fs.unlinkSync(tmp); } catch (e) {}

  console.log('\n' + pass + ' passed, ' + fail + ' failed');
  if (fail) process.exit(1);
}

main().catch((e) => {
  console.error('TEST CRASH', e && e.stack || e);
  process.exit(1);
});
