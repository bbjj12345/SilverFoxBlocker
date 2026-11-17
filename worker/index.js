// worker/index.js
var GITHUB_OWNER = "bbjj12345";
var GITHUB_REPO = "SilverFoxBlocker-Cloud";
var BRANCH = "main";

// 名单文件在仓库里的位置（依次尝试）。用户可能把文件放在根目录，也可能放在 List/ 子目录，
// 两种布局都认，省得挪一次文件就得改代码。
var LIST_DIRS = ["", "List/"];
// Gitee 分支名依次尝试。实测本仓库镜像的默认分支是 master，所以把它排在最前：
// 少打一次 404，也少消耗一次 Gitee 的接口配额。空字符串 = 用仓库默认分支。
var GITEE_REFS = ["master", "main", ""];

var REQ_TIMEOUT_MS = 5000;      // 单次上游请求超时
var GH_BUDGET_MS = 4500;        // 主源最多占用的时间，剩下的强制留给备源
var TOTAL_BUDGET_MS = 9000;     // 一次 /list 的总预算；必须小于扩展侧的云端接口超时（10s），
                                // 否则 Worker 还在跑、扩展已经判超时，用户看到的是「失败」而服务端其实成功了
var UA = "Cloudflare-Worker-SilverFox";

// ============================================================================
// CORS：从通配符 `*` 收紧到「已上架扩展的固定 ID」（2026-11-11）
//
// 为什么不是靠 API Key 当唯一门禁：X-API-Key 随扩展包一起分发，任何人解包就能看到，
//   它从来不是秘密。真正能挡住「随便写个网页去读名单」的是 Origin 白名单——
//   浏览器会强制带上 `Origin: chrome-extension://<id>`，网页无法把自己伪造成扩展源。
//
// 边界（必须写清楚，别当成万能的）：
//   · Origin 只能约束浏览器侧的跨源读取；防不住直接 curl / 脚本（它们可以不带 Origin）。
//     所以「无 Origin」的请求仍然返回数据，但**不下发任何 CORS 头**——命令行与健康检查
//     照常可用，而任何浏览器上下文都读不到响应体。
//   · Edge 商店版 ID 与「加载已解压」的本地 ID 不同：本地实例的 ID 由解压路径决定，
//     已连同商店版一起写进下面的数组；若你换了解压路径导致本地 ID 变化，把新 ID 追加
//     到环境变量 ALLOWED_ORIGINS（逗号分隔）即可，不必改代码、不必重新部署。
//   · Access-Control-Allow-Origin 只允许单个值（不支持逗号列表），因此必须按请求
//     回显具体 Origin，并配合 Vary: Origin，避免 CDN / 浏览器缓存串源。
// ============================================================================
var EXTENSION_IDS = [
  "hckibmmlfmcgpelphibapghnlbcjkmih",   // Edge 商店版（已上架）
  "mfnbgkpnnfjpglcclfmakolmopcdkoed"    // 本地「加载已解压」实例（本机调试用；ID 由解压路径决定，换路径会变）
];

function allowedOrigins(env) {
  var extra = String((env && env.ALLOWED_ORIGINS) || "").split(",");
  var out = EXTENSION_IDS.map(function (id) { return "chrome-extension://" + id; });
  for (var i = 0; i < extra.length; i++) {
    var v = extra[i].trim();
    if (v) out.push(v);
  }
  return out;
}

// 返回 { ok, headers }：ok=false 表示来源不在白名单 → 调用方直接 403
function corsFor(request, env) {
  var origin = request.headers.get("Origin") || "";
  if (!origin) return { ok: true, headers: {} };   // 非浏览器请求：给数据、不给跨源许可
  if (allowedOrigins(env).indexOf(origin) === -1) return { ok: false, headers: {} };
  return {
    ok: true,
    headers: {
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, X-API-Key",
      // 扩展侧要能读到「这份数据来自哪个源」，自定义响应头必须显式暴露
      "Access-Control-Expose-Headers": "X-Data-Source, X-Data-Path",
      "Access-Control-Max-Age": "86400",
      "Vary": "Origin"
    }
  };
}

function leftMs(deadline) {
  return deadline - Date.now();
}

// 带超时的取文本：超时/网络错误都折成 { ok:false }，不抛异常，方便逐通道记录原因
async function getText(url, opts, ms) {
  const controller = new AbortController();
  const timer = setTimeout(function () { try { controller.abort(); } catch (e) {} }, Math.max(400, ms));
  try {
    const res = await fetch(url, Object.assign({}, opts || {}, { signal: controller.signal }));
    const text = await res.text();
    return { ok: res.ok, status: res.status, text: text };
  } catch (e) {
    const msg = (e && e.message) || String(e);
    return { ok: false, status: 0, text: "", error: /abort/i.test(msg) ? "超时" : msg };
  } finally {
    clearTimeout(timer);
  }
}

// 只接受「真的是一份名单」的 JSON。两个源出错时都可能回 200 + {"message":...} 之类的 JSON，
// 那种内容绝不能当名单下发——扩展只会报「结构无法识别」，但响应头已经标成 Gitee，
// 排查时会误以为是镜像读到了数据。
function parseList(text) {
  let j;
  try { j = JSON.parse(text); } catch (e) { return { ok: false, why: "不是合法 JSON（可能拿到登录页/错误页）" }; }
  if (!j || !Array.isArray(j.domains)) return { ok: false, why: "JSON 里没有 domains 数组" };
  return { ok: true, json: j, count: j.domains.length };
}

// 主源：GitHub 私有仓库（token 只在服务端，浏览器永远拿不到）
async function readFromGithub(env, file, deadline) {
  const tries = [];
  if (!env.GITHUB_TOKEN) return { ok: false, tries: [{ src: "GitHub", error: "未配置 GITHUB_TOKEN" }] };

  for (let i = 0; i < LIST_DIRS.length; i++) {
    const path = LIST_DIRS[i] + file;
    const ms = Math.min(REQ_TIMEOUT_MS, leftMs(deadline));
    if (ms < 500) { tries.push({ src: "GitHub", path: path, error: "总预算已用尽" }); break; }

    const url = "https://api.github.com/repos/" + GITHUB_OWNER + "/" + GITHUB_REPO +
      "/contents/" + path + "?ref=" + BRANCH;
    const r = await getText(url, {
      headers: {
        "Authorization": "Bearer " + env.GITHUB_TOKEN,
        "Accept": "application/vnd.github.v3.raw",
        "User-Agent": UA
      }
    }, ms);

    if (r.ok) {
      const pi = parseList(r.text);
      if (!pi.ok) { tries.push({ src: "GitHub", path: path, error: pi.why }); continue; }
      return { ok: true, text: r.text, source: "GitHub", path: path, count: pi.count, tries: tries };
    }
    tries.push({ src: "GitHub", path: path, status: r.status, error: r.error || ("HTTP " + r.status) });
    // 401/403 是 token 失效或没权限；429 是 GitHub 限流。换目录也一样，别浪费预算
    if (r.status === 401 || r.status === 403 || r.status === 429) break;
  }
  return { ok: false, tries: tries };
}

// 备源：Gitee 私有镜像仓库。同样只在服务端持有 token，密钥不进 URL（用 Authorization 头），
// 免得 access_token 出现在任何日志/报错里。
async function readFromGitee(env, file, deadline) {
  const tries = [];
  const owner = env.GITEE_OWNER;
  const repo = env.GITEE_REPO;
  const token = env.GITEE_TOKEN;
  if (!owner || !repo) return { ok: false, tries: [{ src: "Gitee", error: "未配置 GITEE_OWNER / GITEE_REPO" }] };
  if (!token) return { ok: false, tries: [{ src: "Gitee", error: "未配置 GITEE_TOKEN" }] };

  let stop = "";
  for (let d = 0; d < LIST_DIRS.length && !stop; d++) {
    for (let b = 0; b < GITEE_REFS.length; b++) {
      const path = LIST_DIRS[d] + file;
      const ref = GITEE_REFS[b];
      const ms = Math.min(REQ_TIMEOUT_MS, leftMs(deadline));
      if (ms < 500) { tries.push({ src: "Gitee", path: path, ref: ref || "(默认)", error: "总预算已用尽" }); return { ok: false, tries: tries }; }

      const url = "https://gitee.com/api/v5/repos/" + owner + "/" + repo + "/raw/" + path +
        (ref ? "?ref=" + encodeURIComponent(ref) : "");
      const r = await getText(url, {
        headers: {
          "Authorization": "token " + token,
          "User-Agent": UA
        }
      }, ms);

      if (r.ok) {
        const pi = parseList(r.text);
        if (!pi.ok) { tries.push({ src: "Gitee", path: path, ref: ref || "(默认)", error: pi.why }); continue; }
        return { ok: true, text: r.text, source: "Gitee", path: path, ref: ref || "(默认)", count: pi.count, tries: tries };
      }

      tries.push({ src: "Gitee", path: path, ref: ref || "(默认)", status: r.status, error: r.error || ("HTTP " + r.status) });
      // 令牌无效（401/403）与接口限流（429）：后面的组合都不会有不同结果，立刻停
      if (r.status === 401 || r.status === 403) { stop = "令牌无效或无权限"; break; }
      if (r.status === 429) { stop = "Gitee 接口限流"; break; }
    }
  }
  if (stop) tries.push({ src: "Gitee", error: stop + "，已停止重试" });
  return { ok: false, tries: tries };
}
// ============================================================================
// 名单存活巡检（RDAP）—— 2026-11-17
//
// 目标：定期确认 blacklist.json 里的条目「是否还注册着」，给作者一份可核对的死链清单。
//   只做探测与记录，**不自动改名单**：名单的真相在私有仓库里，Worker 没有写权限，
//   擅自过滤会出现「服务端说 15 条、客户端拿到 14 条」这种更难排查的偏差。
//
// 为什么用 RDAP 而不是 HTTP：
//   · HTTP 会被三类噪声淹没——钓鱼站按 IP/地区/UA 屏蔽、自签证书让 fetch 直接 reject、
//     「302 到正常站洗白」。这三件事都无法区分「站在不在」。
//   · RDAP 问的是**注册局**：域名在不在册、有没有进 pendingDelete / redemptionPeriod。
//     这是注册状态，不依赖目标站点是否愿意回应你，也不会替你访问恶意站点。
//
// 三条判定纪律：
//   1) 只有「注册局明确说没有」才算 dead（404 / 废弃状态）；超时、429、5xx、
//      该后缀根本没有 RDAP 服务，一律 unknown —— 宁可漏报，不可误删。
//   2) 通配条目跳过：`*.*deepseek-*.*` 没有确定主机名，探测它等于探测一个正则。
//   3) 路径条目只探主机部分（`host/path` 的 host），路径本身不参与存活判断。
//
// 与 KV 的关系（回答「FEEDBACK 能不能这么用」）：
//   · FEEDBACK 是反馈/限流的命名空间，生命周期是「一天」；巡检结果是「长期状态」。
//     混在一起会导致：想清限流就得小心别删巡检数据，想换 KV 又得动反馈链路。
//     所以新建独立绑定 HEALTH。
//   · 名单正文**不**进 KV —— 它已经在私有仓库里，KV 再存一份就有了两个真相。
//     这里只存：每条主机的巡检状态、轮转游标、IANA RDAP 引导表缓存。
//   · 没有绑定 HEALTH 也能跑：结果只写日志，功能降级但不报错（方便先部署再建 KV）。
// ============================================================================
var RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json";
var RDAP_BOOTSTRAP_KEY = "rdap:bootstrap:v1";
var RDAP_BOOTSTRAP_TTL = 7 * 24 * 3600;   // 引导表变动极少，一周一刷足够
var RDAP_TIMEOUT_MS = 4000;
var RDAP_BUDGET_MS = 25000;               // 单次总预算，远小于 Worker 的 CPU 上限
var PROBE_MAX_PER_RUN = 30;               // 免费版每次调用 50 个子请求，留足余量给引导表与名单
var PROBE_CONCURRENCY = 3;                // 并发 3：对注册局友好，也不至于把预算耗在等超时上
var HEALTH_CURSOR_KEY = "health:cursor";
var HEALTH_SUMMARY_KEY = "health:summary";
var HEALTH_HOST_PREFIX = "health:host:";
var HEALTH_HOST_TTL = 90 * 24 * 3600;
// 注册局侧「这个域名已经废了」的状态。
// 注意**不要**收录 clientDeleteProhibited / clientTransferProhibited 这类保护锁，
// 它们是正常域名常开的锁，不是废弃信号。
var RDAP_DEAD_STATUS = ["pendingDelete", "redemptionPeriod", "clientHold", "serverHold", "inactive"];

function healthKv(env) { return (env && env.HEALTH) || null; }

// 从一条名单条目里取出可探测的主机名；取不到返回 ''（调用方据此跳过）
function probeHostOf(entry) {
  var s = String(entry == null ? "" : entry).trim();
  if (!s) return "";
  if (s.indexOf("*") !== -1 || s.indexOf("?") !== -1) return "";   // 通配条目：没有确定主机
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");                    // 去掉协议（完整链接也能贴）
  s = s.split("/")[0].split("#")[0].split("?")[0];                  // 去掉路径/查询/锚点
  var at = s.lastIndexOf("@");
  if (at !== -1) s = s.slice(at + 1);                               // 去掉 userinfo
  s = s.replace(/:\d+$/, "").replace(/\.$/, "").toLowerCase();
  if (!s || s.indexOf(".") === -1) return "";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return "";                 // 裸 IP 没有 RDAP 记录
  return s;
}

// 只挑「正常网址」，并如实报告跳过了哪些、为什么
function selectProbeTargets(domains) {
  var hosts = [];
  var seen = Object.create(null);
  var skipped = [];
  var arr = Array.isArray(domains) ? domains : [];
  for (var i = 0; i < arr.length; i++) {
    var raw = String(arr[i] == null ? "" : arr[i]).trim();
    if (!raw) continue;
    var h = probeHostOf(raw);
    if (!h) {
      skipped.push({ entry: raw, why: (/[*?]/.test(raw) ? "通配条目" : "不是主机名") });
      continue;
    }
    if (seen[h]) continue;
    seen[h] = 1;
    hosts.push(h);
  }
  return { hosts: hosts, skipped: skipped };
}

// IANA RDAP 引导表：TLD → 该注册局的 RDAP 根地址。
// 不走 rdap.org 中转：它是社区服务、按 IP 限流，且对不支持的后缀也会回 404，
// 用它判「域名已删除」会假阳性。直接问注册局才拿得到确定结论。
async function loadRdapBootstrap(env) {
  var kv = healthKv(env);
  if (kv) {
    try {
      var cached = await kv.get(RDAP_BOOTSTRAP_KEY);
      if (cached) {
        var cj = JSON.parse(cached);
        if (cj && cj.map && Object.keys(cj.map).length) return { map: cj.map, cached: true };
      }
    } catch (e) { /* 缓存坏了就重新拉 */ }
  }
  var r = await getText(RDAP_BOOTSTRAP_URL, {
    headers: { "User-Agent": UA, "Accept": "application/json" }
  }, RDAP_TIMEOUT_MS);
  if (!r.ok) return { map: null, error: r.error || ("HTTP " + r.status) };
  var j;
  try { j = JSON.parse(r.text); } catch (e) { return { map: null, error: "引导表不是合法 JSON" }; }
  var map = {};
  var svcs = (j && j.services) || [];
  for (var i = 0; i < svcs.length; i++) {
    var tlds = svcs[i][0] || [];
    var urls = svcs[i][1] || [];
    if (!urls.length) continue;
    for (var k = 0; k < tlds.length; k++) map[String(tlds[k]).toLowerCase()] = urls[0];
  }
  if (kv) {
    try { await kv.put(RDAP_BOOTSTRAP_KEY, JSON.stringify({ map: map, at: Date.now() }), { expirationTtl: RDAP_BOOTSTRAP_TTL }); } catch (e) {}
  }
  return { map: map, cached: false };
}

// 探测单个主机：只回三种状态，unknown 永远不参与「剔除」判断
async function probeRdapHost(host, bootstrapMap) {
  var labels = host.split(".");
  var tld = labels[labels.length - 1] || "";
  var base = (bootstrapMap && bootstrapMap[tld]) || "";
  if (!base) return { host: host, state: "unknown", reason: "该后缀没有 RDAP 服务（." + tld + "）" };

  var url = base.replace(/\/+$/, "") + "/domain/" + host;
  var ctrl = new AbortController();
  var timer = setTimeout(function () { try { ctrl.abort(); } catch (e) {} }, RDAP_TIMEOUT_MS);
  try {
    var res = await fetch(url, {
      headers: { "Accept": "application/rdap+json", "User-Agent": UA },
      signal: ctrl.signal,
      redirect: "follow"
    });
    if (res.status === 404) return { host: host, state: "dead", reason: "注册局返回 404（不在册或已删除）" };
    if (!res.ok) return { host: host, state: "unknown", reason: "RDAP HTTP " + res.status };
    var data;
    try { data = await res.json(); } catch (e) { return { host: host, state: "unknown", reason: "RDAP 响应不是 JSON" }; }
    var st = (data && Array.isArray(data.status)) ? data.status : [];
    var bad = [];
    for (var i = 0; i < st.length; i++) { if (RDAP_DEAD_STATUS.indexOf(st[i]) !== -1) bad.push(st[i]); }
    if (bad.length) return { host: host, state: "dead", reason: "注册局状态 " + bad.join(",") };

    // 到期时间顺带记下来：接近到期的条目下个月很可能变成 dead，提前看得到
    var exp = "";
    var evts = (data && data.events) || [];
    for (var e = 0; e < evts.length; e++) {
      if (evts[e] && evts[e].eventAction === "expiration") { exp = evts[e].eventDate || ""; break; }
    }
    return {
      host: host,
      state: "alive",
      reason: st.length ? ("注册局状态 " + st.join(",")) : "正常在册",
      expires: exp
    };
  } catch (err) {
    var msg = (err && err.message) || String(err);
    return { host: host, state: "unknown", reason: /abort/i.test(msg) ? "RDAP 超时" : ("网络错误：" + msg) };
  } finally {
    clearTimeout(timer);
  }
}

// 巡检主流程：读名单 → 挑目标 → 分批评测 → 汇总写 KV / 日志
async function runHealthCheck(env, opts) {
  var t0 = Date.now();
  var deadline = t0 + RDAP_BUDGET_MS;
  var kv = healthKv(env);
  var verbose = !!(opts && opts.verbose);

  // 1) 名单：与 /list 同一套双源逻辑，保证「探的就是线上那一刻的名单」
  var gh = await readFromGithub(env, "blacklist.json", Math.min(deadline, t0 + GH_BUDGET_MS));
  var src = gh.ok ? gh : null;
  if (!src) {
    var gt = await readFromGitee(env, "blacklist.json", deadline);
    if (gt.ok) src = gt;
  }
  if (!src) {
    return { ok: false, at: new Date().toISOString(), error: "名单读取失败：GitHub 与 Gitee 均不可用" };
  }

  var list;
  try { list = JSON.parse(src.text); } catch (e) {
    return { ok: false, at: new Date().toISOString(), error: "名单不是合法 JSON" };
  }
  var sel = selectProbeTargets(list.domains);
  var hosts = sel.hosts;
  if (!hosts.length) {
    return { ok: true, at: new Date().toISOString(), source: src.source, total: 0, probed: 0, alive: 0, dead: 0, unknown: 0, deadList: [], skipped: sel.skipped };
  }

  // 2) 游标：名单比单次上限长时，每天接着上次的位置探，几天覆盖一轮
  var cursor = 0;
  if (kv) {
    try { cursor = parseInt(await kv.get(HEALTH_CURSOR_KEY), 10) || 0; } catch (e) { cursor = 0; }
  }
  if (cursor < 0 || cursor >= hosts.length) cursor = 0;
  var take = Math.min(PROBE_MAX_PER_RUN, hosts.length);
  var slice = [];
  for (var i = 0; i < take; i++) slice.push(hosts[(cursor + i) % hosts.length]);

  // 3) 引导表（1 个子请求，缓存 7 天）
  var bs = await loadRdapBootstrap(env);
  if (!bs.map) {
    return { ok: false, at: new Date().toISOString(), error: "RDAP 引导表不可用：" + (bs.error || "未知原因") };
  }

  // 4) 分批探测：并发 3，超预算就停（剩下的下一轮继续）
  var results = [];
  var stopped = "";
  for (var n = 0; n < slice.length; n += PROBE_CONCURRENCY) {
    if (Date.now() > deadline) { stopped = "总预算用尽，剩余条目下一轮继续"; break; }
    var batch = slice.slice(n, n + PROBE_CONCURRENCY);
    var rs = await Promise.all(batch.map(function (h) { return probeRdapHost(h, bs.map); }));
    for (var b = 0; b < rs.length; b++) results.push(rs[b]);
  }

  // 5) 汇总
  var alive = [], dead = [], unknown = [], deadList = [];
  for (var r = 0; r < results.length; r++) {
    var it = results[r];
    if (it.state === "dead") { dead.push(it); deadList.push(it.host); }
    else if (it.state === "alive") alive.push(it);
    else unknown.push(it);
    if (verbose) console.log("[health] " + it.state + " " + it.host + "  " + it.reason);
  }

  var summary = {
    ok: true,
    at: new Date().toISOString(),
    source: src.source,
    path: src.path || "",
    elapsedMs: Date.now() - t0,
    total: Array.isArray(list.domains) ? list.domains.length : 0,
    probed: results.length,
    alive: alive.length,
    dead: dead.length,
    unknown: unknown.length,
    deadList: deadList,
    // 只留前 20 条明细，避免摘要随名单增长而膨胀（KV 单值上限很大，但摘要没必要那么大）
    deadDetail: dead.slice(0, 20),
    unknownDetail: unknown.slice(0, 20),
    skipped: sel.skipped,
    note: stopped || "",
    cursorNext: hosts.length > take ? (cursor + results.length) % hosts.length : 0
  };

  // 6) 落盘：逐主机状态（带 TTL）+ 摘要 + 游标
  if (kv) {
    try {
      for (var w = 0; w < results.length; w++) {
        var x = results[w];
        await kv.put(HEALTH_HOST_PREFIX + x.host, JSON.stringify({
          state: x.state, reason: x.reason, expires: x.expires || "", at: summary.at
        }), { expirationTtl: HEALTH_HOST_TTL });
      }
      await kv.put(HEALTH_SUMMARY_KEY, JSON.stringify(summary));
      await kv.put(HEALTH_CURSOR_KEY, String(summary.cursorNext));
    } catch (e) {
      console.error("[health] KV 写入失败：" + ((e && e.message) || e));
    }
  }

  return summary;
}

var index_default = {
  async fetch(request, env, ctx) {
    // 来源校验前置：不在白名单的 Origin 一律 403（含 OPTIONS 预检），
    // 且响应里不带 ACAO，浏览器侧读不到任何内容。
    const cors = corsFor(request, env);
    if (!cors.ok) {
      console.warn("[cors] 拒绝未授权来源：" + (request.headers.get("Origin") || "(none)"));
      return new Response(JSON.stringify({
        error: "Origin not allowed",
        detail: "该来源未被授权访问本接口。仅限已上架的 SilverFoxBlocker 扩展调用。"
      }), {
        status: 403,
        headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
      });
    }
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors.headers });
    }

    const url = new URL(request.url);

    // ==========================================
    // 功能 A: 实时拉取并返回名单 (GET /list)
    //   主源 GitHub 私有仓库 → 备源 Gitee 私有镜像仓库
    //   加 ?diag=1 只回诊断信息（逐通道的尝试记录），不返回名单正文
    // ==========================================
    if (request.method === "GET" && url.pathname === "/list") {
      const apiKey = request.headers.get("X-API-Key");
      if (apiKey !== env.LIST_API_KEY) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
          status: 401,
          headers: { "Content-Type": "application/json", ...cors.headers }
        });
      }

      const type = url.searchParams.get("type") || "black";
      const fileName = type === "white" ? "whitelist.json" : "blacklist.json";
      const diag = url.searchParams.get("diag");
      // ?force=gitee / ?force=github：只走指定的那一个源，用来「强行验证备源」。
      // 正常同步（扩展）永远不带这个参数，所以线上行为仍然是 GitHub 优先、Gitee 兜底。
      const force = String(url.searchParams.get("force") || "").toLowerCase();
      const useGithub = force !== "gitee";
      const useGitee = force !== "github";
      const t0 = Date.now();
      const deadline = t0 + TOTAL_BUDGET_MS;
      // 主源最多占 GH_BUDGET_MS，剩下的时间强制留给 Gitee：
      // 否则「GitHub 卡死」这种最需要备源的场景，预算反而被主源吃光，备源一次都跑不到。
      const ghDeadline = Math.min(deadline, t0 + GH_BUDGET_MS);

      const gh = useGithub
        ? await readFromGithub(env, fileName, ghDeadline)
        : { ok: false, skipped: true, tries: [{ src: "GitHub", error: "已跳过（force=gitee）" }] };
      if (gh.ok) {
        if (diag) {
          return new Response(JSON.stringify({
            ok: true, type: type, source: gh.source, path: gh.path, count: gh.count,
            force: force || null,
            elapsedMs: Date.now() - t0, tries: gh.tries, giteeAttempted: false
          }, null, 2), {
            status: 200,
            headers: { "Content-Type": "application/json", "X-Data-Source": gh.source, ...cors.headers }
          });
        }
        return new Response(gh.text, {
          headers: {
            "Content-Type": "application/json",
            "X-Data-Source": gh.source,
            "X-Data-Path": gh.path,
            ...cors.headers
          }
        });
      }

      if (useGithub) console.warn("[list] GitHub 拉取失败，切换到 Gitee 镜像：" + JSON.stringify(gh.tries));

      const gt = useGitee
        ? await readFromGitee(env, fileName, deadline)
        : { ok: false, skipped: true, tries: [{ src: "Gitee", error: "已跳过（force=github）" }] };

      if (diag) {
        return new Response(JSON.stringify({
          ok: gt.ok, type: type, source: gt.ok ? gt.source : null,
          path: gt.ok ? gt.path : null, ref: gt.ok ? gt.ref : null,
          count: gt.ok ? gt.count : null,
          force: force || null,
          elapsedMs: Date.now() - t0,
          github: gh.tries, gitee: gt.tries
        }, null, 2), {
          status: 200,
          headers: { "Content-Type": "application/json", ...cors.headers }
        });
      }

      if (!gt.ok) {
        console.error("[list] 双源均失败：" + JSON.stringify({ github: gh.tries, gitee: gt.tries }));
        return new Response(JSON.stringify({
          error: "云端名单服务器暂时不可用，请稍后再试。",
          detail: {
            github: gh.tries.map(function (t) { return (t.path || "") + " → " + (t.error || t.status); }),
            gitee: gt.tries.map(function (t) { return (t.path || "") + "[" + (t.ref || "") + "] → " + (t.error || t.status); })
          }
        }), {
          status: 502,
          headers: { "Content-Type": "application/json", ...cors.headers }
        });
      }

      return new Response(gt.text, {
        headers: {
          "Content-Type": "application/json",
          "X-Data-Source": gt.source,
          "X-Data-Path": gt.path,
          ...cors.headers
        }
      });
    }

    // ==========================================
    // 功能 C: 名单存活巡检（RDAP）
    //   GET /health         → 最近一次巡检的摘要（读 KV）
    //   GET /health?run=1   → 立刻跑一次（最慢约 25s，受 RDAP_BUDGET_MS 约束）
    //   GET /health?dead=1  → text/plain，一行一个疑似失效域名，便于直接粘回 blacklist.json
    //   与 /list 共用 LIST_API_KEY；不带 Origin 的 curl 调用照常可用（便于维护者自查）。
    // ==========================================
    if (request.method === "GET" && url.pathname === "/health") {
      const apiKey = request.headers.get("X-API-Key");
      if (apiKey !== env.LIST_API_KEY) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
          status: 401,
          headers: { "Content-Type": "application/json", ...cors.headers }
        });
      }
      const kv = healthKv(env);
      let summary = null;
      if (url.searchParams.get("run") === "1") {
        summary = await runHealthCheck(env);
      } else if (kv) {
        try {
          const s = await kv.get(HEALTH_SUMMARY_KEY);
          if (s) summary = JSON.parse(s);
        } catch (e) { /* 读不出来就当没有历史结果 */ }
      }
      if (url.searchParams.get("dead") === "1") {
        const list = (summary && summary.deadList) || [];
        return new Response(list.join("\n") + (list.length ? "\n" : ""), {
          status: 200,
          headers: {
            "Content-Type": "text/plain; charset=utf-8",
            "Cache-Control": "no-store",
            "X-Data-Source": "rdap",
            ...cors.headers
          }
        });
      }
      return new Response(JSON.stringify({
        ok: !!summary,
        kvBound: !!kv,
        note: kv ? null : "未绑定 HEALTH KV：巡检结果只在 cron 日志里。新建命名空间后把 id 填进 wrangler.toml 再部署。",
        summary: summary
      }, null, 2), {
        status: 200,
        headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...cors.headers }
      });
    }

    // ==========================================
    // 功能 B: 原有的用户反馈提交 (POST)
    // ==========================================
    if (request.method !== "POST") {
      return new Response(JSON.stringify({ error: "Method not allowed" }), {
        status: 405,
        headers: { "Content-Type": "application/json", ...cors.headers }
      });
    }

    try {
      const clientIP = request.headers.get("CF-Connecting-IP") || "unknown";
      const today = (new Date()).toISOString().split("T")[0];
      const kvKey = `rate_limit_${clientIP}_${today}`;

      let currentCount = await env.RATE_LIMIT_KV.get(kvKey);
      currentCount = currentCount ? parseInt(currentCount) : 0;

      if (currentCount >= 60) {
        return new Response(JSON.stringify({ error: "您今天的提交次数已达上限，请明天再试。" }), {
          status: 429,
          headers: { "Content-Type": "application/json", ...cors.headers }
        });
      }

      const data = await request.json();
      const feedbackText = data.message;
      const userContact = data.contact || "未提供";

      if (!feedbackText || typeof feedbackText !== "string" || feedbackText.length > 2000) {
        return new Response(JSON.stringify({ error: "无效的反馈内容或长度超过限制。" }), {
          status: 400,
          headers: { "Content-Type": "application/json", ...cors.headers }
        });
      }

      const emailResponse = await fetch("https://api.brevo.com/v3/smtp/email", {
        method: "POST",
        headers: {
          "api-key": env.BREVO_API_KEY,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          sender: { name: "SilverFoxBlocker 反馈", email: "feedback@silverfoxblocker.dpdns.org" },
          to: [{ email: "feedback@silverfoxblocker.dpdns.org" }],
          subject: "【SilverFoxBlocker】收到一条新的扩展反馈",
          htmlContent: `
            <h3>新反馈</h3>
            <p><strong>联系方式：</strong> ${userContact}</p>
            <p><strong>内容：</strong></p>
            <p>${feedbackText.replace(/\n/g, "<br>")}</p>
            <hr>
            <p><small>IP: ${clientIP}</small></p>
          `
        })
      });

      if (!emailResponse.ok) {
        const errText = await emailResponse.text();
        throw new Error(`Brevo 邮件发送失败: ${errText}`);
      }

      await env.RATE_LIMIT_KV.put(kvKey, (currentCount + 1).toString(), { expirationTtl: 86400 });

      return new Response(JSON.stringify({ success: true, message: "感谢您的反馈！" }), {
        headers: { "Content-Type": "application/json", ...cors.headers }
      });

    } catch (error) {
      console.error(error);
      return new Response(JSON.stringify({ error: "服务器内部错误，请稍后再试。" }), {
        status: 500,
        headers: { "Content-Type": "application/json", ...cors.headers }
      });
    }
  },
  // Cron 定时任务：名单存活巡检
  async scheduled(event, env, ctx) {
    // ctx.waitUntil 不是可选项：fetch/scheduled 返回后 Worker 立刻被回收，
    //   不挂在这里的 Promise 会被中途掐断，巡检做一半、KV 留下半份状态。
    ctx.waitUntil(runHealthCheck(env).then(function (s) {
      if (!s.ok) { console.error("[cron] 巡检未完成：" + (s.error || "未知原因")); return; }
      console.log("[cron] 巡检完成 " + JSON.stringify({
        source: s.source, total: s.total, probed: s.probed,
        alive: s.alive, dead: s.dead, unknown: s.unknown, elapsedMs: s.elapsedMs
      }));
      if (s.deadList && s.deadList.length) console.warn("[cron] 疑似失效（需人工确认后再删）: " + s.deadList.join(", "));
      if (s.note) console.warn("[cron] " + s.note);
    }).catch(function (e) {
      console.error("[cron] 巡检异常：" + ((e && e.stack) || e));
    }));
  }
};

export { index_default as default };
