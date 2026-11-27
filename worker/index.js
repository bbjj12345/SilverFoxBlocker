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
//
// ----------------------------------------------------------------------------
// 2026-11-27 修订：白名单支持通配符，且默认放行「任意浏览器扩展」
//
// 诱因：本地「加载已解压」的扩展 ID 由解压路径决定，换台电脑就换一个 ID。
//   逐个 ID 往白名单里加根本追不上（用户看到的就是「发送失败：Failed to fetch」，
//   而服务端日志里只有一句 403）。
//
// 判定顺序：精确字符串相等 → 通配匹配（`*` 匹配任意长度，含空）。
//   ALLOWED_ORIGINS 里也可以写通配，例如：
//     chrome-extension://*        任意 Chrome / Edge 扩展
//     https://*.example.com       任意子域（注意：不含 example.com 本身，想含就写两条）
//   匹配时**只有 `*` 是通配**，`.` `+` `(` 等一律按字面转义 —— 否则 `https://a.b.com`
//   会被正则里的 `.` 宽松匹配到 `https://axbxcom`，白名单就成了筛子。
// ----------------------------------------------------------------------------
var EXTENSION_IDS = [
  "hckibmmlfmcgpelphibapghnlbcjkmih",   // Edge 商店版（已上架）
  "mfnbgkpnnfjpglcclfmakolmopcdkoed"    // 本地「加载已解压」实例（本机调试用；ID 由解压路径决定，换路径会变）
];

// 是否默认放行「任意扩展来源」（chrome-extension://*）。
//   为什么敢放：/list 的数据本身就托管在 GitHub 公开仓库，X-API-Key 随扩展包分发、
//   从来不是秘密；Origin 白名单的真实作用只是「挡住普通网页在浏览器里读响应」。
//   放行扩展来源之后，普通网页（https://…）依然被拦，这个边界没有变。
//   想回到「只认固定 ID」的严格模式：把这一行改成 false，其余代码不用动。
var ALLOW_ANY_EXTENSION = true;

/* 旧实现（2026-11-11）：精确比对，不支持通配
function allowedOrigins(env) {
  var extra = String((env && env.ALLOWED_ORIGINS) || "").split(",");
  var out = EXTENSION_IDS.map(function (id) { return "chrome-extension://" + id; });
  for (var i = 0; i < extra.length; i++) {
    var v = extra[i].trim();
    if (v) out.push(v);
  }
  return out;
}
function corsFor(request, env) {
  var origin = request.headers.get("Origin") || "";
  if (!origin) return { ok: true, headers: {} };   // 非浏览器请求：给数据、不给跨源许可
  if (allowedOrigins(env).indexOf(origin) === -1) return { ok: false, headers: {} };
  ...
}
*/

function allowedOrigins(env) {
  var extra = String((env && env.ALLOWED_ORIGINS) || "").split(",");
  var out = EXTENSION_IDS.map(function (id) { return "chrome-extension://" + id; });
  if (ALLOW_ANY_EXTENSION) {
    // 注意：Edge 的扩展来源同样是 chrome-extension://（不是 edge-extension://）
    out.push("chrome-extension://*");
  }
  for (var i = 0; i < extra.length; i++) {
    var v = extra[i].trim();
    if (v) out.push(v);
  }
  return out;
}

// 单条模式匹配：精确相等，或 `*` 通配（`*` 可以出现在任意位置、可以有多条）
function originMatch(pattern, origin) {
  if (!pattern || !origin) return false;
  if (pattern === origin) return true;
  if (pattern.indexOf("*") === -1) return false;
  // 先把正则元字符（含 `*` 自身）全部转义，再把转义后的 `\*` 换回「任意字符」
  var body = pattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\\\*/g, "[\\s\\S]*");
  var re;
  try { re = new RegExp("^" + body + "$", "i"); } catch (e) { return false; }
  return re.test(origin);
}

function allowedOriginHit(env, origin) {
  var list = allowedOrigins(env);
  for (var i = 0; i < list.length; i++) {
    if (originMatch(list[i], origin)) return true;
  }
  return false;
}

// 跨源许可头：必须回显具体 Origin（ACAO 不支持逗号列表）
function corsHeadersFor(origin) {
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-API-Key",
    // 扩展侧要能读到「这份数据来自哪个源」，自定义响应头必须显式暴露
    "Access-Control-Expose-Headers": "X-Data-Source, X-Data-Path",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };
}

// 被拒时的最小跨源头：只回显 Origin + Vary，让客户端能读到 403 的 JSON 原因；
//   不声明 Allow-Methods / Expose-Headers —— 那些是「允许你做什么」，被拒时一个都不给。
function corsRejectHeadersFor(origin) {
  return { "Access-Control-Allow-Origin": origin, "Vary": "Origin" };
}

// 返回 { ok, headers }：ok=false 表示来源不在白名单 → 调用方直接 403
function corsFor(request, env) {
  var origin = request.headers.get("Origin") || "";
  if (!origin) return { ok: true, headers: {} };   // 非浏览器请求：给数据、不给跨源许可
  // 被拒时**也**回显 CORS 头（数据一个字节都不给，只给 403 的 JSON 说明）。
  //   旧行为是被拒就不带 CORS 头，于是浏览器把 403 折成 TypeError('Failed to fetch')，
  //   扩展侧只能笼统说「连不上」，用户和作者都分不清「网络不通」与「来源被拒」。
  if (!allowedOriginHit(env, origin)) return { ok: false, headers: corsRejectHeadersFor(origin) };
  return { ok: true, headers: corsHeadersFor(origin) };
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
// 名单存活巡检（HTTP 探测为主；DNS / RDAP 只做佐证）—— 2026-11-17 第二版
//
// 目标只有一个：找出「用户浏览器打不开」的条目，列成清单给作者人工确认。
//   只探测与记录，**不自动改名单**：名单的真相在私有仓库里，Worker 没有写权限，
//   擅自过滤会出现「服务端 15 条、客户端 14 条」这种更难排查的偏差。
//
// 第一版错在哪（务必别再走回头路）：
//   · 把 RDAP 的 404 直接当「域名已删除」。可 RDAP 的 404 只代表「这个注册局的库里
//     没有这条记录」，最常见的两个原因恰恰是：① 查的是子域名（www.xxx.com、es.xxx.com），
//     而注册局只认可注册主域（eTLD+1）；② 域名在册但注册局尚未回填 RDAP 记录。
//     于是 cchytech.com / wlygrowth.com 这类活得好好的站点被判死。
//   · 只读 IANA 引导表 → .cn 没有分配 RDAP 根，整片 .cn 落进 unknown。
//     （曾尝试补 CNNIC 端点，但 rdap.cnnic.cn 这个域名**根本不存在**（DNS ENOTFOUND），
//      CNNIC 只提供 whois.cnnic.cn:43 的 WHOIS，不做 RDAP。所以 .cn 干脆不查注册局：
//      它对 .cn 的判断已经由 HTTP + DoH 两步给足了，注册局只是「DoH 也失灵时」的兜底。）
//
// 现在的判定链（越靠前越硬）：
//   1) HTTP 探测：带桌面浏览器 UA 的 GET，跟随重定向，先 https 再 http。
//      拿到**任何** HTTP 响应（200 / 403 / 404 / 500 都算）→ 服务器在应答 → alive。
//      这一步直接对应「浏览器能不能打开」，也是本次唯一能判死的依据。
//   2) 全部连不上 → DoH 查一次 DNS：NXDOMAIN 说明域名在 DNS 里根本不存在，
//      浏览器必然打不开 → dead。这条比 RDAP 硬得多，且不需要碰目标站点。
//   3) DoH 说「有记录」→ 域名还活着，站点只是不响应：归 unreachable（不判死）。
//      出口在境外时，国内站点被墙 / 被地域屏蔽 / 临时故障都会长这样。
//   4) DoH 也查不出来 → 才请注册局作证（IANA 引导表，查**可注册主域**）：
//      明确「无记录 / pendingDelete / redemptionPeriod」→ dead；说在册 → unreachable。
//      RDAP 只在这一步出现，且永远不作为唯一证据。
//      查不到 RDAP 的 TLD（.cn 全系、部分小国后缀）就老实写「注册状态未能确认」——
//      一律归 unreachable，不猜、不判死。
//
// 必须知道的代价：
//   · HTTP 探测会**真的访问**被拉黑站点，Cloudflare 的出口 IP 会暴露给对方。
//     这是「判断打不开」绕不开的取舍——RDAP 方案不碰站点，但也答不了这个问题。
//   · 出口在境外：国内小站可能一律超时，从而大量落进 unreachable。
//     所以 unreachable 永远不自动删除，只列出来让人在国内网络点一遍。
// ============================================================================
var HTTP_TIMEOUT_MS = 5000;               // 单个 scheme 的超时；两条 scheme 各算一次
var HTTP_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
var HTTP_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";

var DOH_URL = "https://cloudflare-dns.com/dns-query";
var DOH_TIMEOUT_MS = 4000;

var RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json";
var RDAP_BOOTSTRAP_KEY = "rdap:bootstrap:v1";
var RDAP_BOOTSTRAP_TTL = 7 * 24 * 3600;   // 引导表变动极少，一周一刷足够
var RDAP_TIMEOUT_MS = 4000;

// 单次总预算与墙钟护栏。
//   HEALTH_BUDGET_MS：计划预算，跑到这儿就收手（软上限）。
//   HEALTH_HARD_MS  ：真正不能越过的墙钟线。Cloudflare 官方对 duration 没有硬性上限，
//                     但 event.waitUntil() 只保证「额外 30 秒」不被取消，所以按 30 秒设计。
//   PROBE_WORST_CASE_MS：一条域名最坏要花多久（https 失败 5s + http 失败 5s + DoH 4s + RDAP 4s）。
//                     由下面几个超时常量算出来，改超时不用再改这里。
// 原来只在「批次开始前」看有没超过 25 秒，结果 24.9 秒仍会放行一批，
// 这批最坏再跑 18 秒 → 实际最坏 43 秒，越过 30 秒线。现在改成预留：
// 启动新批次前先算「这一批跑完会不会越线」，会就越线前停手，剩下的下一轮继续。
var HEALTH_BUDGET_MS = 25000;
var HEALTH_HARD_MS = 30000;
var PROBE_WORST_CASE_MS = HTTP_TIMEOUT_MS * 2 + DOH_TIMEOUT_MS + RDAP_TIMEOUT_MS;   // 18000
// 单次最多探几条。名单不超过这个数时，一轮就能全覆盖、游标归 0。
// 原来写 10，导致 11 条名单卡在界外一格：每轮只前进 1 条、9 条重复探测，
// 11 轮才转完一圈（环形窗口一直「倒退 1」）。2026-11-17 抬到 25。
var PROBE_MAX_PER_RUN = 25;
// 真正决定「能不能跑完」的不是条数，而是这次到底发了多少次 fetch：
// 免费版每个请求 50 个子请求，每条最坏 4 次（https+http+DoH+RDAP），25 条最坏 100 次。
// 所以按**真实用量**设硬护栏，而不是按条数猜。超了就停、游标只前进到做完的那条，
// 剩下的下一轮接着来——宁可少探，也不能整轮撞上限失败。
// 30 是「本模块自己发的 fetch」上限，另留余量给：名单读取（GitHub/Gitee 2 次）、
// 引导表（1 次）、KV 写（summary + cursor + 主机状态 3 次），以及**重定向**——
// fetch 用 redirect:"follow"，每一跳在 Worker 内部都算一次子请求，而这里只按 1 次记账，
// 所以刻意比 50 留出更大的缺口（2026-11-17 从 36 降到 30）。
var SUBREQ_BUDGET = 30;
var PROBE_CONCURRENCY = 4;                // 并发 4：对目标站点友好，也不至于把预算耗在等超时
var HEALTH_CURSOR_KEY = "health:cursor";
var HEALTH_SUMMARY_KEY = "health:summary";
var HEALTH_HOSTS_KEY = "health:hosts";    // 全部主机状态的合并快照（一次 put，省子请求）
var HEALTH_HOST_TTL = 90 * 24 * 3600;
// 注册局侧「这个域名已经废了」的状态。
// 注意**不要**收录 clientDeleteProhibited / clientTransferProhibited 这类保护锁，
// 它们是正常域名常开的锁，不是废弃信号。
var RDAP_DEAD_STATUS = ["pendingDelete", "redemptionPeriod", "clientHold", "serverHold", "inactive"];

// 常见多级公共后缀：算 eTLD+1 时必须知道「最后两段是不是一个可注册域」。
// 只要覆盖会出现在名单里的实用集合即可，不追求 PSL 全量（PSL 有上万条，Worker 里塞不下）。
var MULTI_SUFFIX = Object.create(null);
(function () {
  var s = "com.cn net.cn org.cn gov.cn edu.cn ac.cn mil.cn " +
    "com.hk org.hk net.hk edu.hk gov.hk idv.hk " +
    "com.tw org.tw net.tw edu.tw gov.tw idv.tw " +
    "com.mo org.mo net.mo edu.mo gov.mo " +
    "co.uk org.uk me.uk net.uk ac.uk gov.uk ltd.uk plc.uk " +
    "com.au net.au org.au edu.au gov.au id.au asn.au " +
    "co.jp ne.jp or.jp ac.jp go.jp gr.jp ed.jp " +
    "co.kr or.kr ne.kr go.kr re.kr " +
    "com.sg net.sg org.sg edu.sg gov.sg " +
    "com.my net.my org.my edu.my gov.my " +
    "co.nz net.nz org.nz govt.nz ac.nz " +
    "com.br net.br org.br gov.br edu.br " +
    "com.mx org.mx net.mx gob.mx edu.mx " +
    "co.in net.in org.in gen.in firm.in ind.in " +
    "com.tr net.tr org.tr gov.tr edu.tr " +
    "co.za org.za net.za gov.za ac.za " +
    "com.ar org.ar net.ar gob.ar " +
    "com.ua net.ua org.ua gov.ua " +
    "co.id or.id web.id ac.id go.id " +
    "com.vn net.vn org.vn gov.vn edu.vn " +
    "co.th in.th or.th ac.th go.th " +
    "com.eg com.sa com.pk com.bd com.ng com.ph com.co com.pe com.ve com.ru";
  var a = s.split(" ");
  for (var i = 0; i < a.length; i++) MULTI_SUFFIX[a[i]] = 1;
})();

function healthKv(env) { return (env && env.HEALTH) || null; }

// 子请求预算：每次真正要发 fetch 之前先来领一张票。
// 不用「还剩几条」估算，是因为同一条域名在不同状态下消耗 1~4 次不等
// （https 一打就通只花 1 次，全挂才走到 DoH + RDAP）。
function takeSub(budget, n) {
  if (!budget) return true;
  var need = n || 1;
  if (budget.used + need > budget.max) return false;
  budget.used += need;
  return true;
}
function budgetLeft(budget) {
  return budget ? budget.max - budget.used : 999;
}

// 从一条名单条目里取出可探测的主机名；取不到返回 ''
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
  if (!/^[a-z0-9._-]+$/.test(s)) return "";                         // 含空格/尖括号等：不是主机名
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return "";                 // 裸 IP 没有注册记录
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

// 主机名 → 可注册主域（eTLD+1）。RDAP 只能查这个层级：
// 拿 www.xxx.com 去问注册局必然 404，这正是第一版假阳性的来源。
function registrableOf(host) {
  var labels = String(host || "").toLowerCase().replace(/\.$/, "").split(".");
  if (labels.length <= 2) return labels.join(".");
  var last2 = labels.slice(-2).join(".");
  if (MULTI_SUFFIX[last2] && labels.length >= 3) return labels.slice(-3).join(".");
  return last2;
}

// Cloudflare DoH（JSON 口径）。Status 3 = NXDOMAIN：域名在 DNS 里不存在。
async function dohLookup(host, budget) {
  if (!takeSub(budget)) return { ok: false, exhausted: true, error: "子请求预算用尽" };
  var url = DOH_URL + "?name=" + encodeURIComponent(host) + "&type=A";
  var ctrl = new AbortController();
  var timer = setTimeout(function () { try { ctrl.abort(); } catch (e) {} }, DOH_TIMEOUT_MS);
  try {
    var res = await fetch(url, {
      headers: { "Accept": "application/dns-json", "User-Agent": UA },
      signal: ctrl.signal
    });
    if (!res.ok) return { ok: false, error: "DoH HTTP " + res.status };
    var j = await res.json();
    var st = (j && typeof j.Status === "number") ? j.Status : -1;
    var ans = (j && Array.isArray(j.Answer)) ? j.Answer : [];
    return { ok: true, nx: st === 3, status: st, answers: ans.length };
  } catch (err) {
    var msg = (err && err.message) || String(err);
    return { ok: false, error: /abort/i.test(msg) ? "DoH 超时" : ("DoH 失败：" + msg) };
  } finally {
    clearTimeout(timer);
  }
}

// 把 fetch 的报错归类，好在清单里写清楚「为什么打不开」
function httpErrKind(msg) {
  var s = String(msg || "");
  if (/abort|timed? ?out|timeout/i.test(s)) return "超时";
  if (/ENOTFOUND|getaddrinfo|NXDOMAIN|could not resolve|resolve/i.test(s)) return "域名解析失败";
  if (/certificate|tls|ssl|handshake|self.signed|CERT_/i.test(s)) return "证书错误";
  if (/ECONNREFUSED|connection refused/i.test(s)) return "拒绝连接";
  if (/ECONNRESET|reset/i.test(s)) return "连接被重置";
  return "网络错误";
}

// HTTP 探测：只要服务器回了响应就算「能打开」，不管状态码是多少。
// 先 https 再 http：自签证书会让 https 直接 reject，但 http 往往还能给个 301/200，
// 而浏览器此时也只是弹个警告页、点「继续访问」照样进得去。
async function probeHttp(host, budget) {
  var schemes = ["https", "http"];
  var last = null;
  for (var i = 0; i < schemes.length; i++) {
    // https 失败后还想试 http，得再领一张票；领不到就带着已得的错误返回
    if (!takeSub(budget)) return { ok: false, kind: (last && last.kind) || "超时", msg: "子请求预算用尽", via: (last && last.via) || "", exhausted: true };
    var ctrl = new AbortController();
    var timer = setTimeout(function () { try { ctrl.abort(); } catch (e) {} }, HTTP_TIMEOUT_MS);
    try {
      var res = await fetch(schemes[i] + "://" + host + "/", {
        method: "GET",
        headers: {
          "User-Agent": HTTP_UA,
          "Accept": HTTP_ACCEPT,
          "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
          "Cache-Control": "no-cache"
        },
        redirect: "follow",
        signal: ctrl.signal
      });
      var status = res.status;
      var finalUrl = res.url || "";
      // 不读正文，立刻放开连接；cancel 是异步的，吞掉可能的 rejection
      try {
        var cp = res.body && res.body.cancel();
        if (cp && typeof cp.catch === "function") cp.catch(function () {});
      } catch (e) {}
      return { ok: true, status: status, via: schemes[i], finalUrl: finalUrl };
    } catch (err) {
      var msg = (err && err.message) || String(err);
      last = { kind: httpErrKind(msg), msg: msg, via: schemes[i] };
    } finally {
      clearTimeout(timer);
    }
  }
  return { ok: false, kind: (last && last.kind) || "网络错误", msg: (last && last.msg) || "", via: (last && last.via) || "" };
}

// 问一个注册局端点：只回 unregistered / doomed / registered / unknown
async function queryRegistry(base, reg, budget) {
  if (!takeSub(budget)) return { state: "unknown", base: base, exhausted: true, reason: "子请求预算用尽" };
  var url = String(base).replace(/\/+$/, "") + "/domain/" + encodeURIComponent(reg);
  var ctrl = new AbortController();
  var timer = setTimeout(function () { try { ctrl.abort(); } catch (e) {} }, RDAP_TIMEOUT_MS);
  try {
    var res = await fetch(url, {
      headers: { "Accept": "application/rdap+json", "User-Agent": UA },
      signal: ctrl.signal,
      redirect: "follow"
    });
    // 404 只在「DoH 也查不出来」时才会被采信（见 probeOne），所以这里的弱证据不会单独判死
    if (res.status === 404) return { state: "unregistered", base: base };
    if (!res.ok) return { state: "unknown", base: base, reason: "HTTP " + res.status };
    var data;
    try { data = await res.json(); } catch (e) { return { state: "unknown", base: base, reason: "响应不是 JSON" }; }
    var st = (data && Array.isArray(data.status)) ? data.status : [];
    var bad = [];
    for (var i = 0; i < st.length; i++) { if (RDAP_DEAD_STATUS.indexOf(st[i]) !== -1) bad.push(st[i]); }
    if (bad.length) return { state: "doomed", base: base, status: bad.join(",") };
    // 到期时间顺带记下来：接近到期的条目下个月很可能变成 dead，提前看得到
    var exp = "";
    var evts = (data && data.events) || [];
    for (var e = 0; e < evts.length; e++) {
      if (evts[e] && evts[e].eventAction === "expiration") { exp = evts[e].eventDate || ""; break; }
    }
    return { state: "registered", base: base, status: st.join(","), expires: exp };
  } catch (err) {
    var msg = (err && err.message) || String(err);
    return { state: "unknown", base: base, reason: /abort/i.test(msg) ? "RDAP 超时" : ("网络错误：" + msg) };
  } finally {
    clearTimeout(timer);
  }
}

// IANA RDAP 引导表：TLD → 该注册局的 RDAP 根地址（KV 缓存 7 天）。
// 不走 rdap.org 中转：它是社区服务、按 IP 限流，对不支持的后缀也会回 404，用它判死会假阳性。
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

// 问注册局：只有 IANA 引导表里登记过的 TLD 才有 RDAP。
// .cn 全系（含 com.cn / org.cn / .中国）没有 RDAP 服务，CNNIC 只做 WHOIS，
// 这里就老实返回「没有服务」，由调用方归 unreachable —— 不猜、不判死。
// 2026-11-17 撤销了上一版写死的 CNNIC 端点：rdap.cnnic.cn 这个域名不存在（DNS ENOTFOUND）。
async function probeRegistry(reg, bootstrapMap, budget) {
  var tld = reg.split(".").pop();
  var base = (bootstrapMap && bootstrapMap[tld]) ? String(bootstrapMap[tld]).replace(/\/+$/, "") : "";
  if (!base) return { state: "unknown", reason: "该后缀没有 RDAP 服务（." + tld + "），无法核实注册状态", tried: [] };
  var r = await queryRegistry(base, reg, budget);
  if (r.exhausted) return { state: "unknown", exhausted: true, reason: r.reason, tried: [base] };
  if (r.state === "unknown") return { state: "unknown", reason: r.reason || "注册局未给出结论", tried: [base] };
  return r;
}

// 探测单个主机：先看能不能打开，再说域名还在不在，最后才请注册局作证
// budget 用尽时返回 state:"deferred" —— 这条**没得出结论**，不能被算成
// alive/dead/unreachable 中的任何一个（否则邮件会把"没查"写成"打不开"）。
async function probeOne(host, bootstrapMap, budget) {
  var reg = registrableOf(host);
  var defer = { host: host, reg: reg, state: "deferred", reason: "子请求预算用尽，本轮未探完" };

  var http = await probeHttp(host, budget);
  if (http.ok) {
    return {
      host: host, reg: reg, state: "alive",
      reason: "HTTP " + http.status + "（" + http.via + "）",
      http: http.status, via: http.via, finalUrl: http.finalUrl
    };
  }
  if (http.exhausted && !http.via) return defer;   // 一次都没发出去：原样留给下一轮

  // 打不开 → DNS 确认域名还在不在（这一步不需要碰目标站点）
  var dns = await dohLookup(host, budget);
  if (dns.exhausted) return defer;
  if (dns.ok && dns.nx) {
    return { host: host, reg: reg, state: "dead", httpErr: http.kind, reason: "DNS 中不存在（NXDOMAIN），浏览器必然打不开" };
  }
  if (dns.ok) {
    return {
      host: host, reg: reg, state: "unreachable", httpErr: http.kind, dns: "ok",
      reason: "站点不响应（" + http.kind + "），但域名解析正常——可能被墙 / 地域屏蔽 / 临时故障，请人工确认"
    };
  }

  // DoH 也查不出来 → 才请注册局
  var rd = await probeRegistry(reg, bootstrapMap, budget);
  if (rd.exhausted) return defer;
  if (rd.state === "unregistered") {
    return { host: host, reg: reg, state: "dead", httpErr: http.kind, registry: rd.base, reason: "连不上，且注册局无 " + reg + " 的记录" };
  }
  if (rd.state === "doomed") {
    return { host: host, reg: reg, state: "dead", httpErr: http.kind, registry: rd.base, reason: "连不上，注册局状态 " + rd.status };
  }
  if (rd.state === "registered") {
    return {
      host: host, reg: reg, state: "unreachable", httpErr: http.kind, registry: rd.base, expires: rd.expires || "",
      reason: "站点不响应（" + http.kind + "），但域名在册" + (rd.expires ? "（到期 " + rd.expires + "）" : "") + "，请人工确认"
    };
  }
  return {
    host: host, reg: reg, state: "unreachable", httpErr: http.kind,
    reason: "连不上，DNS 查询失败，注册状态未能确认（" + (rd.reason || "未知") + "）"
  };
}

// 巡检主流程：读名单 → 挑目标 → 分批探测 → 汇总写 KV / 日志
async function runHealthCheck(env, opts) {
  var t0 = Date.now();
  var deadline = t0 + HEALTH_BUDGET_MS;
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
    return {
      ok: true, at: new Date().toISOString(), source: src.source, total: 0, probed: 0,
      alive: 0, dead: 0, unreachable: 0, unknown: 0, deadList: [], unreachableList: [], skipped: sel.skipped
    };
  }

  // 2) 游标：名单比单次上限长时，每天接着上次的位置探，几天覆盖一轮。
  //    取数**不环绕**：走到名单尾部就停，下一轮从头开始。
  //    旧写法是环形取满 take 条（hosts[(cursor+i) % len]），后果是「本轮刚探过的尾巴
  //    又被下一轮当成新条目再探一遍」——11 条名单、每轮只能跑 8 条时，第 2 轮里有 5 条
  //    是上一轮刚探完的，白花子请求也白等超时。
  var cursor = 0;
  if (kv) {
    try { cursor = parseInt(await kv.get(HEALTH_CURSOR_KEY), 10) || 0; } catch (e) { cursor = 0; }
  }
  if (cursor < 0 || cursor >= hosts.length) cursor = 0;
  var take = Math.min(PROBE_MAX_PER_RUN, hosts.length - cursor);
  var slice = [];
  for (var i = 0; i < take; i++) slice.push(hosts[cursor + i]);

  // 3) 引导表（1 个子请求，缓存 7 天）。拉不到不致命：会退化成 unreachable，不会误删。
  var bs = await loadRdapBootstrap(env);
  if (!bs.map) console.warn("[health] RDAP 引导表不可用（仅影响佐证）：" + (bs.error || "未知原因"));

  // 4) 分批探测：并发 4；三种预算任一不够就停（剩下的下一轮继续）
  var results = [];
  var stopped = "";
  var budget = { used: 0, max: SUBREQ_BUDGET };
  var hardLine = t0 + HEALTH_HARD_MS;
  for (var n = 0; n < slice.length; n += PROBE_CONCURRENCY) {
    if (Date.now() > deadline) { stopped = "时间预算用尽（" + Math.round(HEALTH_BUDGET_MS / 1000) + "s），剩余条目下一轮继续"; break; }
    // 不能只看「现在超没超」：24.9 秒时放行一批，这批最坏还要 18 秒，总时长就冲到 43 秒。
    // 所以问的是「这一批跑完会不会越线」，会就越线前停手。
    if (Date.now() + PROBE_WORST_CASE_MS > hardLine) {
      stopped = "为不超过 " + Math.round(HEALTH_HARD_MS / 1000) + "s 墙钟，剩余条目下一轮继续";
      break;
    }
    if (budgetLeft(budget) <= 0) { stopped = "子请求预算用尽（上限 " + SUBREQ_BUDGET + " 次），剩余条目下一轮继续"; break; }
    var batch = slice.slice(n, n + PROBE_CONCURRENCY);
    var rs = await Promise.all(batch.map(function (h) { return probeOne(h, bs.map || {}, budget); }));
    for (var b = 0; b < rs.length; b++) results.push(rs[b]);
  }
  // 预算用尽后 probeOne 立刻返回 deferred。并发交错时 deferred 可能夹在中间，
  // 所以只承认「从头开始连续完成」的那一段：游标前进 advance 条，
  // 夹在中间的那些下轮会重探（多花一两次，但绝不会漏）。
  var advance = 0;
  while (advance < results.length && results[advance].state !== "deferred") advance++;
  var deferredCount = 0;
  for (var d = 0; d < results.length; d++) if (results[d].state === "deferred") deferredCount++;
  var done = results.filter(function (x) { return x.state !== "deferred"; });
  if (deferredCount && !stopped) stopped = "子请求预算用尽（上限 " + SUBREQ_BUDGET + " 次），剩余条目下一轮继续";

  // 5) 汇总
  var alive = [], dead = [], unreachable = [], deadList = [], unreachableList = [];
  for (var r = 0; r < done.length; r++) {
    var it = done[r];
    if (it.state === "dead") { dead.push(it); deadList.push(it.host); }
    else if (it.state === "unreachable") { unreachable.push(it); unreachableList.push(it.host); }
    else alive.push(it);
    if (verbose) console.log("[health] " + it.state + " " + it.host + "  " + it.reason);
  }

  var summary = {
    ok: true,
    at: new Date().toISOString(),
    source: src.source,
    path: src.path || "",
    elapsedMs: Date.now() - t0,
    total: Array.isArray(list.domains) ? list.domains.length : 0,
    probeable: hosts.length,
    probed: done.length,
    alive: alive.length,
    dead: dead.length,
    unreachable: unreachable.length,
    unknown: 0,
    subrequests: budget.used,
    subreqBudget: SUBREQ_BUDGET,
    deadList: deadList,
    unreachableList: unreachableList,
    // 只留前 20 条明细，避免摘要随名单增长而膨胀
    deadDetail: dead.slice(0, 20),
    unreachableDetail: unreachable.slice(0, 20),
    skipped: sel.skipped,
    note: stopped || "",
    // 把判据写进结果本身：以后看历史记录也知道这一版是怎么判的
    verdict: {
      dead: "HTTP 不可达 且（DNS 不存在 或 注册局明确无记录/已废弃）→ 可以删",
      unreachable: "HTTP 不可达但域名仍在（或无法确认）→ 不要自动删，请在国内网络点一遍"
    },
    // 游标走到名单尾部就归 0，下一轮从头开始（取数不环绕，所以不会有重复条目）；
    // 中途被预算截断时只前进「连续完成」的条数，剩下的下轮接着来
    cursorNext: (cursor + advance >= hosts.length) ? 0 : (cursor + advance)
  };

  // 6) 落盘：主机状态 / 摘要 / 游标
  //    主机状态合成一个 key 存：KV 的每次 put 都算一个子请求，
  //    25 条逐条 put 就是 25 次，正好把免费版 50 次的额度吃掉一半。
  //    这里只有一个消费者（人看），不需要单条读，合并成一次写更划算。
  if (kv) {
    try {
      // 先读旧快照再合并：一轮可能只探了名单的一段，整份覆盖会把没轮到的条目抹掉。
      // 代价是多 1 次 KV 读（预算里没算，但 SUBREQ_BUDGET 已留出余量）。
      var hostMap = {};
      try {
        var prevRaw = await kv.get(HEALTH_HOSTS_KEY);
        if (prevRaw) {
          var pj = JSON.parse(prevRaw);
          if (pj && pj.items && typeof pj.items === "object") hostMap = pj.items;
        }
      } catch (e) { hostMap = {}; }   // 旧值坏了就当没有，别拖累本轮写入

      for (var w = 0; w < done.length; w++) {
        var x = done[w];
        hostMap[x.host] = {
          state: x.state, reason: x.reason, reg: x.reg || "",
          expires: x.expires || "", at: summary.at   // at 既是「何时探的」，也是过期清理的依据
        };
      }

      // 清掉过期的残留：名单里删掉的域名不会自己消失。
      // 没有 at 的是上一版写入的旧格式，顺手一并清掉。
      var cutoff = Date.now() - HEALTH_HOST_TTL * 1000;
      var tracked = 0;
      for (var hk in hostMap) {
        if (!Object.prototype.hasOwnProperty.call(hostMap, hk)) continue;
        var it = hostMap[hk];
        var ts = it && it.at ? Date.parse(it.at) : NaN;
        if (!(ts >= cutoff)) { delete hostMap[hk]; continue; }
        tracked++;
      }

      await kv.put(HEALTH_HOSTS_KEY, JSON.stringify({ at: summary.at, tracked: tracked, items: hostMap }), { expirationTtl: HEALTH_HOST_TTL });
      await kv.put(HEALTH_SUMMARY_KEY, JSON.stringify(summary));
      await kv.put(HEALTH_CURSOR_KEY, String(summary.cursorNext));
    } catch (e) {
      console.error("[health] KV 写入失败：" + ((e && e.message) || e));
    }
  }

  return summary;
}

// ============================================================================
// 巡检结果邮件（2026-11-17）
//
// 「通过路由转发」是怎么走的：
//   Worker ──Brevo API──▶ feedback@silverfoxblocker.dpdns.org（本域名邮箱）
//                              │
//                              └── Cloudflare Email Routing 的既有规则 ──▶ 你的私人邮箱
//
// 这样做的意义：**私人邮箱地址不进代码、不进仓库**。以后换邮箱只在 Cloudflare
// 面板改一条路由规则即可，不用重新部署、不用改 Git 历史。
//
//   · 收件人默认就是这个域名邮箱；想分箱可新建 health@… 并加一条路由规则，
//     再把环境变量 HEALTH_MAIL_TO 指过去（无需改代码）。
//   · 没配 BREVO_API_KEY 时静默跳过，只在日志里说明——巡检本身照常完成。
//   · 发信失败**不影响**巡检结果落 KV：邮件只是通知渠道，不是数据本身。
// ============================================================================
var HEALTH_MAIL_FROM = "feedback@silverfoxblocker.dpdns.org";
var HEALTH_MAIL_TO_DEFAULT = "feedback@silverfoxblocker.dpdns.org";
var HEALTH_MAIL_TIMEOUT_MS = 8000;

function escMail(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
  });
}

// 邮件里统一用北京时间：cron 是 UTC 03:00，直接显示会被误读成凌晨
function bjTime(iso) {
  var d = new Date(iso);
  if (isNaN(d.getTime())) return String(iso || "");
  return new Date(d.getTime() + 8 * 3600 * 1000).toISOString().replace("T", " ").slice(0, 16) + "（北京时间）";
}

function healthMailSubject(s) {
  if (!s || !s.ok) return "【SilverFoxBlocker】名单巡检失败：" + ((s && s.error) || "未知原因");
  var tail = [];
  if (s.dead) tail.push(s.dead + " 条建议删除");
  if (s.unreachable) tail.push(s.unreachable + " 条待确认");
  if (!tail.length) tail.push("全部正常");
  var day = bjTime(s.at).slice(5, 10);
  return "【SilverFoxBlocker】名单巡检 " + day + "：" + tail.join("，");
}

function healthMailText(s) {
  var L = [];
  if (!s || !s.ok) {
    L.push("巡检没有跑完：" + ((s && s.error) || "未知原因"));
    return L.join("\n");
  }
  L.push("时间：" + bjTime(s.at));
  L.push("来源：" + (s.source || "-") + (s.path ? " / " + s.path : "") + "，耗时 " + s.elapsedMs + " ms");
  L.push("名单共 " + s.total + " 条；本次探测 " + s.probed + " 个主机（通配条目跳过 " + (s.skipped || []).length + " 条）");
  if (s.probeable && s.probed < s.probeable) {
    L.push("可探主机共 " + s.probeable + " 个，剩余 " + (s.probeable - s.probed) + " 个下一轮继续" +
      (s.subrequests ? "（本次发出 " + s.subrequests + " 次请求，预算 " + s.subreqBudget + "）" : ""));
  }
  L.push("存活 " + s.alive + " ｜ 建议删除 " + s.dead + " ｜ 打不开但域名在 " + s.unreachable);
  L.push("");
  L.push("== 建议删除（HTTP 打不开，且 DNS 不存在 / 注册局已注销）==");
  if (!s.deadDetail || !s.deadDetail.length) L.push("（无）");
  (s.deadDetail || []).forEach(function (d, i) {
    L.push((i + 1) + ". " + d.host + (d.reg && d.reg !== d.host ? "（主域 " + d.reg + "）" : "") + " —— " + d.reason);
  });
  L.push("");
  L.push("== 打不开但域名还在（不要直接删，请在国内网络点一遍）==");
  if (!s.unreachableDetail || !s.unreachableDetail.length) L.push("（无）");
  (s.unreachableDetail || []).forEach(function (d, i) {
    L.push((i + 1) + ". " + d.host + " —— " + d.reason);
  });
  if ((s.skipped || []).length) {
    L.push("");
    L.push("== 本次跳过 ==");
    s.skipped.forEach(function (x) { L.push("· " + x.entry + "（" + x.why + "）"); });
  }
  if (s.note) { L.push(""); L.push("备注：" + s.note); }
  L.push("");
  L.push("说明：Worker 只给建议，不会自动改名单。要在 blacklist.json 里手动删掉上面「建议删除」的条目。");
  return L.join("\n");
}

function healthMailHtml(s) {
  var css = "font:14px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI','Microsoft YaHei',sans-serif;color:#1f2328;";
  var card = "border:1px solid #e5e7eb;border-radius:10px;padding:16px 18px;margin:0 0 14px;";
  var th = "text-align:left;font-size:12px;color:#6b7280;font-weight:600;padding:6px 10px 6px 0;border-bottom:1px solid #eee;";
  var td = "padding:7px 10px 7px 0;border-bottom:1px solid #f3f4f6;vertical-align:top;word-break:break-all;";
  var mono = "font-family:ui-monospace,Consolas,monospace;font-size:13px;";

  if (!s || !s.ok) {
    return '<div style="' + css + '"><div style="' + card + '">' +
      '<h2 style="margin:0 0 8px;font-size:18px;color:#b91c1c;">巡检没有跑完</h2>' +
      '<p style="margin:0;">' + escMail((s && s.error) || "未知原因") + '</p>' +
      '<p style="margin:8px 0 0;color:#6b7280;font-size:13px;">时间：' + escMail(bjTime(s && s.at)) + '</p>' +
      '</div></div>';
  }

  var hl = [];
  hl.push('<div style="' + css + '">');
  hl.push('<div style="' + card + '">');
  hl.push('<h2 style="margin:0 0 4px;font-size:18px;">名单巡检 ' + escMail(bjTime(s.at).slice(0, 10)) + '</h2>');
  hl.push('<p style="margin:0;color:#6b7280;font-size:13px;">' + escMail(bjTime(s.at)) +
    ' ｜ 来源 ' + escMail(s.source || "-") + (s.path ? ' / ' + escMail(s.path) : "") +
    ' ｜ 耗时 ' + escMail(s.elapsedMs) + ' ms</p>');
  hl.push('<table style="border-collapse:collapse;margin-top:12px;width:100%;">');
  var nums = [
    ["名单条目", s.total, "#111827"],
    // 没探完时显示「已探 / 可探」，避免把「只探了 12 个」误读成「名单只有 12 个可探」
    ["本次探测", (s.probeable && s.probed < s.probeable) ? (s.probed + "/" + s.probeable) : s.probed, "#111827"],
    ["存活", s.alive, "#15803d"],
    ["建议删除", s.dead, s.dead ? "#b91c1c" : "#6b7280"],
    ["打不开但域名在", s.unreachable, s.unreachable ? "#b45309" : "#6b7280"],
    ["跳过（通配）", (s.skipped || []).length, "#6b7280"]
  ];
  hl.push('<tr>');
  nums.forEach(function (x) {
    hl.push('<td style="text-align:center;padding:10px 6px;border:1px solid #eee;border-radius:6px;">' +
      '<div style="font-size:20px;font-weight:700;color:' + x[2] + ';">' + escMail(x[1]) + '</div>' +
      '<div style="font-size:12px;color:#6b7280;">' + escMail(x[0]) + '</div></td>');
  });
  hl.push('</tr></table>');
  hl.push('</div>');

  // 建议删除
  hl.push('<div style="' + card + '">');
  hl.push('<h3 style="margin:0 0 10px;font-size:15px;color:#b91c1c;">建议删除（' + (s.dead || 0) + '）</h3>');
  if (!s.deadDetail || !s.deadDetail.length) {
    hl.push('<p style="margin:0;color:#15803d;">本次没有发现失效条目。</p>');
  } else {
    hl.push('<table style="border-collapse:collapse;width:100%;"><tr>' +
      '<th style="' + th + '">主机</th><th style="' + th + '">主域</th><th style="' + th + '">依据</th></tr>');
    s.deadDetail.forEach(function (d) {
      hl.push('<tr><td style="' + td + mono + '">' + escMail(d.host) + '</td>' +
        '<td style="' + td + mono + 'color:#6b7280;">' + escMail(d.reg || "-") + '</td>' +
        '<td style="' + td + 'font-size:13px;">' + escMail(d.reason) + '</td></tr>');
    });
    hl.push('</table>');
  }
  hl.push('</div>');

  // 待确认
  hl.push('<div style="' + card + '">');
  hl.push('<h3 style="margin:0 0 10px;font-size:15px;color:#b45309;">打不开但域名还在（' + (s.unreachable || 0) + '）</h3>');
  if (!s.unreachableDetail || !s.unreachableDetail.length) {
    hl.push('<p style="margin:0;color:#6b7280;">（无）</p>');
  } else {
    hl.push('<p style="margin:0 0 10px;color:#6b7280;font-size:13px;">' +
      'Cloudflare 出口在境外，国内站点可能只是被墙 / 被地域屏蔽。这些 <strong>不要</strong> 直接删，请在国内网络点一遍。</p>');
    hl.push('<table style="border-collapse:collapse;width:100%;"><tr>' +
      '<th style="' + th + '">主机</th><th style="' + th + '">依据</th></tr>');
    s.unreachableDetail.forEach(function (d) {
      hl.push('<tr><td style="' + td + mono + '">' + escMail(d.host) + '</td>' +
        '<td style="' + td + 'font-size:13px;">' + escMail(d.reason) + '</td></tr>');
    });
    hl.push('</table>');
  }
  hl.push('</div>');

  // 跳过
  if ((s.skipped || []).length) {
    hl.push('<div style="' + card + '">');
    hl.push('<h3 style="margin:0 0 8px;font-size:15px;">本次跳过（' + s.skipped.length + '）</h3>');
    hl.push('<p style="margin:0;color:#6b7280;font-size:13px;">通配条目没有确定主机名，无法探测。</p>');
    hl.push('<ul style="margin:8px 0 0;padding-left:20px;' + mono + '">');
    s.skipped.forEach(function (x) {
      hl.push('<li>' + escMail(x.entry) + ' <span style="color:#9ca3af;">（' + escMail(x.why) + '）</span></li>');
    });
    hl.push('</ul></div>');
  }

  if (s.note) {
    hl.push('<div style="' + card + '">');
    hl.push('<p style="margin:0;color:#6b7280;font-size:13px;">备注：' + escMail(s.note) + '</p>');
    hl.push('</div>');
  }

  hl.push('<p style="color:#9ca3af;font-size:12px;margin:0;">' +
    'Worker 只给建议，不会自动改名单 —— 请在 blacklist.json 里手动删掉「建议删除」的条目。<br>' +
    '判据：' + escMail(s.verdict && s.verdict.dead) + '<br>' + escMail(s.verdict && s.verdict.unreachable) + '</p>');
  hl.push('</div>');
  return hl.join("");
}

// 发一封巡检结果邮件。返回 { ok, to, id } 或 { ok:false, skipped|error }
async function sendHealthMail(env, summary) {
  if (!env || !env.BREVO_API_KEY) return { ok: false, skipped: "未配置 BREVO_API_KEY" };
  var to = String(env.HEALTH_MAIL_TO || HEALTH_MAIL_TO_DEFAULT).trim();
  if (!to) return { ok: false, skipped: "收件人为空" };

  var payload = {
    sender: { name: "SilverFoxBlocker 巡检", email: HEALTH_MAIL_FROM },
    to: [{ email: to }],
    subject: healthMailSubject(summary),
    htmlContent: healthMailHtml(summary),
    textContent: healthMailText(summary)
  };
  // 只在真有失效条目时才抄送一份到回复地址？不需要——保持单一收件人，避免被当成垃圾邮件。

  var r = await getText("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: { "api-key": env.BREVO_API_KEY, "Content-Type": "application/json", "Accept": "application/json" },
    body: JSON.stringify(payload)
  }, HEALTH_MAIL_TIMEOUT_MS);

  if (!r.ok) return { ok: false, to: to, error: "Brevo HTTP " + r.status + " " + String(r.text || r.error || "").slice(0, 200) };
  return { ok: true, to: to };
}

var index_default = {
  async fetch(request, env, ctx) {
    // 来源校验前置：不在白名单的 Origin 一律 403（含 OPTIONS 预检）。
    //   2026-11-27 起 403 也带 CORS 头（见 corsFor 注释）：扩展侧能读到 error/detail 原文，
    //   而不是被浏览器折叠成一句 TypeError('Failed to fetch')。响应体里没有任何名单数据。
    const cors = corsFor(request, env);
    if (!cors.ok) {
      console.warn("[cors] 拒绝未授权来源：" + (request.headers.get("Origin") || "(none)"));
      return new Response(JSON.stringify({
        error: "Origin not allowed",
        detail: "该来源未被授权访问本接口。仅限 SilverFoxBlocker 扩展（chrome-extension://）调用。"
      }), {
        status: 403,
        headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...cors.headers }
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
    // 功能 C: 名单存活巡检（HTTP 探测为主，DNS / RDAP 佐证）
    //   GET /health                → 最近一次巡检的摘要（读 KV）
    //   GET /health?run=1          → 立刻跑一次（最慢约 25s，受 HEALTH_BUDGET_MS 约束）
    //   GET /health?run=1&mail=1   → 跑一次并把结果发到邮箱（用来验证转发链路通不通）
    //   GET /health?mail=1         → 把 KV 里那份结果再发一次（不重跑探测）
    //   GET /health?dead=1         → text/plain，一行一个「建议删除」的域名
    //   GET /health?unreachable=1  → text/plain，一行一个「打不开但域名还在」的域名（需人工确认）
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
      let mail = null;
      if (url.searchParams.get("run") === "1") {
        summary = await runHealthCheck(env);
      } else if (kv) {
        try {
          const s = await kv.get(HEALTH_SUMMARY_KEY);
          if (s) summary = JSON.parse(s);
        } catch (e) { /* 读不出来就当没有历史结果 */ }
      }
      if (url.searchParams.get("mail") === "1") {
        mail = summary ? await sendHealthMail(env, summary) : { ok: false, skipped: "没有可发的巡检结果" };
      }
      const fmt = String(url.searchParams.get("list") || "").toLowerCase();
      const wantDead = url.searchParams.get("dead") === "1";
      const wantUnreach = url.searchParams.get("unreachable") === "1";
      if (wantDead || wantUnreach || fmt === "dead" || fmt === "unreachable") {
        const pick = (wantDead || fmt === "dead") ? "deadList" : "unreachableList";
        const list = (summary && summary[pick]) || [];
        return new Response(list.join("\n") + (list.length ? "\n" : ""), {
          status: 200,
          headers: {
            "Content-Type": "text/plain; charset=utf-8",
            "Cache-Control": "no-store",
            "X-Data-Source": "http-probe",
            ...cors.headers
          }
        });
      }
      return new Response(JSON.stringify({
        ok: !!summary,
        kvBound: !!kv,
        note: kv ? null : "未绑定 HEALTH KV：巡检结果只在 cron 日志里。新建命名空间后把 id 填进 wrangler.toml 再部署。",
        mail: mail,   // 只有带 &mail=1 时非 null
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
      if (!s.ok) {
        console.error("[cron] 巡检未完成：" + (s.error || "未知原因"));
        return sendHealthMail(env, s).then(function (m) {
          // 巡检失败也要通知到人，否则「没收到邮件」和「没跑」分不清
          if (!m.ok) console.warn("[cron] 失败通知未发出：" + (m.skipped || m.error));
        });
      }
      console.log("[cron] 巡检完成 " + JSON.stringify({
        source: s.source, total: s.total, probeable: s.probeable, probed: s.probed,
        alive: s.alive, dead: s.dead, unreachable: s.unreachable,
        subrequests: s.subrequests, elapsedMs: s.elapsedMs
      }));
      if (s.deadList && s.deadList.length) console.warn("[cron] 疑似失效（需人工确认后再删）: " + s.deadList.join(", "));
      if (s.note) console.warn("[cron] " + s.note);
      // 邮件失败不影响巡检结果（已写进 KV），这里只记日志
      return sendHealthMail(env, s).then(function (m) {
        if (m.ok) console.log("[cron] 巡检结果已发往 " + m.to + "（由 Email Routing 转发到私人邮箱）");
        else console.warn("[cron] 巡检邮件未发出：" + (m.skipped || m.error));
      });
    }).catch(function (e) {
      console.error("[cron] 巡检异常：" + ((e && e.stack) || e));
    }));
  }
};

export { index_default as default };
