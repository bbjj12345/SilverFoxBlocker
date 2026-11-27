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
    "Access-Control-Allow-Headers": "Content-Type, X-API-Key, X-SF-Ts, X-SF-Sig",
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
// openSigned=true 时（反馈接口 /send）不做来源判定：那里的门禁是 HMAC 签名，与 Origin 无关，
//   任何来源都必须拿到 CORS 头，否则网页侧 / 扩展侧都读不到 401 的原因，又退回「Failed to fetch」。
function corsFor(request, env, openSigned) {
  var origin = request.headers.get("Origin") || "";
  if (!origin) return { ok: true, headers: {} };   // 非浏览器请求：给数据、不给跨源许可
  if (openSigned) return { ok: true, headers: corsHeadersFor(origin) };
  // 被拒时**也**回显 CORS 头（数据一个字节都不给，只给 403 的 JSON 说明）。
  //   旧行为是被拒就不带 CORS 头，于是浏览器把 403 折成 TypeError('Failed to fetch')，
  //   扩展侧只能笼统说「连不上」，用户和作者都分不清「网络不通」与「来源被拒」。
  if (!allowedOriginHit(env, origin)) return { ok: false, headers: corsRejectHeadersFor(origin) };
  return { ok: true, headers: corsHeadersFor(origin) };
}

// ============================================================================
// 反馈接口鉴权：共享密钥 + HMAC-SHA256（2026-11-27）
//
// 为什么不在 Origin 白名单上继续加码：本地「加载已解压」的扩展 ID 由解压路径决定，
//   换台电脑就换一个，白名单永远追不上；而一旦为了省事写成 `chrome-extension://*`，
//   就等于「任何装了的扩展都能往作者邮箱灌垃圾」。
//
// 现在的分工：/send 只认签名，不认 Origin。
//   · 扩招端内置同一把密钥，用 密钥 + (路径 + 时间戳 + 请求体) 算 HMAC-SHA256，
//     把 时间戳 与 签名 放进 X-SF-Ts / X-SF-Sig 两个请求头。
//   · Worker 端用 SECRET_DATA（Cloudflare Secret，不进仓库、不进扩展包）重算并逐字节比对；
//     同时要求时间戳落在 ±5 分钟内，超窗即拒 —— 截获的旧请求过一会儿就自动作废。
//   · 没有密钥的人（爬虫、脚本、别的网站）算不出有效签名，连限流配额都碰不到，
//     因为验签在限流之前、也在发信之前。
//
// 边界（必须说清）：密钥随扩展包分发，解包就能看到，所以它挡的是「随手打接口」，
//   不是「有决心逆向的人」。真被人拿去刷，改 SECRET_DATA（`wrangler secret put`）
//   并发一版扩展即可止血，历史请求的签名分布对新密钥全部失效。
// ============================================================================
var FEEDBACK_TS_SKEW_MS = 5 * 60 * 1000;     // 允许的时间偏差（同时充当重放窗口）
var SIGN_SECRET_MIN_LEN = 16;                // 太短的密钥直接当没配

// 哪些请求属于「反馈提交」，从而不看 Origin、改看签名：
//   现有路由只有 GET /list、GET /health 与「其它一律当反馈 POST」，
//   所以这里用排除法，避免把签名的路径写死成某个具体字符串（以后加路径不会漏配）。
//   /challenge 也落在这一类里（它是无数据页面，被 iframe 加载时 CORS 本来也不生效），
//   所以任何来源都能读它 —— 差别只在于「读到的是一张没有用户数据的验证页」。特意不加白名单：
//   一旦扩展 ID 不在白名单，挑战页会变成 403 白屏，反而看不出原因。
function isFeedbackPath(pathname) {
  return pathname !== "/list" && pathname !== "/health";
}

function hexFromBytes(bytes) {
  var out = "";
  for (var i = 0; i < bytes.length; i++) {
    out += (bytes[i] < 16 ? "0" : "") + bytes[i].toString(16);
  }
  return out;
}

// 定长逐字节比较，不做提前返回：避免用响应时间逐个试出签名的前缀
function constantTimeEqualHex(a, b) {
  a = String(a || "").toLowerCase();
  b = String(b || "").toLowerCase();
  if (a.length !== b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// 待签名串：路径 + "\n" + 时间戳 + "\n" + 请求体
//   路径参与签名，防止把 /list 上的签名搬到 /send 上复用；
//   "\n" 分隔是为了让各段边界明确（否则 路径+时间戳 的拼接可以被挪位）。
function feedbackSignString(pathname, ts, body) {
  return pathname + "\n" + ts + "\n" + body;
}

async function feedbackHmacHex(secret, msg) {
  var enc = new TextEncoder();
  var key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  var mac = await crypto.subtle.sign("HMAC", key, enc.encode(msg));
  return hexFromBytes(new Uint8Array(mac));
}

// 返回 { ok } 或 { ok:false, status, error, detail }
//   error 用英文常量（便于脚本判断 / 记录日志），detail 是给人看的中文
async function verifyFeedbackSignature(request, bodyText, env) {
  var secret = String((env && env.SECRET_DATA) || "");
  if (secret.length < SIGN_SECRET_MIN_LEN) {
    return {
      ok: false, status: 503, error: "FEEDBACK_DISABLED",
      detail: "服务端未配置反馈签名密钥（SECRET_DATA），该接口暂时关闭。"
    };
  }
  var ts = String(request.headers.get("X-SF-Ts") || "").trim();
  var sig = String(request.headers.get("X-SF-Sig") || "").trim();
  if (!ts || !sig) {
    return { ok: false, status: 401, error: "SIGNATURE_REQUIRED", detail: "缺少签名头 X-SF-Ts / X-SF-Sig。" };
  }
  var t = Number(ts);
  if (!isFinite(t) || t <= 0) {
    return { ok: false, status: 401, error: "TIMESTAMP_INVALID", detail: "时间戳不是有效的毫秒数。" };
  }
  var skew = Date.now() - t;
  if (skew > FEEDBACK_TS_SKEW_MS || skew < -FEEDBACK_TS_SKEW_MS) {
    return {
      ok: false, status: 401, error: "TIMESTAMP_EXPIRED",
      detail: "时间戳超出 ±5 分钟窗口：多为本机时间不准，或这条请求被重放。"
    };
  }
  var pathname = new URL(request.url).pathname;
  var expect = await feedbackHmacHex(secret, feedbackSignString(pathname, ts, bodyText));
  if (!constantTimeEqualHex(expect, sig)) {
    return { ok: false, status: 401, error: "BAD_SIGNATURE", detail: "签名校验失败（密钥不一致，或请求体被改动）。" };
  }
  return { ok: true };
}

// ============================================================================
// 人机验证：Cloudflare Turnstile（2026-11-27，方案二）
//
// 为什么需要：HMAC 密钥随扩展包分发（本仓库公开，等于人人可见），它挡得住「随手打接口」，
//   挡不住把密钥抄出来跑脚本的人。Turnstile 是第二道闸：一次请求必须附一张「Cloudflare 现场
//   签发、只能用一次、5 分钟过期」的凭据，而这张凭据只能由真实浏览器在 widget 里换出来。
//
// 三个角色：
//   ① 挑战页 GET /challenge —— 本 Worker 自己吐的一小段 HTML，里面加载 Turnstile 官方脚本，
//      验证通过后用 postMessage 把 token 交给发起方。
//      为什么不让扩展直接引 challenges.cloudflare.com 的 api.js：MV3 扩展页面的 CSP 是
//      script-src 'self'，远程脚本一律被拒；iframe 不受这条限制。放在服务端还有个好处 ——
//      site key、widget 模式（managed / invisible）、主题都能在 Cloudflare 后台改，不必发版。
//   ② 提交 POST / —— 请求体多带一个 turnstileToken，验完签名、验完内容之后调 siteverify。
//   ③ 失败即关闭：只配了 site key 却没配 secret 时不生效（见 turnstileEnabled）。
//
// 与 HMAC 的关系：两道闸都开、且顺序是「验签 → 验人机」——签名不合格的请求连 siteverify
//   的子请求都不会发出去（不烧配额、不给 Cloudflare 添负载）。
// 未配置 TURNSTILE_SECRET_KEY 时整段透明跳过：老部署升级 Worker 不会突然收不到反馈。
// ============================================================================
var TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
var TURNSTILE_API_JS = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=sfbTsOnload";
var TURNSTILE_MAX_TOKEN = 2048;              // 正常 token 约 1~2 KB，超长直接拒
var TURNSTILE_TIMEOUT_MS = 6000;             // siteverify 超时：宁可让人重试，也别让请求挂死
var TURNSTILE_SECRET_MIN_LEN = 16;
var FEEDBACK_DAILY_QUOTA = 60;               // 正常通道：每 IP 每天上限（与 v1.13.11 一致）
var TURNSTILE_SOFT_QUOTA_DEFAULT = 3;        // 降级通道：没过人机验证时每 IP 每天上限

function turnstileSiteKey(env) { return String((env && env.TURNSTILE_SITE_KEY) || "").trim(); }
function turnstileSecret(env) { return String((env && env.TURNSTILE_SECRET_KEY) || "").trim(); }

// ============================================================================
// soft / strict（2026-11-27 修订，默认 soft）
//
// 起因：v1.13.12 是硬拦截 —— 没有任何 token 一律 403。可「拿不到 token」有两种完全不同的原因，
//   硬拦截把它们混为一谈：
//     (a) 真是机器人 / 脚本；
//     (b) 用户网络打不开 challenges.cloudflare.com（大陆网络下并不罕见），验证框 12 秒出不来，
//         重试多少次都一样 —— 人被永久挡在门外，且他没有任何自救手段。
//
// soft 的语义：人机验证是「配额通行证」，不是「门票」。
//   · 通过验证            → 正常配额（60 次/天）
//   · 过不了（框没出来 / 凭据过期 / siteverify 连不上 / 服务端密钥错）→ **仍然放行**，但只给 soft 配额（3 次/天）
//   · 明显伪造（token 超长）→ 仍然 400，不奖励
//
// 三个刻意的设计点：
//   ① soft **不等于**「不弹验证框」。第一次请求照旧回 403 TURNSTILE_REQUIRED 去触发弹框；
//      只有客户端明确带 `turnstileFallback: true`（意思是「框我试过了，确实出不来」）才降级。
//      否则 soft 就退化成「完全不验证」，那等于白配。
//   ② 降级额度单独计数（rate_limit_soft_*），且**主计数照样累加**：防「先发满 60 次正常额度，
//      再靠降级通道继续发」，总量仍在 60/天 之下。
//   ③ 降级是「有成本」的：3 次/天 对真实用户够用（谁会一天反馈 4 次？），对刷子等于封顶。
// ============================================================================
function turnstileEnforce(env) {
  var v = String((env && env.TURNSTILE_ENFORCE) || "").trim().toLowerCase();
  if (v === "strict" || v === "soft") return v;
  return "soft";                              // 默认值：宁可少挡几个机器人，也别挡掉真实用户
}

function turnstileSoftQuota(env) {
  var n = parseInt((env && env.TURNSTILE_SOFT_QUOTA) || "", 10);
  if (!isFinite(n) || n <= 0) return TURNSTILE_SOFT_QUOTA_DEFAULT;
  return Math.min(n, FEEDBACK_DAILY_QUOTA);   // 降级额度不能超过正常额度，否则 soft 比 strict 还松
}

// 只认 secret：只有 site key 时页面能画出 widget，服务端却验不了，那是最坏的「看起来能用」。
function turnstileEnabled(env) {
  return turnstileSecret(env).length >= TURNSTILE_SECRET_MIN_LEN;
}

/* 旧实现（v1.13.12）：无 token 一律 403 REQUIRED —— 硬拦截。
//   问题：把「机器人」和「网络打不开 challenges.cloudflare.com 的真实用户」判成同一类，
//   后者重试多少次都会被挡，且没有任何自救手段。2026-11-27 起默认改为 soft，见上方说明。
// // 返回 { ok:true, mode:'off'|'pass' } 或 { ok:false, status, error, detail }
// //   error 是英文常量（扩展据此决定「弹验证框重试」还是「直接报错」），detail 是给人看的中文。
// async function verifyTurnstile(token, ip, env) {
//   if (!turnstileEnabled(env)) return { ok: true, mode: "off" };
//   token = String(token || "").trim();
//   if (!token) {
//     return {
//       ok: false, status: 403, error: "TURNSTILE_REQUIRED",
//       detail: "该接口需要人机验证：请重新点击发送，并在验证框里完成验证。"
//     };
//   }
//   if (token.length > TURNSTILE_MAX_TOKEN) {
//     return { ok: false, status: 400, error: "TURNSTILE_BAD_TOKEN", detail: "人机验证凭据格式不正确（过长）。" };
//   }
//
//   var form = new URLSearchParams();
//   form.set("secret", turnstileSecret(env));
//   form.set("response", token);
//   if (ip && ip !== "unknown") form.set("remoteip", ip);   // 可选：让 token 与本机 IP 绑定
//
//   var ctrl = new AbortController();
//   var timer = setTimeout(function () { try { ctrl.abort(); } catch (e) {} }, TURNSTILE_TIMEOUT_MS);
//   var json = null;
//   try {
//     var res = await fetch(TURNSTILE_VERIFY_URL, { method: "POST", body: form, signal: ctrl.signal });
//     json = await res.json();
//   } catch (e) {
//     return {
//       ok: false, status: 503, error: "TURNSTILE_UNREACHABLE",
//       detail: "人机验证服务暂时无法连接，请稍后重试。"
//     };
//   } finally {
//     clearTimeout(timer);
//   }
//
//   if (json && json.success === true) return { ok: true, mode: "pass" };
//
//   var codes = (json && json["error-codes"]) || [];
//   var code = String(codes[0] || "unknown");
//   // 单次有效：重复提交、超过 5 分钟都会拿到 timeout-or-duplicate —— 这是最常见的一种失败，
//   //   必须让扩展侧能区分出来（提示「请重新验证」，而不是「签名错了」）。
//   if (code === "timeout-or-duplicate") {
//     return {
//       ok: false, status: 403, error: "TURNSTILE_EXPIRED",
//       detail: "人机验证凭据已过期或已使用过（每张凭据只能提交一次），请重新验证。"
//     };
//   }
//   if (code === "invalid-input-secret" || code === "missing-input-secret") {
//     return {
//       ok: false, status: 503, error: "TURNSTILE_MISCONFIGURED",
//       detail: "服务端人机验证密钥无效（TURNSTILE_SECRET_KEY 与 site key 不匹配），该接口暂时关闭。"
//     };
//   }
//   return { ok: false, status: 403, error: "TURNSTILE_FAILED", detail: "人机验证未通过，请重试。" };
// }
*/

// 返回 { ok:true, mode:'off'|'pass'|'soft-degraded', quota, degraded? }
//   或   { ok:false, status, error, detail }
//   quota ：本次请求适用的每日上限（通过验证 60 / 降级 3），由调用方拿去和 KV 计数比
//   degraded：降级原因，只进日志与响应体，不进用户界面文案
//   fallback：客户端声明「验证框我试过了，确实出不来」——soft 模式下据此放行
async function verifyTurnstile(token, ip, env, fallback) {
  // 未配置 secret → 整段透明跳过，老部署升级后行为不变
  if (!turnstileEnabled(env)) return { ok: true, mode: "off", quota: FEEDBACK_DAILY_QUOTA };

  var soft = turnstileEnforce(env) === "soft";
  var softQuota = turnstileSoftQuota(env);

  // 降级出口：soft 模式下「没通过验证」一律走这里 —— 放行，但配额收紧。
  //   注意这里**不是**放行给所有人：调用方还会拿 quota 去查 KV，3 次/天 是硬顶。
  function degrade(reason) {
    return { ok: true, mode: "soft-degraded", quota: softQuota, degraded: reason };
  }

  token = String(token || "").trim();
  if (!token) {
    // 带 fallback 标记 = 客户端已经弹过框、确实没拿到 token（超时 / 脚本被拦 / 服务端没配 site key）
    if (soft && fallback) return degrade("no-token-fallback");
    return {
      ok: false, status: 403, error: "TURNSTILE_REQUIRED",
      detail: soft
        ? "该接口需要人机验证：请重新点击发送完成验证；若验证框加载不出来，扩展会自动以低配额发送。"
        : "该接口需要人机验证：请重新点击发送，并在验证框里完成验证。"
    };
  }
  if (token.length > TURNSTILE_MAX_TOKEN) {
    // 格式非法＝明显伪造，soft 也不放行（否则「随便塞一坨超长串」就成免费通道了）
    return { ok: false, status: 400, error: "TURNSTILE_BAD_TOKEN", detail: "人机验证凭据格式不正确（过长）。" };
  }

  var form = new URLSearchParams();
  form.set("secret", turnstileSecret(env));
  form.set("response", token);
  if (ip && ip !== "unknown") form.set("remoteip", ip);   // 可选：让 token 与本机 IP 绑定

  var ctrl = new AbortController();
  var timer = setTimeout(function () { try { ctrl.abort(); } catch (e) {} }, TURNSTILE_TIMEOUT_MS);
  var json = null;
  try {
    var res = await fetch(TURNSTILE_VERIFY_URL, { method: "POST", body: form, signal: ctrl.signal });
    json = await res.json();
  } catch (e) {
    // Cloudflare 自己连不上 —— 纯服务端故障，与用户无关。soft 下不该让用户吃这个亏。
    if (soft) return degrade("unreachable");
    return {
      ok: false, status: 503, error: "TURNSTILE_UNREACHABLE",
      detail: "人机验证服务暂时无法连接，请稍后重试。"
    };
  } finally {
    clearTimeout(timer);
  }

  if (json && json.success === true) return { ok: true, mode: "pass", quota: FEEDBACK_DAILY_QUOTA };

  var codes = (json && json["error-codes"]) || [];
  var code = String(codes[0] || "unknown");
  // 单次有效：重复提交、超过 5 分钟都会拿到 timeout-or-duplicate —— 这是最常见的一种失败，
  //   必须让扩展侧能区分出来（提示「请重新验证」，而不是「签名错了」）。
  if (code === "timeout-or-duplicate") {
    if (soft) return degrade("expired");
    return {
      ok: false, status: 403, error: "TURNSTILE_EXPIRED",
      detail: "人机验证凭据已过期或已使用过（每张凭据只能提交一次），请重新验证。"
    };
  }
  if (code === "invalid-input-secret" || code === "missing-input-secret") {
    // 服务端密钥错：所有用户都验不过。strict 下等于全站关闭反馈，soft 下退到低配额 ——
    //   宁可让作者从日志里看到配置错了，也别让用户替作者的配置背锅。
    if (soft) return degrade("misconfigured");
    return {
      ok: false, status: 503, error: "TURNSTILE_MISCONFIGURED",
      detail: "服务端人机验证密钥无效（TURNSTILE_SECRET_KEY 与 site key 不匹配），该接口暂时关闭。"
    };
  }
  if (soft) return degrade("failed:" + code);
  return { ok: false, status: 403, error: "TURNSTILE_FAILED", detail: "人机验证未通过，请重试。" };
}

// 挑战页：一段自包含 HTML。不加载任何本站资源，只有 Cloudflare 的 widget 脚本。
//   三种状态都通过 postMessage 告诉父窗口（扩展），避免「页面白屏、扩展一直转圈」：
//     {type:'off'}    服务端没开人机验证 → 扩展照常发送
//     {type:'error'}  配置/加载失败      → 扩展明确报错，不静默失败
//     {type:'token'}  验证通过           → 扩展把 token 拼进请求体
// 不加严格 CSP：Turnstile 的 api.js 自身会注入内联样式与 iframe，配错 CSP 的代价是
//   「谁也发不出反馈」，而这张页面上没有任何用户数据可被 XSS 偷走（不读 cookie、不带凭据）。
function turnstileChallengeHtml(env, opts) {
  var o = opts || {};
  var theme = (o.theme === "light" || o.theme === "dark") ? o.theme : "auto";
  var siteKey = turnstileSiteKey(env);
  var on = turnstileEnabled(env);
  var mode, reason = "";
  if (!on) mode = "off";
  else if (!siteKey) { mode = "error"; reason = "no-sitekey"; }
  else mode = "on";

  var boot = "{mode:" + JSON.stringify(mode)
    + ",siteKey:" + JSON.stringify(mode === "on" ? siteKey : "")
    + ",theme:" + JSON.stringify(theme)
    + ",reason:" + JSON.stringify(reason)
    + ",api:" + JSON.stringify(TURNSTILE_API_JS) + "}";

  var lines = [
    "<!DOCTYPE html>",
    '<html lang="zh-CN"><head>',
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width,initial-scale=1">',
    "<title>人机验证</title>",
    "<style>",
    "html,body{margin:0;padding:0;background:transparent}",
    'body{min-height:72px;display:flex;align-items:center;justify-content:center;',
    'font:13px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,"Microsoft YaHei",sans-serif;',
    "color:#8b96a8}",
    "#sfbW{display:flex;justify-content:center}",
    "#sfbTip{font-size:12px;opacity:.7;padding:8px 6px;text-align:center}",
    "</style>",
    "</head><body>",
    '<div id="sfbW"></div>',
    '<div id="sfbTip">正在加载人机验证…</div>',
    "<script>",
    "(function(){",
    "  var CFG = " + boot + ";",
    "  var tip = document.getElementById('sfbTip');",
    "  function toParent(m){ m.source='sfb-challenge'; try{ parent.postMessage(m,'*'); }catch(e){} }",
    "  if (CFG.mode === 'off') { toParent({type:'off'}); return; }",
    "  if (CFG.mode === 'error') { tip.textContent='人机验证未配置'; toParent({type:'error',reason:CFG.reason}); return; }",
    "  var done = false, rendered = false;",
    "  function pass(t){ if(done) return; done = true; tip.textContent=''; toParent({type:'token',token:t}); }",
    "  window.sfbTsOnload = function(){",
    "    if (document.getElementById('sfbW').childNodes.length) return;",
    "    if (!window.turnstile) { tip.textContent='验证组件加载失败'; toParent({type:'error',reason:'script'}); return; }",
    "    rendered = true; tip.textContent='';",
    "    try {",
    "      window.turnstile.render('#sfbW', {",
    "        sitekey: CFG.siteKey, theme: CFG.theme, language: 'zh-cn',",
    "        callback: pass,",
    "        'error-callback': function(c){ toParent({type:'error',reason:String(c||'widget')}); return true; },",
    "        'expired-callback': function(){ done = false; tip.textContent='验证已过期，请重新勾选'; },",
    "        'timeout-callback': function(){ done = false; tip.textContent='验证超时，请重新勾选'; }",
    "      });",
    "    } catch (e) { toParent({type:'error',reason:'render'}); }",
    "  };",
    "  setTimeout(function(){ if(!rendered) toParent({type:'error',reason:'timeout'}); }, 12000);",
    "})();",
    "</" + "script>",
    '<script src="' + TURNSTILE_API_JS + '" async defer></' + "script>",
    "</body></html>"
  ];
  return lines.join("\n");
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
// /list 的「5 分钟缓存」（v1.13.15）
//
// 为什么必须加：/list 原先没有任何缓存，**每个请求都真的去打一次 GitHub → Gitee**。
//   配合「任意扩展来源放行」之后，任何人写个脚本循环 curl 就能：
//     ① 烧掉 Worker 的每日请求额度；② 吃光 GitHub token 的 5000 次/小时配额；
//     ③ 把 Gitee 镜像打到限流（429），于是**真用户也拉不到名单**。
//   名单一天最多变几次，却按「每个请求一次上游」的代价去取，纯属浪费。
//
// 做法（不是「限流」，但把上游压力压到理论下限）：
//   · 命中 5 分钟内的副本 → 直接返回，**一个上游子请求都不发**；
//   · 过期才去拉，拉到就写回 KV；同一 isolate 内并发请求共享同一个 Promise（防击穿）；
//   · 上游双源都失败时，**有旧副本就发旧的**（标 X-Data-Stale: 1），总比让用户看到 502 强；
//   · diag / force / nocache 三个参数一律穿透缓存 —— 诊断必须看到「此刻」的真实上游行为。
//
// 为什么是 5 分钟：名单更新频率以「天」计，5 分钟已经足够新鲜；再长会让作者改完名单后
//   自己都要等，反而添乱。要改只动 LIST_CACHE_TTL_MS。
//
// 存储复用已有 KV，不要求新建命名空间：
//   LIST_CACHE（可选，想独立管理时再建）→ 没绑就退到 HEALTH；
//   都没有（本地 wrangler dev 没配 KV）→ 自动降级成「不缓存」，行为与旧版一致。
//   留存 24 小时是为了「上游挂了还能发旧的」，新鲜度只看记录里的 ts，不看 TTL。
//
// 边界（如实写清）：这是**共享缓存**，不是鉴权。拿到 X-API-Key 的人依然能读名单
//   （它本来就随扩展包分发、仓库公开），缓存只保证「读的人再多，上游只被打一次/5 分钟」。
// ============================================================================
var LIST_CACHE_TTL_MS = 5 * 60 * 1000;          // 新鲜期：5 分钟
// nocache=1 的「最短刷新间隔」：它本意是「我改完名单想立刻看到」，但它同时也是
//   绕过缓存的免费通道 —— 参数写在公开代码里，谁都能带。所以再加一道：距上次拉取不足 60 秒
//   就先把那份副本发回去（最多旧 60 秒），把「带 nocache 刷接口」的上游压力也锁在 1 次/分钟。
var LIST_CACHE_MIN_REFRESH_MS = 60 * 1000;
var LIST_CACHE_KEEP_S = 24 * 60 * 60;           // KV 留存：24 小时（用于上游故障时兜底）
var LIST_CACHE_MAX_BYTES = 20 * 1024 * 1024;    // 单份名单上限（KV 单值上限 25MB，留余量）

function listCacheKv(env) {
  return (env && (env.LIST_CACHE || env.HEALTH)) || null;
}

function listCacheKey(file) {
  return 'list_cache_v1:' + String(file).replace(/[^A-Za-z0-9]/g, '_');
}

// 返回记录对象或 null；任何异常都当「没缓存」，绝不让缓存层把主流程弄挂
async function readListCache(env, file) {
  var kv = listCacheKv(env);
  if (!kv) return null;
  try {
    var raw = await kv.get(listCacheKey(file));
    if (!raw) return null;
    var rec = JSON.parse(raw);
    if (!rec || typeof rec.text !== 'string' || !rec.text || typeof rec.ts !== 'number') return null;
    return rec;
  } catch (e) {
    console.warn('[list] 读缓存失败，按未命中处理：' + ((e && e.message) || e));
    return null;
  }
}

function listCacheFresh(rec) {
  return !!rec && typeof rec.ts === 'number' && (Date.now() - rec.ts) < LIST_CACHE_TTL_MS;
}

async function writeListCache(env, file, rec) {
  var kv = listCacheKv(env);
  if (!kv || !rec || typeof rec.text !== 'string' || !rec.text) return false;
  if (rec.text.length > LIST_CACHE_MAX_BYTES) {
    console.warn('[list] 名单过大（' + rec.text.length + ' 字节），跳过写缓存');
    return false;
  }
  try {
    await kv.put(listCacheKey(file), JSON.stringify(rec), { expirationTtl: LIST_CACHE_KEEP_S });
    return true;
  } catch (e) {
    console.warn('[list] 写缓存失败（不影响本次返回）：' + ((e && e.message) || e));
    return false;
  }
}

// 双源拉取：主源 GitHub → 备源 Gitee。只负责「去拿」，不碰缓存、不拼响应。
async function fetchListUpstream(env, file, force) {
  var t0 = Date.now();
  var deadline = t0 + TOTAL_BUDGET_MS;
  // 主源最多占 GH_BUDGET_MS，剩下的时间强制留给 Gitee：
  // 否则「GitHub 卡死」这种最需要备源的场景，预算反而被主源吃光，备源一次都跑不到。
  var ghDeadline = Math.min(deadline, t0 + GH_BUDGET_MS);
  var useGithub = force !== 'gitee';
  var useGitee = force !== 'github';

  var gh = useGithub
    ? await readFromGithub(env, file, ghDeadline)
    : { ok: false, skipped: true, tries: [{ src: 'GitHub', error: '已跳过（force=gitee）' }] };

  if (gh.ok) {
    return {
      ok: true, text: gh.text, source: gh.source, path: gh.path, count: gh.count,
      ghTries: gh.tries, gtTries: [], giteeAttempted: false, elapsedMs: Date.now() - t0
    };
  }

  if (useGithub) console.warn('[list] GitHub 拉取失败，切换到 Gitee 镜像：' + JSON.stringify(gh.tries));

  var gt = useGitee
    ? await readFromGitee(env, file, deadline)
    : { ok: false, skipped: true, tries: [{ src: 'Gitee', error: '已跳过（force=github）' }] };

  return {
    ok: !!gt.ok, text: gt.ok ? gt.text : '', source: gt.ok ? gt.source : null,
    path: gt.ok ? gt.path : null, ref: gt.ok ? gt.ref : null, count: gt.ok ? gt.count : null,
    ghTries: gh.tries, gtTries: gt.tries, giteeAttempted: true, elapsedMs: Date.now() - t0
  };
}

// 同一 isolate 内的并发合并：10 个请求同时未命中，只让 1 个真去打上游。
//   只在 isolate 内存里有效（Cloudflare 会起多个 isolate），所以它是「锦上添花」，
//   真正的止血靠上面的 KV 缓存。
var LIST_INFLIGHT = Object.create(null);

function fetchListShared(env, file, force) {
  if (force) return fetchListUpstream(env, file, force);   // 强制源不参与合并，诊断语义更干净
  var k = String(file);
  if (LIST_INFLIGHT[k]) return LIST_INFLIGHT[k];
  var p = fetchListUpstream(env, file, force);
  LIST_INFLIGHT[k] = p;
  var done = function () { if (LIST_INFLIGHT[k] === p) delete LIST_INFLIGHT[k]; };
  p.then(done, done);
  return p;
}

// 统一的名单响应：把「数据来自哪、是不是缓存、缓存多旧」都放进响应头，便于排障
function listDataResponse(rec, cacheState, corsHeaders, stale) {
  var headers = {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',   // 缓存由服务端统一管，别让浏览器/CDN 再存一份（否则改动后要等两层过期）
    'X-Cache': cacheState,
    ...corsHeaders
  };
  if (rec.source) headers['X-Data-Source'] = rec.source;
  if (rec.path) headers['X-Data-Path'] = rec.path;
  if (rec.ts) headers['X-Cache-Age'] = String(Math.max(0, Math.round((Date.now() - rec.ts) / 1000)));
  if (stale) headers['X-Data-Stale'] = '1';
  return new Response(rec.text, { headers: headers });
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
    //   例外：反馈提交（/list、/health 之外的路径）不看 Origin —— 它用 HMAC 签名鉴权，见 verifyFeedbackSignature。
    const url = new URL(request.url);
    const cors = corsFor(request, env, isFeedbackPath(url.pathname));
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

    // ==========================================
    // 功能 A-1: 人机验证挑战页 (GET /challenge)
    //   由扩展在 iframe 里加载（扩展页面 CSP 禁止远程脚本，但不禁止 iframe）。
    //   页面只做一件事：换一张 Turnstile 凭据，postMessage 回父窗口。
    // ==========================================
    if (request.method === "GET" && url.pathname === "/challenge") {
      return new Response(turnstileChallengeHtml(env, { theme: url.searchParams.get("theme") }), {
        status: 200,
        headers: {
          "Content-Type": "text/html; charset=utf-8",
          "Cache-Control": "no-store",
          "Referrer-Policy": "no-referrer",
          "X-Content-Type-Options": "nosniff",
          "X-Robots-Tag": "noindex",
          ...cors.headers
        }
      });
    }

    // ==========================================
    // 功能 A: 实时拉取并返回名单 (GET /list)
    //   主源 GitHub 私有仓库 → 备源 Gitee 私有镜像仓库
    //   加 ?diag=1 只回诊断信息（逐通道的尝试记录），不返回名单正文
    //   加 ?nocache=1 跳过缓存强制回源（改完名单想立刻看到效果时用）
    //   带 ?force=gitee|github 时同样穿透缓存 —— 它本来就是「强行验证某个源」的诊断开关
    //   v1.13.15：正常请求走 5 分钟缓存，命中时**一个上游子请求都不发**
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
      const nocache = url.searchParams.get("nocache") === "1";
      const t0 = Date.now();
      // 诊断 / 强制源：既不读缓存也不写缓存 —— 诊断要是看到缓存，等于什么都没诊断出来；
      //   强制源的结果只该用于「验证某个源」，不该覆盖正常缓存。
      // nocache=1：**不读**但**写** —— 它是「我想立刻看到最新的」，拉到的新数据理应顺手刷新缓存。
      const cacheOn = !diag && !force && !!listCacheKv(env);
      const readCache = cacheOn && !nocache;

      let cached = null;
      if (cacheOn) {
        cached = await readListCache(env, fileName);
        // 正常请求：5 分钟内直接发缓存
        if (!nocache && listCacheFresh(cached)) {
          return listDataResponse(cached, "HIT", cors.headers, false);
        }
        // nocache 请求：60 秒内也直接发缓存（防止它变成绕过缓存的刷接口通道）
        if (nocache && cached && (Date.now() - cached.ts) < LIST_CACHE_MIN_REFRESH_MS) {
          return listDataResponse(cached, "HIT", cors.headers, false);
        }
      }

      const up = await fetchListShared(env, fileName, force);

      // 诊断模式：永远回「此刻真实的上游尝试记录」，不写缓存、不读缓存
      if (diag) {
        return new Response(JSON.stringify(up.ok ? {
          ok: true, type: type, source: up.source, path: up.path, count: up.count,
          force: force || null, cache: "bypass",
          elapsedMs: Date.now() - t0,
          tries: up.giteeAttempted ? up.gtTries : up.ghTries,
          github: up.ghTries, gitee: up.gtTries,
          giteeAttempted: up.giteeAttempted
        } : {
          ok: false, type: type, source: null, path: null, count: null,
          force: force || null, cache: "bypass",
          elapsedMs: Date.now() - t0,
          github: up.ghTries, gitee: up.gtTries
        }, null, 2), {
          status: 200,
          headers: { "Content-Type": "application/json", "X-Cache": "BYPASS", ...cors.headers }
        });
      }

      if (up.ok) {
        const rec = {
          ts: Date.now(), text: up.text, source: up.source,
          path: up.path, count: up.count
        };
        if (cacheOn) await writeListCache(env, fileName, rec);
        // 写缓存耗时算在这次响应里（未命中本来就慢），但响应头要如实说明它是「刚拉的新鲜数据」。
        //   MISS = 缓存里没有/已过期；REFRESH = 是 nocache 主动回源并顺便刷新了缓存；
        //   BYPASS = 缓存不可用（没绑 KV）或本次请求不参与缓存（diag / force）。
        return listDataResponse(rec, readCache ? "MISS" : (cacheOn ? "REFRESH" : "BYPASS"), cors.headers, false);
      }

      // 双源都失败：有旧副本就发旧的（比 502 有用得多；作者也能从 X-Data-Stale 看出是兜底数据）
      if (cached) {
        console.warn("[list] 双源均失败，回退到缓存副本（" +
          Math.round((Date.now() - cached.ts) / 1000) + " 秒前）");
        return listDataResponse(cached, "STALE", cors.headers, true);
      }

      console.error("[list] 双源均失败且无缓存可用：" + JSON.stringify({ github: up.ghTries, gitee: up.gtTries }));
      return new Response(JSON.stringify({
        error: "云端名单服务器暂时不可用，请稍后再试。",
        detail: {
          github: up.ghTries.map(function (t) { return (t.path || "") + " → " + (t.error || t.status); }),
          gitee: up.gtTries.map(function (t) { return (t.path || "") + "[" + (t.ref || "") + "] → " + (t.error || t.status); })
        }
      }), {
        status: 502,
        headers: { "Content-Type": "application/json", "X-Cache": cacheOn ? "MISS" : "BYPASS", ...cors.headers }
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
        // 人机验证开关的「现场证据」：不用翻 Cloudflare 后台，curl 一下就知道有没有生效。
        //   只回状态，不回 site key / secret（前者公开但没必要，后者绝不能出）。
        turnstile: turnstileEnabled(env) ? (turnstileSiteKey(env) ? "on" : "misconfigured") : "off",
        // 拦截策略与配额：不用翻代码就知道当前是软还是硬、降级通道给了几次
        turnstileEnforce: turnstileEnabled(env) ? turnstileEnforce(env) : null,
        turnstileSoftQuota: turnstileEnabled(env) ? turnstileSoftQuota(env) : null,
        feedbackDailyQuota: FEEDBACK_DAILY_QUOTA,
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
      // ① 先取原文：验签要用**原始字节**，而 request body 只能读一次，
      //    所以这里读 text、验签、再 JSON.parse（不再调用 request.json()）。
      let rawBody = "";
      try { rawBody = await request.text(); } catch (e) { rawBody = ""; }

      // ② 验签放在限流与发信之前：没有密钥的请求连 KV 配额都碰不到、更不会触发发信。
      //    失败一律 401（缺头/时间窗/签名不符），密钥没配则是 503，语义分开便于排查。
      const auth = await verifyFeedbackSignature(request, rawBody, env);
      if (!auth.ok) {
        console.warn("[feedback] 拒绝： " + auth.error + " ip=" + (request.headers.get("CF-Connecting-IP") || "?"));
        return new Response(JSON.stringify({ error: auth.error, detail: auth.detail }), {
          status: auth.status,
          headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...cors.headers }
        });
      }

      const clientIP = request.headers.get("CF-Connecting-IP") || "unknown";
      const today = (new Date()).toISOString().split("T")[0];
      const kvKey = `rate_limit_${clientIP}_${today}`;

      // 旧顺序（v1.13.12）：限流(写死 60) → parse → 内容校验 → 验人机 → 发信。
      //   问题：soft 模式下「降级」的配额只有 3，必须在验完人机之后才知道，所以限流必须后移。
      //   新顺序：parse → 内容校验 → 验人机（拿 quota） → 限流（按 quota） → 发信。
      //   安全性没有变松：rawBody 已通过 HMAC 验签，parse 的是「持密钥的人发来的内容」；
      //   而且降级路径根本不调 siteverify，刷子没法靠打这个接口去烧 Cloudflare 的验证配额。
      let data;
      try {
        data = JSON.parse(rawBody);
      } catch (e) {
        return new Response(JSON.stringify({ error: "INVALID_JSON", detail: "请求体不是合法的 JSON。" }), {
          status: 400,
          headers: { "Content-Type": "application/json", ...cors.headers }
        });
      }
      const feedbackText = data && data.message;
      const userContact = (data && data.contact) || "未提供";

      if (!feedbackText || typeof feedbackText !== "string" || feedbackText.length > 2000) {
        return new Response(JSON.stringify({ error: "无效的反馈内容或长度超过限制。" }), {
          status: 400,
          headers: { "Content-Type": "application/json", ...cors.headers }
        });
      }

      // ④ 人机验证（可选）：只有配了 TURNSTILE_SECRET_KEY 才生效，未配时整段透明跳过。
      //    strict：过不了就拒，不写 KV、不发信。
      //    soft（默认）：过不了也放行，但 quota 从 60 掉到 3 —— 下面的限流按它算。
      const turnstile = await verifyTurnstile(
        (data && data.turnstileToken) || "",
        clientIP,
        env,
        !!(data && data.turnstileFallback === true)
      );
      if (!turnstile.ok) {
        console.warn("[turnstile] 拒绝： " + turnstile.error + " ip=" + clientIP);
        return new Response(JSON.stringify({ error: turnstile.error, detail: turnstile.detail }), {
          status: turnstile.status,
          headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...cors.headers }
        });
      }
      const degraded = !!turnstile.degraded;
      const quota = turnstile.quota || FEEDBACK_DAILY_QUOTA;
      if (degraded) {
        // 降级放行必须留痕：以后看日志就能知道「有多少人是被验证框挡在外面的」
        console.warn("[turnstile] 降级放行：原因=" + turnstile.degraded + " 配额=" + quota + " ip=" + clientIP);
      }

      // ⑤ 限流。两把尺子同时量：
      //    主计数永远按 60 判 —— 总量上限不会因为降级而放宽；
      //    降级通道再额外受 quota（默认 3）约束 —— 否则「先发满 60 次正常额度，再靠降级继续发」就是后门。
      let currentCount = await env.RATE_LIMIT_KV.get(kvKey);
      currentCount = currentCount ? parseInt(currentCount) : 0;

      if (currentCount >= FEEDBACK_DAILY_QUOTA) {
        return new Response(JSON.stringify({ error: "您今天的提交次数已达上限，请明天再试。" }), {
          status: 429,
          headers: { "Content-Type": "application/json", ...cors.headers }
        });
      }

      const softKey = `rate_limit_soft_${clientIP}_${today}`;
      let softUsed = 0;
      if (degraded) {
        softUsed = parseInt(await env.RATE_LIMIT_KV.get(softKey)) || 0;
        if (softUsed >= quota) {
          return new Response(JSON.stringify({
            error: "DEGRADED_QUOTA_EXCEEDED",
            detail: `今日「免人机验证发送」额度（${quota} 次）已用完。`
              + "请换一个能打开人机验证的网络环境再发，或改用「发送反馈到 GitHub Issue」。"
          }), {
            status: 429,
            headers: { "Content-Type": "application/json", ...cors.headers }
          });
        }
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
      if (degraded) {
        await env.RATE_LIMIT_KV.put(softKey, (softUsed + 1).toString(), { expirationTtl: 86400 });
      }

      return new Response(JSON.stringify({
        success: true,
        message: "感谢您的反馈！",
        // degraded 只是给排查用的标记（前端不展示）：表示这封邮件没经过人机验证，
        //   走的是 3 次/天的降级通道。以后统计日志时能一眼看出「验证框坏了多少人受影响」。
        degraded: degraded || undefined
      }), {
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
