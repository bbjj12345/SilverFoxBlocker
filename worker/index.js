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

var corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, X-API-Key",
  // 扩展侧要能读到「这份数据来自哪个源」，自定义响应头必须显式暴露
  "Access-Control-Expose-Headers": "X-Data-Source, X-Data-Path"
};

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

var index_default = {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
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
          headers: { "Content-Type": "application/json", ...corsHeaders }
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
            headers: { "Content-Type": "application/json", "X-Data-Source": gh.source, ...corsHeaders }
          });
        }
        return new Response(gh.text, {
          headers: {
            "Content-Type": "application/json",
            "X-Data-Source": gh.source,
            "X-Data-Path": gh.path,
            ...corsHeaders
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
          headers: { "Content-Type": "application/json", ...corsHeaders }
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
          headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      }

      return new Response(gt.text, {
        headers: {
          "Content-Type": "application/json",
          "X-Data-Source": gt.source,
          "X-Data-Path": gt.path,
          ...corsHeaders
        }
      });
    }

    // ==========================================
    // 功能 B: 原有的用户反馈提交 (POST)
    // ==========================================
    if (request.method !== "POST") {
      return new Response(JSON.stringify({ error: "Method not allowed" }), {
        status: 405,
        headers: { "Content-Type": "application/json", ...corsHeaders }
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
          headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      }

      const data = await request.json();
      const feedbackText = data.message;
      const userContact = data.contact || "未提供";

      if (!feedbackText || typeof feedbackText !== "string" || feedbackText.length > 2000) {
        return new Response(JSON.stringify({ error: "无效的反馈内容或长度超过限制。" }), {
          status: 400,
          headers: { "Content-Type": "application/json", ...corsHeaders }
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
        headers: { "Content-Type": "application/json", ...corsHeaders }
      });

    } catch (error) {
      console.error(error);
      return new Response(JSON.stringify({ error: "服务器内部错误，请稍后再试。" }), {
        status: 500,
        headers: { "Content-Type": "application/json", ...corsHeaders }
      });
    }
  }
};

export { index_default as default };
