// worker/index.js
var GITHUB_OWNER = "bbjj12345";
var GITHUB_REPO = "SilverFoxBlocker-Cloud";
var BRANCH = "main";

// 名单文件在仓库里的位置（依次尝试）。用户可能把文件放在根目录，也可能放在 List/ 子目录，
// 两种布局都认，省得挪一次文件就得改代码。
var LIST_DIRS = ["", "List/"];
// Gitee 分支名依次尝试：main → master（Gitee 建仓默认是 master）→ 空（用仓库默认分支）
var GITEE_REFS = ["main", "master", ""];

var REQ_TIMEOUT_MS = 5000;      // 单次上游请求超时
var TOTAL_BUDGET_MS = 15000;    // 一次 /list 的总预算，超了就直接报错，别让扩展干等
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
      try { JSON.parse(r.text); } catch (e) { tries.push({ src: "GitHub", path: path, error: "返回内容不是合法 JSON" }); continue; }
      return { ok: true, text: r.text, source: "GitHub", path: path, tries: tries };
    }
    tries.push({ src: "GitHub", path: path, status: r.status, error: r.error || ("HTTP " + r.status) });
    // 401/403 是 token 失效或没权限，换目录也一样，别浪费预算
    if (r.status === 401 || r.status === 403) break;
  }
  return { ok: false, tries: tries };
}

// 备源：Gitee 私有镜像仓库。同样只在服务端持有 token，密钥不进 URL（用 Authorization 头），
// 免得 access_token 出现在任何日志/报错里。
async function readFromGitee(env, file, deadline) {
  const tries = [];
  const owner = env.GITEE_OWNER;
  const repo = env.GITEE_REPO;
  if (!owner || !repo) return { ok: false, tries: [{ src: "Gitee", error: "未配置 GITEE_OWNER / GITEE_REPO" }] };
  if (!env.GITEE_TOKEN) return { ok: false, tries: [{ src: "Gitee", error: "未配置 GITEE_TOKEN" }] };

  let tokenBad = false;
  for (let d = 0; d < LIST_DIRS.length && !tokenBad; d++) {
    for (let b = 0; b < GITEE_REFS.length; b++) {
      const path = LIST_DIRS[d] + file;
      const ref = GITEE_REFS[b];
      const ms = Math.min(REQ_TIMEOUT_MS, leftMs(deadline));
      if (ms < 500) { tries.push({ src: "Gitee", path: path, ref: ref || "(默认)", error: "总预算已用尽" }); return { ok: false, tries: tries }; }

      const url = "https://gitee.com/api/v5/repos/" + owner + "/" + repo + "/raw/" + path +
        (ref ? "?ref=" + encodeURIComponent(ref) : "");
      const r = await getText(url, {
        headers: {
          "Authorization": "token " + env.GITEE_TOKEN,
          "User-Agent": UA
        }
      }, ms);

      if (r.ok) {
        try { JSON.parse(r.text); } catch (e) {
          tries.push({ src: "Gitee", path: path, ref: ref || "(默认)", error: "返回内容不是合法 JSON（可能是登录页）" });
          continue;
        }
        return { ok: true, text: r.text, source: "Gitee", path: path, ref: ref || "(默认)", tries: tries };
      }
      tries.push({ src: "Gitee", path: path, ref: ref || "(默认)", status: r.status, error: r.error || ("HTTP " + r.status) });
      // 令牌无效：后面的组合都不用试了
      if (r.status === 401 || r.status === 403) { tokenBad = true; break; }
    }
  }
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
      const deadline = Date.now() + TOTAL_BUDGET_MS;
      const t0 = Date.now();

      const gh = await readFromGithub(env, fileName, deadline);
      if (gh.ok) {
        if (diag) {
          return new Response(JSON.stringify({
            ok: true, type: type, source: gh.source, path: gh.path,
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

      console.warn("[list] GitHub 拉取失败，切换到 Gitee 镜像：" + JSON.stringify(gh.tries));

      const gt = await readFromGitee(env, fileName, deadline);

      if (diag) {
        return new Response(JSON.stringify({
          ok: gt.ok, type: type, source: gt.ok ? gt.source : null,
          path: gt.ok ? gt.path : null, ref: gt.ok ? gt.ref : null,
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
