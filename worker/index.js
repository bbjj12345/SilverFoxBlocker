/*
export default {
  async fetch(request, env, ctx) {
    // 1. 处理跨域 (CORS) 和预检请求
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*", // 建议发布后改为你的扩展ID，例如 "chrome-extension://你的ID"
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    if (request.method !== "POST") {
      return new Response(JSON.stringify({ error: "Method not allowed" }), {
        status: 405, headers: { "Content-Type": "application/json", ...corsHeaders }
      });
    }

    try {
      // 2. 获取客户端 IP 用于限流
      const clientIP = request.headers.get("CF-Connecting-IP") || "unknown";
      
      // 3. 限流逻辑：每个 IP 每天最多提交 60 次
      const today = new Date().toISOString().split('T')[0]; // 获取 YYYY-MM-DD
      const kvKey = `rate_limit_${clientIP}_${today}`;
      
      let currentCount = await env.RATE_LIMIT_KV.get(kvKey);
      currentCount = currentCount ? parseInt(currentCount) : 0;

      if (currentCount >= 60) {
        return new Response(JSON.stringify({ error: "您今天的提交次数已达上限，请明天再试。" }), {
          status: 429, headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      }

      // 4. 解析和校验数据
      const data = await request.json();
      const feedbackText = data.message;
      const userContact = data.contact || "未提供";

      // 限制最大长度为 2000 字符，防止超长文本攻击
      if (!feedbackText || typeof feedbackText !== 'string' || feedbackText.length > 2000) {
        return new Response(JSON.stringify({ error: "无效的反馈内容或长度超过限制。" }), {
          status: 400, headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      }

      // 5. 发送邮件 (调用 Brevo API)
      // 这里的 from 需要用 Brevo 提供的测试地址，或者你以后验证的自有域名
      // 5. 发送邮件 (调用 Brevo API)
      const emailResponse = await fetch("https://api.brevo.com/v3/smtp/email", {
        method: "POST",
        headers: {
          "api-key": env.BREVO_API_KEY, // 注意：Brevo 使用的是 api-key，不是 Bearer
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          sender: { 
            name: "SilverFoxBlocker 反馈", 
            email: "feedback@silverfoxblocker.dpdns.org" // 必须是你 Brevo 认证过的域名
          },
          to: [
            { 
              email: "feedback@silverfoxblocker.dpdns.org" // 依然发到这里，然后通过 Cloudflare 邮件路由转给 QQ
            }
          ],
          subject: "【SilverFoxBlocker】收到一条新的扩展反馈",
          htmlContent: `
            <h3>新反馈</h3>
            <p><strong>联系方式：</strong> ${userContact}</p>
            <p><strong>内容：</strong></p>
            <p>${feedbackText.replace(/\n/g, '<br>')}</p>
            <hr>
            <p><small>IP: ${clientIP}</small></p>
          `
        })
      });
      if (!emailResponse.ok) {
        // 如果 Brevo 报错，抛出异常，方便在 Cloudflare Logs 中看到
        const errText = await emailResponse.text();
        throw new Error(`Brevo 邮件发送失败: ${errText}`);
      }

      // 6. 发送成功，更新 KV 限流计数（有效期设为 24 小时）
      await env.RATE_LIMIT_KV.put(kvKey, (currentCount + 1).toString(), { expirationTtl: 86400 });

      return new Response(JSON.stringify({ success: true, message: "感谢您的反馈！" }), {
        headers: { "Content-Type": "application/json", ...corsHeaders },
      });

    } catch (error) {
      // 如果出错，不要暴露错误细节给前端
      console.error(error);
      return new Response(JSON.stringify({ error: "服务器内部错误，请稍后再试。" }), {
        status: 500, headers: { "Content-Type": "application/json", ...corsHeaders }
      });
    }
  },
};
*/

// 你的私人仓库信息
const GITHUB_OWNER = "bbjj12345"; // 替换为你的 GitHub 用户名
const GITHUB_REPO = "SilverFoxBlocker-Cloud"; // 你的私人仓库名
const BRANCH = "main"; // 私人仓库的默认分支，如果是 master 请修改

// 定义 CORS 头，允许扩展跨域请求
const corsHeaders = {
  "Access-Control-Allow-Origin": "*", // 如果追求极致安全，可以改成 "chrome-extension://你的扩展ID"
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, X-API-Key",
};

// 说明：原 syncListToKV() 已删除。
// 它把 GitHub 上的名单写入 env.LIST_KV，但 LIST_KV 这个 KV 绑定已不存在
// （wrangler.toml 里只绑定了 RATE_LIMIT_KV 与 FEEDBACK），调用时会抛
// "Cannot read properties of undefined (reading 'put')"。
// /list 本来就是实时读 GitHub、不经过 KV，因此删除该函数不影响任何功能。
// 若日后想启用 KV 缓存：先在 wrangler.toml 加 [[kv_namespaces]] binding = "LIST_KV"，
// 再恢复写入逻辑即可。

export default {
  // 1. 处理 HTTP 请求 (用户反馈 & 扩展拉取名单)
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);

    // ==========================================
    // 功能 A: 实时从 GitHub 拉取并返回名单 (GET /list)
    // ==========================================
    if (request.method === "GET" && url.pathname === "/list") {
      // 1. 校验扩展传来的 API Key
      const apiKey = request.headers.get("X-API-Key");
      if (apiKey !== env.LIST_API_KEY) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
          status: 401, headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      }

      // 2. 确定要拉取的文件名
      const type = url.searchParams.get("type") || "black";
      const fileName = type === "white" ? "whitelist.json" : "blacklist.json";

      try {
        // 3. 实时请求 GitHub API
        const ghUrl = `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${fileName}?ref=${BRANCH}`;
        const res = await fetch(ghUrl, {
          headers: {
            "Authorization": `Bearer ${env.GITHUB_TOKEN}`,
            "Accept": "application/vnd.github.v3.raw",
            "User-Agent": "Cloudflare-Worker-SilverFox"
          }
        });

        if (!res.ok) {
          if (res.status === 404) throw new Error("云端文件不存在，请检查仓库名/分支名/文件名。");
          throw new Error(`GitHub API 报错: ${res.status}`);
        }

        const content = await res.text();
        
        // 简单验证一下是不是合法 JSON
        JSON.parse(content); 

        // 4. 将内容返回给扩展
        return new Response(content, {
          headers: { 
            "Content-Type": "application/json", 
            ...corsHeaders 
          }
        });

      } catch (error) {
        console.error(error);
        return new Response(JSON.stringify({ error: error.message }), {
          status: 500, headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      }
    }

    // ==========================================
    // 功能 B: 原有的用户反馈提交 (POST)
    // ==========================================
    if (request.method !== "POST") {
      return new Response(JSON.stringify({ error: "Method not allowed" }), {
        status: 405, headers: { "Content-Type": "application/json", ...corsHeaders }
      });
    }

    try {
      const clientIP = request.headers.get("CF-Connecting-IP") || "unknown";
      const today = new Date().toISOString().split('T')[0];
      const kvKey = `rate_limit_${clientIP}_${today}`;
      
      let currentCount = await env.RATE_LIMIT_KV.get(kvKey);
      currentCount = currentCount ? parseInt(currentCount) : 0;

      if (currentCount >= 60) {
        return new Response(JSON.stringify({ error: "您今天的提交次数已达上限，请明天再试。" }), {
          status: 429, headers: { "Content-Type": "application/json", ...corsHeaders }
        });
      }

      const data = await request.json();
      const feedbackText = data.message;
      const userContact = data.contact || "未提供";

      if (!feedbackText || typeof feedbackText !== 'string' || feedbackText.length > 2000) {
        return new Response(JSON.stringify({ error: "无效的反馈内容或长度超过限制。" }), {
          status: 400, headers: { "Content-Type": "application/json", ...corsHeaders }
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
            <p>${feedbackText.replace(/\n/g, '<br>')}</p>
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
        headers: { "Content-Type": "application/json", ...corsHeaders },
      });

    } catch (error) {
      console.error(error);
      return new Response(JSON.stringify({ error: "服务器内部错误，请稍后再试。" }), {
        status: 500, headers: { "Content-Type": "application/json", ...corsHeaders }
      });
    }
  }
};
