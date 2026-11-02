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