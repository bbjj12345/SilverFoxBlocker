/* ============================================================================
 * SilverFoxBlocker 反馈邮件转发 Worker
 * ----------------------------------------------------------------------------
 * 作用：接收扩展 POST 来的反馈（{ type, message }），代发邮件到作者邮箱。
 * 这样扩展无需唤起本地邮件客户端，也无需在扩展里写收件地址/域名。
 *
 * 部署：
 *   1) npm i -g wrangler && wrangler login
 *   2) 把下面的密钥写入（不要硬编码在代码里）：
 *        wrangler secret put RESEND_API_KEY   # Resend 的 API Key（https://resend.com）
 *        wrangler secret put TO_EMAIL         # 收件人，例如 feedback@你的域名
 *        wrangler secret put FROM_EMAIL       # 发件人（须在 Resend 已验证域名下，例如 feedback@你的域名）
 *   3) wrangler deploy
 *   4) 把部署得到的端点（如 https://silverfox-feedback.你的子域.workers.dev）用
 *      SFB_makeCodes() 生成字符码数组，填入扩展 ui/feedback-config.js 的 endpointCodes，
 *      并把 enabled 改为 true。
 *
 * 不限于 Resend：把 sendMail() 换成 Mailgun / SendGrid 等即可。
 * 注意 CORS：本文件已对 OPTIONS 预检与 POST 响应加了 Access-Control-Allow-*，
 * 供扩展的 options 页面跨域 fetch 调用。
 * ========================================================================== */

export default {
  async fetch(request, env) {
    const cors = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }
    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405, headers: cors });
    }

    let data;
    try {
      data = await request.json();
    } catch {
      return new Response('Bad Request', { status: 400, headers: cors });
    }

    const type = (data.type || '其他').toString().slice(0, 50);
    const message = (data.message || '').toString().slice(0, 4000);
    if (message.trim().length < 5) {
      return new Response('Bad Request', { status: 400, headers: cors });
    }

    const subject = '[反馈] ' + type + '：' + message.slice(0, 40);

    try {
      await sendMail(env, {
        to: env.TO_EMAIL,
        from: env.FROM_EMAIL,
        subject: subject,
        text: '问题类型：' + type + '\n\n' + message,
      });
      return new Response('OK', { status: 200, headers: cors });
    } catch (e) {
      return new Response('Mail failed', { status: 502, headers: cors });
    }
  },
};

// 示例：Resend REST API（免费额度 3000 封/月）。换成其它服务商改这里即可。
async function sendMail(env, { to, from, subject, text }) {
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: 'Bearer ' + env.RESEND_API_KEY,
    },
    body: JSON.stringify({ to: [to], from: from, subject: subject, text: text }),
  });
  if (!res.ok) {
    throw new Error('Resend HTTP ' + res.status);
  }
}
