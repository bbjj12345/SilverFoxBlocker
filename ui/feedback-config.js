/* ============================================================================
 * 反馈后端配置（使用者填写；请勿将真实值提交到公开仓库）
 * ----------------------------------------------------------------------------
 * 邮件发送流程已改为：扩展 → 你的 Cloudflare Worker → 邮件服务商 → 作者邮箱。
 * 因此扩展里不需要明文写收件地址/域名；收件人与发信凭据只存在于 Worker 端（secret）。
 *
 * ★ endpoint 用「字符码数组」存储，避免你的域名以明文出现在扩展源码中；
 *   运行时由 SFB_FEEDBACK.decode() 拼接还原成真实 URL。
 *
 * 生成 endpointCodes 的方法（浏览器控制台执行）：
 *   SFB_makeCodes('https://你的worker子域.workers.dev/send')
 * 把得到的数组粘贴到下面的 endpointCodes。
 *
 * ---- 2026-11-27 新增：反馈签名密钥（HMAC-SHA256）----
 * 背景：反馈接口原先靠 Cloudflare Worker 的 Origin 白名单挡人，而「加载已解压」的扩展 ID
 *   由解压路径决定、换台电脑就变，白名单永远追不上；一旦为了省事写成 chrome-extension://*
 *   就等于任何扩招都能往作者邮箱灌垃圾。
 * 现在改成：扩展与 Worker 共享同一把密钥，每次请求用「路径 + 时间戳 + 请求体」算 HMAC 签名，
 *   签名与时间戳放在 X-SF-Ts / X-SF-Sig 两个请求头里，Worker 重算比对并要求时间戳在 ±5 分钟内。
 *   /send 从此不看 Origin，与 ALLOWED_ORIGINS 彻底解耦。
 *
 * ★ 这把密钥**必须**与 Worker 端 `wrangler secret put SECRET_DATA` 填的值完全一致，
 *   否则所有反馈都会 401。改密钥时两端必须同时改、同时发布。
 * ★ 如实说明：密钥随扩展包分发，解包就能看到，它不是「秘密」，只是「门槛」——
 *   挡得住随手打接口的脚本与爬虫，挡不住有决心的逆向。真被刷时换密钥 + 发版即可止血。
 *
 * ---- 2026-11-27 追加：人机验证（Cloudflare Turnstile，方案二）----
 * 为补上「密钥被抄走后仍能刷」这个缺口，服务端可以再要求一次人机验证。
 * ★ 这里**不需要任何配置**：site key 只在 Worker 端（TURNSTILE_SITE_KEY），
 *   挑战页由 Worker 现场渲染（GET /challenge），扩展只负责把它嵌进页面并等 token 回来。
 *   所以「开/关人机验证」是纯服务端动作，改完不必发新版扩展。
 * 流程：先照常签名发送 → 服务端回 403 TURNSTILE_REQUIRED → 扩展在反馈卡片里嵌一张验证页
 *   → 验证通过后把 token 拼进请求体、重新签名再发一次。
 *   开关与细节见 README「开启人机验证（Turnstile）」一节，代码见 options.js 的 sfbSendFeedback。
 * ========================================================================== */
(function () {
  function decodeCodes(arr) {
    if (!arr || !arr.length) return '';
    return arr.map(function (c) { return String.fromCharCode(c); }).join('');
  }
  window.SFB_FEEDBACK = {
    enabled: true,             // ★ Worker 已部署并就绪
    endpointCodes: [104,116,116,112,115,58,47,47,97,112,105,46,115,105,108,118,101,114,102,111,120,98,108,111,99,107,101,114,46,100,112,100,110,115,46,111,114,103], // 反馈 Worker 端点（字符码存储，避免明文域名）
    // HMAC 共享密钥（字符码存储）。当前密文对应 Worker 端 SECRET_DATA，改一处必须两端同改。
    secretCodes: [100,101,102,51,50,98,54,101,50,101,50,52,54,51,54,98,99,101,50,49,101,101,102,97,101,52,101,97,53,48,53,99,53,54,49,54,48,50,53,51,48,102,52,102,50,101,101,48,97,98,57,56,51,51,49,98,49,55,50,98,49,55,49,97],
    decode: decodeCodes
  };
  window.SFB_makeCodes = function (s) {
    return Array.from(String(s)).map(function (c) { return c.charCodeAt(0); });
  };
})();
