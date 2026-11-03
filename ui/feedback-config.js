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
 * ========================================================================== */
(function () {
  function decodeCodes(arr) {
    if (!arr || !arr.length) return '';
    return arr.map(function (c) { return String.fromCharCode(c); }).join('');
  }
  window.SFB_FEEDBACK = {
    enabled: true,             // ★ Worker 已部署并就绪
    endpointCodes: [104,116,116,112,115,58,47,47,97,112,105,46,115,105,108,118,101,114,102,111,120,98,108,111,99,107,101,114,46,100,112,100,110,115,46,111,114,103], // 反馈 Worker 端点（字符码存储，避免明文域名）
    decode: decodeCodes
  };
  window.SFB_makeCodes = function (s) {
    return Array.from(String(s)).map(function (c) { return c.charCodeAt(0); });
  };
})();
