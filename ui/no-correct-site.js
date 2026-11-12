/* no-correct-site.js —— 说明页的交互（无内联脚本：extension_pages 的 CSP 只允许 'self'）
 *
 * 三件事：
 *   1) 把 URL 里的 ?host= 回显出来，让用户确认「被拦的是哪个站点」（截断到 80 字符，防超长注入）；
 *   2) 「返回上一页」：优先关掉本标签页（由扩展脚本打开的），关不掉再 history.back()；
 *   3) 「向作者发送反馈」：打开设置页并跳到「关于」（反馈卡就在那一屏）。
 *      走 #sec=about 是设置页既有的锚点机制，不额外做深链。
 */
(function () {
  'use strict';

  function $(id) { return document.getElementById(id); }

  // ---- 1) 回显被拦站点 ----
  try {
    const q = new URLSearchParams(location.search || '');
    let host = String(q.get('host') || '').trim();
    // 只保留主机名字符集，去掉任何可能被塞进来的标签/换行
    host = host.replace(/[^a-z0-9.\-:\u4e00-\u9fa5]/gi, '');
    if (host.length > 80) host = host.slice(0, 80) + '…';
    if (host) {
      const name = $('hostName');
      const line = $('hostLine');
      if (name && line) {
        name.textContent = host;
        line.hidden = false;
      }
    }
  } catch (e) { /* 参数异常时只是不显示这一行 */ }

  // ---- 2) 返回上一页 ----
  try {
    const back = $('backBtn');
    if (back) {
      back.addEventListener('click', function () {
        // 本页通常由 chrome.tabs.create 打开，history 里可能没有上一页；
        // 先试 window.close()，被拒绝（非脚本打开的标签）再退回 history.back()。
        try { window.close(); } catch (e) {}
        setTimeout(function () {
          try {
            if (history.length > 1) history.back();
            else location.replace('about:blank');
          } catch (e) { try { location.replace('about:blank'); } catch (e2) {} }
        }, 120);
      });
    }
  } catch (e) {}

  // ---- 3) 打开设置页的反馈区 ----
  try {
    const fb = $('fbBtn');
    if (fb) {
      fb.addEventListener('click', function () {
        const url = chrome.runtime.getURL('ui/options.html') + '#sec=about';
        try {
          chrome.tabs.create({ url: url, active: true }, function () { void chrome.runtime.lastError; });
        } catch (e) {
          try { location.href = url; } catch (e2) {}
        }
      });
    }
  } catch (e) {}
})();
