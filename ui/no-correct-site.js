/* no-correct-site.js —— 说明页的交互（无内联脚本：extension_pages 的 CSP 只允许 'self'）
 *
 * 旧（2026-11-12）只做三件事：回显被拦主机名、返回上一页、打开反馈页。
 * 页面文案是固定的「没有已收录的正确域名」，因为那时「访问正确的页面」按钮
 * 命中官网就直接跳转，只有查不到时才会走到这里。
 *
 * ★ 2026-11-18：按钮改成**无条件**打开本页，于是本页要承担「列出官方入口」的职责：
 *   1) 回显被拦主机名（截断到 80 字符，防超长注入）；
 *   2) 读 storage.local 的 sfCloudCorrect（云端补录）注入解析器 —— 与内容脚本走同一份数据；
 *   3) 调 analyzer.resolveCorrectSite(host) 拿到**站点列表**（多官网 / 链接级官网都支持）：
 *        有站点 → 标题改成「XX 的官方页面」，逐条列出（自定义文案优先，否则自动编号）；
 *        没站点 → 保持「没有已收录」的原文案，并给出反馈入口；
 *   4) 「返回上一页」：优先关掉本标签页，关不掉再 history.back()；
 *   5) 「向作者发送反馈」：打开设置页并跳到「关于」（反馈卡就在那一屏）。
 *
 * 全部用 DOM API 构建，不用 innerHTML：文案与地址来自数据文件，绝不能让它们变成标签。
 */
(function () {
  'use strict';

  // ==========================================================================
  // 旧实现（2026-11-12）：保留不动，仅停用。
  //   停用原因：固定文案假设「走到这里 = 没有收录」，而新流程下这里是主路径。
  //   用 if (false) 而不是块注释，是因为原代码里本来就有块注释，套起来会截断。
  // ==========================================================================
  if (false) {
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
  }

  // ==========================================================================
  // 新实现（2026-11-18）
  // ==========================================================================

  function $(id) { return document.getElementById(id); }

  // ---- 1) 读被拦主机名（只留主机名字符，截断到 80 字符）----
  function readHost() {
    try {
      const q = new URLSearchParams(location.search || '');
      let host = String(q.get('host') || '').trim().toLowerCase();
      host = host.replace(/[^a-z0-9.\-:\u4e00-\u9fa5]/g, '');
      if (host.length > 80) host = host.slice(0, 80) + '…';
      return host;
    } catch (e) { return ''; }
  }

  function showHost(host) {
    if (!host) return;
    const name = $('hostName');
    const line = $('hostLine');
    if (name && line) {
      name.textContent = host;
      line.hidden = false;
    }
  }

  // ---- 2) 站点在页面上的称呼：自定义文案 > 自动编号 ----
  //   多站点时编号（官网1 / 官网2），单站点就叫「官网」；
  //   链接级条目（GitHub Releases 这类）自动标签写成「官方页面」，避免把它叫成官网。
  function labelOf(site, index, total) {
    const custom = (site && site.label) ? String(site.label).trim() : '';
    if (custom) return custom;
    const base = (site && site.kind === 'link') ? '官方页面' : '官网';
    return total > 1 ? base + (index + 1) : base;
  }

  // ---- 3) 把站点列表画出来 ----
  function renderSites(res) {
    const sites = (res && Array.isArray(res.sites)) ? res.sites : [];
    if (!sites.length) return false;

    const product = (res.product || '').trim();

    // 分组统计（2026-11-22）：无 group 的是本条目自己的站点，有 group 的按来源产品各自编号；
    // 这样「官网1 / 官网2」永远只数本产品的入口，不会把关联版本的站点算进去。
    const mainCount = sites.filter(function (x) { return !(x && x.group); }).length;
    const groupTotal = Object.create(null);
    sites.forEach(function (x) {
      const g = (x && x.group) ? String(x.group) : '';
      if (g) groupTotal[g] = (groupTotal[g] || 0) + 1;
    });
    const title = product ? '「' + product + '」的官方页面' : '已收录的官方页面';

    const titleEl = $('title');
    if (titleEl) titleEl.textContent = title;
    try { document.title = title + ' · SilverFoxBlocker'; } catch (e) {}

    const leadEl = $('lead');
    if (leadEl) {
      leadEl.textContent = '你访问的站点并不是它的官方域名。以下是扩展已收录的官方入口，请从下面进入'
        + (sites.length > 1 ? '（可能不止一个，请按需选择）' : '') + '。';
    }

    // 判定依据：拼写相近 / 主干同名两种推断，说清楚为什么把用户带到这里
    const noteEl = $('verdictNote');
    if (noteEl) {
      let note = '';
      if (res.confidence === 'typo') {
        note = '当前域名的拼写与该品牌相近，疑似错拼或仿冒，很可能不是官方网站。';
      } else if (res.confidence === 'variant') {
        // ★ 2026-11-24：重排 / 插字式变体（deekseep-e / deeposieek）。用户看到的是「字母都对、
        //   只是顺序不同」，说「拼写相近」反而不像，要点明「字母被重排或插入了字母」。
        note = '当前域名的字母与该品牌高度重合（顺序被调换，或插入了个别字母），是仿冒站常见的绕检测写法，很可能不是官方网站。';
      } else if (res.confidence === 'branddomain') {
        note = '当前域名与品牌同名，但注册在另一个后缀下（跨注册局抢注），是仿冒站的典型形态。';
      }
      if (note) { noteEl.textContent = note; noteEl.hidden = false; }
    }

    const list = $('siteList');
    if (list) {
      // 先清空（重绘时不会叠加）；childNodes 快照，边删边遍历不可靠
      while (list.firstChild) list.removeChild(list.firstChild);
      let lastGroup = '';
      let mainSeen = 0;
      const groupSeen = Object.create(null);
      for (let i = 0; i < sites.length; i++) {
        const s = sites[i] || {};
        const url = String(s.url || '');
        if (!url) continue;

        // 关联品牌词：换组时先插一条小标题，用户一眼能看出「这是另一个产品」
        const g = s.group ? String(s.group) : '';
        if (g && g !== lastGroup) {
          const head = document.createElement('li');
          head.className = 'site-group';
          head.textContent = '相关：' + g;
          list.appendChild(head);
        }
        lastGroup = g;

        const li = document.createElement('li');
        li.className = 'site';

        const lab = document.createElement('span');
        lab.className = 'site-label';
        // 编号用「本产品自己的站点数」，关联版本的站点只在各自分组里编号
        const idxInGroup = g ? (groupSeen[g] = (groupSeen[g] || 0) + 1) : -1;
        const totalInGroup = g ? groupTotal[g] : mainCount;
        lab.textContent = labelOf(s, g ? idxInGroup - 1 : (mainSeen++), totalInGroup);

        const a = document.createElement('a');
        a.className = 'site-url';
        // 数据层已经校验过只允许 http/https，这里再兜一次：非 http(s) 一律不给出可点链接
        if (/^https?:\/\//i.test(url)) {
          a.href = url;
        } else {
          a.removeAttribute('href');
        }
        a.textContent = url;
        a.rel = 'noopener noreferrer';

        li.appendChild(lab);
        li.appendChild(a);
        list.appendChild(li);
      }
      list.hidden = false;
    }

    const hint = $('siteHint');
    if (hint) hint.hidden = false;

    const foot = $('foot');
    if (foot) {
      foot.textContent = '列表来自扩展内置表与云端补录，可能没有覆盖全部官方入口。'
        // 有关联版本时补一句口径说明，避免用户以为「相关」里是第三方改版站
        + (sites.some(function (x) { return x && x.group; })
          // 2026-11-22：rel 已从「发行版」扩到「区域版 / 国际版」，措辞随之放宽
          // 旧：'「相关」小节是同一产品的其他官方发行版（如社区增强版），同样是官方入口。'
          ? '「相关」小节是同一产品的其他官方版本（如社区增强版、国际版），同样是官方入口。'
          : '')
        + '请勿在当前页面下载或安装任何程序。';
    }
    return true;
  }

  // ---- 4) 解析：先注入云端补录，再查内置 + 云端合并表 ----
  //   ⚠️ 这里必须用 window.SF_ANALYZER：analyzer.js 对外只挂 SF_ANALYZER（内容脚本里那个
  //   `SF` 是 content.js 自己的局部别名），曾经写成 window.SF 导致说明页永远解析不出官网。
  function api() {
    return (typeof window !== 'undefined' && (window.SF_ANALYZER || window.SF)) || null;
  }

  function resolve(host) {
    if (!host) return null;
    try {
      const A = api();
      if (A && typeof A.resolveCorrectSite === 'function') return A.resolveCorrectSite(host);
    } catch (e) {}
    return null;
  }

  function boot() {
    const host = readHost();
    showHost(host);

    let done = false;
    const finish = function () {
      if (done) return;
      done = true;
      const res = resolve(host);
      try { renderSites(res); } catch (e) { /* 渲染失败就保留默认文案 */ }
    };

    // 云端补录与内容脚本同源（storage.local 的 sfCloudCorrect），不联网、不额外请求；
    // 读不到 / 回调不来都不影响主流程：内置表本身就能覆盖绝大多数品牌。
    try {
      if (window.chrome && chrome.storage && chrome.storage.local) {
        chrome.storage.local.get({ sfCloudCorrect: [] }, function (o) {
          try {
            const arr = (o && Array.isArray(o.sfCloudCorrect)) ? o.sfCloudCorrect : [];
            const A = api();
            if (A && typeof A.registerCloudCorrect === 'function') A.registerCloudCorrect(arr);
          } catch (e) {}
          finish();
        });
        // 兜底：storage 回调异常时不至于一直停在「没有收录」的默认文案上
        setTimeout(finish, 1500);
        return;
      }
    } catch (e) {}
    finish();
  }

  // ---- 5) 返回上一页 ----
  /* ★ 2026-11-28：旧实现（保留备查）
     只会在本地关标签 / history.back()。本页由 chrome.tabs.create 打开、排在最右，
     Chrome 关掉它以后把焦点交给**左邻**（也就是打开前的最后一个标签页），
     所以「返回上一页」实际只是「关掉说明页」，并没有回到跳转前的页面。
  try {
    const back = $('backBtn');
    if (back) {
      back.addEventListener('click', function () {
        // 本页由 chrome.tabs.create 打开，history 里可能没有上一页；
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
  */

  // 新实现：把「回到哪一页」交给后台 —— 后台在打开本页时记下了来源 tabId，
  //   点返回时先激活来源标签页、再关掉本页，焦点就落回跳转前的那个页面。
  //   本页自己拿不到来源 tabId（内容脚本与扩展页都不该为这个申请 tabs 权限）。
  function legacyClose() {
    // 兜底：后台没响应 / 本页是被手动粘贴地址打开的，按老办法关
    try { window.close(); } catch (e) {}
    setTimeout(function () {
      try {
        if (history.length > 1) history.back();
        else location.replace('about:blank');
      } catch (e) { try { location.replace('about:blank'); } catch (e2) {} }
    }, 120);
  }

  try {
    const back = $('backBtn');
    if (back) {
      back.addEventListener('click', function () {
        if (back.dataset.clicked === '1') return;   // 连点只处理一次
        back.dataset.clicked = '1';
        let answered = false;
        try {
          chrome.runtime.sendMessage({ type: 'SF_CLOSE_RETURN' }, function (res) {
            answered = true;
            void chrome.runtime.lastError;
            // 后台成功时会直接把本页关掉，这里一般来不及执行；
            // 只有「没记录 / 来源页已关 / 消息没送到」才退回旧的本地关闭
            if (!res || !res.ok || res.returned !== true) legacyClose();
          });
        } catch (e) { legacyClose(); return; }
        // 兜底：后台没被唤醒（MV3 冷启动 / 扩展刚重载）时 1.2s 后按老办法关，
        // 不至于出现「点了没反应」的死按钮。取 1.2s 而不是 600ms：service worker
        // 冷启动偶尔要几百毫秒，太短会在后台回话之前就把页面关掉，反而回到旧行为。
        setTimeout(function () {
          if (!answered) { legacyClose(); return; }
          // 后台回话了但页面还活着（来源页已关 / 关标签失败）→ 放开连点锁，允许重试
          if (document.visibilityState === 'visible') back.dataset.clicked = '';
        }, 1200);
      });
    }
  } catch (e) {}

  // ---- 6) 打开设置页的反馈区 ----
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

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
