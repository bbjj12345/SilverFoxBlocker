/*
 * content.js — SilverFoxBlocker 内容脚本
 * 职责：1) 采集页面代码 + 工程化指标 + ICP 备案
 *       2) 调用评分引擎（含官方早期退出）
 *       3) 分层响应：safe 不动作 / warn 温和提示不拦 / danger 警告浮层 + 禁用全部下载入口
 *       4) 用户可「离开 / 继续访问(仍拦截) / 完全放行」
 *       5) 拦截任意元素触发的下载：a / button / div / img / 程序化 click / location 跳转 / window.open
 */
(function () {
  'use strict';

  const SF = window.SF_ANALYZER;

  // 性能优化：模块级复用正则与闭包，避免每次调用 / 循环重新编译
  const ABS_URL_RE = /^(https?:)?\/\//i;
  const DLINK_URL_RE = /https?:\/\/[^\s"'<>（）()【】\[\]{}|\\^`]+/gi;
  const TXT_EXT_RE = /\.txt(?:[?#]|$)/i;
  function isDlLink(u) {
    const t = SF.classifyLink(u);
    return t === 'exec' || t === 'archive' || t === 'cloud' || t === 'download';
  }

  // ⚠️ 2026-10-27 误报治理：仅把「真正的 JS 脚本」当作代码扫描对象。
  // 此前 collectCore 把 <script type="application/ld+json">、<script type="application/json">
  // 等结构化数据块也当成内联脚本文本交给 VM/混淆检测，导致深信服博客等技术文章正文里
  // 提到「VMware / 沙箱 / 虚拟机」时（出现在 JSON-LD 或 __NEXT_DATA__ 数据块中）被误判为
  // 「沙箱探测/恶意代码 +35」。这里显式排除非 JS 类型的脚本。
  function isExecutableScript(s) {
    const t = (s && s.getAttribute && (s.getAttribute('type') || '')) || '';
    const lt = t.toLowerCase().trim();
    if (!lt) return true; // 无 type 默认 text/javascript
    return /^(text\/javascript|application\/javascript|module)$/.test(lt);
  }

  const DEFAULTS = {
    enabledGlobal: true,
    showWarning: true,
    autoBlockDownloads: true,
    notify: true,
    sensitivity: 'medium',
    enabled: {
      domainImpersonation: true, icpMissing: true, lowQuality: true,
      execDownload: true, cloudDiskDist: true, obfuscatedJs: true, vmDetection: true,
      socialEngineering: true, fakeOfficial: true, redirectIframe: true, domainStructure: true,
      brandedExe: true, passwordArchive: true
    },
    allowlist: [],
    customKeywords: [],
    customBadDomains: [],
    fontMode: 'system',   // 'system' | 'smiley'
    theme: 'dark',        // 'dark' | 'light'
    fontScale: 1          // 0.85 ~ 1.40，界面字号缩放系数
  };

  let lastResult = { analyzed: false };
  let blockedCount = 0;
  let unblocked = false;
  let observer = null;
  let dangerActive = false;       // 本页已被判危 → 启用硬拦截钩子
  let navBlock = false;           // 仅在高置信木马信号（STRONG 类）判危时才拦「一切程序化导航」
  let fullLockdown = false;       // 高置信木马信号命中也进入「全面锁定」：判危页所有交互型 CTA 入口（不论显示什么文字）一律灰化 + 拦截点击，覆盖伪装成「开始对话」「API 开放平台」的投递按钮
  let hardGuardsInstalled = false; // 硬拦截钩子（window.open / a.click / 点击捕获 / location）是否已安装
  let dangerReported = false;     // 防「报毒」重复上报：同一页面仅向后台/系统通知上报一次 danger
  let dangerAcknowledged = false; // 用户已点「仍然继续」确认进入 → 本页不再重复弹 danger 浮层（拦截仍生效）
  let didRun = false;             // 防 run() 因 DOMContentLoaded + setTimeout 兜底被重复触发（导致二次分析/双记录）

  // ===== 原生 API 快照（防止页面改写原型来对抗扩展 UI）=====
  // ⚠️ 2026-10-29：content.js 以 document_start 注入，此时页面脚本通常尚未执行，
  //   此刻抓一份原生引用快照，后续扩展 UI 的关键操作全部走这份快照。
  //   动机：恶意页会用 `EventTarget.prototype.addEventListener = ...` /
  //   `Document.prototype.getElementById = ...` 之类的手段定向让**扩展浮层**
  //   绑不上事件、也找不到自己的节点 —— 表现出来就是"整屏黑屏 + 按钮点不动"。
  const NATIVE = (function () {
    const grab = (obj, name) => { try { return obj ? obj[name] : undefined; } catch (e) { return undefined; } };
    const ET = grab(window, 'EventTarget') && EventTarget.prototype;
    const DP = grab(window, 'Document') && Document.prototype;
    const EP = grab(window, 'Element') && Element.prototype;
    const NP = grab(window, 'Node') && Node.prototype;
    return {
      addEventListener: grab(ET, 'addEventListener'),
      removeEventListener: grab(ET, 'removeEventListener'),
      getElementById: grab(DP, 'getElementById'),
      createElement: grab(DP, 'createElement'),
      querySelector: grab(EP, 'querySelector'),
      querySelectorAll: grab(EP, 'querySelectorAll'),
      // Document 侧的同类方法：document 不是 Element，必须分开取，否则 Illegal invocation
      querySelectorDoc: grab(DP, 'querySelector'),
      querySelectorAllDoc: grab(DP, 'querySelectorAll'),
      closest: grab(EP, 'closest'),
      setAttribute: grab(EP, 'setAttribute'),
      getAttribute: grab(EP, 'getAttribute'),
      remove: grab(EP, 'remove'),
      appendChild: grab(NP, 'appendChild'),
      // 以原生实现调用（this 固定为指定宿主），绕开页面可能的覆写
      on: function (el, type, fn, opts) {
        if (!el || typeof this.addEventListener !== 'function') return false;
        try { this.addEventListener.call(el, type, fn, opts); return true; } catch (e) { return false; }
      },
      byId: function (id) {
        if (typeof this.getElementById !== 'function') return null;
        try { return this.getElementById.call(document, id); } catch (e) { return null; }
      },
      mk: function (tag) {
        if (typeof this.createElement !== 'function') return null;
        try { return this.createElement.call(document, tag); } catch (e) { return null; }
      },
      qs: function (root, sel) {
        if (!root) return null;
        try {
          const isDoc = (typeof Document !== 'undefined' && root instanceof Document) || root === document;
          const fn = isDoc ? this.querySelectorDoc : this.querySelector;
          if (typeof fn === 'function') return fn.call(root, sel);
        } catch (e) {}
        try { return root.querySelector(sel); } catch (e) {}   // 兜底：退回（可能被改写过的）成员方法
        return null;
      },
      // ⚠️ 2026-10-30 修复「放行后页面变白、点不动」：
      //   document 是 Document 实例，不是 Element。用 Element.prototype.querySelectorAll
      //   以 document 为 this 调用会抛 **Illegal invocation**；原实现把异常吞掉返回 null，
      //   于是 doRelease/revokeWarningIfShown 里的「恢复被禁用入口」循环被静默跳过 ——
      //   被 neutralize 灰化 + pointer-events:none 的元素**永远恢复不了**，
      //   大容器被灰化时整页看起来就是"发白且点不动"。
      //   修法：① 按宿主类型选用 Document/Element 的原型方法；② 失败再退回成员方法。
      qsAll: function (root, sel) {
        if (!root) return null;
        try {
          const isDoc = (typeof Document !== 'undefined' && root instanceof Document) || root === document;
          const fn = isDoc ? this.querySelectorAllDoc : this.querySelectorAll;
          if (typeof fn === 'function') return fn.call(root, sel);
        } catch (e) {}
        try { return root.querySelectorAll(sel); } catch (e) {}
        return null;
      },
      attr: function (el, name) {
        if (!el || typeof this.getAttribute !== 'function') return null;
        try { return this.getAttribute.call(el, name); } catch (e) { return null; }
      },
      rm: function (el) {
        if (!el) return false;
        try {
          if (typeof this.remove === 'function') { this.remove.call(el); return true; }
          if (el.parentNode) el.parentNode.removeChild(el);
          return true;
        } catch (e) { return false; }
      },
      put: function (parent, child) {
        if (!parent || !child) return false;
        try { this.appendChild.call(parent, child); return true; } catch (e) { return false; }
      }
    };
  })();

  // 高置信木马信号：命中这些之一即判危时，除禁用下载入口外，还要拦截本页一切程序化导航
  // （location 跳转 / 锚点 .click / window.open），以堵死「同源带参跳转」「运行时中继取链」这类
  // 服务端吐二进制附件、内容脚本看不到响应体的下载手法。普通 medium 组合误判的页不拦导航，避免误伤。
  const NAV_BLOCK_FEATURES = ['domainImpersonation', 'obfuscatedJs', 'vmDetection', 'brandedExe', 'doubleExt', 'icpStolen', 'noahKit', 'downloadRedirector', 'runtimeDownload'];

  // 用户在「大弹窗」里点「仍要下载」后的短时放行窗口（ms）
  let nextAllowedUntil = 0;
  function isNextAllowed() { return Date.now() < nextAllowedUntil; }
  function allowNextAction(ms) { nextAllowedUntil = Date.now() + (ms || 500); }

  // 字体偏好：用户「切换字体」设置，供网页内横幅跟随（设置页/弹窗已各自处理）
  let currentFontMode = 'system';
  let fontFaceInjected = false;
  let currentScale = 1;

  function getSettings() {
    return new Promise((resolve) => {
      try {
        chrome.storage.sync.get(DEFAULTS, (s) => resolve(Object.assign({}, DEFAULTS, s || {})));
      } catch (e) { resolve(DEFAULTS); }
    });
  }

  // 包装 chrome.runtime.sendMessage，返回 Promise（用于需要响应的消息：sf-check-chain / sf-domain-age）
  function sendMsg(msg) {
    return new Promise((resolve) => {
      try { chrome.runtime.sendMessage(msg, (r) => resolve(r)); } catch (e) { resolve(null); }
    });
  }

  function isAllowlisted(hostname, allowlist) {
    hostname = (hostname || '').toLowerCase();
    return (allowlist || []).some((d) => {
      d = (d || '').trim().toLowerCase();
      return d && (hostname === d || hostname.endsWith('.' + d));
    });
  }

  // ===== 可信分发域名（内容侧分析豁免）=====
  // 网盘、GitHub 官方及镜像等站点的下载（含 .zip/.msi/任意文件）都是合法内容，
  // 分析引擎不应将其判为银狐木马投递站——否则进入即弹「危险网站」警告，并 disable 全部下载入口（变灰不可点）。
  // 与后台背景豁免列表保持同源。
  const TRUSTED_DISPATCH = [
    // 网盘类
    '123pan.com', '123pan.cn',                          // 一二三云盘（分享域名 123pan.cn，如 *.share.123pan.cn）
    'pan.baidu.com', 'wap.baidu.com', 'eyun.baidu.com', // 百度网盘
    'aliyundrive.com',                                  // 阿里云盘
    'weiyun.com',                                       // 腾讯微云
    'lanzou.com', 'lanzous.com', 'lanzoux.com',         // 蓝奏云
    'pan.quark.cn',                                     // 夸克网盘
    'cloud.189.cn',                                     // 天翼云盘
    '115.com', '115cache.com',                          // 115 网盘
    'ctfile.com',                                       // 城通网盘
    'cowtransfer.com',                                  // 奶牛快传
    'wenshushu.cn',                                     // 文叔叔
    'ys168.com',                                        // 永硕网盘
    'jianguoyun.com',                                   // 坚果云
    'quqi.com',                                         // 曲奇云盘
    'caiyun.139.com',                                   // 和彩云（移动）
    'fangcloud.com',                                    // 亿方云
    // GitHub 官方
    'github.com', 'github.io', 'github.dev', 'githubusercontent.com',
    'githubassets.com', 'github.community', 'githubstatus.com', 'github.blog',
    // GitHub 镜像
    'ghproxy.com', 'mirror.ghproxy.com', 'ghproxy.net', 'ghproxy.cfd',
    'kgithub.com', 'github.moeyy.xyz', 'github.bibaiyu.com', 'githubproxy.com',
    'gitclone.com', 'hub.gitmirror.com', 'github.coolapk.com', 'hub.fastgit.xyz',
    'fastgit.org', 'gh.api.99988866.xyz',
    // 项目官方站点（扩展分发页，永不拦截）
    'silverfoxguard.dpdns.org',
    'silverfoxguard.top'      // 新主域名（2026-10-11 接入，避免官网被误报）
  ];
  function isTrustedDispatch(hostname) {
    hostname = (hostname || '').toLowerCase();
    return TRUSTED_DISPATCH.some(function (d) {
      d = String(d).trim().toLowerCase();
      return d && (hostname === d || hostname.endsWith('.' + d));
    });
  }

  function escapeHtml(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => (
      { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
    ));
  }

  // ===== 页面内轻提示（去抖，绝不刷屏）=====
  let toastEl = null, toastTimer = null, lastToastAt = 0;
  function showToast(msg) {
    const now = Date.now();
    if (now - lastToastAt < 1500) return; // 去抖：1.5s 内不重复弹
    lastToastAt = now;
    if (!toastEl || !document.body.contains(toastEl)) {
      toastEl = document.createElement('div');
      toastEl.className = 'sf-toast';
      (document.body || document.documentElement).appendChild(toastEl);
    }
    toastEl.textContent = msg;
    toastEl.style.display = 'block';
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { if (toastEl) toastEl.style.display = 'none'; }, 2600);
  }

  // 带动画的关闭助手：加 .sf-closing 触发 CSS 退场动画，动画结束（或兜底超时）后移除
  function closeEl(el) {
    if (!el) return;
    if (!el.parentNode) { try { el.remove(); } catch (e) {} return; }
    el.classList.add('sf-closing');
    let done = false;
    const finish = () => {
      if (done) return; done = true;
      try { el.style.pointerEvents = 'none'; } catch (e) {}
      try { el.style.display = 'none'; } catch (e) {}
      try { el.remove(); } catch (e) {}
    };
    try {
      el.addEventListener('animationend', finish, { once: true });
      el.addEventListener('transitionend', finish, { once: true });
    } catch (e) {}
    setTimeout(finish, 420); // 兜底：动画未触发时也能移除
  }

  // ================================================================
  //  扩展 UI 的动作分发（事件委托 + 保底出口 + 看门狗）
  // ================================================================
  // ⚠️ 2026-10-29 修复「显示拦截弹窗时整屏变黑、按钮点不动」
  //
  // 【原缺陷（结构性）】
  //   showWarning() 先把整屏深色遮罩挂进 DOM，再调用 renderWarning() 渲染卡片、
  //   并逐个 `card.querySelector('#sf-leave').addEventListener(...)` 绑定事件。
  //   只要这一步失败：
  //     ① querySelector 返回 null → TypeError；
  //     ② renderWarning 在设置 innerHTML 之前就抛错（result.reasons 不是数组）；
  //     ③ 页面改写了 Element.prototype.querySelector / innerHTML setter（对抗手法）；
  //   异常会被上层 run() 的 try/catch 吞掉（只 reportVerdict('safe')），
  //   结果就是：**整屏深色遮罩常驻 + 按钮要么根本没有、要么点了没反应**。
  //   更糟的是 showWarning 的去重条件是 getElementById('sf-overlay')，
  //   遮罩还在 ⇒ 后续重判不会重建 ⇒ **永久黑屏，只能刷新页面**。
  //
  // 【修复思路：把"能不能操作"从"每个按钮各自绑定"改成"根节点一次性委托 + 三重兜底"】
  //   ① 事件委托：在 **window 捕获阶段**挂一个全局分发器（比页面任何 document 级
  //      监听都早，页面 stopPropagation / stopImmediatePropagation 也拦不住），
  //      按钮用 data-sf-act 标识动作，根节点存一张动作表。
  //      绑定与"按钮节点能否被 querySelector 找到"彻底解耦；
  //      innerHTML 重绘（主卡 ⇄ 二次确认）后依然有效。
  //   ② 保底出口：遮罩挂上后立刻插入一条**不依赖 innerHTML / querySelector** 的
  //      极简横条（createElement + textContent），保证任何时刻都有一个真能点的
  //      「离开此网站」；完整卡片渲染成功后再撤掉。
  //   ③ 看门狗：4 秒后校验遮罩是否仍有可用出口，若没有 ⇒ 强制移除遮罩并降级为
  //      顶部提示，**绝不留下点不动的黑屏**。
  //   ④ Esc 键出口：鼠标完全不可用时也能离开。
  let _sfDispatcherInstalled = false;
  let _sfEscInstalled = false;

  // 在 window 捕获阶段做一次全局动作分发（比页面的 document 级监听更早执行）
  function sfInstallActionDispatcher() {
    if (_sfDispatcherInstalled) return;
    _sfDispatcherInstalled = true;
    const dispatch = function (e) {
      let el = e.target;
      if (!el || el.nodeType !== 1) return;
      // 逐级向上找带 data-sf-act 的元素（兼容按钮内含 <span>/<svg> 的情况）
      let act = null, guard = 0;
      while (el && guard++ < 16) {
        const a = NATIVE.attr(el, 'data-sf-act');
        if (a) { act = a; break; }
        el = el.parentElement;
      }
      if (!act) return;
      // 找到承载动作表的根（浮层 / 横幅 / 提示）
      let root = el, g2 = 0;
      while (root && !root.__sfActions && g2++ < 16) root = root.parentElement;
      if (!root || !root.__sfActions) return;
      const fn = root.__sfActions[act];
      if (typeof fn !== 'function') return;
      try { e.preventDefault(); } catch (err) {}
      try { e.stopPropagation(); } catch (err) {}
      try { fn(e, el); } catch (err) {}
    };
    NATIVE.on(window, 'click', dispatch, true);
  }

  // Esc 键出口：鼠标完全不可用（页面掐死 pointer-events 等）时也能离开
  function sfInstallEscExit() {
    if (_sfEscInstalled) return;
    _sfEscInstalled = true;
    NATIVE.on(window, 'keydown', function (e) {
      if (!e || (e.key !== 'Escape' && e.key !== 'Esc')) return;
      const ov = NATIVE.byId('sf-overlay');
      if (!ov) return;
      const fn = ov.__sfActions && ov.__sfActions.__escape;
      if (typeof fn === 'function') {
        try { e.preventDefault(); } catch (err) {}
        try { fn(e); } catch (err) {}
      }
    }, true);
  }

  // 给浮层根节点安装动作表（真正的绑定发生在全局 window 捕获分发器上）
  function sfBindUiActions(root, map) {
    if (!root) return false;
    try { root.__sfActions = map || {}; } catch (e) { return false; }
    sfInstallActionDispatcher();
    sfInstallEscExit();
    return true;
  }

  // 保底出口横条：完全用 createElement + textContent 构造，不依赖 innerHTML / querySelector
  function sfBuildFallbackExit(root, label) {
    let bar = null;
    try {
      bar = NATIVE.mk('div');
      if (!bar) return null;
      bar.className = 'sf-fallback';
      try { NATIVE.setAttribute.call(bar, 'data-sf-fallback', '1'); } catch (e) {}
      const btn = NATIVE.mk('button');
      const span = NATIVE.mk('span');
      if (!btn || !span) return null;
      try { NATIVE.setAttribute.call(btn, 'type', 'button'); } catch (e) {}
      btn.className = 'sf-btn sf-btn-leave';
      btn.textContent = label || '离开此网站';
      try { NATIVE.setAttribute.call(btn, 'data-sf-act', 'leave'); } catch (e) {}
      try { NATIVE.setAttribute.call(btn, 'data-sf-fb', '1'); } catch (e) {}
      span.className = 'sf-fb-text';
      span.textContent = '🛡 SilverFoxBlocker：检测到高风险网站';
      NATIVE.put(bar, span);
      NATIVE.put(bar, btn);
      NATIVE.put(root, bar);
      // 默认隐藏；仅当主 UI 渲染失败时才亮出来（避免正常路径出现视觉抖动）
      try { bar.style.display = 'none'; } catch (e) {}
      return bar;
    } catch (e) { return null; }
  }

  function sfRevealFallback(bar) {
    if (!bar) return;
    try { bar.style.display = ''; } catch (e) {}
  }

  // 看门狗：浮层若在 N 毫秒后仍找不到任何可用出口 ⇒ 强制移除遮罩（宁可漏弹，不可黑屏）
  function sfWatchdogUi(root, onFail) {
    setTimeout(function () {
      try {
        if (!root) return;
        if (!root.parentNode) return;               // 已被关闭/移除
        const map = root.__sfActions;
        const acts = NATIVE.qsAll(root, '[data-sf-act]');
        let real = 0;
        if (acts) for (let i = 0; i < acts.length; i++) {
          if (!NATIVE.attr(acts[i], 'data-sf-fb')) { real++; }   // 保底条不算"主出口"
        }
        // 保底条若已亮出（主 UI 渲染失败），它本身就是可用出口
        const fbBar = NATIVE.qs(root, '[data-sf-fallback]');
        let fbVisible = false;
        if (fbBar) { try { fbVisible = fbBar.style.display !== 'none'; } catch (e) {} }
        // 分发器已装 + 动作表非空 + 存在可用出口 ⇒ UI 可用，放行
        if (_sfDispatcherInstalled && map && Object.keys(map).length && (real > 0 || fbVisible)) return;
        try { root.style.pointerEvents = 'none'; } catch (e) {}
        NATIVE.rm(root);
        if (typeof onFail === 'function') { try { onFail(); } catch (e) {} }
      } catch (e) {}
    }, 4000);
  }

  // 统一的浮层装配（顺序很关键）：
  //   建节点 → 装动作表 → 渲染内容 → 装保底出口（隐藏）→ 挂 DOM → 看门狗
  // ⚠️ 两个顺序陷阱：
  //   ① innerHTML 赋值会**清空**子节点 ⇒ 保底条必须在 innerHTML 之后插；
  //   ② 保底条不能在渲染成功前撤掉 —— 渲染若失败，它就是唯一的出口。
  // 返回 { overlay, fb }：调用方在自己内容渲染成功后调 sfFinishOverlay(fb) 撤掉保底条。
  function sfMountOverlay(opts) {
    opts = opts || {};
    let overlay = null, fb = null;
    try {
      overlay = NATIVE.mk('div');
      if (!overlay) return null;
      overlay.id = opts.id || '';
      overlay.className = opts.className || 'sf-overlay';
      // ① 先装动作表：遮罩一旦出现在屏幕上，动作分发已就绪
      sfBindUiActions(overlay, opts.actions || {});
      // ② 渲染内容
      if (opts.html) overlay.innerHTML = opts.html;
      // ③ 保底出口（默认隐藏，渲染成功后才撤）
      fb = sfBuildFallbackExit(overlay, opts.fallbackLabel);
      // ④ 挂 DOM
      NATIVE.put(document.body || document.documentElement, overlay);
      // ⑤ 看门狗
      sfWatchdogUi(overlay, opts.onFail);
      return { overlay: overlay, fb: fb };
    } catch (e) {
      // 装配失败：绝不留黑屏 —— 退化为"只有保底出口"的极简浮层
      try {
        if (overlay) {
          if (!overlay.parentNode) {
            const fb2 = sfBuildFallbackExit(overlay, opts.fallbackLabel);
            sfRevealFallback(fb2);
            NATIVE.put(document.body || document.documentElement, overlay);
            fb = fb2;
          } else if (fb) {
            sfRevealFallback(fb);
          } else {
            NATIVE.rm(overlay);
          }
        }
      } catch (e2) {}
      try { if (typeof opts.onFail === 'function') opts.onFail(); } catch (e2) {}
      return { overlay: overlay, fb: fb };
    }
  }

  // 渲染成功后撤掉保底条
  function sfFinishOverlay(fb) {
    try { if (fb) NATIVE.rm(fb); } catch (e) {}
  }

  // ===== 采集页面代码 + 工程化指标 + ICP =====
  function collectMetrics() {
    let domElementCount = 0;
    try { domElementCount = document.getElementsByTagName('*').length; } catch (e) {}
    // ⚠️ extRes 只统计【跨域绝对 URL】资源。它衡量的是「用了多少第三方 CDN」，
    // 并不等于「页面工程化程度」——把 CSS/JS/图片全部同域自托管的站点（蓝奏云、
    // 大量政企与自建站）extRes 恒为 0，却被下游检测器当成「页面简陋」的证据。
    // 因此额外统计 resourceCount：不区分同域/跨域的资源引用总数，作为工程化程度的
    // 真实度量；extRes 保留原语义供第三方依赖分析使用。
    let extRes = 0, resourceCount = 0;
    let scriptCount = 0, inlineScriptCount = 0, externalScriptCount = 0, iframeCount = 0;
    try {
      document.querySelectorAll('script').forEach((s) => {
        scriptCount++;
        const src = s.getAttribute('src') || '';
        if (src) {
          externalScriptCount++;
          resourceCount++;
          if (ABS_URL_RE.test(src) && src.indexOf(location.hostname) === -1) extRes++;
        } else if (isExecutableScript(s)) { inlineScriptCount++; }
      });
    } catch (e) {}
    try {
      document.querySelectorAll('img[src],img[data-src],link[href],iframe[src],source[src],video[src],audio[src],object[data],embed[src]')
        .forEach((el) => {
          const a = el.getAttribute('src') || el.getAttribute('href') || el.getAttribute('data-src') || el.getAttribute('data') || '';
          if (!a || /^(?:data:|javascript:|#)/i.test(a)) return;
          resourceCount++;
          if (ABS_URL_RE.test(a) && a.indexOf(location.hostname) === -1) extRes++;
        });
    } catch (e) {}
    try { iframeCount = document.querySelectorAll('iframe').length; } catch (e) {}
    let framework = null;
    try {
      if (window.React || window.__REACT_DEVTOOLS_GLOBAL_HOOK) framework = 'react';
      else if (window.Vue || window.__VUE__) framework = 'vue';
      else if (window.angular) framework = 'angular';
      else if (window.jQuery || (window.$ && window.$.fn)) framework = 'jquery';
      else if (document.querySelector('next-route-announcer,[data-nextjs]')) framework = 'next';
    } catch (e) {}
    let bodyText = '';
    try { bodyText = document.body ? document.body.innerText || '' : ''; } catch (e) {}
    const textLength = bodyText.length;
    // 性能优化：CJK / emoji 统计仅采样前 4000 码元。这二者只是粗粒度启发式信号，
    // 全量遍历长页面（innerText 可达数万字符）开销大，采样对判定无实质影响。
    const _sampleLen = Math.min(bodyText.length, 4000);
    let cjk = 0;
    for (let i = 0; i < _sampleLen; i++) {
      const cp = bodyText.codePointAt(i);
      if ((cp >= 0x4E00 && cp <= 0x9FFF) || (cp >= 0x3400 && cp <= 0x4DBF)) cjk++;
      if (cp > 0xFFFF) i++;
    }
    const _sampleText = bodyText.slice(0, _sampleLen);
    const hasCJK = (_sampleLen > 0 && (cjk / _sampleLen) >= 0.08) || cjk >= 500;
    let emojiCount = 0;
    try { emojiCount = (_sampleText.match(/\p{Emoji_Presentation}|\p{Emoji}/gu) || []).length; } catch (e) {}
    const emojiDensity = _sampleLen > 0 ? (emojiCount / _sampleLen) * 1000 : 0;
    return {
      domElementCount, externalResourceCount: extRes, resourceCount, framework,
      textLength, cjkCount: cjk, cjkRatio: textLength ? cjk / textLength : 0,
      hasCJK, emojiCount, emojiDensity: Math.round(emojiDensity * 100) / 100,
      scriptCount, inlineScriptCount, externalScriptCount, iframeCount
    };
  }

  // 同步主采集：基础 DOM + 页面文本内嵌下载直链扫描（不含 .txt 异步解析）。
  // 必须同步、快速返回，以便 run() 在页面被 meta refresh 秒跳走之前完成判定。
  function collectCore() {
    const hostname = location.hostname;
    const scripts = [];
    try {
      document.querySelectorAll('script').forEach((s) => {
        if (!isExecutableScript(s)) return; // 排除 JSON-LD / 结构化数据等非 JS 脚本
        const t = s.textContent || s.innerText || '';
        if (t && t.length > 30) scripts.push(t);
      });
    } catch (e) {}
    const links = [];
    try {
      document.querySelectorAll('a[href]').forEach((a) => {
        links.push({ href: a.getAttribute('href'), text: (a.innerText || a.textContent || '').trim().slice(0, 40) });
      });
    } catch (e) {}
    const iframeSrcs = [];
    try {
      document.querySelectorAll('iframe,frame,object,embed').forEach((f) => {
        const s = f.getAttribute('src') || f.getAttribute('data-src') || '';
        if (s) iframeSrcs.push(s);
      });
    } catch (e) {}
    // meta refresh 跳转（#4 资源解析器用作种子）：提取 url 与延时
    const metaRefreshUrls = [];
    try {
      document.querySelectorAll('meta[http-equiv]').forEach((m) => {
        const he = (m.getAttribute('http-equiv') || '').toLowerCase();
        if (he !== 'refresh') return;
        const c = m.getAttribute('content') || '';
        const um = c.match(/url\s*=\s*['"]?\s*([^'"\s]+)/i);
        if (!um || !um[1]) return;
        const dm = c.match(/^\s*(\d+)\s*;/);
        metaRefreshUrls.push({ url: um[1], delay: dm ? parseInt(dm[1], 10) : 0, originalContent: c });
      });
    } catch (e) {}
    let html = '';
    try { html = document.documentElement.outerHTML || ''; } catch (e) {}

    // 同步增强：扫描正文/HTML 文本中内嵌的下载直链（如 meta refresh 指向的 .zip 真实地址）。
    // 同步执行、不阻塞主判定；保守：只增强「检测」，不主动 block。
    const seen = new Set(links.map((l) => l.href));
    let bodyText = '';
    try { bodyText = (document.body && document.body.innerText) || ''; } catch (e) {}
    const textHtml = (html || '').replace(/<script[\s\S]*?<\/script>/gi, ' ').replace(/<style[\s\S]*?<\/style>/gi, ' ');
    const combinedText = bodyText + '\n' + textHtml;
    DLINK_URL_RE.lastIndex = 0;
    let mm;
    while ((mm = DLINK_URL_RE.exec(combinedText)) !== null) {
      const u = mm[0];
      if (isDlLink(u) && !seen.has(u)) { seen.add(u); links.push({ href: u, text: '(页面文本内嵌下载链接)' }); }
    }

    return { hostname, title: document.title || '', html, scripts, links, iframeSrcs, metaRefreshUrls, _seen: seen };
  }

  // ★ ICP 权威核验的「值得查」门控（隐私优先）。
  // 核验请求会把本站注册域名发给第三方备案查询接口，因此绝不能对所有站点无脑查询。
  // 仅在以下三种「核验结果确实会改变判定」的场景才发起，其余一律只用页面文本扫描：
  //   ① 页面展示了备案号 → 需要验真伪，才能揪出「盗用他人备案号」的钓鱼站（#3）；
  //   ② .cn 域名但页面找不到任何备案标识 → 可能只是没在页面展示，查一次避免「缺备案号」误扣 35 分；
  //   ③ 已判定域名仿冒 → 若权威库确认确有备案，则跳过仿冒判定（#2），根治正规品牌站误伤。
  function needIcpVerify(settings, data) {
    if (!settings || settings.icpApiVerify === false) return false;
    if (lastResult && (lastResult.allowlisted || lastResult.disabled)) return false; // 白名单/停用站不查
    const icp = data.icp || {};
    if (icp.hasIcpNumber) return true;                                   // ① 验真伪
    const isCn = (location.hostname || '').toLowerCase().endsWith('.cn');
    if (isCn && !icp.hasGovIcp) return true;                             // ② 防误扣
    if (lastResult && lastResult.spoof) return true;                     // ③ 防误伤品牌站
    return false;
  }

  // 本页是否存在指向「下载黑名单」域名的链接（按注册域名逐级后缀匹配，覆盖换子域的载荷桶）
  function anyLinkInBlacklist(data, domains) {
    const set = new Set(domains);
    for (const l of (data.links || [])) {
      const href = (l && l.href) || '';
      if (!href) continue;
      let h = '';
      try { h = new URL(href, location.href).hostname.toLowerCase().replace(/^www\./, ''); } catch (e) { continue; }
      if (!h) continue;
      if (set.has(h)) return true;
      const parts = h.split('.');
      for (let i = 1; i < parts.length - 1; i++) {
        if (set.has(parts.slice(i).join('.'))) return true;
      }
    }
    return false;
  }

  // 等待页面加载到 complete（图片/子帧加载完），最多等 timeoutMs 兜底，避免「页脚备案号尚未渲染」就判定。
  function waitPageSettled(timeoutMs) {
    return new Promise((resolve) => {
      if (document.readyState === 'complete') return resolve();
      const start = Date.now();
      const iv = setInterval(() => {
        if (document.readyState === 'complete' || (Date.now() - start) >= timeoutMs) {
          clearInterval(iv);
          resolve();
        }
      }, 200);
    });
  }

  // 关键异步补强（必须在主判定之前 await 完成）：云端官网库 + ICP 权威核验 + 域名年龄 + 下载黑名单。
  // 这些项会改变判定（尤其 ICP 核验决定「是否扣缺备案号 18 分」），若像旧逻辑那样「先判定、后补强」，
  // 就会出现「首屏 70 分（缺备案）→ 补强后 52 分」的评分跳变与重复记录。
  async function collectCriticalEnrichments(settings, data) {
    // 0) 云端官网库（纯内存查，无网络等待）：命中即豁免，避免官方站被本地规则误伤。
    try {
      const rc = await sendMsg({ type: 'sf-cloud-official', host: location.hostname });
      if (rc && rc.official && rc.matched) {
        if (SF.registerCloudOfficial) SF.registerCloudOfficial([rc.matched]);
        data.cloudOfficial = true;
      }
    } catch (e) {}
    // 1) ICP 权威核验（三态：确有备案 / 确认无备案 / 查询失败）。失败时后台返回 {queried:false}，引擎回退页面文本扫描。
    if (needIcpVerify(settings, data)) {
      try {
        const ra = await sendMsg({ type: 'sf-icp-verify', hostname: location.hostname });
        if (ra && ra.queried) data.icpAuth = ra;
      } catch (e) {}
    }
    // 2) 下载黑名单（纯本地读）：只有本页确实存在指向黑名单域名的链接时才注入。
    try {
      const rb = await sendMsg({ type: 'sf-dl-blacklist' });
      const domains = (rb && rb.domains) || [];
      if (domains.length) data.dlBlacklist = domains;
    } catch (e) {}
    // 3) 域名年龄（RDAP，查不到则保持 undefined，引擎优雅跳过）。
    try {
      const r = await sendMsg({ type: 'sf-domain-age', hostname: location.hostname });
      if (r && typeof r.days === 'number') data.domainAgeDays = r.days;
    } catch (e) {}
  }

  // 深度异步补强：同域 .txt 内嵌下载链接 + BFS 资源下挖（耗时可达 10s）。
  // 仅当确实补到「新」下载入口时才重判一次；后台按 tabId 去重，不会重复计数 / 重复记录。
  // 注意：此处不再做 ICP 核验 / 域名年龄 / 黑名单 —— 那些已在 collectCriticalEnrichments 完成，
  // 否则再次设置 data.icpAuth 等会触发「结果变更」假阳性，造成无谓的重判与跳变。
  async function enrichDeepAsync(settings, chained, data) {
    if (!settings || !settings.enabledGlobal) return;
    let changed = false;

    // 1) 同域 .txt 文件解析，提取隐藏的压缩包/网盘直链（银狐常用 .txt 藏真实下载地址）
    const seen = data._seen || new Set(data.links.map((l) => l.href));
    const txtHrefs = data.links
      .map((l) => l.href)
      .filter((h) => TXT_EXT_RE.test(h || ''))
      .filter((h) => { try { return new URL(h, location.href).hostname === location.hostname; } catch (e) { return false; } })
      .slice(0, 3);
    for (const href of txtHrefs) {
      try {
        const ctrl = new AbortController();
        const timer = setTimeout(() => { try { ctrl.abort(); } catch (e) {} }, 5000);
        const rr = await fetch(href, { cache: 'no-store', signal: ctrl.signal });
        clearTimeout(timer);
        if (!rr.ok) continue;
        const txt = await rr.text();
        DLINK_URL_RE.lastIndex = 0;
        const localSeen = new Set();
        let m2;
        while ((m2 = DLINK_URL_RE.exec(txt)) !== null) {
          const u = m2[0];
          if (isDlLink(u) && !seen.has(u) && !localSeen.has(u)) {
            seen.add(u); localSeen.add(u);
            data.links.push({ href: u, text: '(.txt 文件内嵌下载链接)' });
            changed = true;
          }
        }
      } catch (e) { /* 跨域/超时/404 等，静默忽略 */ }
    }
    // 2) BFS 资源解析器：异步下挖脚本内直链 / 重定向链 / 同域 .txt 递归 / iframe。
    try {
      if (typeof SF_RESOLVER !== 'undefined' && SF_RESOLVER.resolve) {
        const pageUrl = location.href;
        const initialData = {
          inlineScripts: (data.scripts || []).map((t) => ({ text: t })),
          metaRefreshUrls: data.metaRefreshUrls || [],
          iframeSrcs: data.iframeSrcs || [],
          links: data.links,
          pageText: (data.html || '').replace(/<script[\s\S]*?<\/script>/gi, ' ').replace(/<style[\s\S]*?<\/style>/gi, ' ')
        };
        const graph = await SF_RESOLVER.resolve(pageUrl, initialData, {
          maxDepth: 3, maxTotalResources: 20, perResourceTimeout: 2000,
          totalTimeout: 5000, maxRedirects: 5, maxTxtRecursion: 2
        });
        for (const d of (graph.downloadLinks || [])) {
          const href = d.href;
          if (href && !seen.has(href)) { seen.add(href); data.links.push({ href: href, text: d.text || '(.txt 内嵌)' }); changed = true; }
        }
      }
    } catch (e) { /* 解析器异常不影响主判定 */ }

    // 仅当真正补到新下载入口时才重判一次（且 analyzeAndAct 内部 danger 已去重上报）。
    if (changed) analyzeAndAct(settings, chained, data);
  }

  // ⚠️ 2026-08-31 加固：原实现只读 document.body.innerText，取不到三类常见写法 ——
  //   ① 备案号写在被 CSS 折叠/隐藏的页脚容器里（innerText 跳过不可见文本）；
  //   ② 备案号只作为 <a title="..."> / alt 属性存在；
  //   ③ 页脚仅放一个指向 beian.miit.gov.cn 的官方备案查询链接。
  // 采集不到就会被「缺备案号」维度扣分，实测 www.52pojie.cn / www.lanzou.com 均因此误报。
  // 现改为 innerText → textContent → innerHTML 三级兜底，并额外识别官方备案查询链接。
  function extractIcp() {
    let hasIcpNumber = false, hasGovIcp = false, hasBeianLink = false, icpNumber = null;
    try {
      const body = document.body;
      const t = (body && (body.innerText || body.textContent)) || '';
      const raw = (body && body.innerHTML) || '';
      const scan = t + '\n' + raw;
      const m = scan.match(/[\u4e00-\u9fa5]?ICP备[\s]*[A-Za-z0-9]+号?-?\d*/i) ||
                scan.match(/ICP备案号[\s]*[：:]?[\s]*[A-Za-z0-9]+号?/i) ||
                scan.match(/[\u4e00-\u9fa5]?ICP证\s*\d+号/i);
      if (m) { hasIcpNumber = true; icpNumber = m[0].trim(); }
      if (/公网安备\s*\d+号?|网安备|联网备案/i.test(scan)) hasGovIcp = true;
      // 官方备案查询入口：工信部 / 全国互联网安全管理服务平台
      if (/beian\.miit\.gov\.cn|beian\.gov\.cn|tsm\.miit\.gov\.cn/i.test(raw)) hasBeianLink = true;
    } catch (e) {}
    return { hasIcpNumber, hasGovIcp, hasBeianLink, icpNumber };
  }

  // ===== 下载入口识别 =====
  const DOWNLOAD_TEXT = ['下载', '立即下载', '高速下载', '普通下载', '安全下载', '官方下载',
    '客户端', 'windows', 'win', 'macos', 'mac', 'linux', 'ubuntu', '安卓', 'android', 'ios', 'iphone',
    '安装包', '安装程序', 'pc版', '电脑版', '桌面版', '企业版', '个人版', '点击下载'];
  const DOWNLOAD_ATTRS = ['data-url', 'data-href', 'data-download', 'data-link', 'data-src', 'data-file', 'download'];

  function isDownloadUrl(url) {
    if (!url || typeof url !== 'string') return false;
    const u = url.toLowerCase();
    if (u.startsWith('blob:')) return true;
    if (u.startsWith('data:') && /base64/.test(u) && u.length > 500) return true;
    const t = SF.classifyLink(url);
    return t === 'exec' || t === 'cloud' || t === 'download' || t === 'archive';
  }

  function elementText(el) {
    let s = '';
    try {
      s += (el.innerText || el.textContent || '') + ' ';
      s += (el.getAttribute('title') || '') + ' ';
      s += (el.getAttribute('aria-label') || '') + ' ';
      s += (el.getAttribute('alt') || '') + ' ';
      s += (el.getAttribute('placeholder') || '');
    } catch (e) {}
    return s.toLowerCase();
  }

  // ===== 判断元素是否属于扩展自身 UI =====
  // ⚠️ 2026-10-29：这里**不能**用 el.closest('.sf-overlay,...')。
  //   页面可以改写 Element.prototype.closest 让它返回 null —— 此时
  //   isDownloadEntry 会把扩展浮层里的「离开此网站 / 继续访问」按钮
  //   当成"页面上的下载入口"→ 灰化 + 拦截点击（neutralize 还会设 pointer-events:none）
  //   ⇒ 表现为「拦截弹窗的按钮点了没反应，甚至又弹出一个下载拦截窗」。
  // 改为自行沿 parentElement 上溯并直接比对 class，完全不依赖 closest/querySelector。
  const _SF_UI_CLASSES = ['sf-overlay', 'sf-banner', 'sf-hint', 'sf-toast', 'sf-fallback'];
  function isSfUiElement(el) {
    let cur = el, guard = 0;
    while (cur && cur.nodeType === 1 && guard++ < 64) {
      let cls = '';
      try {
        const cn = cur.className;
        cls = (cn && cn.baseVal !== undefined) ? String(cn.baseVal) : String(cn || '');
      } catch (e) { cls = ''; }
      cls = cls.toLowerCase();
      if (cls) {
        const parts = cls.split(/\s+/);
        for (let i = 0; i < _SF_UI_CLASSES.length; i++) {
          if (parts.indexOf(_SF_UI_CLASSES[i]) !== -1) return true;
        }
      }
      cur = cur.parentElement;
    }
    return false;
  }

  // 判断单个元素是否像下载入口（div/button/a/img 等）
  function isDownloadEntry(el) {
    if (!el || el.nodeType !== 1) return false;
    // 排除扩展自身的浮层/横幅/提示（其 class 含 card/btn 等易误判词，且文本含"下载"）
    if (isSfUiElement(el)) return false;
    // 全面锁定：高置信木马信号（仿冒站 / NOAH / 运行时取链投递 / 自跳转下载页）命中时，
    // 页面上所有「交互型入口」都视作木马投递点 —— 攻击者可把下载木马的按钮伪装成
    // 「开始对话」「API 开放平台」等官网正常功能名，不再要求文字含「下载」。
    // 覆盖：button 标签 / 非导航锚点(a href=javascript:#) / role=button|link / 带 CTA 类 / 带 onclick。
    // 真实导航 a（指向官网/首页的 http(s) 链接）不强制锁定，避免把整页正常链接全灰掉；
    // 良性误判页因 navBlock=false → fullLockdown=false，此分支不触发，不误伤。
    if (fullLockdown) {
      const tag = el.tagName;
      const href = (el.getAttribute && el.getAttribute('href')) || '';
      const role = el.getAttribute && el.getAttribute('role');
      const cls = String(el.className || '').toLowerCase();
      const hasOnclick = el.hasAttribute && (el.hasAttribute('onclick') || typeof el.onclick === 'function');
      if (tag === 'BUTTON') return true;
      if (tag === 'A') {
        // 非导航锚点（javascript:/#）→ 锁定；真实 http(s) 导航链接 → 不锁定
        if (/^(javascript:|#)/i.test(href)) return true;
        return false;
      }
      if (role === 'button' || role === 'link') return true;
      if (hasOnclick) return true;
      if (/btn|button|cta|card-link|card|nav-link|nav-btn|download|down|client|item|primary|secondary/i.test(cls)) return true;
      return false;
    }
    if (el.tagName === 'A' && el.hasAttribute('href')) {
      const href = el.getAttribute('href') || '';
      // 真实导航链接：按下载 URL 特征判定
      if (!/^(javascript:|#|mailto:|tel:)/i.test(href)) return isDownloadUrl(href);
      // 非导航锚点（如深狐 NOAH 的 <a href="javascript:void(0)" data-download>）：
      // 退化到下方「形态判定」——命中下载词/类/属性即视为下载入口，必须禁用其点击
    }
    const text = elementText(el);
    if (!DOWNLOAD_TEXT.some((k) => text.indexOf(k) !== -1)) return false;
    // 命中下载文本后，再判断它是否可点击或者是下载链接容器
    const tag = el.tagName;
    const role = el.getAttribute('role');
    const cls = String(el.className || '').toLowerCase();
    const id = String(el.id || '').toLowerCase();
    const hasOnclick = el.hasAttribute('onclick') || typeof el.onclick === 'function';
    const dataUrl = DOWNLOAD_ATTRS.map((a) => el.getAttribute(a)).filter(Boolean).join(' ');
    const isClickableTag = tag === 'BUTTON' || tag === 'A' || tag === 'INPUT' ||
                           role === 'button' || role === 'link' || el.hasAttribute('tabindex') ||
                           /btn|button|download|down|client|card|item/i.test(cls + ' ' + id) ||
                           hasOnclick || dataUrl;
    if (!isClickableTag) return false;
    return isDownloadUrl(dataUrl) || true;
  }

  // 向上找下载入口祖先（最多 5 层）
  function findDownloadAncestor(el) {
    let cur = el && el.parentElement;
    for (let i = 0; cur && i < 6; i++) {
      if (isDownloadEntry(cur)) return cur;
      cur = cur.parentElement;
    }
    return null;
  }

  // ===== 链接与下载入口静默禁用 =====
  // 被禁用元素的**权威账本**：放行/撤销时用这份列表直接恢复，
  // 不再依赖 querySelectorAll('[data-sf-blocked]') 重新查找 —— 查找一旦失败
  // （见 NATIVE.qsAll 的 Illegal invocation 注释），整页就会永久停在"发白且点不动"的状态。
  const _blockedEls = [];

  // 大容器不灰化：整页/大区块被设成 pointer-events:none 会让页面"变白且点不动"
  // （AdGuard 知识库这类文档站的内容容器很容易命中 card/item 类名）。
  // 点击拦截由 globalClickGuard 在捕获阶段负责，**不依赖灰化**，所以跳过容器不影响防护。
  function _isHugeContainer(el) {
    try {
      if (!el || !el.getElementsByTagName) return false;
      return el.getElementsByTagName('*').length > 40;
    } catch (e) { return false; }
  }

  function neutralize(el) {
    if (!el || (el.dataset && el.dataset.sfBlocked) || unblocked) return;
    if (el.tagName === 'A') {
      const href = el.getAttribute('href');
      // mailto:/tel: 等非下载外链直接跳过
      if (!href || /^(mailto:|tel:)/i.test(href)) return;
      if (/^(javascript:|#)/i.test(href)) {
        // 非导航锚点（JS 触发下载，如深狐 NOAH 的 <a href="javascript:void(0)" data-download>）：
        // 仅当它本身被识别为下载入口（下载词/类/属性）时才禁用
        if (!isDownloadEntry(el)) return;
      } else if (!isDownloadUrl(href)) {
        return;
      }
    } else {
      if (!isDownloadEntry(el) && !findDownloadAncestor(el)) return;
      if (_isHugeContainer(el)) return;   // ★ 2026-10-30：不灰化整页级容器
    }
    el.dataset.sfBlocked = '1';
    _blockedEls.push(el);                 // ★ 记账，供后续无条件恢复
    el.addEventListener('click', blockHandler, true);
    el.addEventListener('contextmenu', blockHandler, true);
    el.style.pointerEvents = 'none';
    el.style.opacity = '0.55';
    el.style.filter = 'grayscale(0.6)';
    if (el.tagName === 'A') {
      el.dataset.sfOriginalHref = el.getAttribute('href');
      el.removeAttribute('href');
    }
    blockedCount++;
  }

  // 恢复所有被禁用的入口（放行 / 判定被推翻时调用）。
  // 逐元素 try/catch：单个元素恢复失败绝不影响其余元素。
  function restoreBlockedEntries() {
    for (let i = _blockedEls.length - 1; i >= 0; i--) {
      const el = _blockedEls[i];
      try {
        if (!el || !el.dataset) continue;
        el.style.pointerEvents = '';
        el.style.opacity = '';
        el.style.filter = '';
        if (el.dataset.sfOriginalHref) {
          try { el.setAttribute('href', el.dataset.sfOriginalHref); } catch (e) {}
          delete el.dataset.sfOriginalHref;
        }
        delete el.dataset.sfBlocked;
      } catch (e) {
        // 极端情况：dataset 不可写 —— 至少把可点击性还回去
        try { el.style.pointerEvents = ''; el.style.opacity = ''; el.style.filter = ''; } catch (e2) {}
      }
    }
    _blockedEls.length = 0;
    blockedCount = 0;
  }

  // 点击被禁入口：弹大弹窗，由用户选择放行/保持拦截
  function blockHandler(e) {
    if (unblocked || !dangerActive || isNextAllowed()) return;
    const t = e.target;
    if (isSfUiElement(t)) return;
    const entry = (e.target && (isDownloadEntry(e.target) || findDownloadAncestor(e.target))) || e.target;
    e.preventDefault();
    e.stopPropagation();
    e.stopImmediatePropagation();
    showDownloadBlocked(location.hostname, {
      target: entry
    });
    return false;
  }

  function blockAllDownloadEntries() {
    if (unblocked) return;
    try {
      document.querySelectorAll('a[href]').forEach(neutralize);
      // 额外扫描常见下载入口标签
      document.querySelectorAll('button, div, span, img, section, article, li').forEach(neutralize);
    } catch (e) {}
    // 拦截 JS 弹窗下载
    try {
      const _open = window.open;
      window.open = function (url) {
        if (!dangerNavBlocked(url)) return _open.apply(window, arguments);
        return null;
      };
    } catch (e) {}
    // 拦截程序化 a.click（常见 fetch→blob→a.click 投递）
    try {
      const proto = window.HTMLAnchorElement && window.HTMLAnchorElement.prototype;
      if (proto && proto.click && !proto._sfClick) {
        const _click = proto.click;
        proto._sfClick = _click;
        proto.click = function () {
          const a = this;
          if (unblocked || isNextAllowed()) return _click.call(a);
          const href = a.getAttribute('href') || a.href || '';
          // 仅拦截真实导航（排除 javascript:/#/mailto:/tel:/about: 等非导航）
          const navHref = (href && !/^(javascript:|#|mailto:|tel:|about:)/i.test(href)) ? href : null;
          // 高置信信号(navBlock) 或 明确下载 URL → 拦截，堵死运行时中继取链 / 直接甩文件
          if (navHref && (navBlock || isDownloadUrl(navHref))) {
            if (!NATIVE.byId('sf-overlay')) showDownloadBlocked(location.hostname, { url: navHref });
            return;
          }
          return _click.call(a);
        };
      }
    } catch (e) {}
    // 拦截 location 跳转下载
    installLocationGuard();
    // 全局点击捕获：拦截非 a/button/div 卡片的点击
    document.addEventListener('click', globalClickGuard, true);
    // 早期拦截：IDM 等第三方下载器常在 mousedown 阶段就把链接 URL 抢走（早于 click），
    // 故在 mousedown / pointerdown 捕获阶段即拦截，阻断其接管下载。
    document.addEventListener('mousedown', globalClickGuard, true);
    document.addEventListener('pointerdown', globalClickGuard, true);
    // 拦截表单提交到外部下载
    document.addEventListener('submit', function (e) {
      if (unblocked || !dangerActive || isNextAllowed()) return;
      const f = e.target;
      const action = (f && f.getAttribute && f.getAttribute('action')) || '';
      if (isDownloadUrl(action)) {
        e.preventDefault();
        showDownloadBlocked(location.hostname, { url: action });
      }
    }, true);
    // 监视动态注入的任意元素
    if (!observer) {
      observer = new MutationObserver((muts) => {
        if (unblocked) return;
        muts.forEach((m) => m.addedNodes && m.addedNodes.forEach((n) => {
          if (n.nodeType === 1) {
            neutralize(n);
            try { n.querySelectorAll && n.querySelectorAll('a[href],button,div,span,img,section,article,li').forEach(neutralize); } catch (e) {}
          }
        }));
      });
      observer.observe(document.documentElement, { childList: true, subtree: true });
    }
  }

  // 高置信木马信号判危页拦截「任何程序化导航」（location 跳转 / 锚点 .click / window.open），
  // 不再只认「下载 URL」特征——攻击者常用同源带参跳转、或运行时从 relay 拉来的中转 URL
  // 触发二进制下载，这些 URL 不匹配下载特征却照样把访客甩去下载页（即「跳转没被去掉」）。
  // 拦截条件（任一即拦）：
  //   ① 本页命中 NAV_BLOCK_FEATURES 高置信信号（navBlock=true）→ 拦一切程序化导航；
  //   ② 任意 danger 页若出现「明确下载 URL」导航（如 ?la_download=1 / .exe / 网盘直链）→ 拦。
  // 普通页面跳转（/dashboard 等）不含下载特征 → 不误伤良性页；
  // 用户主动点「完全放行」(unblocked) 或短时窗口(isNextAllowed) 时放行。
  function dangerNavBlocked(url) {
    if (unblocked || isNextAllowed()) return false;
    // 高置信木马信号(navBlock)命中 → 拦截本页一切程序化导航；
    // 任意 danger 页若出现「明确下载 URL」的导航（如 ?la_download=1 / .exe / 网盘直链）也拦截，
    // 堵死直接甩二进制附件的手法；普通页面跳转（/dashboard 等）不含下载特征 → 不误伤。
    if (!navBlock && !(url && isDownloadUrl(url))) return false;
    // 主警告浮层已显示时不再叠加「下载被拦截」浮层，仅静默阻断导航
    if (!NATIVE.byId('sf-overlay')) showDownloadBlocked(location.hostname, { url: url || '' });
    return true;
  }

  function installLocationGuard() {
    if (window.location && window.location._sfGuarded) return;
    window.location._sfGuarded = true;
    try {
      const hrefDesc = Object.getOwnPropertyDescriptor(window.location, 'href');
      if (hrefDesc && hrefDesc.set) {
        const origSet = hrefDesc.set;
        Object.defineProperty(window.location, 'href', {
          configurable: true,
          get: function () { return hrefDesc.get.call(window.location); },
          set: function (url) {
            if (!dangerNavBlocked(url)) return origSet.call(window.location, url);
          }
        });
      }
    } catch (e) {}
    try {
      const origReplace = window.location.replace;
      window.location.replace = function (url) {
        if (!dangerNavBlocked(url)) return origReplace.apply(window.location, arguments);
      };
    } catch (e) {}
    try {
      const origAssign = window.location.assign;
      window.location.assign = function (url) {
        if (!dangerNavBlocked(url)) return origAssign.apply(window.location, arguments);
      };
    } catch (e) {}
  }

  function globalClickGuard(e) {
    if (unblocked || !dangerActive || isNextAllowed()) return;
    const target = e.target;
    if (!target || target.nodeType !== 1) return;
    // 扩展自身 UI 点击放行（双保险，避免误吞弹窗按钮）
    if (isSfUiElement(target)) return;
    const entry = isDownloadEntry(target) ? target : findDownloadAncestor(target);
    if (!entry) return;
    e.preventDefault();
    e.stopPropagation();
    e.stopImmediatePropagation();
    showDownloadBlocked(location.hostname, { target: entry });
    return false;
  }

  // ===== 警告浮层 =====
  const SHIELD_SVG = '<svg class="sf-icon" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">' +
    '<path d="M12 2 4 5v6c0 5 3.4 8.5 8 11 4.6-2.5 8-6 8-11V5l-8-3Z" fill="rgba(255,90,90,.16)" stroke="#ff7a7a" stroke-width="1.4"/>' +
    '<path d="M12 8v5" stroke="#ffd36e" stroke-width="1.8" stroke-linecap="round"/>' +
    '<circle cx="12" cy="16.4" r="1.25" fill="#ffd36e"/></svg>';

  // 主拦截浮层当前所在的根节点（供二次确认等子视图更新动作表）
  let warningOverlay = null;

  function showWarning(result) {
    // 用户已确认「仍然继续」→ 本页不再重复弹 danger 浮层（下载拦截仍生效）。
    // 修复：原逻辑仅靠 DOM 里是否存在 #sf-overlay 判重，但「继续访问」会 closeEl 移除 overlay，
    // 导致 enrichDeepAsync 异步补强 / SPA 重跑 analyzeAndAct 时再次弹窗。
    if (dangerAcknowledged) return;
    if (NATIVE.byId('sf-overlay')) return;
    let card = null;
    try {
      card = NATIVE.mk('div');
      if (!card) throw new Error('createElement failed');
      card.className = 'sf-card';
    } catch (e) {
      try { showToast('⚠️ SilverFoxBlocker：检测到高风险网站（弹窗渲染异常，请离开该网站）'); } catch (e2) {}
      return;
    }
    const mounted = sfMountOverlay({
      id: 'sf-overlay',
      className: 'sf-overlay' + (currentFontMode === 'smiley' ? ' sf-font-smiley' : ''),
      html: '',
      fallbackLabel: '离开此网站',
      actions: {
        leave: function () { leaveSite(); },
        continue: function () { try { showContinueConfirm(card, result); } catch (e) {} },
        __escape: function () { leaveSite(); }
      },
      onFail: function () {
        try { showToast('⚠️ 拦截弹窗异常，已自动移除遮罩，请离开该网站'); } catch (e) {}
      }
    });
    if (!mounted || !mounted.overlay) return;
    const overlay = mounted.overlay;
    warningOverlay = overlay;
    // 内容渲染放进 mount 之后的独立步骤：失败时保底条仍在，屏幕上永远有可点的出口
    try {
      NATIVE.put(overlay, card);
      renderWarning(card, result);
      sfFinishOverlay(mounted.fb);
    } catch (e) {
      try { sfRevealFallback(mounted.fb); } catch (e2) {}
      try { showToast('⚠️ 拦截弹窗渲染异常，已切换为简易提示，请离开该网站'); } catch (e2) {}
    }
  }

  function renderWarning(card, result) {
    // ⚠️ reasons 未必是数组（异常判定路径），必须兜底，否则 map 直接抛错 → 整屏只剩遮罩
    const reasons = Array.isArray(result && result.reasons) ? result.reasons : [];
    const reasonsHtml = reasons.map((r) =>
      '<li><span class="sf-dot"></span><span><b>' + escapeHtml(r && r.label) + '</b><br>' + escapeHtml((r && r.detail) || '') + '</span></li>'
    ).join('');

    const subText =
      '当前站点 <b>' + escapeHtml(location.hostname) + '</b> 命中 ' + reasons.length +
      ' 项风险特征（风险分 ' + (result.score || 0) + ' / 阈值 ' + (result.threshold || 0) + '）。<br>为防止木马植入，已自动禁用本页所有下载入口。';

    card.innerHTML =
      SHIELD_SVG +
      '<h2 class="sf-title">检测到银狐木马风险网站</h2>' +
      '<p class="sf-sub">' + subText + '</p>' +
      '<ul class="sf-reasons">' + reasonsHtml + '</ul>' +
      '<div class="sf-actions">' +
      // ★ 动作改用 data-sf-act 标识，由 window 捕获阶段的事件委托统一分发
      //   （不再逐个 querySelector('#id').addEventListener —— 那正是黑屏死按钮的根源）
      '<button class="sf-btn sf-btn-leave" id="sf-leave" data-sf-act="leave" type="button">离开此网站</button>' +
      '<button class="sf-btn sf-btn-continue" id="sf-continue" data-sf-act="continue" type="button">继续访问（仍拦截下载）</button>' +
      '</div>' +
      '<p class="sf-foot">银狐（游蛇）木马常通过仿冒官网投递带毒安装包，请勿轻易放行下载。<br>若已安装 IDM 等第三方下载器，请临时关闭其「浏览器接管」，以免其从链接直接抓取下载。</p>';

  }


  // 二次确认：用户点击「继续访问」后，再次确认是否进入被判定为银狐木马的风险站点
  function showContinueConfirm(card, result) {
    card.innerHTML =
      SHIELD_SVG +
      '<h2 class="sf-title">二次确认</h2>' +
      '<p class="sf-sub">你确定要访问 <b>' + escapeHtml(location.hostname) + '</b> 吗？<br>该站点已被判定为银狐木马风险网站。关闭警告后我们仍会拦截下载，但页面本身可能包含钓鱼表单或恶意脚本。</p>' +
      '<div class="sf-actions">' +
      '<button class="sf-btn sf-btn-leave" id="sf-cc-back" data-sf-act="cc-back" type="button">返回</button>' +
      '<button class="sf-btn sf-btn-continue" id="sf-cc-go" data-sf-act="cc-go" type="button">仍然继续</button>' +
      '</div>' +
      '<p class="sf-foot">强烈建议点击「离开此网站」返回安全页面。如确需访问，请务必不要在此页面输入任何账号密码或下载文件。</p>';

    // 切换视图时更新浮层根节点上的动作表（事件委托在根上，重绘后依然有效）
    const root = warningOverlay || card;
    sfBindUiActions(root, {
      leave: function () { leaveSite(); },
      'cc-back': function () { try { renderWarning(card, result); } catch (e) {} },
      'cc-go': function () {
        dangerAcknowledged = true; // 标记本页已确认继续，不再重复弹报毒浮层
        closeEl(root);
        showBanner(result);
      },
      __escape: function () { leaveSite(); }
    });
  }

  function showBanner(result) {
    if (NATIVE.byId('sf-banner')) return;
    let banner = null;
    try {
      banner = NATIVE.mk('div');
      if (!banner) return;
      banner.id = 'sf-banner';
      banner.className = 'sf-banner' + (currentFontMode === 'smiley' ? ' sf-font-smiley' : '');
      sfBindUiActions(banner, {
        release: function () { requestRelease(); },
        bclose: function () { closeEl(banner); },
        'release-confirm': function () { doRelease(); },
        'release-cancel': function () { try { renderBanner(banner, lastResult); } catch (e) {} }
      });
      NATIVE.put(document.body || document.documentElement, banner);
      renderBanner(banner, result);
    } catch (e) {
      try { if (banner) NATIVE.rm(banner); } catch (e2) {}
    }
  }

  function renderBanner(banner, result) {
    banner.innerHTML =
      '<div class="sf-btext">🛡 SilverFoxBlocker：已禁用本页 <b id="sf-bcount">' + blockedCount + '</b> 个下载/跳转入口</div>' +
      '<div class="sf-bbtns">' +
      '<button id="sf-release" data-sf-act="release" type="button">我已知晓风险，完全放行</button>' +
      '<button id="sf-bclose" data-sf-act="bclose" type="button">✕</button>' +
      '</div>';
  }

  function updateBannerCount() {
    const b = NATIVE.byId('sf-bcount');
    if (b) b.textContent = blockedCount;
  }

  function requestRelease() {
    const banner = NATIVE.byId('sf-banner');
    if (!banner) return;
    banner.innerHTML =
      '<div class="sf-btext">⚠️ 确认完全放行？放行后本页所有下载入口将不再受 SilverFoxBlocker 保护。</div>' +
      '<div class="sf-bbtns sf-confirm-row">' +
      '<button id="sf-release-confirm" data-sf-act="release-confirm" class="sf-btn-danger" type="button">确认放行</button>' +
      '<button id="sf-release-cancel" data-sf-act="release-cancel" type="button">再想想</button>' +
      '</div>';
  }

  function doRelease() {
    unblocked = true;
    dangerActive = false;
    navBlock = false;
    fullLockdown = false;
    dangerReported = false;
    try { const o = NATIVE.byId('sf-overlay'); if (o) closeEl(o); } catch (e) {}
    try { const b = NATIVE.byId('sf-banner'); if (b) closeEl(b); } catch (e) {}
    // ★ 2026-10-30：改用「已禁用元素账本」直接恢复，不再靠查询重新找一遍。
    //   旧实现用 document.querySelectorAll('[data-sf-blocked]')，一旦查询失效
    //   就会静默跳过恢复 → 页面停在"发白且点不动"的状态。
    restoreBlockedEntries();
    // 二次兜底：账本之外仍有残留（如跨重判遗留）时，再按属性查一遍补齐
    try {
      const rest = NATIVE.qsAll(document, '[data-sf-blocked]');
      if (rest && rest.length) {
        for (let i = 0; i < rest.length; i++) {
          const el = rest[i];
          try {
            el.style.pointerEvents = ''; el.style.opacity = ''; el.style.filter = '';
            if (el.dataset && el.dataset.sfOriginalHref) {
              try { el.setAttribute('href', el.dataset.sfOriginalHref); } catch (e) {}
              delete el.dataset.sfOriginalHref;
            }
            if (el.dataset) delete el.dataset.sfBlocked;
          } catch (e) {}
        }
      }
    } catch (e) {}
    try {
      if (chrome.runtime && chrome.runtime.sendMessage)
        chrome.runtime.sendMessage({ type: 'sf-release', hostname: location.hostname });
    } catch (e) {}
    showToast('⚠️ 已完全放行该站下载入口');
  }

  // ===== 云端官网库命中后：撤销此前的 danger 告警 =====
  //
  //  ★ 为什么需要它（2026-10-05）：
  //   showWarning() 是"只弹不收"的 —— 第 750 行 `if (NATIVE.byId('sf-overlay')) return;`
  //   一旦弹出就不会自动消失。而云端库查询是**异步**的（要发消息给后台），
  //   在它返回之前，页面可能已经因滚动/懒加载触发重判并弹了 danger 卡。
  //   ⇒ 一旦命中官方域名，那张写着「检测到银狐木马风险网站」的卡片必须撤掉，
  //      否则用户已经读到了误报文案，体验上等于没修。
  //
  //  ★ 与 doRelease() 的区别（别复用它）：
  //   doRelease 会设 `unblocked = true` —— 那是"用户主动永久放行"，
  //   语义是"这个站我信了"。这里是"判定结果被推翻"，
  //   必须让后续重判走正常逻辑，否则会把一次误报变成永久漏防。
  function revokeWarningIfShown(reason) {
    const ov = NATIVE.byId('sf-overlay');
    const bn = NATIVE.byId('sf-banner');
    const hint = NATIVE.byId('sf-hint');
    // 没有任何告警 UI 出现过 → 无需撤销
    if (!ov && !bn && !hint) return false;
    try { if (ov) closeEl(ov); } catch (e) {}
    try { if (bn) closeEl(bn); } catch (e) {}
    try { if (hint) closeEl(hint); } catch (e) {}
    // 复位拦截状态，让后续重判按新结论（safe）走
    dangerActive = false;
    navBlock = false;
    fullLockdown = false;
    dangerReported = false;
    dangerAcknowledged = false;
    // 恢复被灰化/禁用的下载入口（改走「已禁用元素账本」，与 doRelease 同一套机制）
    restoreBlockedEntries();
    try {
      const rest = NATIVE.qsAll(document, '[data-sf-blocked]');
      if (rest && rest.length) {
        for (let i = 0; i < rest.length; i++) {
          const el = rest[i];
          try {
            el.style.pointerEvents = ''; el.style.opacity = ''; el.style.filter = '';
            if (el.dataset && el.dataset.sfOriginalHref) {
              try { el.setAttribute('href', el.dataset.sfOriginalHref); } catch (e) {}
              delete el.dataset.sfOriginalHref;
            }
            if (el.dataset) delete el.dataset.sfBlocked;
          } catch (e) {}
        }
      }
    } catch (e) {}
    try { showToast('✅ ' + reason + '，已恢复该页'); } catch (e) {}
    return true;
  }

  function leaveSite() {
    try { const o = NATIVE.byId('sf-overlay'); if (o) closeEl(o); } catch (e) {}
    try {
      if (chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage({ type: 'sf-leave' });
      }
    } catch (e) {}
    try { if (history.length > 1) { history.back(); return; } } catch (e) {}
  }

  // ===== 温和提示（warn 层） =====
  function showWarnHint(result) {
    if (NATIVE.byId('sf-hint')) return;
    let hint = null;
    try {
      hint = NATIVE.mk('div');
      if (!hint) return;
      hint.id = 'sf-hint';
      hint.className = 'sf-hint' + (currentFontMode === 'smiley' ? ' sf-font-smiley' : '');
      sfBindUiActions(hint, { hclose: function () { closeEl(hint); } });
      NATIVE.put(document.body || document.documentElement, hint);
      hint.innerHTML =
        '🛡 SilverFoxBlocker 提示：当前站点 <b>' + escapeHtml(location.hostname) + '</b> 存在可疑特征（风险分 ' + (result && result.score || 0) + '），请谨慎点击任何下载链接。' +
        '<button id="sf-hclose" data-sf-act="hclose" type="button">知道了</button>';
    } catch (e) {
      try { if (hint) NATIVE.rm(hint); } catch (e2) {}
    }
  }

  // ===== 被拦下载的大弹窗（两个选项） =====
  function showDownloadBlocked(host, opts) {
    opts = opts || {};
    if (NATIVE.byId('sf-dl-blocked')) return;
    const html =
      '<div class="sf-card">' + SHIELD_SVG +
      '<h2 class="sf-title">下载已被拦截</h2>' +
      '<p class="sf-sub">SilverFoxBlocker 已阻止来自 <b>' + escapeHtml(host) + '</b> 的可疑下载文件。该站点被判定为银狐木马风险网站，下载可能植入木马。</p>' +
      '<div class="sf-actions">' +
      '<button class="sf-btn sf-btn-leave" id="sf-dl-keep" data-sf-act="dl-keep" type="button">保持拦截</button>' +
      '<button class="sf-btn sf-btn-continue" id="sf-dl-allow" data-sf-act="dl-allow" type="button">仍要下载</button>' +
      '</div>' +
      '<p class="sf-foot">仅当您明确信任该文件来源时才选择「仍要下载」。</p>' +
      '</div>';
    let overlayRef = null;
    const mounted = sfMountOverlay({
      id: 'sf-dl-blocked',
      className: 'sf-overlay' + (currentFontMode === 'smiley' ? ' sf-font-smiley' : ''),
      html: html,
      fallbackLabel: '保持拦截',
      actions: {
        'dl-keep': function () { closeEl(overlayRef); },
        'dl-allow': function () {
          closeEl(overlayRef);
          allowNextAction(700);
          if (opts.url) {
            const a = document.createElement('a');
            a.href = opts.url;
            a.download = '';
            a.target = '_blank';
            a.style.display = 'none';
            document.body.appendChild(a);
            a.click();
            setTimeout(() => a.remove(), 100);
          } else if (opts.target && opts.target.click) {
            opts.target.click();
          }
          try {
            if (chrome.runtime && chrome.runtime.sendMessage)
              chrome.runtime.sendMessage({ type: 'sf-allow-download', url: opts.url || '', hostname: host, fromPage: true });
          } catch (e) {}
        },
        __escape: function () { closeEl(overlayRef); }
      },
      onFail: function () {
        try { showToast('⚠️ 下载拦截弹窗异常，已自动移除遮罩'); } catch (e) {}
      }
    });
    if (!mounted || !mounted.overlay) return;
    overlayRef = mounted.overlay;
    sfFinishOverlay(mounted.fb);
  }


  // ===== 下载器扩展「绕过下载」拦截 → 询问放行 =====
  // 迅雷/IDM 等下载器扩展发起的高危下载被后台拦下后，弹此窗询问用户是否放行。
  // 「放行」复用 sf-allow-download 链路：加入会话放行名单并由后台重新触发下载。
  function showExtDlConfirm(host, opts) {
    opts = opts || {};
    if (NATIVE.byId('sf-dl-ext')) return;
    const fname = opts.filename ? '<b>' + escapeHtml(String(opts.filename).slice(0, 120)) + '</b>' : '一个可执行/压缩文件';
    const html =
      '<div class="sf-card">' + SHIELD_SVG +
      '<h2 class="sf-title">已拦截可疑下载（下载器扩展）</h2>' +
      '<p class="sf-sub">检测到已安装的下载器扩展（如迅雷 / IDM 等）试图绕过浏览器，直接抓取来自 <b>' + escapeHtml(String(host || '未知站点')) + '</b> 的 ' + fname + '。<br>此类"绕过浏览器"的下载不受浏览器安全机制约束，SilverFoxBlocker 已将其拦截。</p>' +
      '<div class="sf-actions">' +
      '<button class="sf-btn sf-btn-leave" id="sf-dl-ext-keep" data-sf-act="dl-ext-keep" type="button">保持拦截</button>' +
      '<button class="sf-btn sf-btn-continue" id="sf-dl-ext-allow" data-sf-act="dl-ext-allow" type="button">我信任此文件，放行</button>' +
      '</div>' +
      '<p class="sf-foot">仅当您明确信任该文件来源时才放行；放行后本次下载将重新发起。</p>' +
      '</div>';
    let overlayRef = null;
    const mounted = sfMountOverlay({
      id: 'sf-dl-ext',
      className: 'sf-overlay' + (currentFontMode === 'smiley' ? ' sf-font-smiley' : ''),
      html: html,
      fallbackLabel: '保持拦截',
      actions: {
        'dl-ext-keep': function () { closeEl(overlayRef); },
        'dl-ext-allow': function () {
          closeEl(overlayRef);
          try {
            if (chrome.runtime && chrome.runtime.sendMessage)
              chrome.runtime.sendMessage({ type: 'sf-allow-download', url: opts.url || '', hostname: host });
          } catch (e) {}
          showToast('已放行，正在重新下载该文件');
        },
        __escape: function () { closeEl(overlayRef); }
      },
      onFail: function () {
        try { showToast('⚠️ 下载拦截弹窗异常，已自动移除遮罩'); } catch (e) {}
      }
    });
    if (!mounted || !mounted.overlay) return;
    overlayRef = mounted.overlay;
    sfFinishOverlay(mounted.fb);
  }

  // ===== 危险弹窗提醒（Windows 系统通知，chrome.notifications）=====
  // 不再使用声音提示：浏览器自动播放策略在扩展上下文无法稳定解锁，且用户实测声音未生效。
  // 改为调用后台创建原生系统通知（Windows 右下角 toast），更可靠、无需用户手势。
  function sfNotify(result) {
    try {
      const host = (location && location.hostname) || '';
      const msg = {
        type: 'sf-notify',
        title: '⚠️ SilverFoxBlocker：发现高风险网站',
        message: '检测到 ' + host + ' 疑似银狐(游蛇)木马投递站，已弹出页面警告并禁用下载/跳转链接。'
      };
      if (chrome.runtime && chrome.runtime.sendMessage) chrome.runtime.sendMessage(msg);
    } catch (e) {}
  }

  // 上报「分析闸门」判定（每次分析必发，含 safe/warn/danger，供后台默认拒绝闸门解除）
  function reportVerdict(level) {
    try {
      if (chrome.runtime && chrome.runtime.sendMessage)
        chrome.runtime.sendMessage({ type: 'sf-verdict', hostname: location.hostname, level: level || 'safe' });
    } catch (e) {}
  }

  // ===== 上报 =====
  function reportDetection(result) {
    try {
      if (chrome.runtime && chrome.runtime.sendMessage)
        chrome.runtime.sendMessage({ type: 'sf-detected', hostname: location.hostname, data: result });
    } catch (e) {}
  }


  // ===== 主流程 =====
  function recomputeLevel(result, sensitivity) {
    const t = SF.thresholds ? SF.thresholds(sensitivity) : { warn: 35, danger: 70 };
    if (result.score >= t.danger) result.level = 'danger';
    else if (result.score >= t.warn) result.level = 'warn';
    else result.level = 'safe';
    result.detected = result.level === 'danger';
    result.threshold = t.danger;
    return result;
  }

  function analyzeAndAct(settings, chained, data) {
    if (!settings.enabledGlobal) { lastResult = { analyzed: true, disabled: true }; reportVerdict('safe'); return; }
    // ★ 可信分发域名（网盘 / GitHub 官方及镜像）：直接判安全、跳过分析。
    //   否则网盘站点（含大量「下载」入口与网盘链接）会被评分引擎判 danger → 进入即弹「危险网站」警告
    //   并 disable 全部下载按钮（变灰不可点），属严重误伤。与后台 .msi/.zip 豁免同源。
    if (isAllowlisted(location.hostname, settings.allowlist) || isTrustedDispatch(location.hostname)) {
      lastResult = { analyzed: true, allowlisted: true };
      reportVerdict('safe');
      return;
    }

    data.metrics = collectMetrics();
    data.icp = extractIcp();
    let result = SF.analyze(data, { enabled: settings.enabled, sensitivity: settings.sensitivity, weights: settings.weights });

    // 自定义规则叠加
    const htmlLower = (data.html || '').toLowerCase();
    if (settings.customKeywords && settings.customKeywords.length) {
      const found = settings.customKeywords.filter((k) => htmlLower.indexOf(String(k).toLowerCase()) !== -1);
      if (found.length) {
        result.reasons.push({ label: '命中自定义风险关键词', detail: found.join('、'), weight: 10 });
        result.score += 10;
      }
    }
    if (settings.customBadDomains && settings.customBadDomains.length) {
      const h = location.hostname.toLowerCase();
      if (settings.customBadDomains.some((d) => { d = String(d).trim().toLowerCase(); return d && (h === d || h.endsWith('.' + d)); })) {
        result.reasons.push({ label: '域名命中自定义黑名单', detail: location.hostname, weight: 100 });
        result.score += 100;
      }
    }
    recomputeLevel(result, settings.sensitivity);

    // 跳转链污染升级：本标签由危险站跳转而来，且本页有下载入口/网盘/低质量等信号，升级为 danger 强制拦截
    if (chained && result.level !== 'danger') {
      const hasDownloadSignal = result.features.execDownload || result.features.cloudDiskDist || result.features.fakeOfficial || result.features.domainImpersonation;
      if (hasDownloadSignal || result.score >= 30) {
        result.level = 'danger';
        result.detected = true;
        result.chained = true;
        result.reasons.push({ label: '跳转链污染升级', detail: '该页面由已被拦截的银狐站跳转而来，且包含下载入口，强制启用拦截', weight: 60 });
        result.score += 60;
      }
    }

    // ===== 评分 / 等级稳定性护栏（2026-10-27）=====
    // 异步补强（ICP 核验 / .txt 下挖 / BFS 从脚本里挖下载入口）会给 data.links 追加条目后
    // 重判。这类「同类证据变多」曾让同一页面从 71 分跳到 81 分并突然拦截。
    // 具体判据（只认新强特征或分值跃升 ≥12）见 analyzer.stabilizeVerdict。
    result = SF.stabilizeVerdict(lastResult, result);

    lastResult = Object.assign({ analyzed: true, hostname: location.hostname, blockedCount: 0 }, result);

    if (result.level === 'danger') {
      dangerActive = true;
      // 高置信木马信号（NAV_BLOCK_FEATURES 之一）命中，或跳转链污染升级 → 除禁用下载入口外，
      // 还要拦截本页一切程序化导航（location 跳转 / 锚点 .click / window.open），
      // 堵死「同源带参跳转」「运行时中继取链」这类内容脚本看不到响应体的二进制下载手法。
      // 普通 medium 组合误判的 danger 页不拦导航，避免良性页被误伤。
      navBlock = NAV_BLOCK_FEATURES.some((f) => result.features && result.features[f]) || !!result.chained;
      // 高置信信号命中即进入「全面锁定」：仿冒站 / NOAH / 运行时取链投递 / 自跳转下载页等页面，
      // 所有交互型 CTA 入口（含伪装成「开始对话」「API 开放平台」的按钮）一律灰化 + 拦截点击
      fullLockdown = navBlock;
      installHardGuards();
      if (settings.autoBlockDownloads) blockAllDownloadEntries();
      updateBannerCount();
      if (settings.showWarning) showWarning(result);
      // 同一页面仅上报一次「报毒」，避免初始分析 + 异步补强 + 二次扫描重复弹出系统通知
      if (!dangerReported) {
        if (settings.notify) sfNotify(result);
        reportDetection(result);
        dangerReported = true;
      }
    } else if (result.level === 'warn') {
      dangerActive = false;
      navBlock = false;
      fullLockdown = false;
      dangerReported = false;
      // ★ warn 只做页面内温和提示，不计入「拦截」：不上报后台统计、不写拦截记录。
      //   后台仅 danger 才计入「拦截风险网站」并写入「近期拦截记录」（见 background.updateStats）。
      if (settings.showWarning) showWarnHint(result);
      // 本页完全无辜（真官网/有备案/无下载），清除跳转链污染
      if (chained) {
        try { chrome.runtime.sendMessage({ type: 'sf-clear-chain' }); } catch (e) {}
      }
    } else {
      dangerActive = false;
      navBlock = false;
      fullLockdown = false;
      dangerReported = false;
      if (chained) {
        try { chrome.runtime.sendMessage({ type: 'sf-clear-chain' }); } catch (e) {}
      }
    }
    reportVerdict(result.level);
  }

  async function run() {
    // 注入得意黑 @font-face（供网页内横幅使用；字体文件经 manifest web_accessible_resources 对 <all_urls> 开放）
    if (!fontFaceInjected) {
      fontFaceInjected = true;
      try {
        const url = chrome.runtime.getURL('fonts/SmileySans-Oblique.woff2');
        const st = document.createElement('style');
        st.textContent = "@font-face{font-family:'SmileySans';src:url('" + url + "') format('woff2');font-display:swap;}";
        (document.head || document.documentElement).appendChild(st);
      } catch (e) {}
    }
    // 仅对普通 http(s) 网页做检测。
    // 本地文件(file://)、浏览器内部页(chrome://、edge://…)、本地开发服务器(localhost/127.0.0.1)
    // 一律跳过——它们没有 ICP 备案且可能是中文页面，会被误判成风险站。
    const proto = (location.protocol || '').toLowerCase();
    if (proto !== 'http:' && proto !== 'https:') return;
    const _host = (location.hostname || '').toLowerCase();
    if (_host === 'localhost' || _host === '127.0.0.1' || _host === '[::1]') return;

    const settings = await getSettings();
    currentFontMode = settings.fontMode || 'system';
    currentScale = (typeof settings.fontScale === 'number') ? settings.fontScale : 1;
    // 得意黑内置 110% 基准系数（用户实测最佳）；跟随系统仍按滑块原值。
    // 把最终系数注入第三方页面根元素，供网页内横幅的 calc(var(--sf-scale)) 继承。
    if (currentFontMode === 'smiley') currentScale *= 1.10;
    try { document.documentElement.style.setProperty('--sf-scale', currentScale.toFixed(3)); } catch (e) {}
    // 跳转链污染状态（本页是否由已判危站跳转而来）
    let chained = false;
    try { const r = await sendMsg({ type: 'sf-check-chain' }); chained = !!(r && r.tainted); } catch (e) {}

    // ★ 单次权威判定流程（2026-10-28 重构，根治「两次检测 / 评分跳变 / 重复记录」）：
    //   ① 等页面加载到 complete（最多 5s 兜底）——页脚备案号渲染完整后再判定；
    //   ② await 关键补强（云端官网库 / ICP 核验 / 域名年龄 / 下载黑名单）——
    //      这些会改判定（尤其 ICP 决定「是否扣缺备案号 18 分」），必须在判定前拿到；
    //   ③ 只做一次 analyzeAndAct；
    //   ④ 深度补强（.txt / BFS 下挖）若补到新下载入口才再重判一次，后台按 tabId 去重不会重复计数。
    //   注：下载拦截由后台「分析闸门」默认拒绝兜底（检测未出前先挂起下载），
    //       故延后到 5s 判定不会削弱 meta refresh 秒跳下载的防护。
    // ★ 默认拒绝闸门的内容侧兜底：任何异常都按安全放行，绝不因内容脚本报错把用户下载卡死。
    try {
      const data = collectCore();
      await waitPageSettled(5000);
      await collectCriticalEnrichments(settings, data);
      analyzeAndAct(settings, chained, data);   // 单次权威判定
      enrichDeepAsync(settings, chained, data);  // 后台深度补强（可能再重判一次，已去重）
    } catch (e) {
      reportVerdict('safe');
    }
  }

  // ===== 硬拦截钩子（document_start 即安装，抢在站点脚本之前） =====
  function installHardGuards() {
    if (hardGuardsInstalled) return;
    hardGuardsInstalled = true;

    // 1) window.open（站点脚本之前覆盖）
    try {
      const _open = window.open;
      window.open = function (url) {
        if (!dangerNavBlocked(url)) return _open.apply(window, arguments);
        return null;
      };
    } catch (e) {}

    // 2) HTMLAnchorElement.prototype.click
    try {
      const proto = window.HTMLAnchorElement && window.HTMLAnchorElement.prototype;
      if (proto && proto.click && !proto._sfClick) {
        const _click = proto.click;
        proto._sfClick = _click;
        proto.click = function () {
          const a = this;
          if (unblocked || isNextAllowed()) return _click.call(a);
          const href = a.getAttribute('href') || a.href || '';
          // 仅拦截真实导航（排除 javascript:/#/mailto:/tel:/about: 等非导航）
          const navHref = (href && !/^(javascript:|#|mailto:|tel:|about:)/i.test(href)) ? href : null;
          // 高置信信号(navBlock) 或 明确下载 URL → 拦截，堵死运行时中继取链 / 直接甩文件
          if (navHref && (navBlock || isDownloadUrl(navHref))) {
            if (!NATIVE.byId('sf-overlay')) showDownloadBlocked(location.hostname, { url: navHref });
            return;
          }
          return _click.call(a);
        };
      }
    } catch (e) {}

    // 3) location.href / replace / assign 守卫
    installLocationGuard();

    // 4) 全局点击捕获（拦截 div/button/img 等下载卡片）
    if (!document._sfClickGuard) {
      document._sfClickGuard = true;
      document.addEventListener('click', globalClickGuard, true);
    // 早期拦截：IDM 等第三方下载器常在 mousedown 阶段就把链接 URL 抢走（早于 click），
    // 故在 mousedown / pointerdown 捕获阶段即拦截，阻断其接管下载。
    document.addEventListener('mousedown', globalClickGuard, true);
    document.addEventListener('pointerdown', globalClickGuard, true);
    }
  }

  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg && msg.type === 'sf-getStatus') { sendResponse(lastResult); return true; }
    if (msg && msg.type === 'sf-download-blocked') { showDownloadBlocked(location.hostname, { url: msg.url || '' }); }
    if (msg && msg.type === 'sf-dl-ext-blocked') { showExtDlConfirm(location.hostname, { url: msg.url || '', filename: msg.filename || '' }); }
    if (msg && msg.type === 'sf-download-allow-failed') { showToast('⚠️ 请手动在站内点击下载，已临时放行该链接'); }
  });

  // 启动：document_start 时先装硬钩子（此时 body 可能未就绪，run 等 DOM）
  installHardGuards();
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', run);
  else run();

  // 兜底：极少数「DOMContentLoaded 已错过 + run 未被调用」的场景下补触发一次。
  // 用 didRun 守卫，run() 内部也自带 didRun 防重入，故绝不会触发第二次分析。
  setTimeout(() => { if (!didRun) run(); }, 2000);
})();
