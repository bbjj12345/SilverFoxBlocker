/*
 * content.js — SilverFoxBlocker 内容脚本
 * 职责：1) 采集页面代码 + 工程化指标 + ICP 备案
 *       2) 调用评分引擎（含官方早期退出）
 *       3) 分层响应：safe 不动作 / warn 温和提示不拦 / danger 警告浮层 + 禁用全部下载入口
 *       4) 用户可「离开 / 继续访问(仍拦截下载) / 完全放行」
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
    fontScale: 1,         // 0.85 ~ 1.40，界面字号缩放系数
    // 威胁情报 API（可选）：默认关闭；启用后扩展实时查询当前域名在第三方情报库的判定。
    // VirusTotal 需用户自有 Key；URLhaus / NetAPI 无需 Key（免费公开接口）。
    threatIntel: {
      enabled: false,
      providers: { virustotal: { enabled: false, apiKey: '' }, urlhaus: { enabled: false }, netapi: { enabled: false },       googlesafebrowsing: { enabled: false, apiKey: '' } }
    },
    // 社区维护的本地黑名单总开关（默认关）：关着时三个名单一律不查询、不渲染横幅
    communityLists: { enabled: false },
    // OpenPhish 本地钓鱼黑名单：启用后与本地静态域名名单比对，命中即渲染横幅
    openphish: { enabled: false, lastUpdated: 0 },
    // PhishDestroy 本地钓鱼黑名单：同上的第二个静态名单源（独立横幅、独立开关）
    phishdestroy: { enabled: false, lastUpdated: 0 },
    // HaGeZi's Threat Intelligence Feeds：第三个静态名单源（约 181 万条，独立横幅、独立开关）
    hagezi: { enabled: false, lastUpdated: 0, variant: 'full' }
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
  let revoked = false;            // 云端官网库命中 → 已撤销 danger 判定（本页不再拦截，且不被 establishedDanger 重新拉起）
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

  // ===== 云端名单（storage.local）注入 =====
  // 名单来源：设置页「关于 → 从云端更新黑/白名单」，由 worker 的 /list 接口下发。
  // 为什么不放 storage.sync：sync 单键上限 8192 bytes ≈ 550 个域名，上千条必然静默写失败；
  //   storage.local 有 unlimitedStorage 权限，实际无上限。
  // 为什么在内容脚本注入：analyzer 的名单集合是「每个 JS 上下文各一份」，
  //   后台注入只影响后台，页面判定用的是内容脚本自己这份 —— 两边都得注入。
  // 时机：必须在第一次 analyze 之前完成，所以挂在 getSettings 上（所有分析流程都先取设置）。
  let _cloudListsPromise = null;
  function ensureCloudLists() {
    if (_cloudListsPromise) return _cloudListsPromise;
    _cloudListsPromise = new Promise((resolve) => {
      const done = () => resolve();
      try {
        chrome.storage.local.get({ sfCloudWhite: [], sfCloudBlack: [] }, (o) => {
          try {
            const w = (o && Array.isArray(o.sfCloudWhite)) ? o.sfCloudWhite : [];
            const b = (o && Array.isArray(o.sfCloudBlack)) ? o.sfCloudBlack : [];
            // 覆盖语义：storage 是云端镜像，注入前先清空，云端删掉的条目不能残留。
            // 空数组也照常注入（等价于清空），不再用 length 做前置判断。
            if (SF.registerCloudOfficial) SF.registerCloudOfficial(w, { replace: true });
            if (SF.registerCloudBad) SF.registerCloudBad(b, { replace: true });
          } catch (e) {}
          done();
        });
      } catch (e) { done(); }
    });
    return _cloudListsPromise;
  }

  function getSettings() {
    return new Promise((resolve) => {
      try {
        chrome.storage.sync.get(DEFAULTS, (s) => {
          const merged = Object.assign({}, DEFAULTS, s || {});
          // 先保证云端名单已注入，再交回设置：否则首屏分析会以「未注入」的名单判定，
          // 出现「刚同步的域名第一次打开仍被判危、刷新后才正常」的怪现象。
          ensureCloudLists().then(() => resolve(merged), () => resolve(merged));
        });
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
    'lanzou.com', 'lanzous.com', 'lanzoux.com', 'lanzoui.com', // 蓝奏云（lanzoui.com 官网，避免被误判为投递站而拦截下载）
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
    toastEl.style.setProperty('color', '#ffd9d9', 'important');
    toastEl.style.display = 'block';
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { if (toastEl) toastEl.style.display = 'none'; }, 2600);
  }

  // ★ 强制扩展 UI 文本为白色（行内 !important，不被任何页面级 CSS 压过）。
  //   仅当 content.css 的 !important 仍被极端页面覆盖（如祖先 filter invert、内联样式）时兜底。
  function forceWhiteText(root, keepTitleGradient) {
    if (!root) return;
    try {
      const items = root.querySelectorAll('*');
      for (let i = 0; i < items.length; i++) {
        const el = items[i];
        if (el.nodeType !== 1) continue;
        if (keepTitleGradient && el.classList && el.classList.contains('sf-title')) {
          el.style.setProperty('-webkit-text-fill-color', 'transparent', 'important');
          continue;
        }
        el.style.setProperty('color', '#fff', 'important');
        el.style.setProperty('-webkit-text-fill-color', '#fff', 'important');
      }
      root.style.setProperty('color', '#fff', 'important');
    } catch (e) {}
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
    // 原作者的「云端官网库」查询步骤已于 2026-11-01 移除。
    // 移除原因：源由第三方控制且无签名校验，命中即撤销告警，存在漏放风险。
    // 原文备份：.bak_20261101010207_remove-cloud/content.js
    // 日后若改用自有名单，在此恢复查询步骤，并配合 background.js 的「我的云端库」模板启用。
    // 1) ICP 权威核验（三态：确有备案 / 确认无备案 / 查询失败）。失败时后台返回 {queried:false}，引擎回退页面文本扫描。
    if (needIcpVerify(settings, data)) {
      try {
        const ra = await sendMsg({ type: 'sf-icp-verify', hostname: location.hostname });
        if (ra && ra.queried) data.icpAuth = ra;
      } catch (e) {}
    }
    // 2) 下载黑名单（纯本地读）：只有本页确实存在指向黑名单域名的链接时才注入（供评分加分 + 页面级拦截提示）。
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

  // 从下载入口元素提取「将要下载的文件 URL」，供「仍要下载」时登记进后台放行名单。
  // 入口可能是 <a href>、<img src>、带 data-url/data-href/data-download 的按钮，或是
  // 包着 <a> 的容器 div。相对路径按当前页 location 解析为绝对 URL；只认 http(s)/data:/blob:，
  // 提取不到（如纯 JS 触发下载）返回 ''，由后台退化为「临时放行本标签」兜底。
  function getEntryDownloadUrl(el) {
    if (!el || !el.getAttribute) return '';
    function resolve(raw) {
      if (!raw) return '';
      raw = String(raw).trim();
      if (!raw || /^(javascript:|#|mailto:|tel:)/i.test(raw)) return '';
      let abs = null;
      try { abs = new URL(raw, location.href).href; } catch (e) { abs = null; }
      if (abs && /^https?:|^data:|^blob:/i.test(abs)) return abs;
      return '';
    }
    const attrs = ['href', 'src', 'data-href', 'data-url', 'data-download', 'data-link', 'data-src'];
    for (let i = 0; i < attrs.length; i++) {
      const v = resolve(el.getAttribute(attrs[i]));
      if (v) return v;
    }
    // 入口为容器（如带「下载」文字的 div）时，真实 URL 常在子元素 <a> 上
    try {
      if (el.querySelector) {
        const a = el.querySelector('a[href]');
        const v = a && resolve(a.getAttribute('href'));
        if (v) return v;
      }
    } catch (e) {}
    return '';
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
    // ★ 激进兜底：物理层面让元素彻底失去触发能力，堵死任何绕过点击拦截的下载手法
    //   （如 onclick / addEventListener / 程序化 .click() / 事件委托）。
    try { if (el.tagName === 'BUTTON') el.disabled = true; } catch (e) {}
    try { if (el.onclick) el.onclick = null; if (el.removeAttribute) el.removeAttribute('onclick'); } catch (e) {}
    try { if (el.click && typeof el.click === 'function') { el._sfClick = el.click; el.click = function () { return false; }; } } catch (e) {}
    el.addEventListener('click', blockHandler, true);
    el.addEventListener('contextmenu', blockHandler, true);
    // 注意：不再设置 pointer-events:none。一旦置 none，点击会「穿透」到父节点（事件委托），
    // 父节点并非下载入口 → 全局守卫放行 → CDN 下载照常触发（即「变暗却仍可点击」的根因）。
    // 改为保留元素可点击，由 blockHandler（捕获阶段）与 globalClickGuard 拦截点击，
    // 视觉上仍用 opacity / grayscale 表达「已禁用」。
    el.style.opacity = '0.5';
    el.style.filter = 'grayscale(0.85)';
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
          // 高置信信号(navBlock) 或 明确下载 URL 或 已被禁用(带 data-sf-blocked) 或 命中下载入口 → 拦截，
          // 堵死运行时中继取链 / 直接甩文件 / fetch→blob→a.click() 等手法
          if (navHref && (navBlock || isDownloadUrl(navHref) || (a.dataset && a.dataset.sfBlocked) || isDownloadEntry(a))) {
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
    if (!entry) {
      // 兜底：点击落点或其祖先若曾被 neutralize（带 data-sf-blocked），同样视为下载入口拦截。
      // 即便某些元素仍带 pointer-events:none 导致点击穿透到父节点，也能在此兜住。
      let p = target;
      while (p && p !== document.documentElement) {
        if (p.dataset && p.dataset.sfBlocked) { entry = p; break; }
        p = p.parentElement;
      }
    }
    if (!entry) return;
    e.preventDefault();
    e.stopPropagation();
    e.stopImmediatePropagation();
    showDownloadBlocked(location.hostname, { target: entry, url: getEntryDownloadUrl(entry) });
    return false;
  }

  // ===== 警告浮层 =====
  const SHIELD_SVG = '<svg class="sf-icon" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">' +
    '<path d="M12 2 4 5v6c0 5 3.4 8.5 8 11 4.6-2.5 8-6 8-11V5l-8-3Z" fill="rgba(255,90,90,.16)" stroke="#ff7a7a" stroke-width="1.4"/>' +
    '<path d="M12 8v5" stroke="#ffd36e" stroke-width="1.8" stroke-linecap="round"/>' +
    '<circle cx="12" cy="16.4" r="1.25" fill="#ffd36e"/></svg>';

  // 主拦截浮层当前所在的根节点（供二次确认等子视图更新动作表）
  let warningOverlay = null;

  // 黑名单条目归一化：允许用户粘贴带协议/路径的地址
  function normBlackDomain(d) {
    return String(d || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  }
  // 当前站点是否已命中你的恶意域名黑名单（含父域匹配）
  function isHostBlacklisted(host, list) {
    const h = String(host || '').toLowerCase().replace(/^www\./, '');
    if (!h) return false;
    return (Array.isArray(list) ? list : []).some(function (d) {
      d = normBlackDomain(d);
      return d && (h === d || h.endsWith('.' + d));
    });
  }
  // 已拉黑时把按钮直接置为「已完成」态，避免用户重复点击
  function syncBlacklistButton(card) {
    if (!card) return;
    try {
      chrome.storage.sync.get({ customBadDomains: [] }, function (s) {
        if (!isHostBlacklisted(location.hostname, s && s.customBadDomains)) return;
        let btn = null;
        try { btn = card.querySelector('.sf-btn-blocklist') || document.getElementById('sf-blocklist'); } catch (e) {}
        if (!btn) return;
        try {
          btn.textContent = '✓ 已在你的恶意域名黑名单';
          btn.disabled = true;
          btn.classList.add('sf-btn-done');
        } catch (e) {}
      });
    } catch (e) {}
  }

  // ★ 用户主动「添加到你的恶意域名黑名单」：写入 customBadDomains（chrome.storage.sync，跨站点永久生效）。
  //   设计变更（2026-11-03）：判危本身**不再自动拉黑**（原逻辑会把 84 分的页面自动记入
  //   sfBlockedHosts，导致二次访问被连坐判 100 分，误报无法复查）。现在只有用户点这个按钮才拉黑。
  function addHostToGlobalBlacklist(btn) {
    const host = String(location.hostname || '').toLowerCase().replace(/^www\./, '');
    if (!host) return;
    const markDone = function (ok, msg) {
      if (!btn) return;
      try {
        if (ok) {
          btn.textContent = '✓ 已加入你的恶意域名黑名单';
          btn.disabled = true;
          btn.classList.add('sf-btn-done');
        } else {
          btn.textContent = '加入失败，请重试';
        }
      } catch (e) {}
      if (msg) { try { showToast(msg); } catch (e) {} }
    };
    try {
      chrome.storage.sync.get({ customBadDomains: [] }, function (s) {
        try {
          let arr = Array.isArray(s && s.customBadDomains) ? s.customBadDomains.slice() : [];
          if (!isHostBlacklisted(host, arr)) arr.push(host);
          chrome.storage.sync.set({ customBadDomains: arr }, function () {
            const err = chrome.runtime && chrome.runtime.lastError;
            if (err) { markDone(false, '加入你的恶意域名黑名单失败：' + err.message); return; }
            markDone(true, '已加入你的恶意域名黑名单：' + host);
          });
        } catch (e) { markDone(false, '加入你的恶意域名黑名单失败'); }
      });
    } catch (e) { markDone(false, '加入你的恶意域名黑名单失败'); }
  }

  function showWarning(result) {
    // 用户已确认「仍然继续」→ 本页不再重复弹 danger 浮层（下载拦截仍生效）。
    if (dangerAcknowledged) return;
    // ★ 2026-11-04 修复「浮层评分与下拉菜单不一致」：
    //   原实现只要浮层已存在就 return（防重复弹窗），于是异步补强/SPA 重判产生的新分数
    //   从不回写到卡片 —— 卡片冻结在首次渲染的分数，而 lastResult 已被更新，下拉菜单读到新值。
    //   现改为「原地重绘」：复用同一浮层，仅重写卡片内容（不重播动画、不新增节点），
    //   并避开「二次确认」视图（那里没有 #sf-blocklist，用户正在做选择，不能被抢画）。
    const _existing = NATIVE.byId('sf-overlay');
    if (_existing) {
      try {
        const _card = _existing.querySelector('.sf-card');
        if (_card && _card.querySelector('#sf-blocklist')) {
          renderWarning(_card, result);
          forceWhiteText(_card, true);
        }
      } catch (e) {}
      return;
    }
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
        // ★ 用户主动拉黑：判危不再自动写入你的恶意域名黑名单，避免误报无法复查；只有点这个按钮才永久拉黑
        'add-blacklist': function (e, el) { addHostToGlobalBlacklist(el); },
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
      forceWhiteText(card, true);
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
      '<div class="sf-actions sf-actions-stack">' +
      '<button class="sf-btn sf-btn-blocklist" id="sf-blocklist" data-sf-act="add-blacklist" type="button">添加到你的恶意域名黑名单</button>' +
      '</div>' +
      '<div class="sf-actions">' +
      // ★ 动作改用 data-sf-act 标识，由 window 捕获阶段的事件委托统一分发
      //   （不再逐个 querySelector('#id').addEventListener —— 那正是黑屏死按钮的根源）
      '<button class="sf-btn sf-btn-leave" id="sf-leave" data-sf-act="leave" type="button">离开此网站</button>' +
      '<button class="sf-btn sf-btn-continue" id="sf-continue" data-sf-act="continue" type="button">继续访问（仍拦截下载）</button>' +
      '</div>' +
      '<p class="sf-foot">银狐（游蛇）木马常通过仿冒官网投递带毒安装包，请勿轻易放行下载。<br>若已安装 IDM 等第三方下载器，请临时关闭其「浏览器接管」，以免其从链接直接抓取下载。</p>';

    // 若该域名已在你的恶意域名黑名单中，按钮直接显示「✓ 已在你的恶意域名黑名单」并禁用
    syncBlacklistButton(card);
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
      // 从二次确认返回主卡后，「添加到你的恶意域名黑名单」按钮仍需可用
      'add-blacklist': function (e, el) { addHostToGlobalBlacklist(el); },
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
      forceWhiteText(banner, false);
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
    revoked = true;
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
      forceWhiteText(hint, false);
    } catch (e) {
      try { if (hint) NATIVE.rm(hint); } catch (e2) {}
    }
  }

  // ===== 下载拦截的「计数 + 自学习」补偿 =====
  // 内容脚本在页面级（点击/入口/表单）拦截下载时，后台并未走 chrome.downloads 取消流程，
  // 故 cancelDownload 里的「拦截下载次数 +1 / 写入自动学习黑名单」不会执行——导致计数恒为 0、黑名单恒空。
  // 这里在拦截发生时主动通知后台补计（与 cancelDownload 同源逻辑），覆盖后台取消流程到不了的路径。
  function extractBlockUrl(opts) {
    if (opts && typeof opts.url === 'string' && opts.url) return opts.url;
    const el = opts && opts.target;
    if (el && el.getAttribute) {
      const u = el.getAttribute('href') || el.getAttribute('src') ||
                el.getAttribute('data-href') || el.getAttribute('data-url');
      if (u) return u;
    }
    return '';
  }
  function recordBlockedDownload(host, url) {
    try {
      if (chrome.runtime && chrome.runtime.sendMessage)
        chrome.runtime.sendMessage({ type: 'sf-record-blocked-download', host: host, url: url || '' });
    } catch (e) {}
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
          // 拿到真实下载 URL（优先 opts.url，其次从入口元素提取），登记进后台放行名单。
          const url = (opts.url || getEntryDownloadUrl(opts.target) || '').trim();
          // 触发本页实际下载：优先点击原始入口（保留站内 JS 行为 / 鉴权上下文），否则用 <a> 兜底。
          const trigger = function () {
            if (opts.target && opts.target.click) { try { opts.target.click(); return; } catch (e) {} }
            if (url) {
              const a = document.createElement('a');
              a.href = url; a.download = ''; a.target = '_blank'; a.style.display = 'none';
              document.body.appendChild(a); a.click();
              setTimeout(function () { try { a.remove(); } catch (e) {} }, 100);
            }
          };
          if (chrome.runtime && chrome.runtime.sendMessage) {
            try {
              // 等后台回执（已把 URL 写入放行名单）后再触发下载，规避「消息未达、onCreated 先取消」的竞态，
              // 否则会出现点了「仍要下载」仍被静默拦截。无法提取 URL 时后台会临时放行本标签兜底。
              chrome.runtime.sendMessage(
                { type: 'sf-allow-download', url: url, hostname: host, fromPage: true },
                function () { try { void chrome.runtime.lastError; } catch (e) {} trigger(); }
              );
              return;
            } catch (e) {}
          }
          trigger();
        },
        __escape: function () { closeEl(overlayRef); }
      },
      onFail: function () {
        try { showToast('⚠️ 下载拦截弹窗异常，已自动移除遮罩'); } catch (e) {}
      }
    });
    if (!mounted || !mounted.overlay) return;
    overlayRef = mounted.overlay;
    // 页面级拦截即构成一次「下载被拦截」事件：后台未走 chrome.downloads 取消流程，
    // 故在此主动补计「拦截下载次数」并把载荷域名写入自动学习的下载黑名单。
    // 后台 sf-download-blocked 消息路径（fromBackground）已由 cancelDownload 计过数，跳过避免重复。
    if (!opts.fromBackground) recordBlockedDownload(host, extractBlockUrl(opts));
    forceWhiteText(overlayRef, true);
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
    forceWhiteText(overlayRef, true);
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

  // ===== 域名级联动（祖/父/子/孙 递归连坐）=====
  // 任一被拦截域名的子孙（子域/子页）一律连坐拦截，但只有「最先被拦截的那一级」记入统计，
  // 其下级仅拦截不记录，避免同域反复刷屏。完整域名链示例：
  //   祖(com) / 父(wlygrowth.com) / 子(es.wlygrowth.com) / 孙(x.es.wlygrowth.com)
  // 若「子」被判危 → 记录「子」完整域名；「孙」因父域名被标记而连坐拦截，但不记录。
  let _blockedHosts = null;   // 已被判危 host 集合（chrome.storage.local.sfBlockedHosts 持久化）
  // ★ 一次性清理名单（2026-11-04）：历史上「评高分即自动拉黑」误写入连坐集合的域名，需从本地黑名单移除。
  //   只删除这里列出的域名（含其子域），其余条目保留，连坐逻辑不变。
  const _PURGED_BLOCKED_HOSTS = ['malware-filter.gitlab.io'];
  function _isPurgedBlockedHost(h) {
    h = String(h || '').toLowerCase().replace(/^www\./, '');
    if (!h) return false;
    return _PURGED_BLOCKED_HOSTS.some((p) => h === p || h.endsWith('.' + p));
  }
  function _ensureBlockedHostsLoaded() {
    if (_blockedHosts) return Promise.resolve(_blockedHosts);
    return new Promise((resolve) => {
      try {
        chrome.storage.local.get({ sfBlockedHosts: [], sfBlockedHostsCleared: false }, (o) => {
          // ★ 一次性迁移（2026-11-03）：旧版本「判危即自动记入」产生的连坐集合不可信
          //   （用户从未主动拉黑），会让二次访问被抬到 100 分、误报无法复查 —— 升级后清空一次。
          if (!o || !o.sfBlockedHostsCleared) {
            try { chrome.storage.local.set({ sfBlockedHosts: [], sfBlockedHostsCleared: true }); } catch (e) {}
            _blockedHosts = new Map();
            resolve(_blockedHosts);
            return;
          }
          // 兼容两种存储格式：旧版纯 host 字符串数组（一律视为 danger）、
          // 新版 "host|level"（danger / warn）数组。
          const m = new Map();
          let purged = 0;
          (Array.isArray(o.sfBlockedHosts) ? o.sfBlockedHosts : []).forEach((s) => {
            if (typeof s !== 'string') return;
            const i = s.lastIndexOf('|');
            const hostKey = (i === -1 ? s : s.slice(0, i)).toLowerCase();
            // ★ 移出「自动拉黑」误伤名单（含其子域），并持久化，避免下次再被连坐判 100 分
            if (_isPurgedBlockedHost(hostKey)) { purged++; return; }
            if (i === -1) m.set(hostKey, 'danger');
            else m.set(hostKey, s.slice(i + 1) === 'warn' ? 'warn' : 'danger');
          });
          if (purged) {
            const arr = Array.from(m.entries()).map(([k, v]) => k + '|' + v);
            try { chrome.storage.local.set({ sfBlockedHosts: arr }); } catch (e) {}
          }
          _blockedHosts = m;
          resolve(_blockedHosts);
        });
      } catch (e) { _blockedHosts = new Map(); resolve(_blockedHosts); }
    });
  }
  // 当前 host 的所有层级后缀（自身 → 父 → 祖…直至注册域），用于递归连坐判定
  function _hostAncestors(host) {
    const h = (host || '').toLowerCase().replace(/^www\./, '');
    const out = [h];
    let idx = h.indexOf('.');
    while (idx !== -1) {
      out.push(h.slice(idx + 1));
      idx = h.indexOf('.', idx + 1);
    }
    return out;
  }
  function _sevOf(lv) { return lv === 'danger' ? 2 : 1; }
  // 当前 host 是否因「自身/祖先域名此前已被判危/可疑」而需连坐（仍判相应等级但不记录）。
  // 返回 'danger' | 'warn' | null（null 表示无需连坐）；危险优先于可疑。
  function _inheritedLevel(host) {
    if (!_blockedHosts) return null;
    let best = null, bestSev = 0;
    for (const a of _hostAncestors(host)) {
      const lv = _blockedHosts.get(a);
      if (!lv) continue;
      const s = _sevOf(lv);
      if (s > bestSev) { bestSev = s; best = lv; }
    }
    return best;
  }
  // 记录一个刚被判危/可疑的完整 host（供其子孙连坐）；持久化并限容。只升不降。
  function _recordBlockedHost(host, level) {
    level = (level === 'warn') ? 'warn' : 'danger';
    if (!host) return;
    const h = String(host).toLowerCase().replace(/^www\./, '');
    _blockedHosts = _blockedHosts || new Map();
    const prev = _blockedHosts.get(h);
    if (prev && _sevOf(prev) >= _sevOf(level)) return;  // 只升不降
    _blockedHosts.set(h, level);
    let arr = Array.from(_blockedHosts.entries()).map(([k, v]) => k + '|' + v);
    if (arr.length > 500) arr = arr.slice(arr.length - 500); // 限容防无限增长
    _blockedHosts = new Map(arr.map((s) => { const i = s.lastIndexOf('|'); return [s.slice(0, i), s.slice(i + 1)]; }));
    try { chrome.storage.local.set({ sfBlockedHosts: arr }); } catch (e) {}
  }
  // 清除某 host 及其全部子域在连坐集合中的残留记录（用于用户豁免域名解除历史连坐）
  function _clearBlockedHost(host) {
    host = (host || '').toLowerCase().replace(/^www\./, '');
    if (!host || !_blockedHosts || !_blockedHosts.size) return;
    let changed = false;
    for (const k of Array.from(_blockedHosts.keys())) {
      if (k === host || k.endsWith('.' + host)) { _blockedHosts.delete(k); changed = true; }
    }
    if (changed) {
      const arr = Array.from(_blockedHosts.entries()).map(([k, v]) => k + '|' + v);
      try { chrome.storage.local.set({ sfBlockedHosts: arr }); } catch (e) {}
    }
  }

  function analyzeAndAct(settings, chained, data) {
    if (!settings.enabledGlobal) { lastResult = { analyzed: true, disabled: true, skip: 'disabled' }; reportVerdict('safe'); return; }
    // ★ 可信分发域名（网盘 / GitHub 官方及镜像）：直接判安全、跳过分析。
    //   否则网盘站点（含大量「下载」入口与网盘链接）会被评分引擎判 danger → 进入即弹「危险网站」警告
    //   并 disable 全部下载按钮（变灰不可点），属严重误伤。与后台 .msi/.zip 豁免同源。
    // ★ 2026-11-06：区分「用户白名单」与「扩展内置可信分发名单」两种来源，
    //   供弹窗如实说明为何跳过（原本文案一律写「白名单」，对 GitHub 这类内置名单并不准确）。
    const _alwUser = isAllowlisted(location.hostname, settings.allowlist);
    if (_alwUser || isTrustedDispatch(location.hostname)) {
      // skip 标记：明确告诉弹窗「这一页没有参加评分」，避免弹窗把「无 score」误渲染成「未知」。
      lastResult = { analyzed: true, allowlisted: true, skip: 'allowlist', skipBy: _alwUser ? 'user' : 'builtin', score: 0, level: 'official', reasons: [] };
      reportVerdict('safe');
      return;
    }

    // ★ 用户指定豁免域名（qianwenai.com 等）：整站不拦截、不评分告警、不参与连坐；
    //   并主动清除其可能残留于连坐集合 sfBlockedHosts 的历史记录（避免此前误判写入的
    //   连坐记录持续生效，表现为「score 100 / 域名级联动拦截」）。
    // ⚠️ 2026-11-08 修正：本分支原先独立返回 { exception:true, score:0, level:'safe', reasons:[] }，
    //   但没有 skip 标记；而 2026-11-08 已把 EXCEPTION_DOMAINS 并入白名单，isExceptionHost()
    //   现在等价于「命中内置白名单」——于是所有白名单域名都先落到这里并 return，
    //   下面官方分支的 skip:'official' 永远走不到。弹窗只能按「有 score 数字」渲染，
    //   就显示成「0 分 / 保持警惕 / 未命中任何风险特征」，看起来像白名单完全没生效。
    //   现改为：先做连坐清理，再统一走官方分支，由它给出 skip:'official'。
    if (SF.isExceptionHost && SF.isExceptionHost(location.hostname)) _clearBlockedHost(location.hostname);
    // 官方白名单（cloud.gjhdr.xyz 及其子域等）→ 直接判安全，且优先级高于域名级联动拦截
    // ★ 2026-11-05：这里原先是 `{ analyzed: true, official: true }`，没有任何 score/level，
    //   弹窗就把它渲染成「— / 未知 / 未命中任何风险特征」，与「微步云沙箱」的异常显示同源。
    //   现已补上 skip 标记与明确的 0 分/官方等级：这类站点确实没跑评分引擎，必须让弹窗
    //   如实显示「官方域名 · 已跳过评分」，而不是装作「未知」。与上面豁免域名分支的处理保持一致。
    if (SF.isOfficialDomain(location.hostname)) {
      lastResult = { analyzed: true, official: true, skip: 'official', score: 0, level: 'official', reasons: [] };
      reportVerdict('safe');
      return;
    }
    // ★ 域名级联动（祖/父/子/孙 递归连坐）：当前 host 自身或其祖先域名此前已被判危/可疑时，
    //   本页连坐判相应等级（危险→拦截下载/弹层；可疑→提示），但「不记录」统计——
    //   仅「最先被判定（危险或可疑）的那一级」记入，其余子孙仅连坐拦截/提示。
    const _inh = _inheritedLevel(location.hostname);   // 'danger' | 'warn' | null
    let result;
    if (_inh === 'danger') {
      result = {
        analyzed: true, hostname: location.hostname, blockedCount: 0,
        score: 100, level: 'danger', detected: true, official: false, inherited: true,
        reasons: [{ label: '域名级联动拦截', detail: '该域名（或其父域）此前已被判定为银狐木马投递站，子域名/子页连坐拦截，不重复记录', weight: 100 }],
        features: {}, threshold: 72
      };
    } else {
      data.metrics = collectMetrics();
      data.icp = extractIcp();
      result = SF.analyze(data, { enabled: settings.enabled, sensitivity: settings.sensitivity, weights: settings.weights });

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
        result.reasons.push({ label: '用户自定义黑名单', detail: '该域名在你的恶意域名黑名单中，已强制判定为危险并拦截。', weight: 100 });
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

    // ★ 连坐升级（可疑）：本域此前已被判定「可疑(warn)」，而本页自身分析为「安全」时，
    //   连坐提升为可疑（提示但不硬拦截下载），使同域各页评级一致，避免「根页安全 /
    //   子页可疑」这类评分不一致。本页自身确为危险时不会被降级（上面 danger 分支已优先）。
    if (_inh === 'warn' && result.level === 'safe') {
      result.level = 'warn';
      result.detected = true;
      result.inherited = true;
      if (typeof result.score !== 'number' || result.score < 44) result.score = 44;
      result.reasons.push({ label: '域名级联动（可疑）', detail: '该域名（或其父域）此前已被判定为可疑站点，子域名/子页连坐提示，不重复记录', weight: 44 });
    }

    // ===== 评分 / 等级稳定性护栏（2026-10-27）=====
    // 异步补强（ICP 核验 / .txt 下挖 / BFS 从脚本里挖下载入口）会给 data.links 追加条目后
    // 重判。这类「同类证据变多」曾让同一页面从 71 分跳到 81 分并突然拦截。
    // 具体判据（只认新强特征或分值跃升 ≥12）见 analyzer.stabilizeVerdict。
    }

    const _prevResult = lastResult;
    result = SF.stabilizeVerdict(_prevResult, result);

    // ★ 已按 danger 出过拦截浮层 / 横幅：即便异步补强（.txt 下挖 / BFS 新增普通链接拉低下载占比）
    //   算出更低分，也不得把活跃拦截状态（dangerActive）关掉 —— 否则会出现
    //   「遮罩判定风险、弹窗却判安全」的矛盾，且「立即下载」按钮会重新变可点击。
    //   维持已生效的拦截结论，保证弹窗评分与页面浮层一致、下载拦截持续生效。
    //   （revokeWarningIfShown 命中云端官网库、或用户主动 doRelease 时 revoked/unblocked 为真，仍可正常放行。）
    const establishedDanger = _prevResult && _prevResult.analyzed && _prevResult.level === 'danger' &&
      !_prevResult.allowlisted && !_prevResult.disabled && !unblocked && !revoked;
    if (establishedDanger && result.level !== 'danger') {
      result.level = 'danger';
      result.detected = true;
      result.stabilizedKept = true;
    }

    // ★ 2026-11-04：lastResult 必须在「所有对 result 的修正」之后才快照。
    //   原实现先快照、后由 establishedDanger 把 result.level 改成 danger，
    //   于是浮层按 danger 渲染、下拉菜单读到的 lastResult 却仍是 warn/safe（又一处评分不一致）。
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
      blockAllDownloadEntries();   // ★ danger 级一律硬拦截下载（不再受 autoBlockDownloads 开关限制）
      updateBannerCount();
      if (settings.showWarning) showWarning(result);
      // ★ 2026-11-03 行为变更：判危**不再自动写入黑名单**。
      //   旧逻辑在此调用 _recordBlockedHost(host,'danger')，导致「评分 84 的页面被自动拉黑，
      //   二次访问时被连坐抬到 100 分」，误报既无法复查也无法撤销。
      //   现在只有用户点击拦截弹窗里的「添加到你的恶意域名黑名单」才写入 customBadDomains。
      if (!dangerReported) {
        // 通知保持「同页仅一次」：连坐/复访不再重复弹系统通知，避免刷屏；
        // 但 reportDetection 必须上报——否则连坐/复访的危险页不会被计入「拦截风险网站」记录。
        if (settings.notify && !result.inherited) sfNotify(result);
        reportDetection(result);   // ★ 已移除 inherited 门控：连坐/复访也上报计数，避免漏记
        dangerReported = true;
      }
    } else if (result.level === 'warn') {
      dangerActive = false;
      navBlock = false;
      fullLockdown = false;
      dangerReported = false;
      // ★ warn（可疑）上报后台写入「近期可疑域名记录」（见 background.updateStats）。
      //   但：若本域（或其父域）已被判为 danger（本地连坐黑名单），则它已属危险域名，
      //   不应再写入「可疑」列表（避免「同一域名同时出现在高危与可疑」）。
      //   此时以 danger 上报计入「拦截风险网站」，确保该域名的访问被记录；否则才按可疑处理。
      const _alreadyDanger = _inheritedLevel(location.hostname) === 'danger';
      if (_alreadyDanger) {
        reportDetection(Object.assign({}, result, { level: 'danger' }));
      } else {
        // ★ 不再自动把「可疑」域名写进连坐集合（同上，避免自动拉黑 + 二次访问被抬分）
        reportDetection(result);
      }
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
    // ★ 单次执行守卫：run() 有两个入口（DOMContentLoaded / 2 秒兜底 setTimeout），
    //   原代码只声明了 didRun 却从未置位，导致两者都会执行 → 一次页面加载跑两遍 run()，
    //   情报查询与本地黑名单查询各发两次，横幅就被 append 两遍（同文案上下两条）。
    if (didRun) return;
    didRun = true;
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

    // —— 威胁情报横幅（尽早、与本地检测并行）：启用后用用户 Key 实时查询第三方情报库，
    //    命中恶意情报源即在网页顶部居中展示动态宽度横幅（仅显示判为恶意的 API）。
    try {
      const ti = (settings && settings.threatIntel) || {};
      const tiEnabled = !!ti.enabled;
      const pro = (ti.providers) || {};
      const vt = pro.virustotal || {};
      const gsb = pro.googlesafebrowsing || {};
      // 注意：Google Safe Browsing 的 Key 以密文存储于 storage，settings 里读到的 apiKey 是密文，不可当明文判定
      const vtOn = !!vt.enabled;
      const gsbOn = !!gsb.enabled;
      console.log('[SilverFoxBlocker][情报] run() 已启动，域名=' + _host +
        '，威胁情报总开关=' + tiEnabled +
        '，已启用源：VirusTotal=' + vtOn + '，URLhaus=' + !!(pro.urlhaus && pro.urlhaus.enabled) +
        '，NetAPI=' + !!(pro.netapi && pro.netapi.enabled) + '，GoogleSafeBrowsing=' + gsbOn);
      if (tiEnabled && _host) {
        const needsKey = (vtOn || gsbOn);
        console.log('[SilverFoxBlocker][情报] 已勾选总开关，发起威胁情报查询（需 Key 的源=' +
          (needsKey ? '已启用；Key 仅在后台 service worker 内解密，绝不进入页面脚本' : '无') + '）');
        queryAndShowThreatIntel(_host);
      }
    } catch (e) {}

    // —— OpenPhish 本地钓鱼黑名单：启用后与本地静态名单（域名集合）比对，命中即渲染横幅 ——
    try {
      const op = (settings && settings.openphish) || {};
      const clOn = !!(settings && settings.communityLists && settings.communityLists.enabled);
      if (clOn && op.enabled && _host) {
        console.log('[SilverFoxBlocker][OpenPhish] 已启用，向后台查询本地黑名单：' + _host);
        sendMsg({ type: 'sf-openphish-check', hostname: _host }).then(function (r) {
          try {
            if (r && r.listed) {
              console.log('[SilverFoxBlocker][OpenPhish] 命中本地黑名单：' + _host + '，渲染横幅');
              renderOpenPhishBanner(_host);
            } else {
              console.log('[SilverFoxBlocker][OpenPhish] 未命中（本地名单数量=' + ((r && r.count) || 0) + '）');
            }
          } catch (e) {}
        }).catch(function () {});
      }
    } catch (e) {}

    // —— PhishDestroy 本地钓鱼黑名单：与 OpenPhish 并列的第二个静态名单，命中同样渲染横幅 ——
    try {
      const pd = (settings && settings.phishdestroy) || {};
      const clOn = !!(settings && settings.communityLists && settings.communityLists.enabled);
      if (clOn && pd.enabled && _host) {
        console.log('[SilverFoxBlocker][PhishDestroy] 已启用，向后台查询本地黑名单：' + _host);
        sendMsg({ type: 'sf-phishdestroy-check', hostname: _host }).then(function (r) {
          try {
            if (r && r.listed) {
              console.log('[SilverFoxBlocker][PhishDestroy] 命中本地黑名单：' + _host + '，渲染横幅');
              renderPhishDestroyBanner(_host);
            } else {
              console.log('[SilverFoxBlocker][PhishDestroy] 未命中（本地名单数量=' + ((r && r.count) || 0) + '）');
            }
          } catch (e) {}
        }).catch(function () {});
      }
    } catch (e) {}

    // —— HaGeZi's TIF 本地威胁情报黑名单：第三个静态名单（约 181 万条），命中同样渲染横幅 ——
    try {
      const hg = (settings && settings.hagezi) || {};
      const clOn = !!(settings && settings.communityLists && settings.communityLists.enabled);
      if (clOn && hg.enabled && _host) {
        console.log('[SilverFoxBlocker][HaGeZi] 已启用，向后台查询本地黑名单：' + _host);
        sendMsg({ type: 'sf-hagezi-check', hostname: _host }).then(function (r) {
          try {
            if (r && r.listed) {
              console.log('[SilverFoxBlocker][HaGeZi] 命中本地威胁情报名单：' + _host + '，渲染横幅');
              renderHaGeZiBanner(_host);
            } else {
              console.log('[SilverFoxBlocker][HaGeZi] 未命中（本地名单数量=' + ((r && r.count) || 0) + '）');
            }
          } catch (e) {}
        }).catch(function () {});
      }
    } catch (e) {}

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
      await _ensureBlockedHostsLoaded();   // 载入域名级联动阻断集合（供子页连坐）
      analyzeAndAct(settings, chained, data);   // 单次权威判定
      enrichDeepAsync(settings, chained, data);  // 后台深度补强（可能再重判一次，已去重）
    } catch (e) {
      reportVerdict('safe');
    }

  }

  // ===== 威胁情报横幅 =====
  // 异步查询后台 sf-intel-query，仅当返回"判定为恶意"的结果时渲染顶部横幅。
  // 设计要点（满足用户需求）：
  //  · 宽度动态（fit-content，居中），只显示判为恶意的 API（background 已过滤未检出的源）；
  //  · VirusTotal 等 hasScore 源展示"评分 X/Y"，无评分源（如后期 URLhaus）只给判定语；
  //  · 与危险横幅(.sf-banner)/温和提示条(.sf-hint)错开，避免重叠（它们固定贴页面最顶且整行铺满）；
  //  · 框架化：后期在 background 的 THREAT_INTEL_PROVIDERS 增加新源，此处无需改动。
  function queryAndShowThreatIntel(host) {
    if (document.getElementById('sfIntelStack')) return; // 避免 SPA 重跑重复渲染
    // 同时把当前页面完整 URL 传给后台：VirusTotal 对「域名」与「网址」分开统计，
    // 钓鱼站常在 URL 端点被标红，需要后台一并查询 URL 端点。
    const pageUrl = (typeof location !== 'undefined' && location && location.href) ? location.href : '';
    console.log('[SilverFoxBlocker][情报] 已向后台发起威胁情报查询：' + host + '（URL=' + pageUrl + '）');
    sendMsg({ type: 'sf-intel-query', hostname: host, url: pageUrl }).then(function (resp) {
      try {
        if (!resp || !Array.isArray(resp.results)) {
          console.log('[SilverFoxBlocker][情报] 查询无有效响应（可能后台未启用情报源 / VirusTotal Key 缺失 / 扩展被重载）：', resp);
          return;
        }
        if (resp.results.length > 0) {
          console.log('[SilverFoxBlocker][情报] 域名 ' + host + ' 命中恶意情报源，渲染横幅：', resp.results);
          renderIntelBanners(resp.results);
        } else {
          // 无命中：区分"VT 判安全"与"查询出错 / Key 无效"，给出明确提示
          const errs = Array.isArray(resp.errors) ? resp.errors : [];
          if (errs.length > 0) {
            errs.forEach(function (e) {
              const name = e.name || e.id || '情报源';
              if (e.status === 401 || e.status === 403) {
                console.log('[SilverFoxBlocker][情报] ⚠ ' + name + ' 查询失败：HTTP ' + e.status + ' —— API Key 无效或权限不足，请到「规则与名单」核对 VirusTotal Key。当前域名判定不可信，未显示横幅。');
              } else if (e.reason === 'no_key') {
                console.log('[SilverFoxBlocker][情报] ℹ ' + name + ' 未配置 Key，已跳过查询。');
              } else if (e.reason === 'network') {
                console.log('[SilverFoxBlocker][情报] ⚠ ' + name + ' 网络请求失败：' + (e.detail || '') + '（可能网络受限或 virustotal.com 不可达）。');
              } else {
                console.log('[SilverFoxBlocker][情报] ⚠ ' + name + ' 查询失败：HTTP ' + (e.status || '?') + '（' + (e.reason || 'unknown') + '）。');
              }
            });
          } else {
            console.log('[SilverFoxBlocker][情报] 域名 ' + host + ' 未被任何"已启用"情报源判为恶意（情报源总开关启用=' + resp.enabled + '，VirusTotal 域名分析返回 0 检出），按设计不显示横幅');
          }
        }
      } catch (e) {}
    }).catch(function () { console.log('[SilverFoxBlocker][情报] 查询异常（后台未响应或扩展被重载）'); });
  }

  function positionIntelStack(stack) {
    let top = 8;
    const topBar = document.querySelector('.sf-banner') || document.querySelector('.sf-hint');
    if (topBar) { try { top = topBar.getBoundingClientRect().bottom + 8; } catch (e) {} }
    stack.style.top = top + 'px';
  }

  // 所有第三方情报 / 本地黑名单拦截横幅末尾统一附带的提醒语（VT、URLhaus、NetAPI、GSB、OpenPhish、PhishDestroy、HaGeZi TIF 共用）
  const SAFETY_ADVICE = '请保持谨慎，不要点击来路不明的链接';

  // 把提醒语追加到横幅末尾（独占一行的小字，不挤压正文与「知道了」按钮）
  function appendSafetyAdvice(banner) {
    if (!banner) return;
    const tip = document.createElement('div');
    tip.className = 'sf-ib-tip';
    tip.textContent = SAFETY_ADVICE;
    banner.appendChild(tip);
  }

  // VT 检出引擎明细（「详情」按钮展开）：引擎名 + 等级 + 检出类别，例「Kaspersky 顶级引擎 Phishing」
  const VT_TIER_LABEL = { top: '顶级引擎', second: '二级引擎', niche: '小众引擎', other: '未分级引擎' };
  const VT_CAT_LABEL = { malicious: '恶意', suspicious: '可疑' };

  function vtEngineLine(e) {
    const tier = VT_TIER_LABEL[(e && e.t) || ''] || '未分级引擎';
    let kind = String((e && e.r) || '').trim();
    if (kind) {
      // VT 的 result 是英文类别（phishing / malware / malicious site…），首字母大写更易读
      kind = kind.charAt(0).toUpperCase() + kind.slice(1);
    } else {
      kind = VT_CAT_LABEL[(e && e.c) || ''] || '检出';
    }
    return String((e && e.n) || '未知引擎') + ' ' + tier + ' ' + kind;
  }

  // 生成「详情」按钮 + 可折叠明细面板（VT 引擎清单 / URLhaus、NetAPI 的字段明细共用）
  function buildDetailPanel(rows) {
    if (!Array.isArray(rows) || !rows.length) return null;
    const panel = document.createElement('div');
    panel.className = 'sf-ib-detail';
    panel.setAttribute('role', 'region');
    rows.forEach(function (line) {
      const row = document.createElement('div');
      row.className = 'sf-ib-detail-row';
      row.textContent = line;
      panel.appendChild(row);
    });
    const toggle = document.createElement('button');
    toggle.type = 'button';
    toggle.className = 'sf-ib-detail-btn';
    toggle.textContent = '详情';
    toggle.setAttribute('aria-expanded', 'false');
    toggle.addEventListener('click', function (ev) {
      try { ev.stopPropagation(); } catch (e) {}
      const open = panel.classList.toggle('sf-ib-detail-open');
      toggle.textContent = open ? '收起' : '详情';
      toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
      // 展开后横幅变高，重新对齐容器位置（避免遮挡或与顶部提示条重叠）
      const stack = document.getElementById('sfIntelStack');
      if (stack) positionIntelStack(stack);
    });
    return { panel: panel, toggle: toggle };
  }

  // 汇总一条情报结果的明细行：VT 用逐引擎清单，URLhaus / NetAPI 用后台给的结构化字段说明
  function detailRowsFor(r) {
    if (Array.isArray(r.engines) && r.engines.length) return r.engines.map(vtEngineLine);
    if (Array.isArray(r.facts) && r.facts.length) return r.facts.filter(Boolean);
    return null;
  }

  // 按结果顺序（后台已按 provider order 排序：VT→URLhaus→NetAPI）渲染一组情报横幅，
  // 每个检出源一条、自上而下堆叠在网页顶部居中；未检出的源不渲染，后续源自动上移补位（无空隙）。
  function renderIntelBanners(results) {
    if (!results || !results.length) return;
    // ★ 不能用「容器已存在」判重：OpenPhish / PhishDestroy / HaGeZi 的黑名单查询走内存，
    //   通常比第三方情报先返回、先建好 #sfIntelStack；旧逻辑此时直接 return，
    //   会把 VT / URLhaus / NetAPI / GSB 的横幅整批吞掉。改为按「来源 + 文案」逐条去重。
    const stack = ensureIntelStack();
    if (!stack) return;
    if (!stack._sfKeys) stack._sfKeys = new Set();

    results.forEach(function (r) {
      const banner = document.createElement('div');
      // 配色：VT「可能是误报」与「仅历史记录」（URLhaus / NetAPI 的 stale 结果）用琥珀色（低置信度）；
      // VT「请提高警惕」用更深的警示红；其余（VT「请保持谨慎」/ URLhaus 活跃 / NetAPI 当前在列 / GSB）
      // 统一用默认红粉。
      const extraCls = [];
      if (r.vtLevel === 'fp') extraCls.push('sf-soft');
      if (r.stale) extraCls.push('sf-soft');
      if (r.vtLevel === 'alert') extraCls.push('sf-vt-alert');
      banner.className = 'sf-intel-banner' + (extraCls.length ? ' ' + extraCls.join(' ') : '');
      // VT 对「域名」与「网址」分开统计：若命中来自 URL 端点则说"该网址"，否则"该域名"
      const target = (r.src === '网址') ? '该网址' : '该域名';
      // 软判定源（如 Google Safe Browsing，其 v4 API 已标记淘汰）：必须用「疑似/可能」等限定词，
      // 不得断言「该网站不安全」——仅提示谷歌威胁情报库「疑似」标记，仅供参考。
      const base = r.soft
        ? (r.name + '疑似将' + target + '标记为存在风险（仅供参考）')
        : (r.name + '已将' + target + '判定为恶意或存在风险');
      // VT 三档结论（可能是误报 / 请保持谨慎 / 请提高警惕）由后台按引擎分级给出；
      // 有 verdictText 时以它为主文案，评分等量化信息留在副行，避免正文过长。
      const textStr = r.verdictText ? r.verdictText
        : (r.hasScore ? (base + '，评分 ' + r.score + '/' + r.scoreMax) : base);
      const key = 'intel|' + (r.name || '') + '|' + textStr + '|' + (r.detail || '');
      if (stack._sfKeys.has(key)) return;   // 已渲染过同一结论 → 跳过，不重复追加
      stack._sfKeys.add(key);
      const text = document.createElement('div');
      text.className = 'sf-ib-text';
      text.textContent = textStr;
      banner.appendChild(text);
      // 非评分源（URLhaus/NetAPI）以副行展示判定细节（无评分，仅给判断结果）
      if (r.detail) {
        const sub = document.createElement('div');
        sub.className = 'sf-ib-sub';
        sub.textContent = r.detail;
        banner.appendChild(sub);
      }
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'sf-ib-close';
      btn.textContent = '知道了';
      // 带明细的横幅（VT 逐引擎清单 / URLhaus、NetAPI 的结构化字段）额外给一个独立「详情」按钮，
      // 放在「知道了」左侧，描边样式、视觉权重更低，不干扰主操作。
      const det = buildDetailPanel(detailRowsFor(r));
      if (det) banner.appendChild(det.toggle);
      banner.appendChild(btn);
      if (det) banner.appendChild(det.panel);
      // 提醒语独占末行（正文 + 按钮之上，整行铺满）。
      // VT 的「请保持谨慎，不要点击来路不明的链接」本身已是正文，末尾不再重复同一句。
      if (!(r.verdictText && r.verdictText.indexOf(SAFETY_ADVICE) >= 0)) appendSafetyAdvice(banner);
      // Google Safe Browsing 服务条款要求：显示警告时须给出数据来源归因，并声明其可靠性与准确性无法保证。
      // GSB 是当前唯一的软判定源（r.soft），故仅在其横幅追加这条免责声明。
      if (r.soft) {
        const note = document.createElement('div');
        note.className = 'sf-ib-note';
        note.textContent = '数据由 Google Safe Browsing 提供，Google 不保证该判定的可靠性与准确性，本扩展亦无法保证，请自行判断。';
        banner.appendChild(note);
      }
      btn.addEventListener('click', function () {
        banner.classList.add('sf-closing');
        setTimeout(function () {
          try { banner.remove(); } catch (e) {}
          if (stack && stack.children.length === 0) { try { stack.remove(); } catch (e) {} }
        }, 280);
      });
      stack.appendChild(banner);
    });

    // 容器本身、以及「跟随 .sf-banner/.sf-hint 下移」的观察器都由 ensureIntelStack() 负责，
    // 这里只补充一次定位，避免重复建观察器。
    positionIntelStack(stack);
  }

  // 情报横幅容器（#sfIntelStack）：第三方情报源、OpenPhish、PhishDestroy、HaGeZi TIF 共用同一个容器，
  // 保证所有横幅上下堆叠、共用同一套定位逻辑（跟随顶部 .sf-banner / .sf-hint 下移）。
  function ensureIntelStack() {
    let stack = document.getElementById('sfIntelStack');
    if (stack) return stack;
    stack = document.createElement('div');
    stack.id = 'sfIntelStack';
    stack.className = 'sf-intel-stack' + (currentFontMode === 'smiley' ? ' sf-font-smiley' : '');
    const root = document.body || document.documentElement;
    if (!root) return null;
    root.appendChild(stack);
    positionIntelStack(stack);
    try {
      const mo = new MutationObserver(function () { positionIntelStack(stack); });
      mo.observe(document.body, { childList: true });
      let n = 0;
      const rechk = setInterval(function () {
        positionIntelStack(stack);
        if (++n >= 12) { clearInterval(rechk); try { mo.disconnect(); } catch (e) {} }
      }, 500);
    } catch (e) {}
    return stack;
  }

  // 往堆叠容器里追加一条横幅（含「知道了」独立关闭按钮）
  // 幂等：同一容器内相同 class + 相同文案只保留一条（run 重跑 / SPA 重判 / 多次情报回包
  // 都不会再叠出两条一模一样的横幅）。用户点「知道了」关掉后也不会被再次打扰。
  function appendIntelBanner(cls, textStr) {
    const stack = ensureIntelStack();
    if (!stack) return;
    if (!stack._sfKeys) stack._sfKeys = new Set();
    const key = cls + '|' + textStr;
    if (stack._sfKeys.has(key)) return;
    stack._sfKeys.add(key);
    const banner = document.createElement('div');
    banner.className = 'sf-intel-banner ' + cls;
    const text = document.createElement('div');
    text.className = 'sf-ib-text';
    text.textContent = textStr;
    banner.appendChild(text);
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'sf-ib-close';
    btn.textContent = '知道了';
    btn.addEventListener('click', function () {
      banner.classList.add('sf-closing');
      setTimeout(function () {
        try { banner.remove(); } catch (e) {}
        if (stack && stack.children.length === 0) { try { stack.remove(); } catch (e) {} }
      }, 280);
    });
    stack.appendChild(banner);
    appendSafetyAdvice(banner);   // OpenPhish / PhishDestroy / HaGeZi TIF 同样附带提醒语
    positionIntelStack(stack);
  }

  // OpenPhish 命中本地黑名单 → 横幅「OpenPhish 已将其拉黑」（.sf-openphish：深红）
  function renderOpenPhishBanner(host) {
    appendIntelBanner('sf-openphish', 'OpenPhish 已将其拉黑（' + host + ' 命中本地钓鱼黑名单）');
  }

  // PhishDestroy 命中本地黑名单 → 横幅「PhishDestroy 已将其拉黑」（.sf-phishdestroy：紫罗兰，与上者区分）
  function renderPhishDestroyBanner(host) {
    appendIntelBanner('sf-phishdestroy', 'PhishDestroy 已将其拉黑（' + host + ' 命中本地钓鱼黑名单）');
  }

  // HaGeZi TIF 命中本地威胁情报名单 → 横幅（.sf-hagezi：青蓝，与红色系、紫罗兰区分）
  function renderHaGeZiBanner(host) {
    appendIntelBanner('sf-hagezi', "HaGeZi's TIF 已将其拉黑（" + host + ' 命中本地威胁情报黑名单）');
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
          // 高置信信号(navBlock) 或 明确下载 URL 或 已被禁用(带 data-sf-blocked) 或 命中下载入口 → 拦截，
          // 堵死运行时中继取链 / 直接甩文件 / fetch→blob→a.click() 等手法
          if (navHref && (navBlock || isDownloadUrl(navHref) || (a.dataset && a.dataset.sfBlocked) || isDownloadEntry(a))) {
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
    if (msg && msg.type === 'sf-download-blocked') { showDownloadBlocked(location.hostname, { url: msg.url || '', fromBackground: true }); }
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
