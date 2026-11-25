/*
 * background.js — SilverFoxBlocker 后台 service worker
 * 职责：
 *   1) 初始化默认设置
 *   2) 接收内容脚本的「检测上报」，记录「被判定为危险的标签页」(dangerTabs) 与「用户已放行的站点」(releasedHosts)
 *   3) 拦截下载：★ 只有「发起下载的页面」本身被判定为危险且用户未放行时才拦，绝不全局误拦
 *   4) 接收「离开此网站」指令，直接关闭该标签页（不再跳百度）
 * 状态保存在 chrome.storage.session，可在 service worker 重启后存活（在同一浏览器会话内有效）。
 */
'use strict';

importScripts('rules/iocs.js', 'rules/analyzer.js', 'rules/liststore.js', 'crypto-helper.js');

// 兼容 service worker（self，无 window）与内容脚本（window 隔离世界）两种上下文：
// iocs.js / analyzer.js 已同时挂到 self 与 window。兜底 stub 防止依赖缺失时崩溃。
const SF = self.SF_ANALYZER || (typeof window !== 'undefined' ? window.SF_ANALYZER : null) || {
  classifyLink: function () { return 'other'; },
  isOfficialDomain: function () { return false; },
  detectSpoof: function () { return null; }
};

// ===== 云端名单注入（storage.local: sfCloudWhite / sfCloudBlack）=====
// 名单由设置页「关于 → 从云端更新黑/白名单」经 worker 的 /list 接口拉取后落盘。
// 后台是独立的 analyzer 实例：不注入的话，云端白名单里的站点会「页面不拦、下载却仍被拦」，
// 云端黑名单里的站点则完全拦不到下载。名单一改（storage.onChanged）立即重新注入。
// ★ 覆盖语义：storage 里存的是云端镜像，注入时必须 replace:true，先清空内存集合再灌入，
//   否则云端删掉的条目会残留到浏览器重启为止。空数组同样要注入（等于清空）。
function applyCloudLists(o) {
  try {
    if (SF.registerCloudOfficial) {
      SF.registerCloudOfficial((o && Array.isArray(o.sfCloudWhite)) ? o.sfCloudWhite : [], { replace: true });
    }
    if (SF.registerCloudBad) {
      SF.registerCloudBad((o && Array.isArray(o.sfCloudBlack)) ? o.sfCloudBlack : [], { replace: true });
    }
    // ★ 2026-11-23：云端「例外」（whitelist.json 的 exceptions）——优先级最高的放行层。
    //   与黑白名单同源同批同步，同样整体覆盖；空数组＝云端没有例外规则。
    if (SF.registerCloudException) {
      SF.registerCloudException((o && Array.isArray(o.sfCloudException)) ? o.sfCloudException : [], { replace: true });
    }
    // ★ 2026-11-12：云端「品牌词 → 正确官网」补录（whitelist.json 的 correct_sites）。
    //   仅服务拦截弹窗的「访问正确的页面」按钮，不参与放行/拦截判定；
    //   与上面两份名单的 replace 语义无关（内置表始终保留，云端只补空缺）。
    if (SF.registerCloudCorrect) {
      SF.registerCloudCorrect((o && Array.isArray(o.sfCloudCorrect)) ? o.sfCloudCorrect : []);
    }
  } catch (e) {}
}
// 云端名单的「就绪」promise。MV3 的 service worker 随时会被唤醒/回收，
// 顶层 reloadCloudLists() 是异步的（storage.get 回调），而 downloads.onCreated 可能在
// 同一个 tick 就触发，此时名单还是空的 → 冷启动后第一次下载会漏判。
// 所以把「最近一次加载」的 promise 暴露出去，判定前 await 一下（成本近乎为零：
// 平时它早已 resolve，只是在微任务里排一次队）。
let _cloudReady = Promise.resolve();
function reloadCloudLists() {
  try {
    _cloudReady = new Promise(function (resolve) {
      chrome.storage.local.get({ sfCloudWhite: [], sfCloudBlack: [], sfCloudCorrect: [], sfCloudException: [] }, function (o) {
        applyCloudLists(o);
        resolve();
      });
    });
  } catch (e) { _cloudReady = Promise.resolve(); }
  return _cloudReady;
}
function cloudReady() { return _cloudReady; }
reloadCloudLists();
try {
  chrome.storage.onChanged.addListener(function (ch, area) {
    if (area === 'local' && (ch.sfCloudWhite || ch.sfCloudBlack || ch.sfCloudCorrect || ch.sfCloudException)) {
      reloadCloudLists();
      // ★ 2026-11-22：名单落地后广播给所有标签页 —— 已打开的页面需要「云端名单已更新，建议重判」提示
      //   （内容脚本的名单副本是页面加载时灌进去的，不广播的话用户只能靠手动刷新）。
      notifyCloudListsUpdated();
    }
  });
} catch (e) {}

// ★ 2026-11-22：云端名单变更 → 通知标签页（内容脚本据此挂「建议重判」横幅）。
//   为什么要防抖：一次同步会写 sfCloudWhite / sfCloudBlack / sfCloudCorrect 三个键，
//   onChanged 可能回调多次，合并成一条广播，避免同一页面上叠出多条一模一样的横幅。
//   为什么在后台读条数：横幅副行要写「黑 N / 白 M」，后台读一次比让每个页面各读一次便宜。
//   ★ 2026-11-22（四）：投递范围从「全部标签页」收窄为「焦点窗口的活跃标签页」。见下方说明。
let _cloudNotifyTimer = null;
function notifyCloudListsUpdated() {
  if (_cloudNotifyTimer) clearTimeout(_cloudNotifyTimer);
  _cloudNotifyTimer = setTimeout(function () {
    _cloudNotifyTimer = null;
    try {
      chrome.storage.local.get({ sfCloudBlack: [], sfCloudWhite: [], sfCloudListMeta: null }, function (o) {
        void chrome.runtime.lastError;
        const nb = (o && Array.isArray(o.sfCloudBlack)) ? o.sfCloudBlack.length : 0;
        const nw = (o && Array.isArray(o.sfCloudWhite)) ? o.sfCloudWhite.length : 0;
        // 名单版本号（= 设置页落盘的 meta.black.updated，Date.now() 数字）。
        // 内容脚本切到前台时会拿它和「自己当初注入的那份名单」比对，比这里旧才提示重判。
        const upd = (o && o.sfCloudListMeta && o.sfCloudListMeta.black && o.sfCloudListMeta.black.updated) || 0;
        try {
          // ★ 2026-11-22（四）：只通知「用户当前正在看的那个标签页」，不再全量广播。
          //   起因：标签页一多，一次同步会让几十个页面同时挂横幅、同时倒计时重判，
          //   后台与渲染进程排队跑 analyze → 卡顿甚至无响应。
          //   口径（用户指定）：只有「焦点窗口里的活跃标签页」算当前页面；打开了但没在看的
          //   标签页不在这里发消息 —— 它们由内容脚本自己的 visibilitychange / focus 惰性检查
          //   （installCloudUpdateLazyWatch）在被切到前台的那一刻再决定是否提示，
          //   从而做到「100% 只对正在看的页面付费」。
          //   为什么用 lastFocusedWindow 而不是 currentWindow：service worker 里没有「当前窗口」
          //   的概念，currentWindow 在后台上下文里不可靠；lastFocusedWindow 才是明确的语义。
          //   为什么必须吞 lastError：活跃标签页可能是 edge://newtab、扩展商店、PDF 阅读器等
          //   没有注入内容脚本的页面，sendMessage 会抛 "Receiving end does not exist"。
          chrome.tabs.query({ active: true, lastFocusedWindow: true }, function (tabs) {
            void chrome.runtime.lastError;
            (tabs || []).forEach(function (t) {
              if (t && t.id != null) {
                safeTabMsg(t.id, { type: 'sf-cloud-lists-updated', black: nb, white: nw, updated: upd });
              }
            });
          });
        } catch (e) {}
      });
    } catch (e) {}
  }, 300);
}

// 用户在当前会话里「仍要下载」明确放行的下载 URL（避免重复拦截；SW 重启后清空，会重新询问，安全）
const allowedDownloads = new Set();
function addAllowedDownload(url) { if (url) allowedDownloads.add(url); }
// 安全地向内容脚本发消息：显式消费 chrome.runtime.lastError，避免「Receiving end does not exist」/
// 「上下文不全」等未捕获异步错误在 Edge/Chrome 控制台刷屏（try/catch 无法捕获异步 lastError）。
function safeTabMsg(tabId, msg) {
  if (tabId == null) return;
  try { chrome.tabs.sendMessage(tabId, msg, function () { void chrome.runtime.lastError; }); } catch (e) {}
}
function isAllowedDownload(url) { return !!(url && allowedDownloads.has(url)); }

// ===== 用户手势（User Gesture）追踪 + 自动下载拦截（2026-11-23，2026-11-24 重写）=====
// 旧实现（2026-11-23，保留在下面注释里备查）只记一个**全局时间戳**，任何 pointerdown /
//   Enter / Space 都算「用户主动」，由此留下三个口子：
//   ① 「滚动背书」：用户只是滚了一下页面 / 点了下空白处，随后 4s 内页面自己的静默下载就被判成
//      「用户主动」，直接放行；
//   ② 「跨标签污染」：时间戳全局共享，在 A 标签页点两下，也能给 B 标签页的静默下载背书；
//   ③ 「白名单豁免」：可信下载源 / 官方域名 / 自定义白名单直接跳过判定 —— 而灰产恰恰在滥用
//      「整站信任」：华军软件园这类大站本身在信任名单里，页面挂机十几秒（远超分析窗口）后
//      静默推 360 安全卫士安装包，旧规则一律放行。
// 新实现（对应截图里的「强手势 / 白名单降级」策略）：
//   · 手势分两级：strong（点击落在 <a>/<button>/[role=button]/[download]/文件后缀链接上，
//     带上该链接的绝对 URL 与主机名）与 weak（其余点击、普通按键）。**只有 strong 能为高危
//     文件背书**；weak 只用于非高危文件的旧规则，不再给任何自动下载开绿灯；
//   · 强手势按「指向的链接」与下载 URL / 主机 / 文件名做关联，而不是只看时间差：
//     同主机或同文件 10s 内有效，任意强手势 2.5s 内视为该次点击的直接后果；
//   · 高危文件（exec / archive / cloud）**不再享受任何白名单豁免**：拿不到强手势证据就
//     「暂停 + 询问」（confirmHighRiskDownload），与主机是否可信无关。
// 强手势为什么仍保留一个「全局」维度：点「下载」后新开标签再落盘是常见合规范式，新标签天然
//   没有手势；但那个窗口被压到 2.5s，且必须真的点在链接/按钮上，靠滚页面拿不到。
let _lastGestureAt = 0;              // 任意手势（weak 也刷新）——仅供非高危文件的旧规则使用
let _lastStrongAt = 0;               // 最近一次强手势
const _strongGestures = [];          // 最近若干次强手势：{ at, tabId, host, url, file }
const STRONG_MATCH_MS = 10000;       // 强手势与下载「同主机 / 同 URL / 同文件名」的有效期
const STRONG_RECENT_MS = 2500;       // 任意强手势在 2.5s 内 → 视为本次下载的直接触发者
const STRONG_MAX = 12;
const GESTURE_FRESH_MS = 4000;       // 非高危文件：4s 内有过任意手势即放行（沿用旧语义）
const GESTURE_ANALYSIS_MS = 1500;    // 分析窗口：1.5s 内没有强手势就认定是自动下载
function _fileOfUrl(u) {
  try {
    const x = new URL(String(u));
    const arr = x.pathname.split('/');
    return (arr[arr.length - 1] || '').toLowerCase();
  } catch (e) { return ''; }
}
function noteUserGesture(strength, info, tabId) {
  const now = Date.now();
  _lastGestureAt = now;
  if (strength !== 'strong') return;
  _lastStrongAt = now;
  // ★ 2026-11-23（授权模型）：强手势额外记下「所在页面的 origin」与 consumed 标记，
  //   用于「origin 精确匹配 + 一次性消费」，见 _authDecide()。
  _strongGestures.push({
    at: now,
    tabId: (tabId != null && tabId >= 0) ? tabId : -1,
    host: String((info && info.host) || '').toLowerCase(),
    url: String((info && info.url) || ''),
    file: String((info && info.file) || '').toLowerCase() || _fileOfUrl(info && info.url),
    origin: String((info && info.origin) || '').toLowerCase(),
    dl: !!(info && info.dl),
    consumed: false
  });
  if (_strongGestures.length > STRONG_MAX) _strongGestures.shift();
  if (typeof _authPersist === 'function') _authPersist();
}
function _hasGesture(winMs) { return _lastGestureAt > 0 && (Date.now() - _lastGestureAt) <= winMs; }
function _hasStrongGesture(winMs) { return _lastStrongAt > 0 && (Date.now() - _lastStrongAt) <= winMs; }
// 强手势是否为本次下载「背书」：返回命中的依据（'' 表示没有证据）
function _strongEvidence(item) {
  const now = Date.now();
  const dHost = parseHost(item.url);
  const dUrl = String(item.url || '');
  const dFile = _fileOfUrl(dUrl);
  for (let i = _strongGestures.length - 1; i >= 0; i--) {
    const g = _strongGestures[i];
    if (now - g.at > STRONG_MATCH_MS) break;   // 数组按时间递增，越早越该停
    if (g.host && dHost && g.host === dHost) return 'host';
    if (g.url && dUrl && g.url === dUrl) return 'url';
    if (g.file && dFile && g.file === dFile) return 'file';
  }
  if (_hasStrongGesture(STRONG_RECENT_MS)) return 'recent';
  return '';
}
// function noteUserGesture() { _lastGestureAt = Date.now(); }
// function _hasGesture(winMs) { return _lastGestureAt > 0 && (Date.now() - _lastGestureAt) <= winMs; }

// ===== 下载授权模型（2026-11-23「最终最终方案」）=====
// 目标：高危下载**每页第一次必须有人工意图**，不能靠「主机在不在白名单」来猜。
// 四条规则（按优先级，见 _authDecide）：
//   ① 本页已授权（用户在本页点过「继续下载」/ 之前确认过）→ 直接放行；
//   ② 强手势匹配：存在未消费的强手势，且其 origin 与 item.initiator 完全一致（2.5s 内）
//      → 放行并把该手势标记 consumed（一次性，避免「一次点击连环下载」）；
//      分卷压缩包的补偿：消费后 500ms 内、同 origin 的后续下载最多再放行 3 个；
//   ③ 子标签继承：新标签（openerTabId）的父标签有授权，且子页 origin 与父页一致
//      （或子页还是 about:blank）→ 继承授权；
//   ④ 其余（静默下载 / 来源为空 / 无手势 / 无授权）→ cancel + 弹确认条，用户点「允许」才重下。
// 存储：浏览器重启/后台休眠会清空内存，故权威副本放 chrome.storage.session（关浏览器即失效），
//   内存里只做同步镜像（downloads.onCreated 需要同步判断，不能等异步回读）。
// 生命周期：页面导航（tabs.onUpdated → loading）立刻撤销该 tab 的授权 = 「刷新即失忆」。
const GESTURE_TTL_MS = 2500;   // 手势有效期（与方案一致：同 origin 直接匹配）
const NAV_INTENT_MS = 10000;   // 跳转携带意图：点了下载链接后经中转/感谢页再下载，10s 内有效
const GRACE_MS = 500;          // 分卷补偿窗口
const GRACE_MAX = 3;           // 分卷最多补偿几个
const _sfAuth = {
  grants: {},      // tabId -> { origin, at }
  openers: {},     // tabId -> openerTabId（子标签继承授权用）
  navIntent: {},   // tabId -> { at, left }：点了「下载」链接后发生跳转，跳转后的页面开始下载视为用户意图
  pending: {},     // tabId -> { url, filename, host, origin, at }（待用户确认的下载）
  graceOrigin: '',
  graceUntil: 0,
  graceLeft: 0,
  // ★ 2026-11-23：最近一次 _authDecide 的放行原因（page / gesture / navlink / navintent / opener）。
  //   只用于决定「放行轻提示」要不要弹、文案怎么写，不参与任何判定。
  lastReason: '',
  ready: null,
  writeTimer: null
};
// ★ 2026-11-23：本次「已按用户意图放行」的下载 id（15s 内有效）。
//   用途：checkAutoDownload 放行后，onCreated 里还有一道「分析闸门」（analyzing → holdDownload）
//   会静默取消并擦除 —— 不在这里打个标记，「点了下载链接 → 跳感谢页 → 开始下载」这条正规链路
//   永远下不来（实测：日志显示已授权放行，但文件始终是 0 字节、下载列表里也没有）。
const _authPassIds = new Map();
function _markAuthPass(item) {
  try {
    const now = Date.now();
    _authPassIds.set(item.id, now);
    _authPassIds.forEach(function (v, k) { if (now - v > 15000) _authPassIds.delete(k); });
  } catch (e) {}
}
function _originOfUrl(u) {
  try {
    const x = new URL(String(u || ''));
    return (x.origin === 'null') ? '' : x.origin.toLowerCase();
  } catch (e) { return ''; }
}
function _authHydrate() {
  return new Promise(function (res) {
    try {
      if (!chrome.storage || !chrome.storage.session) return res();
      chrome.storage.session.get({ sfAuthGrants: {}, sfAuthPending: {}, sfGestures: [] }, function (r) {
        try {
          const now = Date.now();
          // ★ 合并而不是覆盖：SW 可能刚被一条 sf-gesture 唤醒，消息处理会先于这里的
          //   storage 回调执行；若此处直接清空数组，刚刚记下的手势会被抹掉（实测踩到过）。
          const hg = (r && r.sfAuthGrants) || {};
          Object.keys(hg).forEach(function (k) { if (!_sfAuth.grants[k]) _sfAuth.grants[k] = hg[k]; });
          const hp = (r && r.sfAuthPending) || {};
          Object.keys(hp).forEach(function (k) { if (!_sfAuth.pending[k]) _sfAuth.pending[k] = hp[k]; });
          // 手势也只做并集（同样只留 10s 内的）
          const gs = (r && r.sfGestures) || [];
          if (Array.isArray(gs) && gs.length) {
            gs.forEach(function (g) {
              if (!g || !g.at || (now - g.at) >= 10000) return;
              const dup = _strongGestures.some(function (x) { return x.at === g.at && x.tabId === g.tabId; });
              if (!dup) _strongGestures.push(g);
            });
            _strongGestures.sort(function (a, b) { return a.at - b.at; });
            while (_strongGestures.length > STRONG_MAX) _strongGestures.shift();
            const last = _strongGestures[_strongGestures.length - 1];
            if (last && last.at > _lastStrongAt) _lastStrongAt = last.at;
          }
          res();
        } catch (e) { res(); }
      });
    } catch (e) { res(); }
  });
}
function _authPersist() {
  if (_sfAuth.writeTimer) return;
  _sfAuth.writeTimer = setTimeout(function () {
    _sfAuth.writeTimer = null;
    try {
      if (!chrome.storage || !chrome.storage.session) return;
      const now = Date.now();
      // 过期项顺手清掉（手势 10s、授权不超 6h、待确认 10min）
      const gs = _strongGestures.filter(function (g) { return g && (now - g.at) < 10000; }).slice(-STRONG_MAX);
      const grants = {};
      Object.keys(_sfAuth.grants).forEach(function (k) { if (now - (_sfAuth.grants[k].at || 0) < 6 * 3600 * 1000) grants[k] = _sfAuth.grants[k]; });
      const pend = {};
      Object.keys(_sfAuth.pending).forEach(function (k) { if (now - (_sfAuth.pending[k].at || 0) < 600000) pend[k] = _sfAuth.pending[k]; });
      chrome.storage.session.set({ sfGestures: gs, sfAuthGrants: grants, sfAuthPending: pend });
    } catch (e) {}
  }, 120);
}
function _authGrant(tabId, origin) {
  if (tabId == null || tabId < 0) return;
  _sfAuth.grants[tabId] = { origin: String(origin || ''), at: Date.now() };
  _authPersist();
}
function _authRevoke(tabId) {
  if (tabId == null) return;
  let dirty = false;
  if (_sfAuth.grants[tabId]) { delete _sfAuth.grants[tabId]; dirty = true; }
  if (_sfAuth.pending[tabId]) { delete _sfAuth.pending[tabId]; dirty = true; }
  if (dirty) _authPersist();
}
// ===== 「每站首次确认」（2026-11-23）=====
// 为什么需要它：上面 ②～③ 这些「用户意图」规则证明的只是「用户确实点了页面上的某个东西」，
//   而流氓站（高速下载站 / 假下载按钮）正是靠伪造一个「下载」样式的按钮骗取这一次点击，
//   点击之后静默下发 exe，规则②会把它当成用户主动下载直接放行 —— 实测四个杀软官网与
//   「点一下就开始下」的钓鱼站，在这条链路上无法区分。
// 做法：按「站点注册域」记一份「已确认下载可执行文件」的名单（chrome.storage.local，跨会话保留）。
//   某站**第一次**下载高危文件时，无论有没有点击、是不是同一标签，都先暂停并询问一次；
//   用户点「继续下载」后该站入名单，此后回到原有规则（不再重复询问）。
// 优先级：高于 ①②②b②c②d③ 全部「用户意图」放行规则（否则等于没生效），
//   但**低于**硬黑名单（黑名单命中直接拦，不给「是否允许」的选择）。
const SITE_FIRST_KEY = 'sfSiteFirstSeen';
const SITE_FIRST_MAX = 2000;       // 最多记 2000 个站点，超了按最近确认时间淘汰
const SITE_FIRST_TTL = 180 * 24 * 3600 * 1000;  // 半年没再确认过就重新问一次
const _sfSite = { seen: {}, ready: null, timer: null };
// 站点键：优先用「来源页」（用户实际所在的站），拿不到再退回载荷主机；统一取注册域，
// 这样 www./dl./cdn. 等子域共享同一份记录，不会因换子域反复询问。
function _siteKeyOfHost(host) {
  const h = String(host || '').toLowerCase().trim();
  if (!h) return '';
  try { const r = _regDomain(h); if (r) return r; } catch (e) {}
  return h;
}
function _siteKeyOfItem(item) {
  // ① 来源页（initiator / referrer / 本标签的顶级导航）优先 —— 那才是「用户所在的站」
  let h = '';
  try { h = downloadSourceHost(item) || ''; } catch (e) {}
  // ② 拿不到时退回「该下载归到的标签页」当前地址
  if (!h) {
    try {
      const t = _dlUiTab(item);
      if (t != null && t >= 0 && lastTopUrl[t]) h = parseHost(lastTopUrl[t]);
    } catch (e) {}
  }
  // ③ 最后才退回载荷主机（如 cdn.xxx.com）：这样至少还能按注册域归一
  return _siteKeyOfHost(h || parseHost(item.url));
}
function _siteSeen(key) {
  if (!key) return true;   // 拿不到站点就当作「已确认」，避免把无主下载变成永远拦不下来
  const t = _sfSite.seen[key];
  if (!t) return false;
  if (Date.now() - t > SITE_FIRST_TTL) { delete _sfSite.seen[key]; return false; }
  return true;
}
function _siteMark(key) {
  if (!key) return;
  _sfSite.seen[key] = Date.now();
  if (_sfSite.timer) return;
  _sfSite.timer = setTimeout(function () {
    _sfSite.timer = null;
    try {
      const now = Date.now();
      const keys = Object.keys(_sfSite.seen);
      if (keys.length > SITE_FIRST_MAX) {
        keys.sort(function (a, b) { return (_sfSite.seen[a] || 0) - (_sfSite.seen[b] || 0); });
        keys.slice(0, keys.length - SITE_FIRST_MAX).forEach(function (k) { delete _sfSite.seen[k]; });
      }
      Object.keys(_sfSite.seen).forEach(function (k) { if (now - _sfSite.seen[k] > SITE_FIRST_TTL) delete _sfSite.seen[k]; });
      const out = {};
      out[SITE_FIRST_KEY] = _sfSite.seen;
      chrome.storage.local.set(out);
    } catch (e) {}
  }, 300);
}
function _siteHydrate() {
  return new Promise(function (res) {
    try {
      chrome.storage.local.get({ sfSiteFirstSeen: {} }, function (r) {
        try {
          const saved = (r && r.sfSiteFirstSeen) || {};
          Object.keys(saved).forEach(function (k) { if (!_sfSite.seen[k]) _sfSite.seen[k] = saved[k]; });
        } catch (e) {}
        res();
      });
    } catch (e) { res(); }
  });
}
try { _sfSite.ready = _siteHydrate(); } catch (e) { _sfSite.ready = Promise.resolve(); }

// 返回 'allow' | 'confirm'（同时把命中原因记到 _sfAuth.lastReason，供「放行轻提示」区分场景）
function _authDecide(item, tabId) {
  const now = Date.now();
  const tid = (tabId != null && tabId >= 0) ? tabId : -1;
  _sfAuth.lastReason = '';
  // ① 本页已授权
  if (tid >= 0 && _sfAuth.grants[tid]) { _sfAuth.lastReason = 'page'; return 'allow'; }
  const iOrigin = _originOfUrl(item.initiator) || _originOfUrl(item.referrer);
  // ② 强手势（一次性消费）
  for (let i = _strongGestures.length - 1; i >= 0; i--) {
    const g = _strongGestures[i];
    if (g.consumed) continue;
    if (now - g.at > GESTURE_TTL_MS) continue;
    const sameOrigin = !!(iOrigin && g.origin && iOrigin === g.origin);
    // 来源缺失时退化为「同标签页」：initiator 空但确实是这一页刚点的（blob:/表单/JS 取链常见）
    const sameTab = !iOrigin && tid >= 0 && g.tabId === tid;
    if (sameOrigin || sameTab) {
      g.consumed = true;
      _sfAuth.graceOrigin = iOrigin || g.origin || '';
      _sfAuth.graceUntil = now + GRACE_MS;
      _sfAuth.graceLeft = GRACE_MAX;
      _authPersist();
      _sfAuth.lastReason = 'gesture';
      return 'allow';
    }
  }
  // ②b 分卷宽限：同 origin、500ms 内、最多 3 个
  if (_sfAuth.graceLeft > 0 && now <= _sfAuth.graceUntil) {
    if (!_sfAuth.graceOrigin || !iOrigin || iOrigin === _sfAuth.graceOrigin) {
      _sfAuth.graceLeft--;
      _sfAuth.lastReason = 'gesture';
      return 'allow';
    }
  }
  // ②c 导航携带意图：点了下载链接 → 站点跳到「感谢下载 / 中转」页 → 由新页面开始下载。
  //   这是正规站（Avira、华军等）最常见的链路，但新页面的 origin 与点击页不同、initiator 往往为空，
  //   规则②匹配不上，于是被当成「页面自己下载」问一遍。这里补一条：只要 10s 内那次强手势
  //   「指向的链接」与本次下载是同一主机 / 同一 URL / 同一文件名，就认定为用户意图。
  //   注意只认强手势（点在链接/按钮上），且必须真有一项对得上 —— 不按时间无差别放行。
  {
    const dHost2 = parseHost(item.url);
    const dFile2 = _fileOfUrl(item.url);
    const dUrl2 = String(item.url || '');
    for (let i = _strongGestures.length - 1; i >= 0; i--) {
      const g = _strongGestures[i];
      if (g.consumed) continue;
      if (now - g.at > NAV_INTENT_MS) break;
      const hitHost = !!(g.host && dHost2 && g.host === dHost2);
      const hitFile = !!(g.file && dFile2 && g.file === dFile2);
      const hitUrl = !!(g.url && dUrl2 && g.url === dUrl2);
      if (hitHost || hitFile || hitUrl) {
        g.consumed = true;
        _sfAuth.graceOrigin = iOrigin || g.origin || '';
        _sfAuth.graceUntil = now + GRACE_MS;
        _sfAuth.graceLeft = GRACE_MAX;
        _authPersist();
        console.log('[auto-dl] 跳转携带意图放行（' + (hitHost ? 'host' : hitFile ? 'file' : 'url') + '）：' + item.url);
        _sfAuth.lastReason = 'navlink';
        return 'allow';
      }
    }
  }
  // ②d 「点下载链接 → 跳转到感谢下载/中转页 → 由新页面开始下载」
  //   这条链路里，下载页拿不到上一页的点击（origin 变了、initiator 常为空），② 和 ②c 都可能落空。
  //   于是额外记一个「跳转意图」：只要该 tab 刚刚（3s 内）点过带下载语义的链接，随后发生的
  //   顶级导航就把这个 tab 标记为「已由用户的下载点击带入」，15s 内最多放行 2 个高危下载。
  //   为什么带 dl 标记才认：否则「点搜索结果 → 进站 → 站内自动下载」也会被算成用户意图。
  {
    const ni = _sfAuth.navIntent[tid];
    if (ni && ni.left > 0 && (now - ni.at) < (NAV_INTENT_MS + 5000)) {
      ni.left--;
      _sfAuth.graceOrigin = iOrigin || '';
      _sfAuth.graceUntil = now + GRACE_MS;
      _sfAuth.graceLeft = GRACE_MAX;
      console.log('[auto-dl] 跳转下载意图放行：' + item.url);
      _sfAuth.lastReason = 'navintent';
      return 'allow';
    }
  }
  // ③ 子标签继承父标签授权
  if (tid >= 0) {
    const pid = _sfAuth.openers[tid];
    const pg = (pid != null) ? _sfAuth.grants[pid] : null;
    if (pg) {
      const pageUrl = lastTopUrl[tid] || '';
      const pageOrigin = _originOfUrl(pageUrl);
      // about:blank（新窗口占位）或同 origin 才继承；跨站一律不继承
      if (!pageUrl || !pageOrigin || !pg.origin || pageOrigin === pg.origin) {
        _authGrant(tid, pageOrigin || pg.origin);
        _sfAuth.lastReason = 'opener';
        return 'allow';
      }
    }
  }
  return 'confirm';
}
// 高危下载的「硬黑名单」判定：命中就必须硬拦，不能给用户「是否允许」的选择
function _isHardBadDownload(item, settings) {
  try {
    const host = parseHost(item.url);
    const srcHost = downloadSourceHost(item);
    // 旧（2026-11-09 定版）：任意黑名单命中即硬拦，没有「例外」这一层。
    /*
    if (isCloudBadHost(host) || isCloudBadUrl(item.url)) return true;
    if (srcHost && (isCloudBadHost(srcHost) || isCloudBadUrl(downloadSourceUrl(item)))) return true;
    if (isBuiltinBadHost(host)) return true;
    if (srcHost && isBuiltinBadHost(srcHost)) return true;
    if (settings && hostMatch(host, settings.customBadDomains)) return true;
    if (settings && srcHost && hostMatch(srcHost, settings.customBadDomains)) return true;
    */
    // 新（2026-11-23）：逐主机按「例外优先矩阵」判定 —— 命中例外的那一侧直接跳过黑名单，
    //   另一侧仍独立判定（例外不该连带豁免另一个主机名）。
    const srcUrl = downloadSourceUrl(item);
    if (_dlListTier(host, item.url, settings) === 'bad') return true;
    if (srcHost && _dlListTier(srcHost, srcUrl, settings) === 'bad') return true;
    if (isKnownBadFilename(item.filename) || isKnownBadFilename(item.url)) return true;
    if (dlBlacklistHas(host)) return true;
  } catch (e) {}
  return false;
}
// 后台启动即预热（downloads.onCreated 里同步判断要用）
try { _sfAuth.ready = _authHydrate(); } catch (e) { _sfAuth.ready = Promise.resolve(); }

// ===== 授权生命周期（刷新即失忆 / 关标签即清空 / 记下 opener）=====
// 与方案一致：以 tabs.onUpdated 的 status==='loading' 为「页面开始导航」的锚点。
// 这里刻意不申请/不依赖 webNavigation 来完成授权清理（本扩展保留 webNavigation 仅用于
// 「危险站跳转链」与「分析闸门」，与授权表互不影响）。
try {
  if (chrome.tabs && chrome.tabs.onUpdated) {
    chrome.tabs.onUpdated.addListener(function (tabId, info) {
      if (info && info.status === 'loading') _authRevoke(tabId);
    });
  }
} catch (e) {}
try {
  if (chrome.tabs && chrome.tabs.onRemoved) {
    chrome.tabs.onRemoved.addListener(function (tabId) {
      try {
        delete _sfAuth.grants[tabId];
        delete _sfAuth.pending[tabId];
        delete _sfAuth.openers[tabId];
      } catch (e) {}
      _authPersist();
    });
  }
} catch (e) {}
try {
  if (chrome.tabs && chrome.tabs.onCreated) {
    chrome.tabs.onCreated.addListener(function (tab) {
      if (tab && tab.id != null && tab.openerTabId != null) _sfAuth.openers[tab.id] = tab.openerTabId;
    });
  }
} catch (e) {}
function _anyAnalyzingTab() {
  try {
    for (const id in analysisState) if (analysisState[id] === 'analyzing') return Number(id);
  } catch (e) {}
  return null;
}
// ★ 2026-11-23：取消 + 稍后擦除。
//   两个坑：
//   ① chrome.downloads.erase 的签名是 erase(DownloadQuery) —— 直接传数字 id 会同步抛
//      「No matching signature」TypeError（老代码那种写法一直在静默失败，所以下载栏总留
//      「已中断」残影）。必须传 { id: n }。
//   ② 条目还在取消中时 erase 会报 Invalid download state，故延迟 + 失败重试。
function _cancelAndErase(id) {
  try { chrome.downloads.cancel(id); } catch (e) {}
  let tries = 0;
  const wipe = function () {
    tries++;
    try {
      chrome.downloads.erase({ id: id }, function () {
        const err = chrome.runtime.lastError;
        if (err && tries < 5) setTimeout(wipe, 350);
      });
    } catch (e) {}
  };
  setTimeout(wipe, 300);
}
// 计一次「拦截下载」（三个拦截路径共用）
function _bumpBlockStatOnce() {
  try {
    chrome.storage.local.get({ stats: { warnings: 0, blocks: 0, recent: [] } }, function (r) {
      const stats = r.stats || { warnings: 0, blocks: 0, recent: [] };
      stats.blocks = (stats.blocks || 0) + 1;
      chrome.storage.local.set({ stats });
    });
  } catch (e) {}
}
// 解析「这条下载该在哪个标签页里提示」
//   onCreated 的 tabId 常为 -1（meta refresh、服务端强推、window.open），此时依次用
//   来源页反查 → referrer/initiator 主机名反查 → 最近顶级导航主机名反查。
function _dlUiTab(item) {
  if (item.tabId != null && item.tabId >= 0) return item.tabId;
  try { const t = _analyzingTabBySource(item); if (t != null && t >= 0) return t; } catch (e) {}
  const h = downloadSourceHost(item);
  if (h) {
    for (const id in lastTopUrl) {
      try { if (parseHost(lastTopUrl[id]) === h) return Number(id); } catch (e) {}
    }
  }
  return null;
}
// 拦截一次自动下载：取消 + 擦除（不留「已取消」残影）+ 告知页面 + 计一次「拦截下载」
function blockAutoDownload(item, tabId, reason) {
  // try { chrome.downloads.cancel(item.id); } catch (e) {}
  // try { chrome.downloads.erase(item.id); } catch (e) {}
  // ★ 2026-11-23：改用延迟擦除，避免残影（见 _cancelAndErase 注释）
  _cancelAndErase(item.id);
  try {
    if (tabId != null && tabId >= 0) {
      safeTabMsg(tabId, {
        // ★ 2026-11-23：分析期间的暂停改报 sf-dl-checking —— 前台会显示「正在安全检查」，
        //   而不是笼统的「已拦截自动下载」。避免用户以为「点了下载，扩展毫无反应」。
        type: (reason === 'analysis') ? 'sf-dl-checking' : 'sf-auto-dl-blocked',
        host: parseHost(item.url),
        filename: item.filename || '',
        reason: reason || 'auto'
      });
    }
  } catch (e) {}
  // try {
  //   chrome.storage.local.get({ stats: { warnings: 0, blocks: 0, recent: [] } }, function (r) {
  //     const stats = r.stats || { warnings: 0, blocks: 0, recent: [] };
  //     stats.blocks = (stats.blocks || 0) + 1;
  //     chrome.storage.local.set({ stats });
  //   });
  // } catch (e) {}
  _bumpBlockStatOnce();
  console.log('[auto-dl] 已拦截自动下载（' + reason + '）：' + item.url);
}
// ★ 2026-11-24：高危文件「暂停 + 询问」。
//   与 blockAutoDownload 的区别：不是一刀切拦死，而是取消本次下载 + 在页面上挂一条
//   **非阻塞**确认条（来自[域名]的[文件]已暂停，继续下载 / 保持拦截）。
//   为什么要给出口：华军软件园这类大站本身在信任名单里，用户也可能是真的要下某个软件；
//   一味静默拦截会把正常下载也误杀。但「高危文件必须过一次人工确认」这条，
//   对任何主机都成立 —— 灰产利用的正是「整站信任」，所以这里刻意不看白名单。
function confirmHighRiskDownload(item, tabId, reason, siteKey) {
  const host = parseHost(item.url) || '';
  const filename = item.filename || _fileOfUrl(item.url) || '';
  _cancelAndErase(item.id);
  const tid = (tabId != null && tabId >= 0) ? tabId : _dlUiTab(item);
  // ★ 2026-11-23（授权模型）：把这次被取消的下载放进「待确认队列」。
  //   为什么要存：cancel 之后前台只剩一个按钮，用户点「继续下载」时要靠这里的 url 重新发起；
  //   存 session 是为了后台休眠 30s 后（MV3 常态）点了按钮仍能取到它。
  //   ★ 2026-11-23（每站首次确认）：siteKey 一并存进来 —— 用户点「继续下载」时用它把该站
  //     写进「已确认」名单，否则下次又会问一遍（见 sf-allow-download 处理）。
  if (tid != null && tid >= 0) {
    try {
      _sfAuth.pending[tid] = {
        url: item.url || '',
        filename: filename,
        host: host,
        origin: _originOfUrl(lastTopUrl[tid] || ''),
        siteKey: siteKey || _siteKeyOfItem(item),
        at: Date.now()
      };
      _authPersist();
    } catch (e) {}
  }
  if (tid != null && tid >= 0) {
    try {
      safeTabMsg(tid, {
        type: 'sf-exe-confirm',
        url: item.url || '',
        host: host,
        filename: filename,
        reason: reason || 'guard',
        // 前台据此加一句「这是该站第一次下载可执行文件」的说明
        siteFirst: !!siteKey
      });
    } catch (e) {}
  } else {
    // 实在归不到任何标签页（极端：无 referrer 的后台下载）→ 退回系统通知，别让用户一头雾水
    try {
      if (chrome.notifications && chrome.notifications.create) {
        chrome.notifications.create('sf-exe-' + Date.now(), {
          type: 'basic',
          iconUrl: chrome.runtime.getURL('icons/icon128.png'),
          title: '已暂停一个可执行文件下载',
          message: '来自 ' + (host || '未知站点') + ' 的 ' + (filename || '文件') + ' 可能不是由你的点击触发的，已暂停。',
          priority: 1
        }, function () { void chrome.runtime.lastError; });
      }
    } catch (e) {}
  }
  _bumpBlockStatOnce();
  console.log('[auto-dl] 已暂停高危下载待确认（' + (reason || 'guard') + '）：' + item.url);
}
// 返回 true 表示已经拦截（调用方直接 return）
function checkAutoDownload(item, settings, tabId) {
  try {
    // ★ 2026-11-23：页面 JS 触发的下载在 onCreated 里 tabId 常常是 undefined、initiator 也是空
    //   （实测 a.click() / 动态 <a> 都是这样）。若只认 item.tabId，「本页已授权」永远查不到，
    //   用户确认过一次还会被反复询问。这里退化为：分析态反查 → 来源主机反查最近标签页。
    let dlTab = (tabId != null && tabId >= 0) ? tabId : _analyzingTabBySource(item);
    if (dlTab == null || dlTab < 0) dlTab = _dlUiTab(item);
    const analyzing = (dlTab != null && dlTab >= 0)
      ? (analysisState[dlTab] === 'analyzing')
      : (settings.enabledGlobal && !!_anyAnalyzingTab());
    // 其它扩展（迅雷 / IDM 等）发起的下载交给 onCreated 里专门的分支（会弹「下载器扩展」确认窗），
    // 这里不抢它的判定，避免两条 UI 打架。
    if (item.byExtensionId && item.byExtensionId !== chrome.runtime.id) return false;
    const highRisk = isHighRiskFile(item.url);

    // ① 非高危文件：分析期仍「默认拒绝」（静默挂起 + 「正在检查」提示），其余沿用旧规则。
    // if (settings.enabledGlobal && analyzing && !_hasStrongGesture(GESTURE_ANALYSIS_MS)) {
    //   if (highRisk && !hardBad) {
    //     confirmHighRiskDownload(item, (dlTab != null ? dlTab : _dlUiTab(item)), 'analysis');
    //     return true;
    //   }
    //   blockAutoDownload(item, (dlTab != null ? dlTab : _anyAnalyzingTab()), 'analysis');
    //   return true;
    // }
    if (!highRisk) {
      if (settings.enabledGlobal && analyzing && !_hasStrongGesture(GESTURE_ANALYSIS_MS)) {
        blockAutoDownload(item, (dlTab != null ? dlTab : _anyAnalyzingTab()), 'analysis');
        return true;
      }
      if (!settings.enabledGlobal || !settings.autoDownloadGuard) return false;
      if (!_hasGesture(GESTURE_FRESH_MS) && !_dlBlProtected(parseHost(item.url), settings)) {
        blockAutoDownload(item, (dlTab != null ? dlTab : _anyAnalyzingTab()), 'auto');
        return true;
      }
      return false;
    }

    // ② 高危文件（exe / msi / zip / dmg / 网盘 …）：**没有白名单豁免**。
    //   ★ 2026-11-23（授权模型）：黑名单是「硬判定」，命中就交给主链路 cancelDownload，
    //     不弹「是否允许」——否则等于把是否放行木马的决定权交还给用户。
    if (_isHardBadDownload(item, settings)) return false;
    if (!settings.enabledGlobal) return false;
    // 增强开关关闭、且当前不在分析期 → 不干预（保持老行为）
    if (!settings.autoDownloadGuard && !analyzing) return false;

    // ②0 每站首次确认（2026-11-23）：**优先级高于下面所有「用户意图」放行规则**。
    //   原因：②～③ 证明的只是「用户点了页面上的某个东西」，而流氓站正是靠一个假的「下载」按钮
    //   骗取这次点击；一旦点了，规则②就会静默放行 —— 这是现有模型的结构性缺口。
    //   因此某站第一次下载可执行文件时，一律先暂停并询问一次（与有没有手势无关）。
    //   但仍排在「硬黑名单」之后：黑名单命中直接拦，不给「是否允许」的选择。
    const siteKey = _siteKeyOfItem(item);
    if (siteKey && !_siteSeen(siteKey)) {
      console.log('[auto-dl] 该站首次下载可执行文件，先确认一次：' + siteKey + ' / ' + item.url);
      confirmHighRiskDownload(item, (dlTab != null ? dlTab : _dlUiTab(item)),
        analyzing ? 'analysis' : 'siteFirst', siteKey);
      return true;
    }

    // ★ 2026-11-23（体验修复）：授权判定提到「分析期」之前统一做 ——
    //   否则「点了下载链接 → 跳感谢页 → 新页面开始下载」会在分析窗口内被无条件问一次，
    //   用户看到的就是「明明是手点的还被拦」。分析期只是「还没来得及判危」，
    //   有明确的用户意图证据时不该打断。
    if (_authDecide(item, dlTab) === 'allow') {
      console.log('[auto-dl] 授权放行高危下载（' + (_sfAuth.lastReason || '') + '）：' + item.url);
      _markAuthPass(item);   // 让后面的「分析闸门」不要再次静默取消它
      // ★ 2026-11-23（放行轻提示）：只告知、不拦截。页面已授权（lastReason='page'）时不弹，
      //   避免「确认过一次后每次下载都弹一条」。
      _notifyAuthAllow(item, dlTab, _sfAuth.lastReason);
      return false;
    }
    // 无授权：分析期立刻问（不再静默挂起等 11 秒），否则按「每页第一次下载」问。
    //   siteKey 一并传下去：用户点「继续下载」时靠它把该站记入「已确认」名单。
    confirmHighRiskDownload(item, (dlTab != null ? dlTab : _dlUiTab(item)),
      analyzing ? 'analysis' : 'first', siteKey);
    return true;
  } catch (e) {}
  return false;
}

// 「放行轻提示」（2026-11-23）：判定为「用户意图」而**放行**时，给页面一条只告知、不拦截的提示。
// 目的：让用户知道「扩展看见了这次下载、认为是你点的」，而不是 silently 放进去了 —— 这样
//   一旦放行是误判（流氓站骗到一次点击），用户至少有机会发现并去下载器里取消。
// 不弹的情况：lastReason 为空 / 'page'（本页已由用户确认过，逐条弹会变成骚扰）。
function _notifyAuthAllow(item, tabId, reason) {
  try {
    if (!reason || reason === 'page') return;
    const tid = (tabId != null && tabId >= 0) ? tabId : _dlUiTab(item);
    if (tid == null || tid < 0) return;
    safeTabMsg(tid, {
      type: 'sf-allow-note',
      host: parseHost(item.url) || '',
      filename: item.filename || _fileOfUrl(item.url) || '',
      reason: reason
    });
  } catch (e) {}
}

// 临时放行某标签页的全部下载（秒级窗口）。用于内容脚本无法提取到具体下载 URL 的
// 场景（如 JS 触发 / 表单提交下载）：用户点了「仍要下载」但不知道会下到哪个 URL，
// 此时让后台在窗口期内对该标签发起的下载一律放行，避免被再次静默拦截。
const tempAllowedTabs = {}; // tabId -> 过期时间戳(ms)
function isTabTempAllowed(tabId) {
  if (tabId == null || tabId < 0) return false;
  const exp = tempAllowedTabs[tabId];
  if (!exp) return false;
  if (exp > Date.now()) return true;
  delete tempAllowedTabs[tabId]; // 顺手清理过期项
  return false;
}

// 记录每个标签页最近一次「顶级导航」的 URL，用于检测「危险站 → 跳转新站」的银狐跳转链
const lastTopUrl = {};
// 记录每个标签页「本次导航前的上一跳」页面 URL（用于下载来源归属回退：
// 当跳转下载的 referrer/initiator 为空时，用上一跳页面定位真实来源，避免秒跳下载漏归）
const prevTopUrl = {};
// 记录每次顶级导航「提交完成」的时间戳，用于识别「点进即下载 / 服务端强制下载」的自动下载竞速
const navCommitTime = {};
// 自动下载判定窗口：页面提交后该时间窗内发起的高危文件下载，视为「自动下载」而非用户手动点击
const AUTO_WINDOW_MS = 1500;

// ============================================================================
// 原作者的云端官网库已于 2026-11-01 完整移除
// ----------------------------------------------------------------------------
// 原实现：从 https://site-directory-cache.pages.dev/official-domains.json 拉取整库。
// 实测：3.94 MB / 250,603 条 / Tranco Top-1M 衍生的「热门站点」清单，
//       语义是「该域名足够主流，不按仿冒站处理」，并非人工审核的软件官网表。
// 移除原因：源由第三方控制且无签名校验（命中即撤销告警，存在漏放风险）；
//           本 fork 已移除 unlimitedStorage，该库会吃掉 10MB 配额的约 40%；
//           SW 每次唤醒需重建 25 万条 Set；且设置页无对应 UI，属静默运行。
// 替代方案：见本文件下方「我的云端库」模板（已注释，启用步骤写在模板头部）。
// 备份位置：.bak_20261101010207_remove-cloud/
// ============================================================================

// 分析闸门：标签页「检测未出结果前默认拒绝下载」的状态机
//   analyzing = 已加载、内容脚本尚未回传判定 → 该标签全部下载先取消挂起
//   safe      = 已判定安全 → 挂起下载静默重下，后续下载直接放行
//   danger    = 已判定危险 → 挂起下载保持取消并弹警告，后续下载按危险拦截
const analysisState = {};
const heldDownloads = {};       // tabId -> [{id,url,filename}]
const reissuedUrls = new Set(); // 判安后已静默重下的 URL，避免 onCreated 二次闸控
const analysisTimers = {};      // tabId -> 超时兜底句柄
// ★ 2026-11-11 超时重定（原 4000 太短）：
//   内容侧分析要跑 ICP / RDAP / 情报 enrichment，实测常 3–9 秒；后台闸门原先 4 秒就「失效开放」，
//   而内容侧的兜底是 6 秒 —— 也就是说第 4 秒下载已经被静默重下、第 6 秒才判出危险，文件早已落盘。
//   现在：内容侧名义分析预算 10s（横幅文案同步）、硬兜底 12s；后台 11s，
//   始终比内容侧多 1s，保证「判定先到、失效开放后到」，两侧不会互相抢跑。
const ANALYSIS_TIMEOUT_MS = 11000;

// 性能优化：模块级复用正则，避免重复编译
const WWW_RE = /^www\./;

const DEFAULTS = {
  enabledGlobal: true, showWarning: true, autoBlockDownloads: true, notify: true,
  // ★ 2026-11-23：增强版「自动下载拦截」——没有用户手势却自己开始的下载，永久拦截（不限分析期）。
  //   默认开启；只在「高危文件类型 + 无近期手势 + 非可信/官方/白名单主机」时才拦，避免误伤。
  autoDownloadGuard: true,
  // ★ 2026-11-23：拦截/询问下载时是否附一行「IDM/迅雷 可能已接管」的静态提示（内容脚本读取）。
  dlManagerNotice: true,
  // ★ 2026-11-23：运行时取链探测（解析器跟随）。已判危页面上，用一个不激活的后台标签页
  //   重跑该页自己的同源跳转端点，看载荷最终落在哪个域名。这是唯一会主动开标签页的行为，
  //   因此给一个显式开关（默认开，内容脚本与后台各判一次）。
  resolverFollow: true,
  // 敏感度：设置页已无对应控件（2026-11-11），恒为 'medium'；引擎侧依赖此值给阈值与组合升级分档
  sensitivity: 'medium',
  aiPersona: 'balanced',   // AI 助手性格档：'balanced' 均衡 | 'efficient' 高效 | 'gentle' 温柔 | 'pro' 严谨 | 'humorous' 幽默
  remindMode: 'normal',    // 扩展整体报毒识别/提醒偏好：'normal' 正常（危险告警 + 适度主动提示）| 'quiet' 安静（仅危险告警，不弹软提示/主动建议）
  // ICP 备案权威核验总开关：关闭后完全不向第三方备案接口发起任何请求，
  // 备案判定退回「仅扫描页面文本」的旧行为（判定更保守，但零外部请求）。
  icpApiVerify: true,
  enabled: {
    knownIoc: true, vmDetection: true, domainImpersonation: true, execDownload: true,
    cloudDiskDist: true, obfuscatedJs: true, fakeOfficial: true,
    socialEngineering: true, domainStructure: true, redirectIframe: true
  },
  allowlist: [], customKeywords: [], customBadDomains: [],
  // ★ 2026-11-23：用户自定义「黑名单例外」（可推翻自定义黑名单，不能推翻云端/内置黑名单）
  exceptionDomains: [],
  // 威胁情报 API（可选）：默认关闭；启用后扩展用用户自有 Key 实时查询当前域名在第三方情报库的判定。
  // 框架化设计：providers 下可动态增加更多情报源；VT / GSB 两个需 Key 的源均以密文存储。
  threatIntel: {
    enabled: false,
    providers: {
      // 两个 Key 都只以 AES-GCM 密文落盘（crypto-helper 加解密），明文仅在后台 SW 内短暂存在。
      // 兼容：旧版明文 VT Key 由 handler 直接使用，设置页打开时自动迁移为密文。
      virustotal: { enabled: false, apiKey: '' },
      googlesafebrowsing: { enabled: false, apiKey: '' },
      // 银狐防护云端名单（FoxAPI）：合作者维护的云端官网/信任名单。
      // 与其它情报源不同，它**不渲染横幅**，只作为本地评分的一个补充判据（见 content.js）。
      // Key 同样以 AES-GCM 密文落盘，且仅在后台 SW 内解密使用。
      foxapi: { enabled: false, apiKey: '' }
    }
  },
  // 社区维护的本地黑名单总开关（默认关闭）：关闭时三个名单既不加载、不自动更新，也不参与比对。
  // 开启后各名单再按自己的 enabled 开关决定是否参与。后续新增名单沿用同一结构即可。
  communityLists: { enabled: false },
  // OpenPhish 本地钓鱼黑名单：免费 feed.txt（无需 API Key），默认每天自动更新一次，
  // 名单保存在 chrome.storage.local；访问网站时与本地静态名单（域名集合）比对，命中即渲染横幅。
  openphish: { enabled: false, lastUpdated: 0 },
  // PhishDestroy 本地钓鱼黑名单：与 OpenPhish 并列的第二个静态名单源（约 14 万条裸域名），
  // 同样是「每日自动更新 + 手动更新 → 落盘 storage.local → 启动即载入内存常驻」。
  phishdestroy: { enabled: false, lastUpdated: 0 },
  // HaGeZi's Threat Intelligence Feeds（TIF）：AdBlock 语法，量级最大，机制同上但改用布隆位图
  hagezi: { enabled: false, lastUpdated: 0, variant: 'full' },
  // 2026-11-11 新增：两份「社区 AdBlock 风险名单」，结构同 TIF（布隆位图 + IndexedDB），
  // 但从 AdBlock 语法里**只提取整站域名规则** ||host^，IP / 路径 / 正则 / 例外 / TLD 规则全部丢弃。
  // badware = uBlock Origin - Badware risks；dsam = Dandelion Sprout's Anti-Malware List
  badware: { enabled: false, lastUpdated: 0 },
  dsam: { enabled: false, lastUpdated: 0 }
};

// ===== 威胁情报 API 注册表（框架化）=====
// 每个 provider 描述一个第三方情报源；只需在下方数组追加一项即可动态接入新情报源，
// 其余逻辑（启用判定 / 并行查询 / 仅返回恶意结果 / 缓存）完全复用，无需改动调用方。
// query(domain, apiKey, pageUrl) → 返回 { malicious:true, score, scoreMax, detail }（有评分源）
//   或 { malicious:true, detail }（无评分源，如 URLhaus 仅给出"检出/未检出"）
//   或 { malicious:false }（未检出）或 { error:true }（查询失败，视为未检出，不阻断页面）
// 注意：VirusTotal 对「域名」与「网址(URL)」分开统计；许多钓鱼站只在 URL 端点被引擎标红，
// 因此 VirusTotal provider 会同时查询两个端点，任一被标红即判恶意。

// 将字符串按 RFC 4648 做 base64url 编码（VT 的 /api/v3/urls/{id} 中 id 即 URL 的 base64url）
function base64urlEncode(str) {
  try {
    const bytes = new TextEncoder().encode(String(str));
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  } catch (e) { return null; }
}

// ===== VirusTotal 引擎分级（顶级 / 二级 / 小众）=====
// 名单由用户提供；比对前做归一化（小写，去掉空格/点/下划线/连字符/括号），
// 以兼容 VT 引擎名的写法差异（例如 "Google Safe Browsing" 与 "Google Safebrowsing"）。
// 归类优先级：顶级 > 小众 > 二级（二级与小众名单有重叠引擎时按更弱的「小众」计，
// 这样「三检查出」不会被不可信引擎凑数）。
function vtNormEngine(s) {
  return String(s || '').toLowerCase().replace(/[\s._\-()（）]/g, '');
}

const VT_TOP_NAMES = [
  'BitDefender',
  'Kaspersky',
  'ESET',
  'Fortinet',
  'Sophos',
  'Google Safe Browsing',
  'Dr.Web',
  'Emsisoft',
  'G-Data',
  'VIPRE',
  'Webroot',
  'Quick Heal',
  'Yandex Safebrowsing',
  'AlienVault',
  'Juniper Networks',
  'LevelBlue',
  'EmergingThreats',
  'URLhaus',
  'Phishtank',
  'OpenPhish'
];

const VT_SECOND_NAMES = [
  'alphaMountain.ai',
  'Cluster25',
  'CRDF',
  'CyRadar',
  'Forcepoint ThreatSeeker',
  'Lionic',
  'Rising',
  'Seclookup',
  'SOCRadar',
  'URLQuery',
  'DNS8',
  'Gridinsoft',
  'Abusix',
  'Acronis',
  'ADMINUSLabs',
  'AILabs (MONITORAPP)',
  'Antiy-AVL',
  'BlockList',
  'Blueliv',
  'Certego',
  'Chong Lua Dao',
  'CINS Army',
  'CTX AI',
  'Cyble',
  'desenmascara.me',
  'ESTsecurity',
  'GreenSnow',
  'Heimdal Security',
  'IPsum',
  'Malwared',
  'MalwarePatrol',
  'Phishing Database',
  'PREBYTES',
  'Quttera',
  'Sangfor',
  'Scantitan',
  'SCUMWARE.org',
  'StopForumSpam',
  'Sucuri SiteCheck',
  'ThreatHive',
  'Viettel Threat Intelligence',
  'ViriBack',
  'VX Vault',
  'ZeroCERT',
  '0xSI_f33d',
  'AlphaSOC',
  'ArcSight Threat Intelligence',
  'AutoShun',
  'Bfore.Ai PreCrime',
  'ChainPatrol',
  'Criminal IP',
  'CSIS Security Group',
  'Cyan',
  'Ermes',
  'Fortra',
  'GCP Abuse Intelligence',
  'GreyNoise',
  'Guardpot',
  'Hunt.io Intelligence',
  'K7AntiVirus',
  'Lumu',
  'MalwareURL',
  'Mimecast',
  'Netcraft',
  'Orcapot',
  'PhishFort',
  'PrecisionSec',
  'SafeToOpen',
  'Sansec eComscan',
  'Snort IP sample list',
  'Synthient',
  'Xcitium Verdict Cloud',
  'ZeroFox'
];

const VT_NICHE_NAMES = [
  'Bkav',
  'Blueliv',
  'CINS Army',
  'IPsum',
  'Malwared',
  'SCUMWARE.org',
  'StopForumSpam',
  'ViriBack',
  'VX Vault',
  '0xSI_f33d',
  'AutoShun',
  'Guardpot',
  'Orcapot',
  'Snort IP sample list',
  'Synthient'
];

const VT_TOP_SET = new Set(VT_TOP_NAMES.map(vtNormEngine));
const VT_SECOND_SET = new Set(VT_SECOND_NAMES.map(vtNormEngine));
const VT_NICHE_SET = new Set(VT_NICHE_NAMES.map(vtNormEngine));

// 按「检出引擎落在哪一档」给出三档结论：
//   顶级 >= 2              → alert   请提高警惕
//   顶级 == 1 或 二级 >= 3 → caution 请保持谨慎，不要点击来路不明的链接
//   其余（仅小众/二级<3）  → fp      可能是误报
// 仅统计 category 为 malicious / suspicious 的引擎（harmless / undetected / timeout 不算检出）。
function vtClassifyEngines(lastResults) {
  if (!lastResults || typeof lastResults !== 'object') return null;
  const hits = { top: [], second: [], niche: [], other: [] };
  // 逐引擎明细：供内容脚本「详情」按钮展开显示（引擎名 + 等级 + 检出类别）。
  // 用短键 n/t/r/c 压缩体积（一次最多几十条，随消息传给内容脚本）。
  const engines = [];
  const seen = new Set();   // 域名端点与 URL 端点可能返回同一引擎，按归一化名称去重
  Object.keys(lastResults).forEach(function (k) {
    const v = lastResults[k] || {};
    const cat = String(v.category || '').toLowerCase();
    if (cat !== 'malicious' && cat !== 'suspicious') return;
    const name = String(v.engine_name || k || '').trim();
    if (!name) return;
    const n = vtNormEngine(name);
    if (seen.has(n)) return;
    seen.add(n);
    let tier = 'other';
    if (VT_TOP_SET.has(n)) { hits.top.push(name); tier = 'top'; }
    else if (VT_NICHE_SET.has(n)) { hits.niche.push(name); tier = 'niche'; }
    else if (VT_SECOND_SET.has(n)) { hits.second.push(name); tier = 'second'; }
    else hits.other.push(name);
    engines.push({ n: name, t: tier, r: String(v.result || '').trim(), c: cat });
  });
  // 明细按「顶级 → 二级 → 小众 → 未分级」排序，同级按引擎名字母序，与横幅结论的严重度顺序一致
  const TIER_RANK = { top: 0, second: 1, niche: 2, other: 3 };
  engines.sort(function (a, b) {
    const d = (TIER_RANK[a.t] || 0) - (TIER_RANK[b.t] || 0);
    return d !== 0 ? d : String(a.n).localeCompare(String(b.n));
  });
  const fmt = function (a) {
    if (!a.length) return '';
    const head = a.slice(0, 4).join('、');
    return a.length > 4 ? (head + ' 等 ' + a.length + ' 个') : head;
  };
  const topHits = hits.top, secHits = hits.second, nicheHits = hits.niche, otherHits = hits.other;
  let level = 'fp', text = '';
  if (topHits.length >= 2) {
    level = 'alert';
    text = 'VirusTotal：请提高警惕（顶级引擎 ' + topHits.length + ' 个检出：' + fmt(topHits) + '）';
  } else if (topHits.length === 1 || secHits.length >= 3) {
    level = 'caution';
    const why = [];
    if (topHits.length === 1) why.push('顶级引擎检出：' + topHits[0]);
    if (secHits.length) {
      why.push('二级引擎 ' + secHits.length + ' 个检出' + (secHits.length <= 4 ? '：' + fmt(secHits) : ''));
    }
    text = 'VirusTotal：请保持谨慎，不要点击来路不明的链接（' + why.join('；') + '）';
  } else if (nicheHits.length) {
    text = 'VirusTotal：可能是误报（仅 ' + nicheHits.length + ' 个小众引擎检出：' + fmt(nicheHits) + '）';
  } else if (secHits.length) {
    text = 'VirusTotal：可能是误报（仅 ' + secHits.length + ' 个二级引擎检出：' + fmt(secHits) + '）';
  } else if (otherHits.length) {
    text = 'VirusTotal：可能是误报（仅 ' + otherHits.length + ' 个未分级引擎检出：' + fmt(otherHits) + '）';
  } else {
    text = 'VirusTotal：可能是误报（检出引擎均不在分级名单内）';
  }
  return { level: level, text: text, top: topHits, second: secHits, niche: nicheHits, other: otherHits, engines: engines };
}

// ===== 情报源字段中文化 / 日期规整（URLhaus、NetAPI 共用）=====
// URLhaus 的 threat 标签是英文机器值（malware_download 等），直接展示对普通用户不可读，
// 这里做中文映射；未收录的标签原样显示，保证新增类型不会丢信息。
const URLHAUS_THREAT_LABELS = {
  malware_download: '恶意软件下载',
  malware_upload: '恶意软件上传',
  malware: '恶意软件',
  malware_distribution: '恶意软件分发',
  phishing: '钓鱼站点',
  botnet_cc: '僵尸网络 C2',
  botnet: '僵尸网络',
  c2: 'C2 服务器',
  ransomware: '勒索软件',
  loader: '加载器',
  dropper: '释放器',
  exploit: '漏洞利用',
  'exploit kit': '漏洞利用套件',
  scam: '诈骗',
  spam: '垃圾邮件',
  ddos: 'DDoS 攻击源',
  'malicious url': '恶意网址'
};
function urlhausThreatLabel(t) {
  const raw = String(t || '').trim();
  if (!raw) return '';
  return URLHAUS_THREAT_LABELS[raw.toLowerCase()] || raw;
}

// NetAPI 的 block_reason 同样返回英文来源标签，映射成中文并保留原值对照
const NETAPI_REASON_LABELS = {
  phishing: '钓鱼',
  malware: '恶意软件',
  malware_distribution: '恶意软件分发',
  c2: '命令与控制服务器',
  botnet: '僵尸网络',
  ransomware: '勒索软件',
  exploit: '漏洞利用',
  spam: '垃圾邮件',
  scam: '诈骗',
  brute_force: '暴力破解',
  scanning: '扫描探测',
  compromised: '站点失陷'
};
function netapiReasonLabel(r) {
  const raw = String(r || '').trim();
  if (!raw) return '';
  return NETAPI_REASON_LABELS[raw.toLowerCase()] || raw;
}

// 把接口返回的时间串统一成 YYYY-MM-DD（无法识别时截断原值，避免超长打乱横幅布局）
function fmtIntelDate(v) {
  const s = String(v || '').trim();
  if (!s) return '';
  const m = s.match(/^(\d{4}-\d{2}-\d{2})/);
  if (m) return m[1];
  const t = Date.parse(s);
  if (isFinite(t)) {
    try { return new Date(t).toISOString().slice(0, 10); } catch (e) {}
  }
  return s.slice(0, 20);
}

const THREAT_INTEL_PROVIDERS = [
  {
    id: 'virustotal',
    name: 'VirusTotal',
    hasScore: true,
    encryptsKey: true,        // Key 以 AES-GCM 密文落盘，查询前由 handler 解密（明文不出后台）
    async query(domain, apiKey, pageUrl) {
      if (!apiKey) return { error: true, reason: 'no_key' };
      const key = String(apiKey).trim();   // 去除复制粘贴可能带入的首尾空格
      if (!key) return { error: true, reason: 'no_key' };
      const headers = { 'x-apikey': key };

      // 并行查询「域名端点」与「网址(URL)端点」——VT 对二者分开统计，
      // 钓鱼站常在 URL 端点被标红而域名端点仍为空，必须两者都查。
      const tasks = [
        fetch('https://www.virustotal.com/api/v3/domains/' + encodeURIComponent(domain), { headers })
      ];
      let urlId = null;
      if (pageUrl && /^https?:\/\//i.test(pageUrl)) {
        try { urlId = base64urlEncode(pageUrl); } catch (e) { urlId = null; }
      }
      if (urlId) {
        tasks.push(fetch('https://www.virustotal.com/api/v3/urls/' + encodeURIComponent(urlId), { headers }));
      }

      const settled = await Promise.allSettled(tasks);
      const domRes = settled[0];
      const urlRes = settled[1];

      // 解析域名端点（attributes 里同时含 last_analysis_stats 与 last_analysis_results，
      // 后者是逐引擎判定，用于按「顶级/二级/小众引擎」分级——只留 stats 就无法分级）
      let domAttr = null, domErr = null;
      if (domRes && domRes.status === 'fulfilled') {
        const r = domRes.value;
        if (r.status === 401 || r.status === 403) return { error: true, status: r.status, reason: 'auth', detail: 'API Key 无效或权限不足' };
        if (!r.ok) domErr = { status: r.status };
        else { const j = await r.json().catch(() => null); domAttr = (j && j.data && j.data.attributes) || null; }
      } else { domErr = { status: 0, reason: 'network' }; }

      // 解析网址端点
      let urlAttr = null, urlErr = null;
      if (urlId && urlRes && urlRes.status === 'fulfilled') {
        const r = urlRes.value;
        if (r.status === 401 || r.status === 403) return { error: true, status: r.status, reason: 'auth', detail: 'API Key 无效或权限不足' };
        if (!r.ok) urlErr = { status: r.status };
        else { const j = await r.json().catch(() => null); urlAttr = (j && j.data && j.data.attributes) || null; }
      }
      const domStats = (domAttr && domAttr.last_analysis_stats) || null;
      const urlStats = (urlAttr && urlAttr.last_analysis_stats) || null;

      // 合并：优先采用被标红的来源（URL 或 域名）
      const flaggedOf = function (s) { if (!s) return 0; return (s.malicious || 0) + (s.suspicious || 0); };
      const totalOf = function (s) { if (!s) return 0; return (s.malicious || 0) + (s.suspicious || 0) + (s.harmless || 0) + (s.undetected || 0) + (s.timeout || 0); };
      const flaggedDom = flaggedOf(domStats), flaggedUrl = flaggedOf(urlStats);
      let stats = null, srcLabel = '', attr = null;
      if (flaggedUrl > 0) { stats = urlStats; attr = urlAttr; srcLabel = '网址'; }
      else if (flaggedDom > 0) { stats = domStats; attr = domAttr; srcLabel = '域名'; }

      if (stats) {
        const malicious = stats.malicious || 0;
        const suspicious = stats.suspicious || 0;
        const total = totalOf(stats) || 1;
        const flagged = malicious + suspicious;
        // 逐引擎分级：决定横幅走「可能是误报 / 请保持谨慎 / 请提高警惕」哪一档
        const cls = vtClassifyEngines(attr && attr.last_analysis_results);
        const tierNote = cls
          ? '（顶级 ' + cls.top.length + ' / 二级 ' + cls.second.length + ' / 小众 ' + cls.niche.length + ' / 未分级 ' + cls.other.length + '）'
          : '';
        return {
          malicious: true,
          score: flagged,
          scoreMax: total,
          src: srcLabel,
          vtLevel: cls ? cls.level : '',
          verdictText: cls ? cls.text : '',
          engines: (cls && Array.isArray(cls.engines)) ? cls.engines : [],
          detail: '来源=' + srcLabel + '，恶意 ' + malicious + ' / 可疑 ' + suspicious + ' / 共 ' + total + ' 个引擎，评分 ' + flagged + '/' + total + tierNote
        };
      }

      // 两个端点都无标红：若任一端点鉴权失败(401/403)仍按错误上报，否则视为判安全
      const authErr = (domErr && (domErr.status === 401 || domErr.status === 403)) || (urlErr && (urlErr.status === 401 || urlErr.status === 403));
      if (authErr) return { error: true, status: 401, reason: 'auth', detail: 'API Key 无效或权限不足' };
      const httpErr = (domErr && domErr.status && domErr.status !== 200) || (urlErr && urlErr.status && urlErr.status !== 200);
      if (httpErr) return { error: true, status: (domErr && domErr.status) || (urlErr && urlErr.status) || 0, reason: 'http' };
      return { malicious: false };
    }
  },
  // —— URLhaus（abuse.ch，无需 Key）：并行查询「主机」与「当前 URL」——
  // 判定标准（2026-11 细化）：只有存在「活跃证据」才判为当前恶意——
  //   · 精确 URL 命中且 url_status === 'online'；或
  //   · 主机在线恶意 URL 数（urls_online 或 urls 里 status=online 的条数）> 0。
  // 仅有历史记录（全部 offline）时降级为 stale：仍然提示「曾被标记」，但用「历史记录 / 目前无活跃记录」
  // 的限定措辞，配色也降到琥珀档，避免把早已下线的旧记录说成「该网站是恶意的」。
  {
    id: 'urlhaus',
    name: 'URLhaus',
    hasScore: false,
    order: 1,
    async query(domain, apiKey, pageUrl) {
      const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
      const tasks = [
        { kind: 'host', p: fetch('https://urlhaus-api.abuse.ch/v1/host/', { method: 'POST', headers: headers, body: 'host=' + encodeURIComponent(domain) }) }
      ];
      if (pageUrl && /^https?:\/\//i.test(pageUrl)) {
        tasks.push({ kind: 'url', p: fetch('https://urlhaus-api.abuse.ch/v1/url/', { method: 'POST', headers: headers, body: 'url=' + encodeURIComponent(pageUrl) }) });
      }
      const settled = await Promise.allSettled(tasks.map(function (t) { return t.p; }));
      let hostHit = null, urlHit = null;
      for (let i = 0; i < settled.length; i++) {
        const s = settled[i];
        if (!s || s.status !== 'fulfilled') continue;
        let j = null;
        try { j = await s.value.json(); } catch (e) { continue; }
        // query_status: "ok" 表示命中；"no_results"/"invalid_host" 等表示未命中
        if (!j || j.query_status !== 'ok') continue;
        if (tasks[i].kind === 'url') urlHit = j; else hostHit = j;
      }
      if (!hostHit && !urlHit) return { malicious: false };

      const threats = [];
      const addThreat = function (t) {
        const v = String(t || '').trim();
        if (v && threats.indexOf(v) < 0) threats.push(v);
      };
      const dates = [];
      let onlineCount = 0, offlineCount = 0, exactOnline = false, exactOffline = false;

      if (hostHit) {
        const list = Array.isArray(hostHit.urls) ? hostHit.urls : [];
        list.forEach(function (u) {
          if (!u) return;
          const st = String(u.url_status || '').toLowerCase();
          if (st === 'online') onlineCount++; else if (st) offlineCount++;
          addThreat(u.threat);
          if (u.date_added) dates.push(String(u.date_added));
        });
        // 接口可能只回传部分 url 明细，但汇总字段更准：取两者较大值
        const rep = Number(hostHit.urls_online);
        if (isFinite(rep) && rep > onlineCount) onlineCount = rep;
        const totalRep = Number(hostHit.url_count);
        if (isFinite(totalRep) && totalRep > onlineCount + offlineCount) offlineCount = totalRep - onlineCount;
        if (hostHit.firstseen) dates.push(String(hostHit.firstseen));
      }
      if (urlHit) {
        const st = String(urlHit.url_status || '').toLowerCase();
        if (st === 'online') exactOnline = true; else if (st) exactOffline = true;
        addThreat(urlHit.threat);
        if (urlHit.date_added) dates.push(String(urlHit.date_added));
      }

      const onlineTotal = onlineCount + (exactOnline && onlineCount === 0 ? 1 : 0);
      const active = onlineTotal > 0;
      const totalCount = onlineTotal + offlineCount;
      // ISO / "YYYY-MM-DD HH:MM:SS" 串的字典序即时间序，取最大即最近记录
      const recent = dates.slice().sort().slice(-1)[0] || '';
      const recentStr = fmtIntelDate(recent);
      const threatStr = threats.map(urlhausThreatLabel).filter(Boolean).join('、');
      const targetLabel = (exactOnline || exactOffline) ? '精确 URL' : '主机';

      const facts = [
        '数据来源：URLhaus（abuse.ch）',
        '查询目标：' + targetLabel,
        '在线恶意 URL：' + onlineTotal + ' 条' + (exactOnline ? '（当前网址在列）' : ''),
        '历史记录（已离线）：' + offlineCount + ' 条',
        '威胁类型：' + (threatStr || '未标注'),
        recentStr ? '最近记录：' + recentStr : ''
      ].filter(Boolean);

      if (active) {
        return {
          malicious: true,
          active: true,
          stale: false,
          verdictText: 'URLhaus：当前存在活跃的恶意内容关联记录（在线 ' + onlineTotal + ' 条）',
          detail: '在线 ' + onlineTotal + ' / 已离线 ' + offlineCount + ' 条' + (threatStr ? '，' + threatStr : '') + (recentStr ? '，最近 ' + recentStr : ''),
          facts: facts
        };
      }
      return {
        malicious: true,
        active: false,
        stale: true,          // 仅历史记录：内容脚本据此降级为琥珀配色 + 限定措辞
        verdictText: 'URLhaus：该地址曾被标记为恶意内容分发（最后记录于 ' + (recentStr || '未知日期') + '），目前无活跃记录，仅供参考',
        detail: '仅历史记录 ' + (totalCount || 1) + ' 条（均已离线）' + (threatStr ? '，' + threatStr : ''),
        facts: facts
      };
    }
  },
  // —— NetAPI（netapi.com，免费方法无需 Key）：查询域名是否在失陷情报库 ——
  // 判定标准（2026-11 细化）：listed_now=true（24h 内在列）= 当前失陷，判为 malicious 并提示「请谨慎」；
  // listed_ever 仅为历史记录：不判「当前恶意」，但最近一次记录在 1 年内时以「历史记录」口径轻提示一次
  // （超过 1 年的旧记录噪音太大，直接忽略，避免耽误用户）。
  // NetAPI 官方明确说明：域名在列不代表持有者存在恶意意图，很多站点是在不知情的情况下被入侵托管了钓鱼页，
  // 故文案一律使用「可能为被入侵的受害者站点」等限定措辞，绝不断言「该网站是恶意的」。
  {
    id: 'netapi',
    name: 'NetAPI',
    hasScore: false,
    order: 2,
    async query(domain, apiKey, pageUrl) {
      let res;
      try {
        res = await fetch('https://netapi.com/api-json/?method=compromised-check&value=' + encodeURIComponent(domain));
      } catch (e) {
        return { error: true, reason: 'network', detail: String((e && e.message) || e) };
      }
      if (!res.ok) {
        if (res.status === 429) return { error: true, status: 429, reason: 'ratelimit' };
        return { error: true, status: res.status, reason: 'http' };
      }
      let j = null;
      try { j = await res.json(); } catch (e) { return { error: true, reason: 'json' }; }
      if (j && j.error) {
        return { error: true, reason: 'api', detail: (j.error && j.error.message) || 'NetAPI 查询错误' };
      }
      if (!j) return { malicious: false };

      const listedNow = j.listed_now === true;
      const listedEver = j.listed_ever === true;
      if (!listedNow && !listedEver) return { malicious: false };

      const firstStr = fmtIntelDate(j.first_seen);
      const lastStr = fmtIntelDate(j.last_seen);
      const reasonRaw = String(j.block_reason || '').trim();
      const reasonZh = netapiReasonLabel(reasonRaw);
      const matched = String(j.matched_value || '').trim();

      const facts = [
        '数据来源：NetAPI（compromised-check）',
        '监控状态：' + (listedNow ? '当前在列（24 小时内被报告）' : '仅历史记录（当前未在列表中）'),
        firstStr ? '首次记录：' + firstStr : '',
        lastStr ? '最近记录：' + lastStr : '',
        reasonRaw ? ('来源标签：' + reasonZh + (reasonZh !== reasonRaw ? '（' + reasonRaw + '）' : '')) : '',
        (matched && matched.toLowerCase() !== String(domain || '').toLowerCase()) ? ('匹配值：' + matched) : '',
        '说明：域名出现在失陷名单中，可能是站点被入侵后被动托管了恶意内容，不代表持有者存在恶意意图'
      ].filter(Boolean);

      if (listedNow) {
        return {
          malicious: true,
          active: true,
          stale: false,
          verdictText: 'NetAPI：该域名近期（24 小时内）出现在威胁情报监控列表中，可能为被入侵的受害者站点，请谨慎',
          detail: '当前在列' + (reasonZh ? '，来源标签：' + reasonZh : '') + (lastStr ? '，最近记录 ' + lastStr : ''),
          facts: facts
        };
      }

      // 仅历史记录：最近一次在 1 年内才提示
      const ts = Date.parse(String(j.last_seen || '')) || Date.parse(String(j.first_seen || ''));
      const withinYear = isFinite(ts) && (Date.now() - ts) < 365 * 24 * 3600 * 1000;
      if (!withinYear) return { malicious: false };
      return {
        malicious: true,
        active: false,
        stale: true,
        verdictText: 'NetAPI：该域名有历史失陷记录（最近一次 ' + (lastStr || '未知日期') + '），当前未在监控列表中，仅供参考',
        detail: '仅历史记录，当前未在列' + (reasonZh ? '，来源标签：' + reasonZh : ''),
        facts: facts
      };
    }
  },
  // —— Google Safe Browsing（v4 Lookup API，需自有 API Key；Key 以密文存储，见 background 解密分支）——
  // 说明：Google Safe Browsing API v4 已被官方标记为「已淘汰（deprecated）」，推荐使用 v4 的 Lookup API
  //   （即本实现所用的 threatMatches:find）或迁移到 Web Risk。此处仅用于「疑似」提示，绝不断言「该网站不安全」。
  // 横幅措辞必须带「疑似 / 可能」等限定词（GSB 返回 matches 即视为疑似命中）。
  {
    id: 'googlesafebrowsing',
    name: 'Google Safe Browsing',
    hasScore: false,
    order: 3,                 // 显示在 NetAPI(2) 下方
    encryptsKey: true,        // 提示 sf-intel-query handler 在调用前先解密 apiKey
    async query(domain, apiKey, pageUrl) {
      if (!apiKey) return { error: true, reason: 'no_key' };
      const key = String(apiKey).trim();
      if (!key) return { error: true, reason: 'no_key' };
      // 优先用完整页面 URL（GSB 对 URL 做归一化匹配，最贴近真实命中）；无 URL 时回退到 http://domain/
      const targetUrl = (pageUrl && /^https?:\/\//i.test(pageUrl)) ? pageUrl : ('http://' + domain + '/');
      const url = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' + encodeURIComponent(key);
      const body = {
        client: { clientId: 'silverfoxblocker', clientVersion: '1.0.6' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['WINDOWS', 'ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url: targetUrl }]
        }
      };
      let res;
      try {
        res = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body)
        });
      } catch (e) {
        return { error: true, reason: 'network', detail: String((e && e.message) || e) };
      }
      if (!res.ok) {
        // 400 多为 Key 无效 / 请求格式错误；403 为权限或配额耗尽
        if (res.status === 400) return { error: true, status: 400, reason: 'auth', detail: 'API Key 无效或请求被拒（请检查 Google Cloud 控制台中该 Key 是否启用 Safe Browsing API 且未限制来源）' };
        if (res.status === 403) return { error: true, status: 403, reason: 'auth', detail: 'API Key 权限不足或配额耗尽' };
        return { error: true, status: res.status, reason: 'http' };
      }
      let j = null;
      try { j = await res.json(); } catch (e) { return { error: true, reason: 'json' }; }
      // matches 非空即视为「疑似命中」（v4 Lookup 已标记淘汰，仅作疑似提示，不做绝对断言）
      if (j && Array.isArray(j.matches) && j.matches.length > 0) {
        const types = j.matches.map(function (m) { return (m.threatType || '').toLowerCase(); }).filter(Boolean);
        const uniq = types.filter(function (t, i) { return types.indexOf(t) === i; });
        const labelMap = {
          'malware': '恶意软件', 'social_engineering': '钓鱼/社工', 'unwanted_software': '潜在多余软件',
          'potentially_harmful_application': '可能有害的程序', 'api_abuse': 'API 滥用'
        };
        const zh = uniq.map(function (t) { return labelMap[t] || t; });
        return {
          malicious: true,
          soft: true,   // 软判定：横幅必须用「疑似/可能」措辞，不断言「该网站不安全」
          detail: 'Google 安全浏览疑似将其标记为存在风险（类型=' + (zh.join('/') || '未知') + '）。此判定来自谷歌威胁情报库，仅供参考，不代表本扩展断言该网站已确认不安全。'
        };
      }
      return { malicious: false };
    }
  }
];

// ===== 银狐防护云端名单（FoxAPI，合作者 Yinbo 维护）=====
// 与上面 THREAT_INTEL_PROVIDERS 的区别（刻意不注册为 provider）：
//   · 它**不渲染任何横幅**——用户明确要求「开启后不显示横幅，只作为评分判据」；
//   · 它返回的是「该域名是否在合作者的云端官网/信任名单里」，不是一个恶意判定，
//     不能套用「命中即横幅」的展示模型；
//   · 结果由内容脚本取走并并入本地评分（official:false → +45 分），因此走独立消息。
// 保护措施：
//   · Key 与 VT / GSB 一样以 AES-GCM 密文落盘，只在后台 SW 内解密，绝不进入页面上下文；
//   · 免费额度有限（对方为 Go 版，约 2 次/秒），本扩展主动二次限流为**每秒最多 1 次**；
//   · 同一域名结果缓存 10 分钟，避免站内多点导航反复消耗额度。
const FOXAPI_ENDPOINT = 'https://api.silverfoxguard.dpdns.org/v1/domain/lookup';
const FOXAPI_MIN_INTERVAL = 1000;              // 两次请求的最小间隔（ms）
const FOXAPI_CACHE_TTL = 10 * 60 * 1000;       // 单域名结果缓存 10 分钟
const FOXAPI_TIMEOUT = 8000;
const _foxCache = new Map();                   // host -> { t, data }
let _foxLastAt = 0;                            // 上次实际发起请求的时间
let _foxQueue = Promise.resolve();             // 串行队列：保证并发页面不会同时打过去

async function foxApiLookup(host) {
  const h = String(host || '').toLowerCase().trim();
  if (!h) return { ok: false, reason: 'no_host' };

  const cached = _foxCache.get(h);
  if (cached && (Date.now() - cached.t) < FOXAPI_CACHE_TTL) return cached.data;

  const s = await getSettings();
  const ti = (s && s.threatIntel) || {};
  const cfg = (ti.providers && ti.providers.foxapi) || {};
  // 总开关或本项未开启 → 一次请求都不发
  if (!ti.enabled || !cfg.enabled) return { ok: false, reason: 'disabled' };

  let key = cfg.apiKey || '';
  if (key && typeof sfLooksEncrypted === 'function' && sfLooksEncrypted(key)) {
    try { key = await sfDecryptKey(key); } catch (e) { key = ''; }
  }
  if (!key) return { ok: false, reason: 'no_key' };

  // 串行 + 最小间隔：把「并发 tab」摊平到每秒 1 次，避免触发对方限流
  const run = async () => {
    const wait = FOXAPI_MIN_INTERVAL - (Date.now() - _foxLastAt);
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
    _foxLastAt = Date.now();

    const ctrl = new AbortController();
    const timer = setTimeout(function () { try { ctrl.abort(); } catch (e) {} }, FOXAPI_TIMEOUT);
    try {
      const res = await fetch(FOXAPI_ENDPOINT + '?domain=' + encodeURIComponent(h), {
        method: 'GET',
        headers: { 'Authorization': 'Bearer ' + key },   // Key 只在请求头里，不写日志、不进 URL
        cache: 'no-store',
        signal: ctrl.signal
      });
      if (res.status === 401 || res.status === 403) return { ok: false, status: res.status, reason: 'auth' };
      if (res.status === 429) return { ok: false, status: 429, reason: 'ratelimit' };
      if (!res.ok) return { ok: false, status: res.status, reason: 'http' };
      let j = null;
      try { j = await res.json(); } catch (e) { return { ok: false, reason: 'json' }; }
      if (!j || typeof j.official !== 'boolean') return { ok: false, reason: 'format' };
      const data = {
        ok: true,
        official: j.official,
        matched: String(j.matched || ''),
        source: String(j.source || '')
      };
      _foxCache.set(h, { t: Date.now(), data: data });
      // 缓存上限：极端情况下（大量不同域名）避免无限增长
      if (_foxCache.size > 500) {
        const first = _foxCache.keys().next().value;
        if (first) _foxCache.delete(first);
      }
      return data;
    } catch (e) {
      const aborted = e && (e.name === 'AbortError' || /abort/i.test(String(e.message || '')));
      return { ok: false, reason: aborted ? 'timeout' : 'network' };
    } finally {
      clearTimeout(timer);
    }
  };

  const task = _foxQueue.then(run, run);
  _foxQueue = task.then(function () {}, function () {});   // 队列永不因单次失败中断
  return task;
}

// 情报查询结果内存缓存（按 hostname，10 分钟有效），避免重复查询命中 API 速率限制
const _intelCache = {};
const _INTEL_CACHE_TTL = 10 * 60 * 1000;

// ===== OpenPhish 本地钓鱼黑名单（免费 feed.txt，无需 API Key）=====
// 设计：后台定时（默认每天）抓取 https://openphish.com/feed.txt，解析出域名集合存入
// chrome.storage.local；访问网站时内容脚本把 hostname 发来，后台用内存 Set 做 O(1) 本地比对。
// 名单保存在本地、不上传，符合「本地静态黑名单」诉求。
// OpenPhish 免费公开钓鱼 feed：openphish.com/feed.txt 会 302 跳转到 GitHub raw，
// 而该跳转响应无 CORS 头，扩展 service worker 的 fetch 跨域重定向会被拦（报 Failed to fetch）。
// 故直接拉取「最终内容源」，并按「jsDelivr 镜像(中国可达性最好) → GitHub raw → openphish 官方(兜底)」顺序尝试，
// 任一成功即采用，最大化在受限网络下也能更新成功。
// 中国大陆网络常无法解析 cdn.jsdelivr.net / raw.githubusercontent.com（DNS 污染/封锁）。
// 故优先使用 jsDelivr 的备用域名（fastly / gcore / testingcf，实测均返回真实 feed 且带 CORS *），
// 再退到 GitHub 反代(gh-proxy.com)，最后才用原域名与 openphish 官方源兜底；任一成功即采用。
const OPENPHISH_FEED_SOURCES = [
  'https://fastly.jsdelivr.net/gh/openphish/public_feed@main/feed.txt',
  'https://gcore.jsdelivr.net/gh/openphish/public_feed@main/feed.txt',
  'https://testingcf.jsdelivr.net/gh/openphish/public_feed@main/feed.txt',
  'https://gh-proxy.com/https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt',
  'https://cdn.jsdelivr.net/gh/openphish/public_feed@main/feed.txt',
  'https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt',
  'https://openphish.com/feed.txt'
];
const SF_OP_DOMAINS_KEY = 'sfOpenPhishDomains';   // storage.local: string[]（已 lowercased 的域名）
const SF_OP_META_KEY = 'sfOpenPhishMeta';         // storage.local: { updated, count, error }
let _opDomains = null;                            // 内存缓存 Set，加速页面访问时的本地比对
let _opMeta = null;                               // 内存缓存 meta（避免每次导航都读一次 storage.local）

async function loadOpenPhishDomains() {
  try {
    const r = await new Promise((res) => chrome.storage.local.get({ [SF_OP_DOMAINS_KEY]: [], [SF_OP_META_KEY]: null }, res));
    _opDomains = new Set((r[SF_OP_DOMAINS_KEY] || []).map((d) => String(d).toLowerCase()));
    _opMeta = r[SF_OP_META_KEY] || { updated: 0, count: _opDomains.size, error: '' };
  } catch (e) { _opDomains = new Set(); _opMeta = { updated: 0, count: 0, error: '' }; }
  return _opDomains;
}

// 通用：域名是否命中某个本地名单 Set —— 先精确匹配，再逐级回溯父域
// （www.a.evil.com → a.evil.com → evil.com）。实测 14 万条名单下每级 has() 约 15ns，整轮 <0.2µs。
function domainListHit(set, host) {
  if (!set || !set.size) return false;
  let d = String(host || '').toLowerCase();
  if (d.charAt(d.length - 1) === '.') d = d.slice(0, -1);
  while (d) {
    if (set.has(d)) return true;
    const i = d.indexOf('.');
    if (i < 0) return false;
    d = d.slice(i + 1);
  }
  return false;
}
function openPhishHit(host) { return domainListHit(_opDomains, host); }

// 社区维护的本地黑名单总开关（默认关）：关闭时三个名单不加载、不更新、不比对。
// 单独抽成函数，后续新增名单只需在后台上沿用同一个判定，不必重复读 settings。
async function communityListsOn() {
  try {
    const s = await getSettings();
    return !!(s && s.communityLists && s.communityLists.enabled);
  } catch (e) { return false; }
}
// 关闭总开关时立刻释放常驻内存（HaGeZi 位图约 5MB），不必等 SW 被回收
function releaseCommunityLists() {
  _opDomains = null; _opMeta = null;
  _pdDomains = null; _pdMeta = null;
  _hgBits = null; _hgMeta = null; _hgCount = 0; _hgLoadTried = false;
  // 两份 AdBlock 风险名单（位图很小，但同样按「关掉即释放」处理，语义一致）
  try {
    Object.keys(_adl).forEach(function (k) {
      _adl[k].bits = null; _adl[k].m = 0; _adl[k].count = 0;
      _adl[k].loadTried = false; _adl[k].meta = null;
    });
  } catch (e) {}
}

// 将 feed 文本解析为去重域名数组（仅收录含点、无空格/端口冒号的「域名形态」，避免把异常行当域名污染名单）
function extractOpenPhishDomains(text) {
  // 跳过 # 开头的注释行：PhishDestroy 的 domains.txt 头部有
  // "# Destroylist ... | 142,347 domains ..." 与 "# https://github.com/..."，
  // 不过滤的话后者会被解析成 github.com 混进名单。
  const lines = String(text).split(/\r?\n/).map((l) => l.trim()).filter((l) => l && l.charAt(0) !== '#');
  const domains = new Set();
  for (const u of lines) {
    try {
      let host = u;
      if (/^https?:\/\//i.test(host)) {
        host = new URL(host).hostname;
      } else if (host.indexOf('://') >= 0) {
        host = host.split('://')[1].split('/')[0].split('?')[0];
      } else {
        host = host.split('/')[0].split('?')[0];
      }
      if (host && /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(host)) domains.add(host.toLowerCase());
    } catch (e) {}
  }
  return Array.from(domains);
}

async function fetchOpenPhishFeed() {
  const failures = [];
  for (const src of OPENPHISH_FEED_SOURCES) {
    try {
      // 加超时，避免单个源访问慢/被拦截时 fetch 无限挂起（曾导致后台 SW 被回收、消息端口关闭）
      const ctrl = new AbortController();
      const to = setTimeout(function () { try { ctrl.abort(); } catch (_) {} }, 15000);
      let res;
      try {
        res = await fetch(src, { method: 'GET', cache: 'no-store', signal: ctrl.signal, redirect: 'follow' });
      } finally {
        clearTimeout(to);
      }
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const text = await res.text();
      const arr = extractOpenPhishDomains(text);
      if (arr.length === 0) throw new Error('内容非 feed（无可解析域名）');
      const meta = { updated: Date.now(), count: arr.length, error: '', source: src };
      await new Promise((res) => chrome.storage.local.set({
        [SF_OP_DOMAINS_KEY]: arr,
        [SF_OP_META_KEY]: meta
      }, res));
      _opDomains = new Set(arr);
      _opMeta = meta;
      return { ok: true, count: arr.length, source: src };
    } catch (e) {
      // 记录每个源的失败原因（便于设置页定位：网络被拦 / 404 / 非 feed 等）
      const host = (function () { try { return new URL(src).host; } catch (_) { return src; } })();
      failures.push(host + ': ' + ((e && e.message) || String(e)));
    }
  }
  // 全部源失败：把逐源原因拼成可读提示
  const brief = failures.map(function (s) { return s.replace('Failed to fetch', '网络不可达'); }).join('；');
  const errMsg = brief || '所有更新源均失败';
  try {
    _opMeta = { updated: Date.now(), count: (_opDomains ? _opDomains.size : 0), error: errMsg };
    await new Promise((res) => chrome.storage.local.set({
      [SF_OP_META_KEY]: _opMeta
    }, res));
  } catch (_) {}
  return { ok: false, error: errMsg, attempts: failures.length };
}

// ★ 2026-11-26：手动「立即更新」= 无条件强制更新（force === true）。
//   背景：社区名单的自动更新有两条时间护栏（24 小时内已更新跳过、失败后 30 分钟再试），
//   以前 force 只跳过这两条，但**总开关 / 名单子开关未开启时仍会直接 skipped**——
//   于是「长期关着总开关 → 打开开关（还没点保存）→ 立刻点立即更新」会被判成
//   「master-off」，设置页又把它显示成「24 小时内已更新」，用户只能干等次日自动更新。
//   现在：只要 force，时间护栏、总开关、名单子开关一律不看，真的去抓一次；
//   命中判定那边仍受 communityListsOn() 约束，所以总开关确实关着时不会因此误拦。
//   结果统一打上 manual:true，设置页据此区分「自动跳过」与「手动结果」。
function sfResIsManual(res, manual) {
  if (manual && res && typeof res === 'object') res.manual = true;
  return res;
}

async function maybeUpdateOpenPhish(force) {
  const manual = force === true;   // 手动「立即更新」：跳过下面所有护栏
  const s = await getSettings();
  if (!manual && !(s && s.communityLists && s.communityLists.enabled)) return { ok: false, skipped: true, reason: 'master-off' };
  const op = (s && s.openphish) || {};
  if (!manual && !op.enabled) return { ok: false, skipped: true, reason: 'list-off' };
  let last = (_opMeta && _opMeta.updated) || 0;
  if (!last) {
    const meta = await new Promise((res) => chrome.storage.local.get({ [SF_OP_META_KEY]: { updated: 0 } }, res));
    last = (meta[SF_OP_META_KEY] && meta[SF_OP_META_KEY].updated) || 0;
    if (!_opMeta && meta[SF_OP_META_KEY]) _opMeta = meta[SF_OP_META_KEY];
  }
  // 非强制更新：24 小时内已更新则跳过，避免频繁请求（手动点击永不受此限）
  if (!manual && (Date.now() - last) < 24 * 3600 * 1000) return { ok: true, skipped: true, count: (_opDomains ? _opDomains.size : 0) };
  return sfResIsManual(await fetchOpenPhishFeed(), manual);
}

// OpenPhish 每日自动更新（仅启用时由后台 alarm 触发）；手动更新复用一次性 alarm，保证 SW 在抓取期间存活
function notifyOpenPhishUpdated(r) {
  // 单向推送结果给设置页（无长连接，不受 MV3 SW 回收影响）；结果同时已写入 storage.local，设置页打开时会回读
  sfBroadcast({ type: 'sf-openphish-updated', result: (r || { ok: true }) });
}
try {
  chrome.alarms.create('sfOpenPhishDaily', { periodInMinutes: 1440 });
  chrome.alarms.onAlarm.addListener(async (alarm) => {
    if (!alarm) return;
    try {
      if (alarm.name === 'sfOpenPhishDaily') {
        const s = await getSettings();
        const op = (s && s.openphish) || {};
        if (!op.enabled) return;            // 未启用则不抓取
        const r = await maybeUpdateOpenPhish(false);
        notifyOpenPhishUpdated(r);
      } else if (alarm.name === 'sfOpenPhishManual') {
        const r = await maybeUpdateOpenPhish(true);   // 强制抓取
        notifyOpenPhishUpdated(r);
      }
    } catch (e) {
      notifyOpenPhishUpdated({ ok: false, error: String((e && e.message) || e) });
    }
  });
} catch (e) {}

// ===== PhishDestroy 本地钓鱼黑名单（与 OpenPhish 并列的第二个静态名单源）=====
// 数据源：phishdestroy/destroylist 的 primary_active/domains.txt —— 约 14 万条「裸域名」，逐行一条，
//   文件头部有 2 行 # 注释。抓取顺序按需求排定：jsDelivr CDN → GitHub raw(domains.txt) → GitHub raw(list.txt)，
//   其后追加同内容的 jsDelivr 备用镜像与 GitHub 反代（与 OpenPhish 相同的可达性兜底策略）。
// 落盘：chrome.storage.local
//   · sfPhishDestroyDomains：整个名单压成「每行一个域名」的**字符串**（14 万条实测约 3~4MB，
//     比字符串数组省一半配额与序列化开销）；
//   · sfPhishDestroyMeta：{ updated, count, error, source }。
// 常驻：解析成 Set 缓存在 service worker 内存（_pdDomains），访问网站时 O(1) 比对（含父域回溯），不再读盘。
const PD_FEED_SOURCES = [
  'https://cdn.jsdelivr.net/gh/phishdestroy/destroylist@main/rootlist/formats/primary_active/domains.txt',
  'https://raw.githubusercontent.com/phishdestroy/destroylist/main/rootlist/formats/primary_active/domains.txt',
  'https://raw.githubusercontent.com/phishdestroy/destroylist/main/list.txt',
  'https://fastly.jsdelivr.net/gh/phishdestroy/destroylist@main/rootlist/formats/primary_active/domains.txt',
  'https://gcore.jsdelivr.net/gh/phishdestroy/destroylist@main/rootlist/formats/primary_active/domains.txt',
  'https://testingcf.jsdelivr.net/gh/phishdestroy/destroylist@main/rootlist/formats/primary_active/domains.txt',
  'https://gh-proxy.com/https://raw.githubusercontent.com/phishdestroy/destroylist/main/rootlist/formats/primary_active/domains.txt'
];
const PD_DOMAINS_KEY = 'sfPhishDestroyDomains';
const PD_META_KEY = 'sfPhishDestroyMeta';
let _pdDomains = null;   // 内存缓存 Set（常驻）
let _pdMeta = null;      // 内存缓存 meta（避免每次导航读 storage.local）

async function loadPhishDestroyDomains() {
  try {
    const r = await new Promise((res) => chrome.storage.local.get({ [PD_DOMAINS_KEY]: '', [PD_META_KEY]: null }, res));
    const raw = typeof r[PD_DOMAINS_KEY] === 'string' ? r[PD_DOMAINS_KEY] : '';
    _pdDomains = new Set(raw ? raw.split('\n') : []);
    _pdMeta = r[PD_META_KEY] || { updated: 0, count: _pdDomains.size, error: '' };
  } catch (e) { _pdDomains = new Set(); _pdMeta = { updated: 0, count: 0, error: '' }; }
  return _pdDomains;
}

function phishDestroyHit(host) { return domainListHit(_pdDomains, host); }

async function fetchPhishDestroyFeed() {
  const failures = [];
  for (const src of PD_FEED_SOURCES) {
    try {
      // 14 万行、约 3.5MB，超时放宽到 40s（仍远小于 MV3 对 fetch 的容忍度，且 alarm 期间 SW 不会被回收）
      const ctrl = new AbortController();
      const to = setTimeout(function () { try { ctrl.abort(); } catch (_) {} }, 40000);
      let res;
      try {
        res = await fetch(src, { method: 'GET', cache: 'no-store', signal: ctrl.signal, redirect: 'follow' });
      } finally {
        clearTimeout(to);
      }
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const text = await res.text();
      const arr = extractOpenPhishDomains(text);   // 同一解析器：# 注释行与非域名行自动丢弃
      if (arr.length === 0) throw new Error('内容非名单（无可解析域名）');
      const meta = { updated: Date.now(), count: arr.length, error: '', source: src };
      await new Promise((res2) => chrome.storage.local.set({
        [PD_DOMAINS_KEY]: arr.join('\n'),   // 压成字符串落盘，省配额
        [PD_META_KEY]: meta
      }, res2));
      _pdDomains = new Set(arr);
      _pdMeta = meta;
      return { ok: true, count: arr.length, source: src };
    } catch (e) {
      const host = (function () { try { return new URL(src).host; } catch (_) { return src; } })();
      failures.push(host + ': ' + ((e && e.message) || String(e)));
    }
  }
  const brief = failures.map(function (s) { return s.replace('Failed to fetch', '网络不可达'); }).join('；');
  const errMsg = brief || '所有更新源均失败';
  try {
    _pdMeta = { updated: Date.now(), count: (_pdDomains ? _pdDomains.size : 0), error: errMsg };
    await new Promise((res) => chrome.storage.local.set({ [PD_META_KEY]: _pdMeta }, res));
  } catch (_) {}
  return { ok: false, error: errMsg, attempts: failures.length };
}

async function maybeUpdatePhishDestroy(force) {
  const manual = force === true;   // 手动「立即更新」：跳过下面所有护栏
  const s = await getSettings();
  if (!manual && !(s && s.communityLists && s.communityLists.enabled)) return { ok: false, skipped: true, reason: 'master-off' };
  const pd = (s && s.phishdestroy) || {};
  if (!manual && !pd.enabled) return { ok: false, skipped: true, reason: 'list-off' };
  let last = (_pdMeta && _pdMeta.updated) || 0;
  if (!last) {
    const meta = await new Promise((res) => chrome.storage.local.get({ [PD_META_KEY]: { updated: 0 } }, res));
    last = (meta[PD_META_KEY] && meta[PD_META_KEY].updated) || 0;
    if (!_pdMeta && meta[PD_META_KEY]) _pdMeta = meta[PD_META_KEY];
  }
  // 非强制：24 小时内已更新则跳过（每日自动更新即靠这条幂等约束，避免 SW 重启反复抓取）
  if (!manual && (Date.now() - last) < 24 * 3600 * 1000) return { ok: true, skipped: true, count: (_pdDomains ? _pdDomains.size : 0) };
  return sfResIsManual(await fetchPhishDestroyFeed(), manual);
}

function notifyPhishDestroyUpdated(r) {
  sfBroadcast({ type: 'sf-phishdestroy-updated', result: (r || { ok: true }) });
}

try {
  // 只在不存在时创建：避免 SW 每次冷启动都把周期的起点重置（OpenPhish 用的是无条件 create，这里改成幂等）
  chrome.alarms.get('sfPhishDestroyDaily', function (a) {
    if (!a) { try { chrome.alarms.create('sfPhishDestroyDaily', { periodInMinutes: 1440 }); } catch (e) {} }
  });
  chrome.alarms.onAlarm.addListener(async (alarm) => {
    if (!alarm) return;
    try {
      if (alarm.name === 'sfPhishDestroyDaily') {
        const s = await getSettings();
        const pd = (s && s.phishdestroy) || {};
        if (!pd.enabled) return;                       // 未启用则不抓取
        notifyPhishDestroyUpdated(await maybeUpdatePhishDestroy(false));
      } else if (alarm.name === 'sfPhishDestroyManual') {
        notifyPhishDestroyUpdated(await maybeUpdatePhishDestroy(true));   // 手动更新：强制抓取
      }
    } catch (e) {
      notifyPhishDestroyUpdated({ ok: false, error: String((e && e.message) || e) });
    }
  });
} catch (e) {}

// ===== HaGeZi's Threat Intelligence Feeds（TIF）本地威胁情报黑名单 =====
// 数据源：hagezi/dns-blocklists 的 adblock/tif.txt —— AdBlock 语法（||domain^），
//   头部注释声明 181 万条，文本约 36MB，是 OpenPhish/PhishDestroy 的十几倍体量。
//
// ★ 2026-11-04 重写（上一版「180 万条双哈希 + 有序数组」实测导致扩展卡死、硬盘灯常亮）：
//   上一版把 14.5MB 的 Uint32 表 base64 成 18.5MB 存进 storage.local，而 MV3 的 service worker
//   空闲 30 秒就会被回收 —— 于是**每打开一个页面**、SW 被唤醒一次，就要重读 18.5MB JSON 字符串、
//   atob 解码、再跑 1800 万次 charCodeAt 重建数组。一次导航就要几百 MB 的临时分配，
//   浏览器表现为内存暴涨 + 磁盘狂读；再叠加几十 MB 名单的下载，就成了「更新 5 分钟不动」。
//
//   现在改用「布隆过滤器（Bloom Filter）+ IndexedDB 原始二进制」：
//   · 构建：单次顺序扫描，边解析边置位 —— 不排序、不产生 180 万条字符串、不用 BigInt；
//     181 万条 → 约 5MB 位图（22 bit/条目，15 个哈希，误判率约 2.5e-5，且**绝无漏判**）。
//   · 落盘：位图以 ArrayBuffer 存进 IndexedDB（不经 JSON、不经 base64）。
//   · 唤醒：SW 冷启动只需 1 次 IDB 读取（约 10~20ms）拿到 5MB 位图，**无需解码**。
//   · 比对：15 次位测试，单域名约 3~5µs（含父域回溯）。
//   · 下载：流式读取 + 进度回推（设置页能看到已下载 MB 数），单源 90s、总预算 4 分钟；
//     同一时刻只允许一个更新任务（_hgUpdating 单飞），避免多个 alarm 同时抓大名单。
//   代价：布隆过滤器有约 2.5e-5 的误判（约 4 万次访问可能出现 1 次误报），但不会有漏报；
//   且本地不再保存明文域名（离线不可还原清单）。
// 名单版本：full = tif.txt（181 万条 / 约 36MB）；medium = tif.medium.txt（31.8 万条 / 约 6.6MB，下载更快、误报更少）
function hgFeedSources(variant) {
  const file = (variant === 'medium') ? 'tif.medium.txt' : 'tif.txt';
  return [
    'https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/' + file,
    'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/' + file,
    'https://fastly.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/' + file,
    'https://gcore.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/' + file,
    'https://testingcf.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/' + file,
    'https://gh-proxy.com/https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/' + file
  ];
}
// 名单体积参考值（解压后的字节数）。CDN 通常以 gzip/br 传输，此时 content-length 是
// **压缩后**的大小（36MB 的 tif.txt 压缩后约 8.3MB）。若直接拿它当进度分母，就会出现
// 「20.0MB / 8.3MB（241%）」这种荒谬显示 —— 压缩传输时一律改用这里的参考值估算。
const HG_EXPECTED_BYTES = { full: 37649904, medium: 6934911 };
const HG_META_KEY = 'sfHaGeZiTifMeta';          // 只存「小字段」meta，供设置页展示
const HG_LEGACY_KEYS = ['sfHaGeZiTifHashes'];   // 旧版 18.5MB base64 键，升级时清理
const HG_DB_NAME = 'sfLocalLists';
const HG_DB_STORE = 'lists';
const HG_IDB_KEY = 'hagezi-tif';
const HG_BITS_PER_ENTRY = 22;                   // m/n
const HG_K = 15;                                // 哈希个数 → 误判率 ≈ 2.5e-5

let _hgBits = null;        // Uint8Array 位图（约 5MB 常驻）
let _hgM = 0;              // 位图总位数
let _hgCount = 0;          // 名单条数
let _hgMeta = null;        // { updated, count, error, source, lastAttempt }
let _hgUpdating = false;   // 单飞锁：同一时刻只跑一个更新任务
let _hgDbPromise = null;   // IDB 连接缓存
let _hgLoadTried = false;  // 本次 SW 生命周期内是否已尝试过读取（没有名单时不必每个页面都重试）

// ---------- IndexedDB：位图直接以 ArrayBuffer 存取（不经过 JSON / base64） ----------
function hgOpenDB() {
  if (_hgDbPromise) return _hgDbPromise;
  _hgDbPromise = new Promise(function (resolve, reject) {
    try {
      if (typeof indexedDB === 'undefined') { reject(new Error('当前环境不支持 IndexedDB')); return; }
      const req = indexedDB.open(HG_DB_NAME, 1);
      req.onupgradeneeded = function () {
        const db = req.result;
        if (!db.objectStoreNames.contains(HG_DB_STORE)) db.createObjectStore(HG_DB_STORE);
      };
      req.onsuccess = function () { resolve(req.result); };
      req.onerror = function () { _hgDbPromise = null; reject(req.error || new Error('打开 IndexedDB 失败')); };
      req.onblocked = function () { _hgDbPromise = null; reject(new Error('IndexedDB 被占用')); };
    } catch (e) { _hgDbPromise = null; reject(e); }
  });
  return _hgDbPromise;
}

function hgIdbGet(key) {
  return hgOpenDB().then(function (db) {
    return new Promise(function (resolve, reject) {
      const tx = db.transaction(HG_DB_STORE, 'readonly');
      const req = tx.objectStore(HG_DB_STORE).get(key);
      req.onsuccess = function () { resolve(req.result || null); };
      req.onerror = function () { reject(req.error || new Error('读取失败')); };
    });
  });
}

function hgIdbPut(key, value) {
  return hgOpenDB().then(function (db) {
    return new Promise(function (resolve, reject) {
      const tx = db.transaction(HG_DB_STORE, 'readwrite');
      tx.objectStore(HG_DB_STORE).put(value, key);
      tx.oncomplete = function () { resolve(true); };
      tx.onerror = function () { reject(tx.error || new Error('写入失败')); };
      tx.onabort = function () { reject(tx.error || new Error('写入被中止')); };
    });
  });
}

// ---------- 哈希：单趟扫描字符区间，顺便做 A-Z→a-z 折叠（不产生任何子串） ----------
let _hgH1 = 0, _hgH2 = 0;
function hgHashRange(s, start, end) {
  let h1 = 0x811c9dc5, h2 = 0x27d4eb2d;
  for (let i = start; i < end; i++) {
    let c = s.charCodeAt(i);
    if (c >= 65 && c <= 90) c += 32;
    h1 = Math.imul(h1 ^ c, 16777619) >>> 0;
    h2 = (h2 + c) >>> 0;
    h2 = Math.imul(h2, 2246822519) >>> 0;
    h2 = (h2 ^ (h2 >>> 13)) >>> 0;
  }
  _hgH1 = h1 >>> 0; _hgH2 = h2 >>> 0;
}

// 15 个位置由 (h1 + i*h2) 派生（Kirsch–Mitzenmacher），只算一次哈希，避免逐字符 ×15
function hgBloomTestRange(s, start, end) {
  if (!_hgBits || !_hgM) return false;
  hgHashRange(s, start, end);
  const a = _hgH1, b = (_hgH2 | 1) >>> 0;
  const bits = _hgBits, m = _hgM;
  for (let i = 0; i < HG_K; i++) {
    const idx = ((a + Math.imul(i, b)) >>> 0) % m;
    if ((bits[idx >>> 3] & (1 << (idx & 7))) === 0) return false;
  }
  return true;
}

// 域名是否命中：精确 + 逐级回溯父域（与 OpenPhish / PhishDestroy 的连坐口径一致）
function haGeZiHit(host) {
  if (!_hgBits || !_hgM) return false;
  let d = String(host || '').toLowerCase();
  if (d.charAt(d.length - 1) === '.') d = d.slice(0, -1);
  while (d) {
    if (hgBloomTestRange(d, 0, d.length)) return true;
    const i = d.indexOf('.');
    if (i < 0) return false;
    d = d.slice(i + 1);
  }
  return false;
}

// ---------- 构建：单趟扫描 AdBlock 规则 → 直接置位（分段让出主线程，避免 SW 被判定无响应） ----------
async function buildHaGeZiBloom(text) {
  const src = String(text);
  const len = src.length;

  // 规模：优先用头部 "! Number of entries: 1814363"，否则按 200 万估
  let expect = 0;
  const head = src.slice(0, Math.min(len, 4096));
  const mm = head.match(/Number of entries:\s*([\d,]+)/i);
  if (mm) expect = parseInt(mm[1].replace(/,/g, ''), 10) || 0;
  const n = expect > 0 ? expect : 2000000;
  const mBits = Math.ceil(n * HG_BITS_PER_ENTRY / 8) * 8;
  const bits = new Uint8Array(mBits >>> 3);
  const m = mBits;

  let count = 0;
  let start = 0;
  let lastYield = 0;

  for (let i = 0; i <= len; i++) {
    if (i !== len && src.charCodeAt(i) !== 10) continue;
    const s0 = start; start = i + 1;
    if (i - lastYield > 4000000) {                 // 每约 4MB 让出一次事件循环
      lastYield = i;
      await new Promise(function (r) { setTimeout(r, 0); });
    }
    let p = s0;
    // 行首空白
    while (p < i && (src.charCodeAt(p) === 32 || src.charCodeAt(p) === 9 || src.charCodeAt(p) === 13)) p++;
    if (p >= i) continue;
    const c0 = src.charCodeAt(p);
    if (c0 === 33 /* ! */ || c0 === 35 /* # */ || c0 === 91 /* [ */ || c0 === 47 /* / */ || c0 === 64 /* @ */) continue;
    if (c0 !== 124 /* | */ || src.charCodeAt(p + 1) !== 124) continue;   // 只接受 ||domain^ 形态
    p += 2;
    // 扫描到 ^ / $ / / / | 为止，并顺带校验字符集
    let e = p, dot = -1, bad = false, lastDot = -1;
    for (; e < i; e++) {
      const c = src.charCodeAt(e);
      if (c === 94 /* ^ */ || c === 36 /* $ */ || c === 47 /* / */ || c === 124 /* | */) break;
      if (c === 46 /* . */) { dot = e; lastDot = e; }
      else if ((c >= 97 && c <= 122) || (c >= 65 && c <= 90) || (c >= 48 && c <= 57) || c === 45 /* - */) { /* ok */ }
      else { bad = true; break; }                  // * ~ _ 等异常字符直接丢弃
    }
    if (bad || dot < 0) continue;
    let end = e;
    if (src.charCodeAt(end - 1) === 46) end--;     // 结尾多余的点
    if (end - p < 4) continue;
    // 顶级域至少 2 个字符（lastDot 之后）
    if (end - lastDot - 1 < 2) continue;
    hgHashRange(src, p, end);
    const a = _hgH1, b = (_hgH2 | 1) >>> 0;
    for (let t = 0; t < HG_K; t++) {
      const idx = ((a + Math.imul(t, b)) >>> 0) % m;
      bits[idx >>> 3] |= (1 << (idx & 7));
    }
    count++;
  }
  return { bits: bits, m: m, count: count };
}

// ---------- 读写 ----------
async function loadHaGeZiFilter(force) {
  if (_hgBits && !force) return true;
  if (_hgLoadTried && !force) return false;
  _hgLoadTried = true;
  try {
    const rec = await hgIdbGet(HG_IDB_KEY);
    if (rec && rec.bits && rec.m) {
      _hgBits = new Uint8Array(rec.bits);
      _hgM = rec.m;
      _hgCount = rec.count || 0;
      return true;
    }
  } catch (e) {}
  // 没有新格式记录：清掉旧版 18.5MB 的 base64 键（释放配额与磁盘），并把 meta 复位
  if (!_hgBits) {
    try {
      await new Promise(function (r) { chrome.storage.local.remove(HG_LEGACY_KEYS, r); });
      const cur = await new Promise(function (r) { chrome.storage.local.get({ [HG_META_KEY]: null }, r); });
      const meta = cur[HG_META_KEY];
      if (meta && meta.updated && !(meta.error && meta.lastAttempt)) {
        await new Promise(function (r) { chrome.storage.local.set({ [HG_META_KEY]: { updated: 0, count: 0, error: '旧版名单已被移除，请重新更新' } }, r); });
      }
    } catch (e) {}
  }
  return false;
}

// 统一的安全广播：chrome.runtime.sendMessage 在没有接收方（设置页已关闭）时会返回一个
// **被拒绝的 Promise**（"Could not establish connection. Receiving end does not exist."）。
// 原来的 try/catch 抓不到 Promise 拒绝，于是后台控制台不断出现 Uncaught (in promise)。
// 这里改用回调式调用并读取 lastError：既不会产生未处理的拒绝，也不会打印告警。
function sfBroadcast(msg) {
  try {
    chrome.runtime.sendMessage(msg, function () { void chrome.runtime.lastError; });
  } catch (_) {}
}

function notifyHaGeZiUpdated(r) {
  sfBroadcast({ type: 'sf-hagezi-updated', result: (r || { ok: true }) });
}
function notifyHaGeZiProgress(received, total, expected, stage) {
  sfBroadcast({ type: 'sf-hagezi-progress', received: received, total: total, expected: expected || 0, stage: stage || 'download' });
}

// 流式读取响应体：边下边回报进度（约 36MB 静态名单，用户需要看到「有在动」）
async function readBodyWithProgress(res, variant) {
  try {
    if (!res || !res.body || typeof res.body.getReader !== 'function') return await res.text();
    const hdr = function (n) {
      try { return (res.headers && res.headers.get && res.headers.get(n)) || ''; } catch (_) { return ''; }
    };
    const expected = HG_EXPECTED_BYTES[(variant === 'medium') ? 'medium' : 'full'] || 0;
    let total = Number(hdr('content-length') || 0);
    // ★ 压缩传输时 content-length 是压缩后的字节数，与实际收到的解压字节不可比 → 判为未知。
    if (!(total > 0) || /gzip|br|deflate/i.test(hdr('content-encoding'))) total = 0;
    // ★ 兜底：个别 CDN/代理会剥掉 content-encoding 却仍返回压缩尺寸的 content-length
    //   （8.3MB vs 实际 36MB）。凡是明显小于该版本参考体积的，一律视为不可信。
    if (total && expected && total < expected * 0.6) total = 0;
    const reader = res.body.getReader();
    const chunks = [];
    let received = 0, lastNotify = 0;
    for (;;) {
      const step = await reader.read();
      if (step.done) break;
      const v = step.value;
      chunks.push(v);
      received += v.length;
      // 兜底：即便 header 声称未压缩，只要实际字节超出（说明 header 不可信），立刻停用百分比
      if (total && received > total * 1.02) total = 0;
      if (received - lastNotify >= 4 * 1024 * 1024) { lastNotify = received; notifyHaGeZiProgress(received, total, expected); }
    }
    notifyHaGeZiProgress(received, total, expected);
    const all = new Uint8Array(received);
    let off = 0;
    for (let i = 0; i < chunks.length; i++) { all.set(chunks[i], off); off += chunks[i].length; }
    return new TextDecoder('utf-8').decode(all);
  } catch (e) {
    return await res.text();
  }
}

async function fetchHaGeZiFeed(variant) {
  const failures = [];
  const startedAt = Date.now();
  const sources = hgFeedSources(variant);
  for (let si = 0; si < sources.length; si++) {
    const src = sources[si];
    if (Date.now() - startedAt > 240000) { failures.push('已超过本次更新总时限（4 分钟）'); break; }
    try {
      const ctrl = new AbortController();
      const to = setTimeout(function () { try { ctrl.abort(); } catch (_) {} }, 90000);
      let res;
      try {
        res = await fetch(src, { method: 'GET', cache: 'no-store', signal: ctrl.signal, redirect: 'follow' });
      } finally {
        clearTimeout(to);
      }
      if (!res.ok) throw new Error('HTTP ' + res.status);
      notifyHaGeZiProgress(0, 0, 0);                     // 「开始下载」信号
      const text = await readBodyWithProgress(res, variant);
      // 下载完后仍有几秒在解析置位：单独报一个阶段，避免用户以为卡在 99%
      notifyHaGeZiProgress(text.length, 0, 0, 'build');
      const built = await buildHaGeZiBloom(text);        // 边解析边置位，无排序、无 BigInt
      if (!built.count) throw new Error('内容非名单（未解析到 ||domain^ 规则）');

      await hgIdbPut(HG_IDB_KEY, { bits: built.bits.buffer, m: built.m, count: built.count, updated: Date.now(), source: src });
      _hgBits = built.bits; _hgM = built.m; _hgCount = built.count;

      const meta = { updated: Date.now(), count: built.count, bytes: text.length, error: '', source: src, variant: variant || 'full' };
      _hgMeta = meta;
      await new Promise(function (r) { chrome.storage.local.set({ [HG_META_KEY]: meta }, r); });
      // 顺手清理旧版 18.5MB base64
      try { chrome.storage.local.remove(HG_LEGACY_KEYS); } catch (e) {}
      return { ok: true, count: built.count, source: src, bytes: text.length, ms: Date.now() - startedAt };
    } catch (e) {
      const h = (function () { try { return new URL(src).host; } catch (_) { return src; } })();
      failures.push(h + ': ' + ((e && e.message) || String(e)));
    }
  }
  const brief = failures.map(function (s) { return s.replace('Failed to fetch', '网络不可达'); }).join('；');
  const errMsg = brief || '所有更新源均失败';
  try {
    const prev = (_hgMeta && _hgMeta.updated) || 0;     // 失败保留旧位图，不推进 updated
    _hgMeta = { updated: prev, count: _hgCount, error: errMsg, lastAttempt: Date.now() };
    await new Promise(function (r) { chrome.storage.local.set({ [HG_META_KEY]: _hgMeta }, r); });
  } catch (_) {}
  return { ok: false, error: errMsg, attempts: failures.length };
}

async function maybeUpdateHaGeZi(force) {
  if (_hgUpdating) return { ok: false, skipped: true, busy: true };   // 单飞：避免并发下载大名单
  const manual = force === true;   // 手动「立即更新」：跳过下面所有护栏
  const s = await getSettings();
  if (!manual && !(s && s.communityLists && s.communityLists.enabled)) return { ok: false, skipped: true, reason: 'master-off' };
  const hg = (s && s.hagezi) || {};
  if (!manual && !hg.enabled) return { ok: false, skipped: true, reason: 'list-off' };
  let meta = _hgMeta;
  if (!meta || (!meta.updated && !meta.lastAttempt)) {
    try {
      meta = await new Promise(function (r) { chrome.storage.local.get({ [HG_META_KEY]: { updated: 0 } }, function (o) { r(o[HG_META_KEY] || { updated: 0 }); }); });
    } catch (e) { meta = { updated: 0 }; }
    _hgMeta = meta;
  }
  const last = (meta && meta.updated) || 0;
  const lastTry = (meta && meta.lastAttempt) || 0;
  if (!manual) {
    if ((Date.now() - last) < 24 * 3600 * 1000) return { ok: true, skipped: true, count: _hgCount };
    if (lastTry && (Date.now() - lastTry) < 30 * 60 * 1000) return { ok: false, skipped: true, reason: 'retry-cooling' };  // 失败后 30 分钟内不再重试
  }
  const variant = (hg.variant === 'medium') ? 'medium' : 'full';
  // 版本切换（full/medium）后旧位图与新版名单不对应，fetchHaGeZiFeed 会按新 variant 重写；
  // ★ 2026-11-26：原先这里写 `if (variantChanged) force = true;`——但护栏在上方已按 manual 判完，
  //   此处再改 force 对本次调用毫无作用（死赋值），删掉以免误读成"换版本能绕过护栏"。
  _hgUpdating = true;
  try {
    return sfResIsManual(await fetchHaGeZiFeed(variant), manual);
  } finally {
    _hgUpdating = false;
  }
}

try {
  chrome.alarms.get('sfHaGeZiDaily', function (a) {
    if (!a) { try { chrome.alarms.create('sfHaGeZiDaily', { periodInMinutes: 1440 }); } catch (e) {} }
  });
  chrome.alarms.onAlarm.addListener(async (alarm) => {
    if (!alarm) return;
    if (alarm.name !== 'sfHaGeZiDaily' && alarm.name !== 'sfHaGeZiManual') return;
    try {
      if (alarm.name === 'sfHaGeZiDaily') {
        const s = await getSettings();
        const hg = (s && s.hagezi) || {};
        if (!hg.enabled) return;
        notifyHaGeZiUpdated(await maybeUpdateHaGeZi(false));
      } else {
        notifyHaGeZiUpdated(await maybeUpdateHaGeZi(true));
      }
    } catch (e) {
      notifyHaGeZiUpdated({ ok: false, error: String((e && e.message) || e) });
    }
  });
} catch (e) {}

// ===== 社区 AdBlock 风险名单：uBlock Origin - Badware risks / Dandelion Sprout =====
// 数据源都是 AdBlock Plus 语法（.txt），文件里混着四类东西：
//   ① 整站域名规则  ||example.com^          ← 只有这类能用
//   ② 路径规则      ||example.com/xxx/$doc  ← 只对某个路径生效，整站收录会误报（如 apps.apple.com）
//   ③ 正则 / 元素隐藏 / 例外(@@) / TLD 规则（||top^，等于封整个顶级域）
//   ④ 头部注释、IP、端口等
// 我们只做「命中即提示」，既不隐藏元素也不按路径拦截，所以**只提取 ①**：
//   · '||' 开头；主机名只允许 [a-z0-9.-]；遇到 ^ $ / | 结束
//   · 结束符必须是 ^ 或 $ 或行尾（遇 '/' 说明是路径规则 → 丢弃）
//   · 必须含点，且最后一段 TLD ≥ 2 字符（顺带挡掉 ||top^ 这类 TLD 级规则）
// 其余全部丢弃，不做任何语法解释。
//
// 存储与 HaGeZi TIF 同构（布隆过滤器 + IndexedDB 位图），但这两份名单实际只有 3 千 / 1.2 万条，
// 位图仅几 KB ~ 几十 KB，构建与比对都是毫秒级；误判率按 16bit/条 + 11 哈希计算约 1e-4，
// 且**绝不漏判**（名单太小，代价可忽略）。
const ADL_LISTS = {
  badware: {
    id: 'badware',
    name: 'uBlock Origin - Badware risks',
    idbKey: 'adlist-ubadware',
    metaKey: 'sfUBlockBadwareMeta',
    expectBytes: 273771,
    // 直链优先，镜像兜底（raw 被墙时走 jsDelivr，再不行走文件反代）
    sources: [
      'https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt',
      'https://cdn.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/filters/badware.txt',
      'https://fastly.jsdelivr.net/gh/uBlockOrigin/uAssetsCDN@main/filters/badware.txt',
      'https://gh-proxy.com/https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/badware.txt'
    ]
  },
  dsam: {
    id: 'dsam',
    name: "Dandelion Sprout's Anti-Malware List",
    idbKey: 'adlist-dsam',
    metaKey: 'sfDandelionAntiMalwareMeta',
    expectBytes: 445662,
    sources: [
      "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Dandelion%20Sprout's%20Anti-Malware%20List.txt",
      // 用户给的「镜像」是 github.com/.../blob/... 网页地址，返回的是 HTML 而不是名单，
      // 直接解析会把整页 HTML 当名单 → 这里改用等价的可直接读取镜像（jsDelivr CDN）。
      "https://cdn.jsdelivr.net/gh/DandelionSprout/adfilt@master/Dandelion%20Sprout's%20Anti-Malware%20List.txt",
      "https://fastly.jsdelivr.net/gh/DandelionSprout/adfilt@master/Dandelion%20Sprout's%20Anti-Malware%20List.txt",
      "https://gh-proxy.com/https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Dandelion%20Sprout's%20Anti-Malware%20List.txt"
    ]
  }
};
const ADL_BITS_PER_ENTRY = 16;
const ADL_K = 11;

// 每份名单一份运行状态（位图 + meta + 单飞锁）
const _adl = {
  badware: { bits: null, m: 0, count: 0, meta: null, updating: false, loadTried: false },
  dsam: { bits: null, m: 0, count: 0, meta: null, updating: false, loadTried: false }
};

// ---------- 哈希（与 TIF 同一套 FNV/乘法混合，单趟折叠大小写） ----------
let _adlH1 = 0, _adlH2 = 0;
function adlHashRange(s, start, end) {
  let h1 = 0x811c9dc5, h2 = 0x27d4eb2d;
  for (let i = start; i < end; i++) {
    let c = s.charCodeAt(i);
    if (c >= 65 && c <= 90) c += 32;
    h1 = Math.imul(h1 ^ c, 16777619) >>> 0;
    h2 = (h2 + c) >>> 0;
    h2 = Math.imul(h2, 2246822519) >>> 0;
    h2 = (h2 ^ (h2 >>> 13)) >>> 0;
  }
  _adlH1 = h1 >>> 0; _adlH2 = h2 >>> 0;
}

// 单趟扫描：只挑出「整站域名规则」的主机名区间，命中时回调 sink(start,end)
// 返回收录条数；sink 为空时即「只统计不置位」（用于先数出 n 再分配位图）
function adlScanHosts(src, sink) {
  const len = src.length;
  let count = 0, start = 0;
  for (let i = 0; i <= len; i++) {
    if (i !== len && src.charCodeAt(i) !== 10) continue;
    const s0 = start; start = i + 1;
    let p = s0;
    while (p < i && (src.charCodeAt(p) === 32 || src.charCodeAt(p) === 9 || src.charCodeAt(p) === 13)) p++;
    if (p >= i) continue;
    if (src.charCodeAt(p) !== 124 || src.charCodeAt(p + 1) !== 124) continue;   // 必须 '||'
    p += 2;
    let e = p, lastDot = -1, bad = false, stop = 0;
    for (; e < i; e++) {
      const c = src.charCodeAt(e);
      if (c === 94 /* ^ */ || c === 36 /* $ */ || c === 47 /* / */ || c === 124 /* | */) { stop = c; break; }
      if (c === 46 /* . */) lastDot = e;
      else if ((c >= 97 && c <= 122) || (c >= 65 && c <= 90) || (c >= 48 && c <= 57) || c === 45) { /* ok */ }
      else { bad = true; break; }                 // * ~ _ : ? 等一律丢弃
    }
    if (bad || lastDot < 0) continue;             // 无点 → TLD 级规则（||top^），丢弃
    if (stop === 47) continue;                    // 路径规则 → 丢弃（避免整站误报）
    let end = e;
    if (src.charCodeAt(end - 1) === 46) end--;    // 结尾多余的点
    if (end - p < 4) continue;
    if (end - lastDot - 1 < 2) continue;          // TLD 至少两位
    if (sink) sink(p, end);
    count++;
  }
  return count;
}

function adlBloomTestRange(st, s, start, end) {
  if (!st.bits || !st.m) return false;
  adlHashRange(s, start, end);
  const a = _adlH1, b = (_adlH2 | 1) >>> 0;
  const bits = st.bits, m = st.m;
  for (let i = 0; i < ADL_K; i++) {
    const idx = ((a + Math.imul(i, b)) >>> 0) % m;
    if ((bits[idx >>> 3] & (1 << (idx & 7))) === 0) return false;
  }
  return true;
}

// 域名是否命中：精确 + 逐级回溯父域（与 TIF / OpenPhish 的连坐口径一致）
function adlHit(id, host) {
  const st = _adl[id];
  if (!st || !st.bits || !st.m) return false;
  let d = String(host || '').toLowerCase();
  if (d.charAt(d.length - 1) === '.') d = d.slice(0, -1);
  while (d) {
    if (adlBloomTestRange(st, d, 0, d.length)) return true;
    const i = d.indexOf('.');
    if (i < 0) return false;
    d = d.slice(i + 1);
  }
  return false;
}

// 构建：先数条数分配位图，再扫一遍置位（两份名单都只有几百 KB，无需分段让出主线程）
async function buildAdlBloom(text) {
  const src = String(text);
  const n = adlScanHosts(src, null) || 1;
  const mBits = Math.max(64, Math.ceil(n * ADL_BITS_PER_ENTRY / 8) * 8);
  const bits = new Uint8Array(mBits >>> 3);
  const st = { bits: bits, m: mBits };
  let count = 0;
  adlScanHosts(src, function (p, e) {
    adlHashRange(src, p, e);
    const a = _adlH1, b = (_adlH2 | 1) >>> 0;
    for (let t = 0; t < ADL_K; t++) {
      const idx = ((a + Math.imul(t, b)) >>> 0) % mBits;
      bits[idx >>> 3] |= (1 << (idx & 7));
    }
    count++;
  });
  await new Promise(function (r) { setTimeout(r, 0); });   // 让出一次事件循环，SW 保持响应
  return { bits: bits, m: mBits, count: count };
}

async function loadAdl(id, force) {
  const st = _adl[id];
  const cfg = ADL_LISTS[id];
  if (!st || !cfg) return false;
  if (st.bits && !force) return true;
  if (st.loadTried && !force) return false;
  st.loadTried = true;
  try {
    const rec = await hgIdbGet(cfg.idbKey);
    if (rec && rec.bits && rec.m) {
      st.bits = new Uint8Array(rec.bits);
      st.m = rec.m;
      st.count = rec.count || 0;
      return true;
    }
  } catch (e) {}
  return false;
}

function notifyAdlUpdated(id, r) {
  sfBroadcast({ type: 'sf-adlist-updated', id: id, result: (r || { ok: true }) });
}
function notifyAdlProgress(id, received, total, stage) {
  sfBroadcast({ type: 'sf-adlist-progress', id: id, received: received, total: total, stage: stage || 'download' });
}

async function fetchAdlFeed(id) {
  const cfg = ADL_LISTS[id];
  const st = _adl[id];
  const failures = [];
  const startedAt = Date.now();
  for (let si = 0; si < cfg.sources.length; si++) {
    const src = cfg.sources[si];
    if (Date.now() - startedAt > 180000) { failures.push('已超过本次更新时限（3 分钟）'); break; }
    try {
      const ctrl = new AbortController();
      const to = setTimeout(function () { try { ctrl.abort(); } catch (_) {} }, 60000);
      let res;
      try {
        res = await fetch(src, { method: 'GET', cache: 'no-store', signal: ctrl.signal, redirect: 'follow' });
      } finally { clearTimeout(to); }
      if (!res.ok) throw new Error('HTTP ' + res.status);
      notifyAdlProgress(id, 0, 0);
      const text = await res.text();
      // 兜底：镜像若返回网页（HTML）而不是名单，这里会一个字都解析不出来
      const built = await buildAdlBloom(text);
      if (!built.count) throw new Error('内容非名单（未解析到 ||domain^ 规则）');
      await hgIdbPut(cfg.idbKey, { bits: built.bits.buffer, m: built.m, count: built.count, updated: Date.now(), source: src });
      st.bits = built.bits; st.m = built.m; st.count = built.count;
      const meta = { updated: Date.now(), count: built.count, bytes: text.length, error: '', source: src };
      st.meta = meta;
      await new Promise(function (r) { chrome.storage.local.set({ [cfg.metaKey]: meta }, r); });
      notifyAdlProgress(id, text.length, text.length, 'done');
      return { ok: true, count: built.count, source: src, bytes: text.length, ms: Date.now() - startedAt };
    } catch (e) {
      const h = (function () { try { return new URL(src).host; } catch (_) { return src; } })();
      failures.push(h + ': ' + ((e && e.message) || String(e)));
    }
  }
  const brief = failures.map(function (s) { return s.replace('Failed to fetch', '网络不可达'); }).join('；');
  const errMsg = brief || '所有更新源均失败';
  try {
    const prev = (st.meta && st.meta.updated) || 0;      // 失败保留旧位图，不推进 updated
    st.meta = { updated: prev, count: st.count, error: errMsg, lastAttempt: Date.now() };
    await new Promise(function (r) { chrome.storage.local.set({ [cfg.metaKey]: st.meta }, r); });
  } catch (_) {}
  return { ok: false, error: errMsg, attempts: failures.length };
}

async function maybeUpdateAdl(id, force) {
  const cfg = ADL_LISTS[id];
  const st = _adl[id];
  if (!cfg || !st) return { ok: false, skipped: true };
  if (st.updating) return { ok: false, skipped: true, busy: true };
  const manual = force === true;   // 手动「立即更新」：跳过下面所有护栏
  const s = await getSettings();
  if (!manual && !(s && s.communityLists && s.communityLists.enabled)) return { ok: false, skipped: true, reason: 'master-off' };
  const cfgUser = (s && s[id]) || {};
  if (!manual && !cfgUser.enabled) return { ok: false, skipped: true, reason: 'list-off' };
  if (!st.meta) {
    try {
      st.meta = await new Promise(function (r) {
        chrome.storage.local.get({ [cfg.metaKey]: { updated: 0 } }, function (o) { r(o[cfg.metaKey] || { updated: 0 }); });
      });
    } catch (e) { st.meta = { updated: 0 }; }
  }
  const last = (st.meta && st.meta.updated) || 0;
  const lastTry = (st.meta && st.meta.lastAttempt) || 0;
  if (!manual) {
    if ((Date.now() - last) < 24 * 3600 * 1000) return { ok: true, skipped: true, count: st.count };
    if (lastTry && (Date.now() - lastTry) < 30 * 60 * 1000) return { ok: false, skipped: true, reason: 'retry-cooling' };
  }
  st.updating = true;
  try {
    return sfResIsManual(await fetchAdlFeed(id), manual);
  } finally {
    st.updating = false;
  }
}

try {
  // 一个每日 alarm 覆盖两份名单（各自内部还有 24h 判断，不会重复抓）
  chrome.alarms.get('sfAdlDaily', function (a) {
    if (!a) { try { chrome.alarms.create('sfAdlDaily', { periodInMinutes: 1440 }); } catch (e) {} }
  });
  chrome.alarms.onAlarm.addListener(async (alarm) => {
    if (!alarm) return;
    const nm = String(alarm.name || '');
    if (nm === 'sfAdlDaily') {
      for (const id of Object.keys(ADL_LISTS)) {
        try {
          const s = await getSettings();
          if (!(s && s.communityLists && s.communityLists.enabled)) return;
          if (!(s[id] && s[id].enabled)) continue;
          notifyAdlUpdated(id, await maybeUpdateAdl(id, false));
        } catch (e) {}
      }
      return;
    }
    if (nm.indexOf('sfAdlManual_') === 0) {
      const id = nm.slice('sfAdlManual_'.length);
      try { notifyAdlUpdated(id, await maybeUpdateAdl(id, true)); }
      catch (e) { notifyAdlUpdated(id, { ok: false, error: String((e && e.message) || e) }); }
    }
  });
} catch (e) {}

// ===== 会话级状态（service worker 重启不丢）=====
function loadState() {
  return new Promise(function (resolve) {
    try {
      chrome.storage.session.get({ dangerTabs: {}, releasedHosts: {} }, function (s) {
        resolve({ dangerTabs: s.dangerTabs || {}, releasedHosts: s.releasedHosts || {} });
      });
    } catch (e) { resolve({ dangerTabs: {}, releasedHosts: {} }); }
  });
}
function saveState(state) {
  try { chrome.storage.session.set({ dangerTabs: state.dangerTabs, releasedHosts: state.releasedHosts }); } catch (e) {}
}

// 内存镜像：用户「完全放行」的主机集合（与 storage.session.releasedHosts 同步），
// 供 onCreated 同步判定，避免每次下载都去读 storage。用户在「完全放行」后期望本页
// 下载不被再拦截（含自动学习的下载黑名单），故放行来源页的下载应整体放过。
let releasedHostsCache = {};
function refreshReleasedCache() {
  loadState().then(function (state) { releasedHostsCache = state.releasedHosts || {}; });
}
try { refreshReleasedCache(); } catch (e) {}
// 判断本次下载是否来自「已被用户完全放行」的页面：是则后续不再拦截。
// 优先用下载的 initiator/referrer，回退到本标签最近一次顶级导航（meta refresh 秒跳下载常无 referrer）。
function isSourceReleased(item) {
  const h = downloadSourceHost(item);
  if (h && releasedHostsCache[h]) return true;
  if (item.tabId && item.tabId >= 0) {
    const t = lastTopUrl[item.tabId];
    if (t) { try { const hh = new URL(t).hostname.toLowerCase(); if (releasedHostsCache[hh]) return true; } catch (e) {} }
  }
  return false;
}

// 内存缓存：下载拦截等高频路径每次都读 storage.sync，service worker 冷启动后首次读即缓存，
// 之后同步返回；监听 storage.onChanged 在设置变更时失效，确保 options 页改动即时生效。
let _settingsCache = null;
function getSettings() {
  if (_settingsCache) return Promise.resolve(_settingsCache);
  return new Promise(function (resolve) {
    chrome.storage.sync.get(DEFAULTS, function (s) {
      // ★ 只填充局部 merged，等名单合并完成后再一次性写入 _settingsCache；
      //   原实现先赋 _settingsCache 再异步覆盖，中间这段时间别的调用会拿到「没有自定义名单」的设置。
      var merged = Object.assign({}, DEFAULTS, s || {});
      // ★ 2026-11-12：自定义名单以 storage.local 为准（sync 单键 8KB ≈ 550 条，超出后 set 静默失败）。
      //   SFListStore 在 local 缺失时会先把 sync 里的旧名单迁移过来，老用户无需操作。
      var finish = function () { _settingsCache = merged; resolve(merged); };
      try {
        if (typeof SFListStore !== 'undefined' && SFListStore.read) {
          SFListStore.read(function (lists) {
            Object.keys(lists || {}).forEach(function (k) { merged[k] = lists[k]; });
            finish();
          });
          return;
        }
      } catch (e) {}
      finish();
    });
  });
}
if (chrome.storage && chrome.storage.onChanged) {
  chrome.storage.onChanged.addListener(function (changes, area) {
    if (area === 'sync' && _settingsCache) _settingsCache = null; // 任意 sync 设置变更 → 下次 getSettings 重新拉取
    // ★ 2026-11-12：自定义名单已挪到 storage.local（见 rules/liststore.js），
    //   设置页保存名单只会触发 local 变更；这里必须一并失效，否则后台仍用旧名单判定下载。
    //   只认这两个键：云端名单 / 统计也写在 local，若不加判断会每次同步都丢掉设置缓存。
    //   2026-11-23：新增 exceptionDomains（例外名单）同样要失效。
    if (area === 'local' && _settingsCache && changes && (changes.allowlist || changes.customBadDomains || changes.exceptionDomains)) _settingsCache = null;
    // 社区名单总开关被关掉 → 立即释放常驻内存（OpenPhish/PhishDestroy 的 Set 与 HaGeZi 位图）
    if (area === 'sync' && changes.communityLists) {
      const cl = changes.communityLists.newValue || {};
      if (!cl.enabled) releaseCommunityLists();
    }
    // session 里的 releasedHosts 被外部改写（如设置页清空放行记录）→ 同步内存镜像
    if (area === 'session' && changes.releasedHosts) refreshReleasedCache();
  });
}

function parseHost(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch (e) { return ''; }
}

// 2026-11-11：自定义黑/白名单（settings.allowlist / customBadDomains）统一改由
//   analyzer 的 matchHostList 匹配，现在支持 `*` / `?` 通配（`*` 不跨标签、`*.foo.com` 归一为后缀、
//   TLD 位禁通配），语义与内置/云端名单完全一致。旧实现保留为回退分支（analyzer 缺失时）。
// 2026-11-12：第 3 个参数是「这份名单属于哪一类」（六份名单之一），决定用哪份通配策略。
//   缺省按自定义黑名单算；放行侧（白名单 / 受保护主机表）必须显式传 customWhite，
//   将来若只放开拦截侧的某条限制，这里不传就会把拦截侧的宽松规则用到放行侧。
function hostMatch(host, list, listKind) {
  try {
    if (SF && typeof SF.matchHostList === 'function') return SF.matchHostList(host, list, listKind || 'customBlack');
  } catch (e) {}
  host = (host || '').toLowerCase();
  return (list || []).some(function (d) {
    d = String(d).trim().toLowerCase();
    return d && (host === d || host.endsWith('.' + d));
  });
}

// 注册域（eTLD+1），含 .com.cn / .net.cn 等二级后缀——域名年龄查询需对「注册域名」取 WHOIS/RDAP，
// 不能对完整子域名（如 www.xxx.com）查，否则查不到。
function _regDomain(host) {
  if (!host) return '';
  host = String(host).toLowerCase().replace(WWW_RE, '');
  const parts = host.split('.');
  if (parts.length <= 2) return host;
  const two = ['com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'co.uk', 'com.au', 'com.tw', 'co.jp'];
  if (parts.length >= 3 && two.includes(parts.slice(-2).join('.'))) return parts.slice(-3).join('.');
  return parts.slice(-2).join('.');
}

// 硬编码银狐木马投递站黑名单（与页面级「扩展内置黑名单」判定同源，来自 iocs.js KNOWN_BAD_DOMAINS）。
// 专门用于下载拦截：命中「下载 URL 域名」或「来源/referrer 域名」即视为已知恶意，下载须强制取消（永不豁免）。
// 背景：此前 onCreated 只查用户自定义黑名单 customBadDomains，漏掉了硬编码名单里的投递站，
//       导致这类站点的 ZIP/EXE 在被页面级标记危险后，下载仍可能放行。
const _KNOWN_BAD_HOSTS = (function () {
  const list = (self.SF_IOCS && self.SF_IOCS.KNOWN_BAD_DOMAINS) || [];
  return list.map(function (d) { return String(d).trim().toLowerCase(); });
})();
// 内置名单：样本 IOC，永不豁免（页面级同样是「命中即判危」，不参与白名单以外的豁免）
// ★ 2026-11-11：内置名单已支持通配（如 `?b?04.8msg8.com` / `*bot.qpefh.com`），
//   通配的正则编译与护栏只存在于 analyzer.js（_splitBuiltinList / _compileBadWild）。
//   这里必须委托给 SF.isBuiltinBad，否则会出现「页面级判危、下载却放行」的半拦截——
//   因为 _KNOWN_BAD_HOSTS 只做后缀比较，通配条目在它眼里永远不命中。
//   下面的本地回退仅用于 analyzer 尚未加载完成的极早期调用，语义仍是「精确 + 子域」。
function isBuiltinBadHost(h) {
  h = (h || '').toLowerCase();
  try { if (SF.isBuiltinBad && SF.isBuiltinBad(h)) return true; } catch (e) {}
  return _KNOWN_BAD_HOSTS.some(function (d) {
    if (!d || d.indexOf('*') !== -1 || d.indexOf('?') !== -1) return false;   // 通配条目交给 analyzer 判定
    return h === d || h.endsWith('.' + d);
  });
}
// 云端名单：云端黑名单命中与内置 IOC 同等处理（2026-11-09 起统一为「任意黑名单 > 任意白名单」，
//   不再被白名单豁免——见下载拦截里的顺序）。
function isCloudBadHost(h) {
  try {
    if (SF.isCloudBad && SF.isCloudBad((h || '').toLowerCase())) return true;
  } catch (e) {}
  return false;
}
// ★ 2026-11-09：云端名单支持「主机名/路径」条目。上面两个函数只认 hostname，
//   路径条目必须拿完整 URL 才能判定，因此另开一对（黑白各一）。
//   下载侧要同时看两处 URL：下载地址本身（item.url）与来源页 URL（referrer/initiator，
//   回退本标签最近一次顶级导航）——「路径白名单」的典型用法就是放行某个下载页，
//   下载地址往往落在同站的另一条路径上。
function isCloudBadUrl(url) {
  try { return !!(SF.matchCloudBadUrl && SF.matchCloudBadUrl(url)); } catch (e) { return false; }
}
function isCloudWhiteUrl(url) {
  try { return !!(SF.matchCloudWhiteUrl && SF.matchCloudWhiteUrl(url)); } catch (e) { return false; }
}
// ★ 2026-11-23：三层「例外」（下载侧）。与页面级 content.js 的 resolveListTier 同一套优先矩阵：
//   云端例外 > 云端黑名单 > 内置例外 > 内置黑名单 > 用户例外 > 用户黑名单。
//   这里按「单个主机名 + 它的 URL」返回 'exc' / 'bad' / ''，因为一次下载有「下载地址」与
//   「来源页地址」两个主机：例外只豁免它自己那一侧，另一侧命中云端黑名单时照样取消。
function isCloudExceptionHost(h) {
  try { return !!(SF.isCloudException && SF.isCloudException((h || '').toLowerCase())); } catch (e) { return false; }
}
function isCloudExceptionUrl(url) {
  try { return !!(SF.matchCloudExceptionUrl && SF.matchCloudExceptionUrl(url)); } catch (e) { return false; }
}
function isBuiltinExceptionHost(h) {
  try { return !!(SF.isBuiltinException && SF.isBuiltinException((h || '').toLowerCase())); } catch (e) { return false; }
}
function _dlListTier(h, url, settings) {
  // ① 云端例外（主机名 / 路径级）
  if ((url && isCloudExceptionUrl(url)) || (h && isCloudExceptionHost(h))) return 'exc';
  // ② 云端黑名单（主机名 / 路径级）
  if ((url && isCloudBadUrl(url)) || (h && isCloudBadHost(h))) return 'bad';
  // ③ 内置例外 → ④ 内置黑名单
  if (h && isBuiltinExceptionHost(h)) return 'exc';
  if (h && isBuiltinBadHost(h)) return 'bad';
  // ⑤ 用户例外 → ⑥ 用户自定义黑名单
  if (h && settings && hostMatch(h, settings.exceptionDomains, 'customException')) return 'exc';
  if (h && settings && hostMatch(h, settings.customBadDomains)) return 'bad';
  return '';
}
// 来源页完整 URL：优先 referrer/initiator，回退到本标签最近一次顶级导航（与 downloadSourceHost 同源逻辑）
function downloadSourceUrl(item) {
  const src = (item && (item.initiator || item.referrer)) || '';
  if (src) return src;
  if (item && item.tabId && item.tabId >= 0) return lastTopUrl[item.tabId] || prevTopUrl[item.tabId] || '';
  return '';
}
// 2026-11-09：名单优先级统一为「任意黑名单 > 任意白名单；同色内 云端 > 内置 > 自定义」。
//   下载侧因此把黑名单（云端/内置/自定义）提到最前，白名单只在全不命中时才放行。
// 可信下载源：用户白名单 + 官方/云端白名单（与页面级 isOfficialDomain 同源）
function isTrustedDownloadHost(h, settings) {
  if (!h) return false;
  if (settings && hostMatch(h, settings.allowlist, 'customWhite')) return true;
  try { return !!(SF.isOfficialDomain && SF.isOfficialDomain(h)); } catch (e) { return false; }
}

// 已知木马化投递物文件名（来自样本静态分析 IOC）：bzy.exe / shanlian_VPN_64.exe 等。
// MV3 扩展读不到下载字节，文件名为最稳定可观测锚点；命中即强拦。
const _KNOWN_BAD_FILENAMES = (self.SF_IOCS && self.SF_IOCS.KNOWN_BAD_FILENAMES) || [];
const _SUSPICIOUS_NAME_PATTERNS = (self.SF_IOCS && self.SF_IOCS.SUSPICIOUS_DOWNLOAD_NAME_PATTERNS) || [];
function _fileNameOf(ref) {
  if (!ref) return '';
  return String(ref).split(/[?#]/)[0].split('/').pop().toLowerCase().trim();
}
function isKnownBadFilename(ref) {
  const name = _fileNameOf(ref);
  if (!name) return false;
  if (_KNOWN_BAD_FILENAMES.some(function (f) { return name === f; })) return true;
  return _SUSPICIOUS_NAME_PATTERNS.some(function (p) { return p && p.test && p.test(name); });
}

// 判断本次下载的「发起页面」是否为危险且未放行，并返回命中的标签页 id 列表
function sourceHostOf(item, state) {
  const dt = state.dangerTabs || {};
  // 1) 直接由该标签页发起
  if (item.tabId && item.tabId >= 0 && dt[item.tabId] && !dt[item.tabId].released) {
    return { host: dt[item.tabId].hostname, tabIds: [item.tabId] };
  }
  // 2) 由 referrer / initiator 页面发起（网页 JS 触发的下载 item.tabId 常为 -1）
  const src = item.initiator || item.referrer || '';
  let h = '';
  try { h = new URL(src).hostname.toLowerCase(); } catch (e) {}
  if (h) {
    if (state.releasedHosts && state.releasedHosts[h]) return { host: '', tabIds: [] }; // 用户已完全放行
    const tabIds = [];
    for (const id in dt) {
      if (!dt[id].released && dt[id].hostname === h) tabIds.push(Number(id));
    }
    if (tabIds.length) return { host: h, tabIds };
  }
  return { host: '', tabIds: [] };
}

// 高危文件类型（银狐木马载体）：直链可执行 + 压缩包 + 网盘分发
function isHighRiskFile(url) {
  const t = (SF && SF.classifyLink) ? SF.classifyLink(url) : 'other';
  return t === 'exec' || t === 'archive' || t === 'cloud';
}

// Chrome 自带 Safe Browsing 的「恶意」判定值（免费加成，用之拦截已知恶意下载）
//   content = 下载的文件已知为恶意；url = 下载网址已知含恶意；host = 来源主机已知分发恶意二进制
// 故意不含 'uncommon'(罕见文件) 与 'unwanted'(潜在不需要)，避免误拦正常新发布软件造成误伤。
function isMaliciousDanger(danger) {
  return danger === 'content' || danger === 'url' || danger === 'host';
}

// 推断本次下载的「来源页面」域名（优先 initiator/referrer，回退到本标签最近一次顶级导航）
function downloadSourceHost(item) {
  const src = item.initiator || item.referrer || '';
  let h = '';
  try { h = new URL(src).hostname.toLowerCase(); } catch (e) {}
  // 回退：referrer/initiator 为空时，用本标签「当前/上一跳」顶级导航页面定位来源
  // （meta refresh 秒跳下载常不带 referrer，但其发起页仍在导航历史里）
  if (!h && item.tabId && item.tabId >= 0) {
    const cand = lastTopUrl[item.tabId] || prevTopUrl[item.tabId] || '';
    if (cand) { try { h = new URL(cand).hostname.toLowerCase(); } catch (e) {} }
  }
  return h;
}

// 将标签页标记为「跳转链污染」（可被内容脚本在判定无害时通过 sf-clear-chain 自动清除）
function markTainted(item, host, state) {
  const tabId = item.tabId;
  if (tabId == null || tabId < 0) return;
  const h = (host || '').toLowerCase();
  const prev = state.dangerTabs[tabId];
  if (!prev || !prev.released) {
    state.dangerTabs[tabId] = { hostname: h || (prev && prev.hostname) || '', released: false, chained: true };
    saveState(state);
  }
}

// 本标签页是否处于「跳转链污染」状态（曾由已判定的危险站跳转而来，且用户未放行）
function isTainted(state, tabId) {
  const t = state.dangerTabs && state.dangerTabs[tabId];
  return !!(t && !t.released && t.chained);
}

// 浏览器启动即把本地黑名单载入内存（服务 Worker 冷启动时也走这里），
// 使首个页面的比对不需要再等一次异步读取。
// 暖加载：仅当「总开关 + 该名单自身开关」都开启时才把名单搬进内存，避免默认关时白读 5MB 位图
async function warmCommunityLists() {
  try {
    if (!(await communityListsOn())) return;
    const s = await getSettings();
    if (s.openphish && s.openphish.enabled) loadOpenPhishDomains().catch(function () {});
    if (s.phishdestroy && s.phishdestroy.enabled) loadPhishDestroyDomains().catch(function () {});
    if (s.hagezi && s.hagezi.enabled) loadHaGeZiFilter().catch(function () {});   // IndexedDB 直接取位图，无需解码
    if (s.badware && s.badware.enabled) loadAdl('badware').catch(function () {});
    if (s.dsam && s.dsam.enabled) loadAdl('dsam').catch(function () {});
  } catch (e) {}
}

if (chrome.runtime.onStartup) {
  chrome.runtime.onStartup.addListener(function () {
    warmCommunityLists();
  });
}

chrome.runtime.onInstalled.addListener(function (details) {  chrome.storage.sync.get(DEFAULTS, function (s) {
    chrome.storage.sync.set(Object.assign({}, DEFAULTS, s || {}));
  });
  chrome.storage.local.get({ stats: { warnings: 0, blocks: 0, recent: [] } }, function (r) {
    if (!r.stats) chrome.storage.local.set({ stats: { warnings: 0, blocks: 0, recent: [] } });
  });
  // 社区名单：仅在总开关与各名单开关都开启时预热内存，并在已启用时触发一次更新
  // （避免首次启用后 24h 内无名单可用；已更新的名单会被 maybeUpdate* 的 24h 幂等约束跳过）
  getSettings().then(function (s) {
    if (!(s && s.communityLists && s.communityLists.enabled)) return;
    const op = (s && s.openphish) || {};
    if (op.enabled) { loadOpenPhishDomains().catch(function () {}); maybeUpdateOpenPhish(false); }
    const pd = (s && s.phishdestroy) || {};
    if (pd.enabled) { loadPhishDestroyDomains().catch(function () {}); maybeUpdatePhishDestroy(false); }
    const hg = (s && s.hagezi) || {};
    if (hg.enabled) { loadHaGeZiFilter().catch(function () {}); maybeUpdateHaGeZi(false); }
    if (s && s.badware && s.badware.enabled) { loadAdl('badware').catch(function () {}); maybeUpdateAdl('badware', false); }
    if (s && s.dsam && s.dsam.enabled) { loadAdl('dsam').catch(function () {}); maybeUpdateAdl('dsam', false); }
  }).catch(function () {});
  // OOBE 首次引导向导已移除：安装/升级不再弹出初始化设置页
  if (details.reason === 'update') {
    // 升级后自动打开设置页（更新日志放映页已移除，不再跳转 #sec=changelog）
    // 关键：在扩展管理页点「重新加载」也会触发 onInstalled(reason=update)，但此时
    // previousVersion 与当前版本号相同、并非真实升级——通过比较版本号过滤，
    // 避免每次重新加载扩展都误弹更新日志。
    var _curVer = (chrome.runtime && chrome.runtime.getManifest && chrome.runtime.getManifest().version) || '';
    if (details.previousVersion && details.previousVersion !== _curVer) {
      try {
        chrome.tabs.create({ url: chrome.runtime.getURL('ui/options.html'), active: true });
      } catch (e) {
        try { chrome.runtime.openOptionsPage(); } catch (_) {}
      }
    }
  }
});

// ===== 危险弹窗系统通知（Windows 右下角 toast）=====
// 由内容脚本（content.js 的 sfNotify）在命中危险时发 sf-notify 消息，后台用
// chrome.notifications 创建原生系统通知。相比声音提示更可靠，无需用户手势解锁。

// ===== 域名年龄查询（RDAP，异步，带缓存与超时）=====
// ① 用 rdap.org 公共引导服务（自动 302 跳转到权威 RDAP 服务器，支持 CORS），
//    无需依赖任何第三方代理，避免不可控外部依赖。
// ② 解析 events 中 eventAction==='registration' 的 eventDate 计算注册天数。
// ③ 失败（网络/CORS/该后缀不支持 RDAP/无注册事件）→ 返回 null，由评分引擎「无数据时优雅跳过」，
//    绝不因查不到而误判（沿用此前「域名年龄维度就绪待数据」的设计）。
// ④ 内存缓存查询结果（同会话内不重复查询），并限制缓存规模。
const _ageCache = new Map(); // regDomain -> {days:number|null, ts:number}
const _AGE_TTL = 6 * 60 * 60 * 1000; // 6 小时
function _ageCacheGet(domain) {
  const e = _ageCache.get(domain);
  if (e && (Date.now() - e.ts) < _AGE_TTL) return e.days;
  return undefined; // undefined=未缓存；null=已查无数据
}
function _ageCacheSet(domain, days) {
  _ageCache.set(domain, { days: days, ts: Date.now() });
  if (_ageCache.size > 500) { // 防止无界增长
    const first = _ageCache.keys().next().value;
    if (first !== undefined) _ageCache.delete(first);
  }
}
async function queryDomainAge(domain) {
  if (!domain) return null;
  const cached = _ageCacheGet(domain);
  if (cached !== undefined) return cached;
  let days = null;
  try {
    const ctrl = new AbortController();
    // 2026-11-09：6s → 4s。域名年龄只是「加分项」（查不到引擎会优雅跳过），
    //   不值得为它把首屏判定拖到 6s 之外；4s 对 rdap.org 的正常响应仍绰绰有余。
    const timer = setTimeout(function () { try { ctrl.abort(); } catch (e) {} }, 4000);
    const resp = await fetch('https://rdap.org/domain/' + encodeURIComponent(domain), {
      redirect: 'follow', signal: ctrl.signal, cache: 'no-store'
    });
    clearTimeout(timer);
    if (resp.ok) {
      const j = await resp.json();
      const events = (j && j.events) || [];
      for (const ev of events) {
        if (ev && ev.eventAction === 'registration' && ev.eventDate) {
          const t = new Date(ev.eventDate).getTime();
          if (!isNaN(t)) {
            const ms = Date.now() - t;
            days = ms < 0 ? 0 : Math.floor(ms / 86400000);
            break;
          }
        }
      }
    }
  } catch (e) { /* RDAP 不可用则保持 null，优雅跳过 */ }
  _ageCacheSet(domain, days);
  return days;
}

// ===== 下载黑名单：被拦下载的载荷域名自动入库 + 跨站复用 =====
// 银狐的运营模式是「一次性落地页 + 复用载荷 CDN」：landing 域名批量换（今天 wps-xz.top、
// 明天 wps-dl.icu），但真正投木马的那个下载域名/对象存储桶往往连用几十个站。
// 因此每次真正取消一个下载时，就把该「下载文件所在注册域名」记下来；
// 下次任何页面（哪怕是全新未判危的落地页）指向同一载荷域名，即可立刻加分甚至直接拦，
// 无需重新把落地页判危一遍 —— 这就是「跨站复用」的价值。
//
// 防误伤三重保险（任何一条命中都不入库）：
//   ① 可信分发域名（GitHub / 微软 / npm / 各发行版镜像等 37 个，见 iocs.js TRUSTED_DOWNLOAD_HOSTS）；
//   ② 品牌官方域名（OFFICIAL_DOMAINS）；
//   ③ 用户信任白名单（settings.allowlist）。
// 另加：90 天自动过期、上限 500 条按最近命中时间淘汰、设置页可逐条删除或一键清空。
const DL_BL_KEY = 'dlBlacklist';
const DL_BL_TTL = 90 * 24 * 60 * 60 * 1000; // 90 天未再命中即过期移除
const DL_BL_MAX = 500;
let _dlBl = null;          // { domain: { first, last, hits, sample, from } }
let _dlBlLoading = null;

function _dlBlLoad() {
  if (_dlBl) return Promise.resolve(_dlBl);
  if (_dlBlLoading) return _dlBlLoading;
  _dlBlLoading = new Promise(function (resolve) {
    try {
      chrome.storage.local.get({ [DL_BL_KEY]: {} }, function (r) {
        _dlBl = (r && r[DL_BL_KEY]) || {};
        _dlBlPrune();
        resolve(_dlBl);
      });
    } catch (e) { _dlBl = {}; resolve(_dlBl); }
  });
  return _dlBlLoading;
}
function _dlBlSave() {
  try { chrome.storage.local.set({ [DL_BL_KEY]: _dlBl || {} }); } catch (e) {}
}
// 过期清理 + 超量淘汰（按 last 最近命中时间保留）
function _dlBlPrune() {
  if (!_dlBl) return false;
  const now = Date.now();
  let changed = false;
  for (const d in _dlBl) {
    const e = _dlBl[d];
    if (!e || !e.last || (now - e.last) > DL_BL_TTL) { delete _dlBl[d]; changed = true; continue; }
    // ★ 2026-11-24：旧版本会把共享存储的注册域（volces.com / aliyuncs.com）整段记进来，
    //   这会把整个平台（含大量正常文件）一起拦掉 —— 启动时直接剔除这类过宽条目。
    if (_isSharedStorageHost(d) && String(d).split('.').length < 3) { delete _dlBl[d]; changed = true; }
  }
  const keys = Object.keys(_dlBl);
  if (keys.length > DL_BL_MAX) {
    keys.sort(function (a, b) { return (_dlBl[b].last || 0) - (_dlBl[a].last || 0); });
    keys.slice(DL_BL_MAX).forEach(function (k) { delete _dlBl[k]; });
    changed = true;
  }
  if (changed) _dlBlSave();
  return changed;
}
// 是否受保护（绝不入库）
// ★ 2026-11-24：共享对象存储平台 —— 桶名随机、注册域却是平台级。
//   把 `qqqqwwee8899.tos-cn-beijing.volces.com` 记成 `volces.com` 等于把整个火山引擎对象存储拉黑
//   （上面还托管着大量正常文件），所以这类只按**桶级**（完整主机名）记账。
const SHARED_STORAGE_DOMAINS = [
  'volces.com',      // 火山引擎 TOS（tos-cn-beijing.volces.com）
  'volcengine.com',
  'aliyuncs.com',    // 阿里云 OSS（oss-cn-hangzhou.aliyuncs.com）
  'myqcloud.com',    // 腾讯云 COS（bucket.cos.ap-x.myqcloud.com）
  'qcloud.com',
  'bcebos.com',      // 百度 BOS
  'bcevod.com',
  'upyun.com',
  'qiniu.com',
  'qiniucdn.com',
  'qbox.me',
  'jdcloud-oss.com',
  'ctyunxs.cn',      // 天翼云
  'hicloud.com'
];
function _isSharedStorageHost(host) {
  const h = String(host || '').toLowerCase();
  if (!h) return false;
  for (let i = 0; i < SHARED_STORAGE_DOMAINS.length; i++) {
    const d = SHARED_STORAGE_DOMAINS[i];
    if (h === d || h.endsWith('.' + d)) return true;
  }
  return false;
}
// 黑名单记账键：普通域名用注册域（eTLD+1，覆盖所有子域）；共享存储用完整主机名（桶级）。
// 返回空串表示「太宽、不该记账」（例如共享平台根域 volces.com 本身）。
function _dlKeyFor(host) {
  const h = String(host || '').toLowerCase().replace(/\.$/, '');
  if (!h) return '';
  if (_isSharedStorageHost(h)) {
    // 至少要「桶.区域.平台.后缀」四级才足够具体。
    // 3 级的是平台自己的区域/服务端点（`tos-cn-beijing.volces.com`、`oss-cn-hangzhou.aliyuncs.com`），
    // 它们同样被成千上万个桶共用，记下来等于拉黑半个平台 —— 一律不记。
    const parts = h.split('.');
    if (parts.length < 4) return '';
    // 首段是服务/区域名（tos / cos / oss / s3 …）而不是桶名 → 也不记
    if (/^(tos|cos|oss|s3|obs|bce|bcebos|kodo|vod|img|cdn|static|dl|file|files)(-[a-z0-9-]+)*$/i.test(parts[0])) return '';
    return h;
  }
  return _regDomain(h) || h;
}
function _dlBlProtected(host, settings) {
  const h = (host || '').toLowerCase();
  if (!h) return true;
  const trusted = (self.SF_IOCS && self.SF_IOCS.TRUSTED_DOWNLOAD_HOSTS) || [];
  if (hostMatch(h, trusted, 'customWhite')) return true;
  // ★ 2026-11-24：共享对象存储的桶名由**用户**随意指定，平台域名在官方表里不代表这个桶可信。
  //   实测 `zzz9.oss-cn-beijing.aliyuncs.com` 会因 `aliyuncs.com` 在官方域名表里而被判成 official，
  //   于是整条学习链路把它当「官方域名」跳过 —— 恶意样本恰恰最爱用这类桶。这里对共享存储只认
  //   trusted / 用户白名单，不再用平台后缀当挡箭牌（记账时也只会记到桶级，见 _dlKeyFor）。
  try {
    if (SF && SF.isOfficialDomain && !_isSharedStorageHost(h) && SF.isOfficialDomain(h)) return true;
  } catch (e) {}
  if (settings && hostMatch(h, settings.allowlist, 'customWhite')) return true;
  return false;
}
// 记一次拦截：只记「下载文件所在的注册域名」（载荷域名），落地页域名仅作来源元数据留档
function dlBlacklistAdd(downloadHost, meta) {
  const h = (downloadHost || '').toLowerCase();
  if (!h) return;
  return Promise.all([_dlBlLoad(), getSettings()]).then(function (arr) {
    const settings = arr[1];
    if (_dlBlProtected(h, settings)) return;
    // ★ 2026-11-24：共享对象存储按桶级记账（见 _dlKeyFor），否则会连累整个平台
    const dom = _dlKeyFor(h);
    if (!dom) return;
    const now = Date.now();
    const cur = _dlBl[dom];
    if (cur) {
      cur.last = now;
      cur.hits = (cur.hits || 1) + 1;
      if (meta && meta.from && cur.from !== meta.from) cur.from = meta.from;
    } else {
      _dlBl[dom] = {
        first: now, last: now, hits: 1,
        sample: (meta && meta.filename) ? String(meta.filename).slice(0, 80) : '',
        from: (meta && meta.from) ? String(meta.from).slice(0, 120) : '',
        via: (meta && meta.via) ? String(meta.via).slice(0, 16) : ''
      };
    }
    _dlBlPrune();
    _dlBlSave();
  }).catch(function () {});
}
// 命中查询（按注册域名匹配，含全部子域名）
function dlBlacklistHas(host) {
  if (!_dlBl) return false;                 // 未加载完成时保守返回 false（不误拦）
  const h = (host || '').toLowerCase();
  if (!h) return false;
  // 先按「记账键」精确匹配（普通域名=注册域；共享存储=桶级主机名）
  const key = _dlKeyFor(h);
  if (key && _dlBl[key]) return true;
  // 兼容旧条目：仍允许用注册域命中，但共享平台的过宽键已在 _dlBlPrune 里剔除
  const dom = _regDomain(h);
  if (dom && _dlBl[dom]) return true;
  // 共享存储：桶级条目也要覆盖它的子域（bucket.region.volces.com 命中 → x.bucket.region.volces.com）
  if (_isSharedStorageHost(h)) {
    let rest = h;
    while (rest.indexOf('.') > 0 && rest.split('.').length >= 3) {
      rest = rest.slice(rest.indexOf('.') + 1);
      if (_dlBl[rest]) return true;
    }
  }
  return false;
}
function dlBlacklistDomains() {
  return _dlBlLoad().then(function () { return Object.keys(_dlBl || {}); });
}
// ===== 载荷链接静态嗅探的落库（2026-11-24）=====
// 内容脚本在「已判危」页面上扫出「按钮背后的地址」（直接指向对象存储的 .zip、或 /download、/dsluc
// 这类分发页），这里做最后一道校验再记账：
//   · 可信下载源 / 官方域名 / 用户白名单 → 不记（_dlBlProtected）
//   · 与落地页同注册域 → 不记（那是页面自己，交给页面级判定处理）
//   · 共享对象存储 → 只记**桶级**主机名（_dlKeyFor），否则会把整个平台拉黑
// 不产生任何网络请求：地址本来就在页面里，扩展只是把它记下来。
function learnPayloadHosts(msg) {
  return Promise.all([_dlBlLoad(), getSettings()]).then(function (arr) {
    const settings = arr[1];
    const pageHost = String((msg && msg.pageHost) || '').toLowerCase().replace(/:\d+$/, '');
    const pageReg = _regDomain(pageHost);
    const learned = [];
    const items = (msg && msg.items) || [];
    for (let i = 0; i < items.length && i < 16; i++) {
      const it = items[i] || {};
      const url = String(it.url || '');
      if (!/^https?:/i.test(url)) continue;
      let host = '';
      try { host = new URL(url).hostname.toLowerCase(); } catch (e) { continue; }
      if (!host) continue;
      if (_dlBlProtected(host, settings)) continue;
      const reg = _regDomain(host);
      if (!reg) continue;
      if (pageReg && reg === pageReg) continue;
      const key = _dlKeyFor(host);
      if (!key) continue;                       // 太宽（平台根域）→ 不记
      const now = Date.now();
      const cur = _dlBl[key];
      if (cur) { cur.last = now; cur.hits = (cur.hits || 1) + 1; continue; }
      _dlBl[key] = {
        first: now, last: now, hits: 1,
        sample: (_fileOfUrl(url) || '').slice(0, 80),
        from: pageHost.slice(0, 120),
        via: 'sniff'
      };
      learned.push(key);
    }
    if (learned.length) { _dlBlPrune(); _dlBlSave(); }
    return learned;
  }).catch(function () { return []; });
}
// service worker 一启动就预热，保证 downloads.onCreated（同步判断）能立即查到黑名单
try { _dlBlLoad(); } catch (e) {}

// ===== 跳转解析器跟随（resolver follow，2026-11-20 新增，方案 A）=====
// 背景：银狐的「下载」按钮往往不是直链，而是同源的解析器端点，例如
//   https://www.deepseekst.net/go/event?type=download&t=<base64 token>
// 真正的载荷域名（如 wqrn59d.com/dsnw）藏在 302 / Refresh / JS 跳转里，DOM 上完全看不到。
// 页面一旦判危就禁用下载入口，用户连 hover 都看不到目标地址 → 自定义黑名单与自动学习都拿不到它。
//
// 做法（最小改动）：后台开一个**不可见标签页**去访问这个解析器 URL，用 webRequest 只观察不阻塞地
//   盯这个 tab 的主文档请求：一旦跳到与落地页不同的注册域，就认定那是隐藏分发域 →
//   写入「自动学习的下载黑名单」→ 立即关掉探测标签页（不让文件落地）。
//   · 用真实标签页而不是 fetch：UA / Referer / Cookie / token 时效全部天然一致（这正是它们要的）；
//   · 不合成点击，因此不涉及 isTrusted；A 拿不到时再考虑 C；
//   · 5s 超时；同一解析器 URL 60s 内只探测一次。
// 前提：manifest 已加 "webRequest"（host_permissions 本来就是 <all_urls>）。
const RESOLVER_TIMEOUT_MS = 5000;
const RESOLVER_DEDUPE_MS = 60 * 1000;
const _resolverProbes = new Map();   // probeTabId -> { fromHost, fromReg, url, started, srcTabId, timer }
const _resolverRecent = new Map();   // 解析器 URL -> 最近一次探测时间

function _resolverRegOf(host) {
  try { return _regDomain(String(host || '').toLowerCase()); } catch (e) { return ''; }
}

// 结束一次探测：关标签页、必要时入库、通知发起页。返回是否命中。
function _resolverEnd(tabId, hitHost, hitUrl, reason) {
  const p = _resolverProbes.get(tabId);
  if (!p) return false;
  _resolverProbes.delete(tabId);
  try { clearTimeout(p.timer); } catch (e) {}
  try { chrome.tabs.remove(tabId); } catch (e) {}
  if (hitHost) {
    // 与页面级拦截同一条学习链路：受保护域名（GitHub/微软/官方/用户白名单）由 _dlBlProtected 排除
    try { dlBlacklistAdd(hitHost, { filename: '', from: p.fromHost }); } catch (e) {}
    if (p.srcTabId != null) {
      try { safeTabMsg(p.srcTabId, { type: 'sf-resolver-hit', host: hitHost, url: hitUrl || '', from: p.fromHost }); } catch (e) {}
    }
    console.log('[resolver] 命中 ' + hitHost + '（' + reason + '），来源 ' + p.url);
  } else {
    console.log('[resolver] 未命中/超时（' + reason + '）：' + p.url);
  }
  return !!hitHost;
}

// 该 URL 是否「像下载物」——用于识别解析器通过 XHR 取回载荷地址的情形
function _resolverLooksPayload(url) {
  const u = String(url || '');
  if (/\.(exe|msi|zip|rar|7z|iso|img|apk|bat|cmd|scr|vbs|jar|dmg|pkg|tgz|tar|gz)(\?|#|$)/i.test(u)) return true;
  try {
    const t = (SF && SF.classifyLink) ? SF.classifyLink(u) : 'other';
    return t === 'exec' || t === 'archive' || t === 'cloud';
  } catch (e) { return false; }
}

// 发起一次跟随。返回 {ok, started} 或 {ok:false, reason}
function followResolver(url, srcTabId) {
  // ★ 2026-11-23：设置项 `resolverFollow`（设置 → 拦截行为 → 运行时取链探测，默认开）。
  //   内容脚本已在入口处判过一次，这里再判一次：万一有其它调用方或旧版本内容脚本，
  //   也不会在用户明确关闭后仍然去开探测标签页。
  try {
    if (_settingsCache && _settingsCache.resolverFollow === false) return { ok: false, reason: 'disabled' };
  } catch (e) {}
  let abs = '';
  try { abs = new URL(String(url || '')).href; } catch (e) { return { ok: false, reason: 'bad-url' }; }
  if (!/^https?:/i.test(abs)) return { ok: false, reason: 'not-http' };

  const now = Date.now();
  const prev = _resolverRecent.get(abs);
  if (prev && now - prev < RESOLVER_DEDUPE_MS) return { ok: true, skipped: 'recent' };
  _resolverRecent.set(abs, now);
  // 顺手清理过期去重记录，避免长期占用内存
  _resolverRecent.forEach(function (ts, k) {
    if (now - ts > RESOLVER_DEDUPE_MS) _resolverRecent.delete(k);
  });

  const fromHost = parseHost(abs);
  const fromReg = _resolverRegOf(fromHost);
  if (!fromHost || !fromReg) return { ok: false, reason: 'bad-host' };

  try {
    // 先开 about:blank 再 update：保证 webRequest 监听器一定能在导航开始前拿到 probe 记录，
    // 否则极快的第一跳可能在 tabs.create 回调之前就发出（竞态）。
    chrome.tabs.create({ url: 'about:blank', active: false }, function (tab) {
      if (chrome.runtime.lastError || !tab || tab.id == null) return;
      const tabId = tab.id;
      const probe = {
        fromHost: fromHost, fromReg: fromReg, url: abs,
        started: Date.now(), srcTabId: (srcTabId == null ? null : srcTabId), timer: null
      };
      probe.timer = setTimeout(function () { _resolverEnd(tabId, '', '', 'timeout'); }, RESOLVER_TIMEOUT_MS);
      _resolverProbes.set(tabId, probe);
      try {
        chrome.tabs.update(tabId, { url: abs }, function () { void chrome.runtime.lastError; });
      } catch (e) { _resolverEnd(tabId, '', '', 'update-failed'); }
    });
  } catch (e) { return { ok: false, reason: 'create-failed' }; }
  return { ok: true, started: true };
}

// 观察器：只读，不阻塞请求（webRequest 非 blocking 用法不需要 "webRequestBlocking"）
try {
  if (chrome.webRequest && chrome.webRequest.onBeforeRequest) {
    chrome.webRequest.onBeforeRequest.addListener(function (d) {
      const p = _resolverProbes.get(d.tabId);
      if (!p || !d.url) return;
      const h = parseHost(d.url);
      if (!h) return;
      const reg = _resolverRegOf(h);
      if (!reg) return;
      // ① 主文档跳到别的注册域 = 解析结果（302 / meta refresh / location= 最终都会走到这里）
      if (d.type === 'main_frame') {
        if (reg !== p.fromReg) _resolverEnd(d.tabId, h, d.url, 'main_frame');
        return;
      }
      // ② 解析器用 XHR/fetch 取回地址：只认跨注册域且「像下载物」的，避免把统计/广告当载荷
      if (reg !== p.fromReg && _resolverLooksPayload(d.url)) {
        _resolverEnd(d.tabId, h, d.url, 'subresource');
      }
    }, { urls: ['<all_urls>'], types: ['main_frame', 'xmlhttprequest', 'other', 'script'] }, []);
  }
} catch (e) {}
// 兜底：标签页自己完成了跳转（webRequest 因权限/时机漏掉时）也能收网
try {
  if (chrome.tabs && chrome.tabs.onUpdated) {
    chrome.tabs.onUpdated.addListener(function (tabId, info) {
      const p = _resolverProbes.get(tabId);
      if (!p) return;
      const u = String(info && info.url || '');
      if (!u) return;
      const h = parseHost(u);
      const reg = _resolverRegOf(h);
      if (h && reg && reg !== p.fromReg) _resolverEnd(tabId, h, u, 'tab-updated');
    });
  }
} catch (e) {}
// 探测标签页被外部关掉（用户手动关 / 崩溃）→ 清掉记录，避免内存泄漏
try {
  if (chrome.tabs && chrome.tabs.onRemoved) {
    chrome.tabs.onRemoved.addListener(function (tabId) {
      const p = _resolverProbes.get(tabId);
      if (!p) return;
      try { clearTimeout(p.timer); } catch (e) {}
      _resolverProbes.delete(tabId);
    });
  }
} catch (e) {}


// ===== ICP 备案「权威核验」（多源 API + 24h 缓存 + 限流 + 超时）=====
// 背景：只扫「页面文本里的备案号」两头都会错——
//   ① 大量合法国内站点并不在页面上展示备案号 → 被误判「无备案」而白白加分；
//   ② 钓鱼站盗用他人备案号写在页脚 → 反被误判「合规」而放行（app-4399.com.cn 即此类）。
// 因此改为按域名调权威备案接口核验，页面文本扫描降级为兜底。
//
// 返回三态（缺一不可，判定逻辑见 analyzer.js 的 detIcpMissing / detIcpStolen）：
//   { queried:true,  hasIcp:true  } → 该域名确有备案主体 → 联动跳过仿冒类判定
//   { queried:true,  hasIcp:false } → 权威确认「本域名无备案」→ 页面若仍显示备案号即为盗用，重罚
//   { queried:false }              → 接口失败/限流/超时 → 回退页面文本扫描，绝不凭此加分
//
// ★ 隐私控制：本查询会把「注册域名」发给第三方备案接口，因此**绝不对所有站点查询**。
//   仅在 content.js 判定「确有核验价值」时才发起（详见 content.js needIcpVerify 门控）：
//   页面出现备案号需验真伪 / .cn 站点未找到备案号 / 已检出域名仿冒。
//   其余站点（绝大多数海外站与普通站）完全不触发任何外部请求。
const _icpCache = new Map();          // regDomain -> { r:{...}, ts:number }
const _ICP_TTL = 24 * 60 * 60 * 1000; // 成功结果缓存 24 小时
const _ICP_FAIL_TTL = 5 * 60 * 1000;  // 失败短缓存，避免高频重试打爆公共接口
const _icpRateWindow = new Map();     // providerName -> [请求时间戳...]

const ICP_PROVIDERS = [
  {
    name: 'uapis', rateLimitPerMin: 0,
    // ★ 2026-11-24：uapis 改版。「无备案」不再返回 200 + serviceLicence:"查询失败"，
    //   而是 HTTP **404** + {"code":"NOT_FOUND","message":"No ICP record found for this domain."}
    //   （实测 ai.deekseep-e.com.cn / deepaiseek.com.cn 均如此）。
    //   旧 queryIcp 对非 2xx 直接 `continue` 换源，于是改版后首源永远"失败"，全部压力落到
    //   第二源 apihz（令牌桶 10 次/分钟）；一旦超限，整次查询返回 {queried:false} ——
    //   「盗用他人备案号」55 分必须 queried:true 且 hasIcp:false 才判，于是整条规则静默失效
    //   （失败结果还有 5 分钟短缓存，一失败就连续 5 分钟都不判）。
    //   现在把 404 收进白名单：只有正文明确是「没有记录」才算**已查询且无记录**。
    acceptStatus: [404],
    buildUrl: function (d) { return 'https://uapis.cn/api/v1/network/icp?domain=' + encodeURIComponent(d); },
    // 有备案：{"code":200,"serviceLicence":"京ICP备xxxxxxx号","unitName":"..."}
    // 无备案：{"code":200,"serviceLicence":"查询失败","unitName":"查询失败"}
    // ⚠️ 查不到时它仍返回 code:200，必须靠「是否含 ICP备/ICP证」区分真实备案号与失败文案，
    //    否则会把无备案的外国站误判成 hasIcp:true，直接放行造成漏检。
    // ★ 2026-11-24：改成三态 —— 命中返回 {hasIcp:true}，**明确的**无记录返回 {hasIcp:false}，
    //   其余（字段缺失 / 未预期结构）返回 null 表示「这一源没给答案」，由调用方换源。
    parse: function (d) {
      const lic = (d && typeof d.serviceLicence === 'string') ? d.serviceLicence.trim() : '';
      const ok = d && (d.code === 200 || d.code === '200');
      if (ok && /ICP[备证]/.test(lic)) {
        return { hasIcp: true, icpNumber: lic, unitName: (d.unitName && d.unitName !== '查询失败') ? d.unitName : '' };
      }
      // 旧：任何非命中都返回 {hasIcp:false} —— 等于把「接口返回了别的东西」也算成「权威确认无备案」。
      if (ok && lic === '查询失败') return { hasIcp: false };
      return null;
    },
    // 非 2xx 时「这条 404 是不是无记录」的判定。只认 uapis 自己的无记录口径：
    //   code 为 NOT_FOUND，或 message 里有 "No ICP record"。
    //   参数错误（如 INVALID_PARAM）、接口改版返回 HTML、网关 5xx 一律不算 ——
    //   「查不到原因」绝不能当成「权威确认无备案」，否则 55 分重罚会砸到正规站。
    noRecord: function (d) {
      const code = String((d && d.code) || '').toUpperCase();
      const msg = String((d && d.message) || '');
      return code === 'NOT_FOUND' || /no\s+icp\s+record/i.test(msg);
    }
  },
  {
    // 公开 demo 凭据，上游可能随时撤销；撤销后本源静默失败并回退首源/页面扫描，不影响判定安全性
    name: 'apihz', rateLimitPerMin: 10, id: '88888888', key: '88888888',
    // ★ 2026-11-24：对冲延迟 —— 见 queryIcp 顶部注释。uapis 有备案时 70~200ms 就答完，
    //   这 400ms 的推迟让「有备案的正常站」根本不会向第二个接口披露域名；只有 uapis 迟迟
    //   不答（无备案要 8~10s）时才真正发出请求。
    hedgeDelay: 400,
    buildUrl: function (d, c) {
      return 'https://cn.apihz.cn/api/wangzhan/icp.php?id=' + encodeURIComponent(c.id) +
             '&key=' + encodeURIComponent(c.key) + '&domain=' + encodeURIComponent(d);
    },
    // 有备案：{"code":200,"icp":"蜀ICP备xxx号","unit":"..."} / 无备案：{"code":400,"msg":"查询失败或没有备案。"}
    // ⚠️ 2026-11-24：这个公开 demo key 经常**被限流**，此时它返回的是
    //   {"code":400,"msg":"调用频次过快，请19秒后再试，或购买钻石会员！…"}（HTTP 仍是 200）。
    //   旧实现把所有 code≠200 都当 {hasIcp:false}，等于把「我刚被限流」当成
    //   「权威确认这个域名没有备案」—— 配合页面上的备案号就是 55 分「盗用他人备案号」，
    //   会砸到真正备过案的正规站。现在只有 msg 明确是「查询失败或没有备案」才算无记录，
    //   限流 / 参数错误 / 未预期结构一律返回 null（= 这一源没答案，换源或按失败处理）。
    parse: function (d) {
      const lic = (d && typeof d.icp === 'string') ? d.icp.trim() : '';
      const msg = String((d && d.msg) || '');
      const code = d && (d.code === 200 || d.code === '200') ? 200 : (d && String(d.code));
      if (code === 200 && /ICP[备证]/.test(lic)) {
        return { hasIcp: true, icpNumber: lic, unitName: (d.unit && d.unit !== '查询失败') ? d.unit : '' };
      }
      if (code === '400' && /查询失败|没有备案/.test(msg) && !/频次|稍后|稍后再试|会员/.test(msg)) {
        return { hasIcp: false };
      }
      // ★ 2026-11-24（第二次实测补）：apihz 对「无记录」还有第二种应答形状 ——
      //   HTTP 200 + {"code":200,"td":"2-1","type":"查询失败","icp":"查询失败","unit":"查询失败",
      //              "domain":"查询失败","time":"查询失败"}（实测同一域名两次请求，一次 400 一次 200）。
      //   旧 parse 只认 code:400 那一种，于是这一形状被当成「这一源没答案」→ 换源 → 整次查询失败。
      //   判据收得很紧：icp 与 type **两个字段都恰好是**「查询失败」、且明确不是限流文案；
      //   限流（含「频次/稍后/会员」）、参数错误、未预期结构一律仍返回 null。
      if (code === 200 && lic === '查询失败' && String((d && d.type) || '').trim() === '查询失败') {
        return { hasIcp: false };
      }
      return null;
    }
  }
];

// 令牌桶：60 秒滑动窗口内限制单源请求数，超限则本周期跳过该源
function _icpAcquire(p) {
  const limit = p.rateLimitPerMin || 0;
  if (!limit) return true;
  const now = Date.now();
  const recent = (_icpRateWindow.get(p.name) || []).filter(function (t) { return now - t < 60000; });
  _icpRateWindow.set(p.name, recent);
  if (recent.length >= limit) return false;
  recent.push(now);
  return true;
}

function _icpCacheGet(domain) {
  const e = _icpCache.get(domain);
  if (!e) return undefined;
  const ttl = e.r && e.r.queried ? _ICP_TTL : _ICP_FAIL_TTL;
  if (Date.now() - e.ts < ttl) return e.r;
  return undefined;
}
function _icpCacheSet(domain, r) {
  _icpCache.set(domain, { r: r, ts: Date.now() });
  if (_icpCache.size > 500) { // 防止无界增长
    const first = _icpCache.keys().next().value;
    if (first !== undefined) _icpCache.delete(first);
  }
}

async function queryIcp(domain) {
  if (!domain) return { queried: false, hasIcp: false };
  const cached = _icpCacheGet(domain);
  if (cached !== undefined) return cached;

  // ★ 2026-11-24（第二次修正）：把「串行换源」改成「并行对冲（hedge）」。
  //   实测（本机、ai.deekseep-e.com.cn，各测两轮）：
  //     · uapis：**有备案** 70~200ms 就回 200 + 备案号；**无备案** 要 **8~10 秒** 才回
  //       404 {"code":"NOT_FOUND"}（实测 9966ms / 8073ms）。
  //     · apihz：两个方向都在 0.9~2.8s 内回，但公开 demo key 限 10 次/分钟。
  //   上一版把单源超时压到 1.5s，本意是让第二源拿到预算，结果**反而把「无记录」这条路砍死**：
  //   8~10s 才到的 404 应答必然被 1.5s 掐断，前面那段 acceptStatus 逻辑成了不可达代码 →
  //   永远 `{queried:false}` →「盗用他人备案号」55 分消失（ai.deekseep-e.com.cn 停在 45 分）。
  //   现在的分工：
  //     · uapis 立刻发。有备案时 200ms 内定案，**根本不会惊动第二源**（保住原隐私口径）；
  //     · apihz 延迟 400ms 对冲。只有 uapis 没在 400ms 内给出确定结论时才真正发请求
  //       （省 apihz 的令牌：它 10 次/分钟，被无谓消耗后整条路都会失效）；
  //     · 谁先给出**确定结论**（确有备案 / 明确无记录）谁胜出，立刻 abort 另一个；
  //     · 单源上限 9s、总预算 10s，让 uapis 那 8~10s 的 404 也能在预算内到达。
  //   内容脚本不再需要为 ICP 阻塞 2.2s 以上：慢结论由「迟到重判」补上（见 content.js 的
  //   collectCriticalEnrichments / onLateIcp），判定不再被第三方接口拖住。
  //
  //   旧（串行 + 单源 1.5s，404 路径实际不可达）：
  //   const ICP_TOTAL_BUDGET = 4500;
  //   const ICP_SOURCE_TIMEOUT = 1500;
  //   const t0 = Date.now();
  //   for (const p of ICP_PROVIDERS) {
  //     if (!_icpAcquire(p)) continue;
  //     const left = ICP_TOTAL_BUDGET - (Date.now() - t0);
  //     if (left <= 300) break;
  //     try {
  //       const ctrl = new AbortController();
  //       const timer = setTimeout(function () { try { ctrl.abort(); } catch (e) {} }, Math.min(ICP_SOURCE_TIMEOUT, left));
  //       const resp = await fetch(p.buildUrl(domain, p), { signal: ctrl.signal, cache: 'no-store' });
  //       clearTimeout(timer);
  //       const text = await resp.text();
  //       if (!text) continue;
  //       let data;
  //       try { data = JSON.parse(text); } catch (e) { continue; }
  //       if (!resp.ok) {
  //         const accepted = (p.acceptStatus || []).indexOf(resp.status) !== -1 &&
  //           typeof p.noRecord === 'function' && p.noRecord(data);
  //         if (!accepted) continue;
  //         const noRecord = { queried: true, hasIcp: false, icpNumber: null, unitName: null, service: p.name };
  //         _icpCacheSet(domain, noRecord);
  //         return noRecord;
  //       }
  //       const parsed = p.parse(data);
  //       if (!parsed) continue;
  //       const result = { queried: true, hasIcp: !!parsed.hasIcp, icpNumber: parsed.icpNumber || null,
  //         unitName: parsed.unitName || null, service: p.name };
  //       _icpCacheSet(domain, result);
  //       return result;
  //     } catch (e) { continue; }
  //   }
  const ICP_TOTAL_BUDGET = 10000;
  const ICP_SOURCE_TIMEOUT = 9000;
  const ctrls = [];
  let winner = null;

  // 单源尝试：返回「确定结论对象」或 null（= 这一源没答案 / 失败 / 被放弃）。
  // 注意 _icpAcquire 放在真正发请求的位置（kick）里，而不是建任务时 —— 否则对冲失败的那一源
  // 会白白吃掉 apihz 的每分钟令牌额度。
  function attempt(p) {
    return new Promise(function (resolve) {
      function kick() {
        if (winner) return resolve(null);            // 已有人胜出 → 连请求都不发
        if (!_icpAcquire(p)) return resolve(null);
        const ctrl = new AbortController();
        ctrls.push(ctrl);
        const timer = setTimeout(function () { try { ctrl.abort(); } catch (e) {} }, ICP_SOURCE_TIMEOUT);
        fetch(p.buildUrl(domain, p), { signal: ctrl.signal, cache: 'no-store' })
          .then(function (resp) {
            return resp.text().then(function (text) { return { resp: resp, text: text }; });
          })
          .then(function (o) {
            clearTimeout(timer);
            if (!o.text) return null;
            let data;
            try { data = JSON.parse(o.text); } catch (e) { return null; } // 非 JSON（接口改版/HTML）→ 没答案
            // ⚠️ 「无备案」在 uapis 是 HTTP 404（见 ICP_PROVIDERS 注释）：非 2xx 也要读正文，
            //    只有「状态码在该源白名单里 + 正文明确说没有记录」才算已查询且无记录；
            //    参数错误 / 5xx / 返回 HTML 一律当「没答案」，绝不臆断成「权威确认无备案」。
            if (!o.resp.ok) {
              const accepted = (p.acceptStatus || []).indexOf(o.resp.status) !== -1 &&
                typeof p.noRecord === 'function' && p.noRecord(data);
              if (!accepted) return null;
              return { queried: true, hasIcp: false, icpNumber: null, unitName: null, service: p.name };
            }
            const parsed = p.parse(data);
            if (!parsed) return null;   // 三态：null = 限流 / 未预期结构 → 没答案
            return {
              queried: true,
              hasIcp: !!parsed.hasIcp,
              icpNumber: parsed.icpNumber || null,
              unitName: parsed.unitName || null,
              service: p.name
            };
          })
          .then(function (res) { resolve(res || null); })
          .catch(function () { clearTimeout(timer); resolve(null); });   // 超时 / 网络错误
      }
      if (p.hedgeDelay) setTimeout(kick, p.hedgeDelay);
      else kick();
    });
  }

  const tasks = ICP_PROVIDERS.map(function (p) { return attempt(p); });
  const result = await new Promise(function (resolve) {
    let left = tasks.length;
    let done = false;
    const budgetTimer = setTimeout(function () {
      if (done) return;
      done = true; resolve(null);
    }, ICP_TOTAL_BUDGET);
    tasks.forEach(function (pr) {
      pr.then(function (r) {
        if (done) return;
        if (r) { done = true; winner = r; clearTimeout(budgetTimer); resolve(r); return; }
        if (--left === 0) { done = true; clearTimeout(budgetTimer); resolve(null); }
      });
    });
  });
  // 胜出后取消还在飞的请求（省流量，也避免对冲那一源白跑一趟）
  ctrls.forEach(function (c) { try { c.abort(); } catch (e) {} });
  if (result) { _icpCacheSet(domain, result); return result; }

  const failed = { queried: false, hasIcp: false };
  _icpCacheSet(domain, failed); // 失败按 _ICP_FAIL_TTL 短缓存
  return failed;
}




/* ============================================================================
 * 我的云端库（模板）
 * ----------------------------------------------------------------------------
 * 状态：整段已注释，不会影响当前任何功能。
 * 目的：日后用「我自己控制的静态源」替换上方原作者的云端名单。
 *
 * ── 启用步骤 ──────────────────────────────────────────────────────────────
 * 1) 准备静态 JSON 文件，结构见下方 MY_CLOUD_SAMPLE_PAYLOAD 注释；
 * 2) 托管到你可控的位置：GitHub Pages / Cloudflare Pages / Gitee Pages / 自建对象存储；
 * 3) 把 MY_CLOUD_OFFICIAL_URL 改成你的地址；
 * 4) 在 manifest.json 的 content_security_policy.extension_pages.connect-src 中加上你的域名。
 *    注意：background service worker 不受 extension_pages 的 CSP 约束，
 *    但 options.html 属于扩展页——若想在设置页手动刷新名单，必须加该条目；
 * 5) 签名：把 MY_CLOUD_PUBKEY_JWK 填为 JWK 公钥，源侧用对应私钥签名。
 *    强烈建议启用；否则源一旦被接管，攻击者即可让任意域名免检；
 * 6) 原作者的云端库代码（常量 / 同步 / 缓存 / 消息处理器）已于 2026-11-01 全部移除，
 *    本文件已不存在 CLOUD_OFFICIAL_URL、CLOUD_CACHE_KEY 等任何相关标识符。
 *    因此启用时只有一条路：整体启用下方 MY_CLOUD_* 全套。
 *    本模板已自带 _myCloudBuildSet（字符串校验建表）与 _myCloudSuffixHit（后缀查表）
 *    两个通用工具函数，不依赖任何已删除的代码，可直接开箱启用。
 * 7) 启用时还需恢复两处调用方：
 *    - 本文件：取消注释模板末尾的 sf-cloud-official 消息处理器
 *      （原处理器已随云端库一并删除）；
 *    - content/content.js：在 collectCriticalEnrichments 中恢复「云端库查询」步骤
 *      （已于 2026-11-01 一并移除，原文见 .bak_20261101010207_remove-cloud/content.js）；
 *    - rules/analyzer.js 的 EXTRA_OFFICIAL_SET 与 registerCloudOfficial 已保留，
 *      作为「运行时动态白名单」的注入槽位，可直接沿用，无需改动。
 *
 * ── 内容取舍建议 ──────────────────────────────────────────────────────────
 * - 名单不是越大越好。原作者那份是「热门站点榜」衍生（25 万条 / 3.94MB），
 *   语义是「该域名足够主流，不按仿冒站处理」，与「某软件官网」不是一回事。
 * - 自制名单建议只收录「本引擎实测误报 + 你人工复核过」的域名，
 *   几十到几百条即可，体积可忽略，也不会触及 10MB 的 storage.local 配额。
 * ============================================================================ */

// const MY_CLOUD_OFFICIAL_URL = 'https://你的域名/official-domains.json';
// const MY_CLOUD_CACHE_KEY = 'sfb_cloud_official';
// const MY_CLOUD_PUBKEY_JWK = null;             // 填 JWK 公钥即启用验签；null = 不校验（仅过渡期可接受）
// const MY_CLOUD_SYNC_THROTTLE_MS = 6 * 60 * 60 * 1000;
//
// // 期望的 JSON 结构（domains 是唯一参与签名的内容，其余字段不签名）
// // {
// //   "updated": "2026-11-01",
// //   "count": 2,
// //   "source": "SilverFoxBlocker 实测误报清单（人工复核后加入）",
// //   "domains": ["example.com", "sub.example.org"],
// //   "signature": "base64url( Ed25519 签名，签的是 JSON.stringify(domains) )"
// // }
//
// let _myCloudSet = null;
// let _myCloudMeta = { count: 0, updated: null, etag: null, cachedAt: 0 };
//
// // 通用工具：域名字符串校验后建 Set（剔除含空格 / 斜杠 / 连续点的异常项）
// function _myCloudBuildSet(arr) {
//   const set = new Set();
//   if (!Array.isArray(arr)) return set;
//   for (const d of arr) {
//     if (typeof d === 'string' && d.indexOf(' ') === -1 && d.indexOf('/') === -1 && d.indexOf('..') === -1) {
//       set.add(d.toLowerCase());
//     }
//   }
//   return set;
// }
//
// // 通用工具：标签对齐后缀匹配（与 analyzer.js 的 isOfficialDomain 同语义）
// function _myCloudSuffixHit(set, hostname) {
//   const h = (hostname || '').toLowerCase().replace(/^www\./, '');
//   if (!h) return null;
//   if (set.has(h)) return h;
//   let idx = h.indexOf('.');
//   while (idx !== -1) {
//     const suf = h.slice(idx + 1);
//     if (set.has(suf)) return suf;
//     idx = h.indexOf('.', idx + 1);
//   }
//   return null;
// }
//
// // 验签：未配置公钥时直接放行（仅过渡期使用）
// async function _myCloudVerify(payload) {
//   if (!MY_CLOUD_PUBKEY_JWK) return true;
//   const key = await crypto.subtle.importKey('jwk', MY_CLOUD_PUBKEY_JWK,
//     { name: 'Ed25519' }, false, ['verify']);
//   const data = new TextEncoder().encode(JSON.stringify(payload.domains));
//   const b64 = String(payload.signature || '').replace(/-/g, '+').replace(/_/g, '/');
//   const sig = Uint8Array.from(atob(b64), function (c) { return c.charCodeAt(0); });
//   return crypto.subtle.verify({ name: 'Ed25519' }, key, sig, data);
// }
//
// async function myCloudSync(force) {
//   try {
//     const head = await fetch(MY_CLOUD_OFFICIAL_URL, { method: 'HEAD', cache: 'no-store' });
//     if (!head.ok) throw new Error('HEAD ' + head.status);
//     const etag = head.headers.get('etag');
//     if (!force && etag && etag === _myCloudMeta.etag) return;      // 未变化，复用已有缓存
//     const resp = await fetch(MY_CLOUD_OFFICIAL_URL, { cache: 'no-store' });
//     if (!resp.ok) throw new Error('GET ' + resp.status);
//     const j = await resp.json();
//     if (!Array.isArray(j.domains)) throw new Error('bad payload');
//     if (!(await _myCloudVerify(j))) throw new Error('signature mismatch');  // 验签失败一律拒绝，不降级
//     _myCloudSet = _myCloudBuildSet(j.domains);
//     _myCloudMeta = { count: j.domains.length, updated: j.updated || null, etag: etag, cachedAt: Date.now() };
//     await new Promise(function (done) {
//       chrome.storage.local.set({
//         [MY_CLOUD_CACHE_KEY]: {
//           domains: j.domains, updated: _myCloudMeta.updated,
//           etag: etag, cachedAt: Date.now()
//         }
//       }, function () {
//         if (chrome.runtime.lastError) console.warn('[myCloud] 写入失败：', chrome.runtime.lastError.message);
//         done();
//       });
//     });
//   } catch (e) {
//     /* 失败静默，保留旧缓存 */
//   }
// }
//
// // 启动：先读本地缓存秒级可用，再按需联网增量更新
// chrome.storage.local.get(MY_CLOUD_CACHE_KEY, function (res) {
//   const d = res && res[MY_CLOUD_CACHE_KEY];
//   if (d && Array.isArray(d.domains)) {
//     _myCloudSet = _myCloudBuildSet(d.domains);
//     _myCloudMeta = { count: d.domains.length, updated: d.updated || null, etag: d.etag || null, cachedAt: d.cachedAt || 0 };
//   }
//   if (!_myCloudMeta.cachedAt || (Date.now() - _myCloudMeta.cachedAt) >= MY_CLOUD_SYNC_THROTTLE_MS) {
//     myCloudSync(false);
//   }
// });
// chrome.runtime.onStartup.addListener(function () { myCloudSync(true); });
//
// // 内容脚本查询入口（启用模板时一并取消注释）
// // 注意：需同时恢复 content.js 里 collectCriticalEnrichments 的云端库查询步骤。
// chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
//   if (!msg || msg.type !== 'sf-cloud-official') return;
//   const host = (msg.host || '').toLowerCase().replace(/^www\./, '');
//   const hit = _myCloudSet ? _myCloudSuffixHit(_myCloudSet, host) : null;
//   try { sendResponse({ official: !!hit, matched: hit || '' }); } catch (e) {}
// });


// ============================================================
// 银狐急救：自动抓取 360 系统急救箱（独立版64位）/ 火绒恶性木马专杀（无签名版）最新下载直链并触发浏览器下载
// 逻辑移植自用户提供的 Python 脚本（update_360jijiuxiang_multi.py / update_hrkill_unsign.py）
// ============================================================

const SF_RESCUE_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36';

// ---- 360 系统急救箱（独立版） ----
// 360c[0o]mpkill_5.1.<bits>.<build>-<mmdd>.zip  （bits: 0=32位, 64=64位）
const SF_360_SOURCES = [
  { name: '官网', url: 'https://weishi.360.cn/jijiuxiang/index.html' },
  { name: '软件宝库', url: 'https://baoku.360.cn/aqsd/221.html' }
];
const SF_360_NAME_RE = /360c[0o]?mpkill_?5\.1\.(\d+)\.(\d{4})-(\d{4})\.zip/i;
const SF_360_PATH_RE = /((?:\/\/|https?:\/\/)[^"'\s<>]*?\/)?(360c[0o]?mpkill_?5\.1\.\d+\.\d{4}-\d{4}\.zip)/ig;
const SF_360_BUDATA_RE = /bu-data="([^"]+)"/g;

function sf360NormalizeUrl(raw) {
  raw = (raw || '').trim();
  if (raw.indexOf('//') === 0) return 'https:' + raw;
  return raw;
}

function sf360DecodeBudata(b64) {
  try {
    const parts = String(b64).split('|||');
    const decoded = [];
    for (let i = 0; i < parts.length; i++) {
      let p = (parts[i] || '').trim();
      if (!p) continue;
      try {
        const pad = (-p.length) % 4;
        const bin = atob(p + (pad > 0 ? '='.repeat(pad) : ''));
        const bytes = Uint8Array.from(bin, function (c) { return c.charCodeAt(0); });
        decoded.push(new TextDecoder('utf-8').decode(bytes));
      } catch (e) { decoded.push(''); }
    }
    if (!decoded.length) return '';
    const head = decoded[0];
    const rest = decoded.slice(1);
    if (head.endsWith(':') || head.endsWith('://')) return head + '//' + rest.join('/');
    if (head.indexOf('//') === 0) return 'https:' + head;
    return head + '/' + rest.join('/');
  } catch (e) { return ''; }
}

function sf360ParseName(name) {
  const m = SF_360_NAME_RE.exec(name || '');
  if (!m) return null;
  return { bits: parseInt(m[1], 10), build: parseInt(m[2], 10), name: name };
}

async function sf360FetchHtml(url) {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(function () { ctrl.abort(); }, 15000);
    const resp = await fetch(url, { headers: { 'User-Agent': SF_RESCUE_UA }, signal: ctrl.signal });
    clearTimeout(t);
    const bytes = new Uint8Array(await resp.arrayBuffer());
    let text = '';
    try { text = new TextDecoder('utf-8').decode(bytes); } catch (e) {}
    if (!text) return '';
    if (/\uFFFD/.test(text) && /[\u0080-\u00ff]/.test(text)) {
      try { text = new TextDecoder('gbk').decode(bytes); } catch (e2) {}
    }
    return text;
  } catch (e) { return ''; }
}

function sf360ExtractCandidates(sourceName, html) {
  const out = [];
  if (!html) return out;
  let m;
  SF_360_PATH_RE.lastIndex = 0;
  while ((m = SF_360_PATH_RE.exec(html))) {
    const prefix = m[1] || '';
    const fname = m[2];
    if (!prefix) continue;
    const url = sf360NormalizeUrl(prefix + fname);
    const p = sf360ParseName(fname);
    if (!p) continue;
    out.push({ source: sourceName, url: url, x: p.bits, yyyy: p.build, name: fname, bits: p.bits === 0 ? '32位' : (p.bits === 64 ? '64位' : '未知') });
  }
  SF_360_BUDATA_RE.lastIndex = 0;
  while ((m = SF_360_BUDATA_RE.exec(html))) {
    const url = sf360DecodeBudata(m[1]);
    if (!url) continue;
    const fm = /\/([^/]+\.zip)$/i.exec(url);
    if (!fm) continue;
    const p = sf360ParseName(fm[1]);
    if (!p) continue;
    out.push({ source: sourceName, url: url, x: p.bits, yyyy: p.build, name: fm[1], bits: p.bits === 0 ? '32位' : (p.bits === 64 ? '64位' : '未知') });
  }
  return out;
}

async function sfFetchRescue360() {
  const all = [];
  for (let i = 0; i < SF_360_SOURCES.length; i++) {
    const src = SF_360_SOURCES[i];
    const html = await sf360FetchHtml(src.url);
    const cands = sf360ExtractCandidates(src.name, html);
    for (let j = 0; j < cands.length; j++) all.push(cands[j]);
  }
  const uniq = {};
  for (let i = 0; i < all.length; i++) {
    const c = all[i];
    const k = c.url.toLowerCase();
    if (!uniq[k]) { uniq[k] = c; uniq[k].sources = [c.source]; }
    else if (uniq[k].sources.indexOf(c.source) < 0) uniq[k].sources.push(c.source);
  }
  const list = [];
  for (const key in uniq) { if (Object.prototype.hasOwnProperty.call(uniq, key)) list.push(uniq[key]); }
  const c64 = list.filter(function (c) { return c.x === 64; }).sort(function (a, b) { return b.yyyy - a.yyyy; });
  if (c64.length) {
    const best = c64[0];
    return { ok: true, url: best.url, filename: best.name, fallback: false };
  }
  return { ok: false, reason: 'no_candidate' };
}

// ---- 火绒恶性木马专杀（无签名版） ----
const SF_HRKILL_SERVERS = ['down3', 'down7', 'update', 'down2', 'down-tencent'];
const SF_HRKILL_RE = /hrkill_unsign-1\.0\.0\.(\d+)\.exe$/i;

function sfHrkillParseVersion(url) {
  const m = SF_HRKILL_RE.exec(url || '');
  return m ? parseInt(m[1], 10) : null;
}

async function sfHrkillVersionExists(v) {
  const checks = SF_HRKILL_SERVERS.map(function (server) {
    const url = 'https://' + server + '.huorong.cn/hrkill/hrkill_unsign-1.0.0.' + v + '.exe';
    return (async function () {
      try {
        const ctrl = new AbortController();
        const t = setTimeout(function () { ctrl.abort(); }, 6000);
        const resp = await fetch(url, { method: 'HEAD', signal: ctrl.signal });
        clearTimeout(t);
        if (resp.status === 200) return server;
        if (resp.status === 404) return null;
        const ctrl2 = new AbortController();
        const t2 = setTimeout(function () { ctrl2.abort(); }, 6000);
        const r2 = await fetch(url, { method: 'GET', headers: { 'Range': 'bytes=0-0' }, signal: ctrl2.signal });
        clearTimeout(t2);
        if (r2.status === 200 || r2.status === 206) return server;
        return null;
      } catch (e) { return null; }
    })();
  });
  const results = await Promise.all(checks);
  for (let i = 0; i < results.length; i++) if (results[i]) return results[i];
  return null;
}

async function sfFetchRescueHrkill(seedVersion) {
  const seed = (seedVersion && seedVersion > 0) ? seedVersion : 200;
  const exists = function (v) { return sfHrkillVersionExists(v); };
  let lo, hi;
  if (await exists(seed)) {
    lo = seed; hi = seed + 2000;
  } else {
    lo = 1; hi = seed - 1;
    if (hi < lo) return { ok: false, reason: 'seed_missing' };
  }
  let last = null;
  while (lo <= hi) {
    const mid = Math.floor((lo + hi) / 2);
    if (await exists(mid)) { last = mid; lo = mid + 1; }
    else hi = mid - 1;
  }
  if (last == null) return { ok: false, reason: 'none_found' };
  const srv = await exists(last);
  if (!srv) return { ok: false, reason: 'verify_failed' };
  return { ok: true, url: 'https://' + srv + '.huorong.cn/hrkill/hrkill_unsign-1.0.0.' + last + '.exe', filename: 'hrkill_unsign-1.0.0.' + last + '.exe', fallback: false };
}

async function sfHandleFetchRescue(msg) {
  const tool = msg.tool;
  const fallbackUrl = msg.fallbackUrl || '';
  try {
    let res;
    if (tool === '360') {
      res = await sfFetchRescue360();
    } else if (tool === 'hrkill') {
      const seed = sfHrkillParseVersion(fallbackUrl) || 200;
      res = await sfFetchRescueHrkill(seed);
    } else {
      return { ok: false, error: 'unknown_tool' };
    }
    if (res.ok) {
      try {
        await new Promise(function (resolve) {
          chrome.downloads.download({ url: res.url, filename: res.filename, conflictAction: 'uniquify' }, function () {
            if (chrome.runtime.lastError) res.downloadError = chrome.runtime.lastError.message;
            resolve();
          });
        });
      } catch (e) { res.downloadError = (e && e.message) || 'download_failed'; }
      return res;
    }
    if (fallbackUrl) {
      const fname = tool === 'hrkill'
        ? ('hrkill_unsign-1.0.0.' + (sfHrkillParseVersion(fallbackUrl) || '172') + '.exe')
        : (fallbackUrl.split('/').pop() || '360系统急救箱.zip');
      try {
        await new Promise(function (resolve) {
          chrome.downloads.download({ url: fallbackUrl, filename: fname, conflictAction: 'uniquify' }, function () { resolve(); });
        });
      } catch (e) {}
      return { ok: true, url: fallbackUrl, filename: fname, fallback: true, reason: res.reason || 'fetch_failed' };
    }
    return { ok: false, error: (res.reason) || 'fetch_failed' };
  } catch (e) {
    if (fallbackUrl) {
      const fname = fallbackUrl.split('/').pop() || 'rescue.bin';
      try { await new Promise(function (resolve) { chrome.downloads.download({ url: fallbackUrl, filename: fname, conflictAction: 'uniquify' }, function () { resolve(); }); }); } catch (e2) {}
      return { ok: true, url: fallbackUrl, filename: fname, fallback: true, reason: 'exception' };
    }
    return { ok: false, error: (e && e.message) || 'exception' };
  }
}

chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
  if (!msg || !msg.type) return;

  // （云端官网库展示已改为「设置页纯前端直接 fetch CDN 公开名单 + 读 storage.local」，不再经此后台消息端口）


  // ===== 「访问正确的页面」开标签页（内容脚本没有 tabs 权限）=====
  //   为什么要经后台：仿冒站常常重写 window.open / 弹窗策略，直接开会被拦成「死按钮」。
  //   只放行 http(s) 与本扩展自身的 chrome-extension:// 地址，防止被页面借此开任意协议
  //   （javascript: / file: / data: 一律拒绝）。
  if (msg.type === 'SF_OPEN_TAB') {
    try {
      const u = String(msg.url || '');
      const selfBase = chrome.runtime.getURL('');
      const okUrl = /^https?:[/][/]/i.test(u) || (u.indexOf(selfBase) === 0);
      if (!okUrl) { try { sendResponse({ ok: false, error: 'bad_url' }); } catch (e) {} return true; }
      chrome.tabs.create({ url: u, active: msg.active !== false }, function (tab) {
        const err = chrome.runtime.lastError;
        try { sendResponse({ ok: !err, tabId: tab && tab.id, error: err ? err.message : '' }); } catch (e) {}
      });
    } catch (e) {
      try { sendResponse({ ok: false, error: (e && e.message) || 'open_failed' }); } catch (e2) {}
    }
    return true;
  }

  // ===== AI 浮球请求打开设置子页面（content script 无 tabs 权限时的兜底通道）=====
  if (msg.type === 'SF_OPEN_OPTIONS_SECTION') {
    try {
      const sec = (msg.section || 'general');
      chrome.tabs.create({ url: chrome.runtime.getURL('ui/options.html') + '#sec=' + encodeURIComponent(sec), active: true });
      try { sendResponse({ ok: true }); } catch (e) {}
    } catch (e) {
      try { sendResponse({ ok: false }); } catch (e2) {}
    }
    return true;
  }

  // ===== 银狐急救：自动抓取 360 系统急救箱（独立版64位）/ 火绒专杀（无签名版）最新直链并触发浏览器下载 =====
  if (msg.type === 'SF_FETCH_RESCUE') {
    sfHandleFetchRescue(msg).then(function (res) {
      try { sendResponse(res); } catch (e) {}
    }).catch(function (err) {
      try { sendResponse({ ok: false, error: (err && err.message) || 'fetch_failed' }); } catch (e2) {}
    });
    return true; // 异步 sendResponse
  }




  if (msg.type === 'sf-icp-verify') {
    // 内容脚本仅在「确有核验价值」时才询问本页域名的权威备案状态
    if (!msg.hostname) { try { sendResponse({ queried: false, hasIcp: false }); } catch (e) {} return true; }
    const dom = _regDomain((msg.hostname || '').toLowerCase().replace(WWW_RE, ''));
    getSettings().then(function (settings) {
      // 总开关关闭 → 不发任何外部请求，调用方回退页面文本扫描
      if (settings.icpApiVerify === false) return { queried: false, hasIcp: false };
      return queryIcp(dom);
    }).then(function (r) {
      try { sendResponse(r || { queried: false, hasIcp: false }); } catch (e) {}
    }).catch(function () {
      try { sendResponse({ queried: false, hasIcp: false }); } catch (e) {}
    });
    return true; // 异步 sendResponse
  }

  // ===== 下载黑名单（#16）通道 =====
  if (msg.type === 'sf-dl-blacklist') {
    // 内容脚本取全量载荷域名列表（纯本地读取，无外部请求），用于给页面下载链接加分
    dlBlacklistDomains().then(function (domains) {
      try { sendResponse({ domains: domains || [] }); } catch (e) {}
    }).catch(function () { try { sendResponse({ domains: [] }); } catch (e) {} });
    return true;
  }
  if (msg.type === 'sf-dl-bl-list') {
    // 设置页取带元数据的完整列表（便于用户核查与逐条删除）
    _dlBlLoad().then(function () {
      const out = Object.keys(_dlBl || {}).map(function (d) {
        return Object.assign({ domain: d }, _dlBl[d]);
      }).sort(function (a, b) { return (b.last || 0) - (a.last || 0); });
      try { sendResponse({ items: out }); } catch (e) {}
    }).catch(function () { try { sendResponse({ items: [] }); } catch (e) {} });
    return true;
  }
  if (msg.type === 'sf-dl-bl-remove') {
    _dlBlLoad().then(function () {
      const d = (msg.domain || '').toLowerCase();
      if (d && _dlBl[d]) { delete _dlBl[d]; _dlBlSave(); }
      try { sendResponse({ ok: true }); } catch (e) {}
    }).catch(function () { try { sendResponse({ ok: false }); } catch (e) {} });
    return true;
  }
  if (msg.type === 'sf-dl-bl-clear') {
    _dlBl = {}; _dlBlSave();
    try { sendResponse({ ok: true }); } catch (e) {}
    return true;
  }

  if (msg.type === 'sf-domain-age') {
    // 内容脚本在分析前询问本页域名的注册天数；异步返回 {days:number|null}
    const host = (msg.hostname || '').toLowerCase().replace(WWW_RE, '');
    const dom = _regDomain(host);
    queryDomainAge(dom).then(function (days) {
      try { sendResponse({ days: (typeof days === 'number') ? days : null }); } catch (e) {}
    }).catch(function () {
      try { sendResponse({ days: null }); } catch (e) {}
    });
    return true; // 异步 sendResponse
  }

  if (msg.type === 'sf-detected') {
    // ★ 2026-10-15：hostname 在**信封顶层**（见 content.js 的 sendMessage），不在 msg.data 里
    updateStats(msg.data, msg.hostname, sender);
    // 仅当被判为 danger 时记录该标签页，用于下载拦截判定
    if (msg.data && msg.data.level === 'danger' && sender.tab && sender.tab.id != null) {
      loadState().then(function (state) {
        const prev = state.dangerTabs[sender.tab.id];
        state.dangerTabs[sender.tab.id] = {
          // ★ 2026-10-15：原来读 msg.data.hostname（恒空）⇒ 危险标签页的域名为空，
          //   会削弱「换落地页不换载荷 CDN」与跳转链污染的域名比对。改从信封取。
          hostname: String(msg.hostname || (msg.data && msg.data.hostname) || '').toLowerCase(),
          released: false,
          chained: !!(prev && prev.chained) // 保留跳转链污染标记
        };
        saveState(state);
      });
    }
  } else if (msg.type === 'sf-verdict') {
    // 内容脚本回传「分析闸门」判定：danger=保持取消挂起下载；safe/warn=静默重下挂起下载
    const tabId = sender.tab ? sender.tab.id : null;
    if (tabId != null) resolveAnalysis(tabId, msg.level);
  } else if (msg.type === 'sf-check-chain') {
    // 内容脚本询问：本标签页是否由已判定危险站跳转而来
    const tabId = sender.tab ? sender.tab.id : null;
    loadState().then(function (state) {
      sendResponse({ chained: isTainted(state, tabId) });
    });
    return true; // 异步 sendResponse，必须返回 true
  } else if (msg.type === 'sf-clear-chain') {
    // 内容脚本判定本页完全无辜（真官网/有备案/无下载入口）→ 清除跳转链污染，避免误拦
    const tabId = sender.tab ? sender.tab.id : null;
    if (tabId != null) {
      loadState().then(function (state) {
        const t = state.dangerTabs[tabId];
        if (t && t.chained && !t.released) { delete state.dangerTabs[tabId]; saveState(state); }
      });
    }
  } else if (msg.type === 'sf-release') {
    const host = (msg.hostname || '').toLowerCase();
    const tabId = sender.tab ? sender.tab.id : null;
    loadState().then(function (state) {
      if (tabId != null && state.dangerTabs[tabId]) state.dangerTabs[tabId].released = true;
      if (host) state.releasedHosts[host] = true;
      saveState(state);
      // 同步内存镜像，使「完全放行」立即对后续下载生效（无需等 storage 回读）
      if (host) releasedHostsCache[host] = true;
      if (tabId != null && state.dangerTabs[tabId]) {
        const hh = (state.dangerTabs[tabId].hostname || '').toLowerCase();
        if (hh) releasedHostsCache[hh] = true;
      }
    });
  } else if (msg.type === 'sf-leave') {
    // 直接关闭触发该消息的标签页；关不掉（如最后一个标签）则退到新标签页
    if (sender.tab && sender.tab.id != null) {
      const tid = sender.tab.id;
      chrome.tabs.remove(tid, function () {
        if (chrome.runtime.lastError) {
          try { chrome.tabs.update(tid, { url: 'chrome://newtab/' }); } catch (e) {}
        }
      });
    }
  } else if (msg.type === 'sf-gesture') {
    // ★ 2026-11-23：内容脚本在真实点击/按键时发来的「用户手势」时间戳（节流 300ms）。
    //   只记时间，不区分标签页 —— 点「下载」后新开标签再下载是常见合规范式。
    // noteUserGesture();
    // ★ 2026-11-24：改为带强度。strong 附带「点到的链接」的绝对 URL / 主机名 / 文件名，
    //   后台据此判断这次点击是否真的指向要下载的那个文件（见 _strongEvidence）。
    //   weak（点空白处、普通按键、滚动）只刷新时间戳，不能给高危下载背书。
    // ★ 2026-11-23（授权模型）：强手势要带「所在页面的 origin」，供 _authDecide 与
    //   item.initiator 做精确匹配（跨站引用不会被误判成同一次点击）。
    noteUserGesture(
      (msg && msg.strength === 'strong') ? 'strong' : 'weak',
      {
        url: (msg && msg.url) || '',
        host: (msg && msg.host) || '',
        file: (msg && msg.file) || '',
        origin: (msg && msg.origin) || _originOfUrl(sender.tab && sender.tab.url),
        dl: !!(msg && msg.dl)
      },
      (sender.tab && sender.tab.id != null) ? sender.tab.id : -1
    );
    try { sendResponse({ ok: true }); } catch (e) {}
  } else if (msg.type === 'sf-exe-deny') {
    // ★ 2026-11-23：用户在确认条上选「保持拦截」→ 清掉待确认队列，避免下次误用旧 URL。
    const tid = sender.tab ? sender.tab.id : null;
    if (tid != null) {
      try { delete _sfAuth.pending[tid]; } catch (e) {}
      _authPersist();
    }
    try { sendResponse({ ok: true }); } catch (e) {}
  } else if (msg.type === 'sf-allow-download') {
    // 用户选择「仍要下载」：将该 URL 加入本次会话放行名单（避免重复拦截）。
    // 来自「页面内钩子」(fromPage) 时由页面自身执行下载（已在收到回执后触发），
    // 后台不必重下，避免双下载；来自「后台大弹窗」(下载已被取消) 时则由后台重新触发下载。
    const url = (msg && msg.url) ? String(msg.url).trim() : '';
    // ★ 2026-11-23（授权模型）：用户点「继续下载」= 明确授权本页。
    //   授权后本页后续的同站下载不再重复询问（直到用户刷新/导航，见 tabs.onUpdated）。
    if (msg && msg.grantPage && sender.tab && sender.tab.id != null) {
      _authGrant(sender.tab.id, (msg.origin || '').toLowerCase() || _originOfUrl(sender.tab.url));
      // ★ 2026-11-23（每站首次确认）：用户点了「继续下载」＝ 明确同意该站下载可执行文件，
      //   把它写进「已确认」名单，否则该站下一次下载又会被问一遍（等于每次都问）。
      //   取 pending 里登记好的 siteKey（那是「来源站」的注册域）；拿不到才退回页面 host。
      try {
        const p = _sfAuth.pending[sender.tab.id];
        const sk = (p && p.siteKey) || _siteKeyOfHost(parseHost(sender.tab.url));
        if (sk) _siteMark(sk);
      } catch (e) {}
      try { delete _sfAuth.pending[sender.tab.id]; } catch (e) {}
      _authPersist();
    }
    if (url) {
      addAllowedDownload(url);
      if (!msg.fromPage && chrome.downloads && chrome.downloads.download) {
        chrome.downloads.download({ url: url }, function () {
          if (chrome.runtime.lastError) {
            // 无法直接重下（如 blob / 需站内鉴权），提示前台让用户手动在站内下载
            try {
              if (sender.tab && sender.tab.id != null) safeTabMsg(sender.tab.id, { type: 'sf-download-allow-failed', url });
            } catch (e2) {}
          }
        });
      }
    }
    // 页面内「仍要下载」(fromPage)：用户已明确放行本页下载，额外给来源标签一个短暂放行窗口，
    // 兜底「链接 href 与最终下载 URL 经重定向不一致」等精确匹配失败的情况，确保浏览器能真正下到文件。
    if (msg && msg.fromPage) {
      const tid = sender.tab ? sender.tab.id : null;
      // ★ 2026-11-19：4s → 6s。内容脚本现在会在回执之后才重放点击，
      //   站点自身的取链/鉴权可能再花一两秒，窗口太短会让重放再次落进闸门。
      if (tid != null) tempAllowedTabs[tid] = Date.now() + (msg && msg.tempMs ? msg.tempMs : 6000);
    }
    if (!url) {
      // 无具体 URL（如 JS 触发 / 表单提交下载）：仅靠上面的临时放行窗口覆盖后续下载
      const tid = sender.tab ? sender.tab.id : null;
      if (tid != null) tempAllowedTabs[tid] = Date.now() + (msg && msg.tempMs ? msg.tempMs : 8000);
    }
    // 回执确认：内容脚本在收到回执后才真正触发本页下载，确保本 URL 已登记进放行名单，
    // 避免「消息异步未达、onCreated 先取消」的竞态（导致「仍要下载」后仍被拦截）。
    try { sendResponse({ ok: true, url: url }); } catch (e) {}
  } else if (msg.type === 'sf-record-blocked-download') {
    // 内容脚本在页面级（点击/入口/表单）拦截了一次下载——后台并未走 chrome.downloads 取消流程，
    // 故在此补计「拦截下载次数」并把载荷域名写入自动学习的下载黑名单（与 cancelDownload 同源逻辑）。
    // 受保护域名（可信下载源/官方/用户白名单）由 dlBlacklistAdd 内部 _dlBlProtected 自动排除，不会误入库。
    try {
      dlBlacklistAdd(parseHost((msg.url || '').trim()), { filename: '', from: (msg.host || '') });
    } catch (e) {}
    try {
      chrome.storage.local.get({ stats: { warnings: 0, blocks: 0, recent: [] } }, function (r) {
        const stats = r.stats || { warnings: 0, blocks: 0, recent: [] };
        stats.blocks = (stats.blocks || 0) + 1;
        chrome.storage.local.set({ stats });
      });
    } catch (e) {}
  } else if (msg.type === 'sf-learn-payload') {
    // ★ 2026-11-24：危险页的「按钮背后的下载地址」静态嗅探结果（内容脚本只扫 DOM，不发请求）。
    //   异步落库后把真正新增的域名回推给页面，由页面弹一条 toast 告知用户（与解析器跟随同一套口径）。
    const tabId = sender.tab ? sender.tab.id : null;
    learnPayloadHosts(msg).then(function (learned) {
      try {
        if (learned && learned.length && tabId != null) {
          safeTabMsg(tabId, { type: 'sf-payload-learned', hosts: learned });
        }
      } catch (e) {}
      try { sendResponse({ ok: true, learned: learned || [] }); } catch (e) {}
    });
    return true;   // 异步回执
  } else if (msg.type === 'sf-probe-resolver') {
    // ★ 2026-11-20：解析器跟随（方案 A）。内容脚本在危险页发现「同源跳转端点」时调用，
    //   后台开不可见标签页跑一次跳转链，命中跨域载荷域就写进自动学习黑名单并立刻关标签页。
    //   立刻回执（started），真正结果通过 sf-resolver-hit 推回发起页，不阻塞内容脚本。
    let r = { ok: false, reason: 'error' };
    try { r = followResolver(msg.url || '', sender.tab ? sender.tab.id : null); } catch (e) {}
    try { sendResponse(r); } catch (e) {}
  } else if (msg.type === 'sf-notify') {
    // 危险弹窗系统通知（Windows 右下角 toast）：内容脚本转发，后台创建原生通知
    try {
      if (chrome.notifications && chrome.notifications.create) {
        const nid = 'sf-' + Date.now();
        chrome.notifications.create(nid, {
          type: 'basic',
          iconUrl: chrome.runtime.getURL('icons/icon128.png'),
          title: (msg.title || '⚠️ SilverFoxBlocker 提醒'),
          message: (msg.message || '发现高风险站点'),
          priority: 1,
          requireInteraction: false
        }, function () {});
        // 兜底：无论系统通知设置如何，10 秒后强制清除，避免 toast 常驻右下角
        setTimeout(function () {
          try { chrome.notifications.clear(nid, function () {}); } catch (e) {}
        }, 10000);
      }
    } catch (e) {}
  } else if (msg.type === 'sf-intel-query') {
    // 威胁情报查询：按设置中启用的 provider 查询当前域名，仅返回"判定为恶意"的结果
    // （满足"只显示判断为恶意的 API"），供内容脚本在网页顶部横幅展示。
    (async function () {
      try {
        const host = (msg.hostname || '').toLowerCase();
        const cacheKey = 'sf_intel_' + host;
        const cached = _intelCache[cacheKey];
        if (cached && (Date.now() - cached.t) < _INTEL_CACHE_TTL) {
          try { sendResponse({ enabled: true, results: cached.r, errors: cached.e || [] }); } catch (e) {}
          return;
        }
        const settings = await getSettings();
        const ti = settings.threatIntel || { enabled: false, providers: {} };
        if (!ti.enabled || !host) {
          try { sendResponse({ enabled: !!ti.enabled, results: [] }); } catch (e) {}
          return;
        }
        const providers = ti.providers || {};
        const results = [];
        const errors = [];
        for (const p of THREAT_INTEL_PROVIDERS) {
          const cfg = providers[p.id];
          if (!cfg || !cfg.enabled) continue;
          // 需加密存储 Key 的情报源（VirusTotal / Google Safe Browsing）：先解密再传入 query，
          // 明文 Key 不出后台。兼容旧版：v1.6.1 及更早存下的 VT Key 是明文，此处暂按明文使用，
          // 用户打开一次设置页即自动迁移为密文（见 options.js 的 migrateVtPlainKey）。
          let key = cfg.apiKey || '';
          if (p.encryptsKey && key) {
            if (typeof sfLooksEncrypted === 'function' && sfLooksEncrypted(key)) {
              try { key = await sfDecryptKey(key); } catch (e) { key = ''; }
            }
            if (!key) {
              errors.push({ id: p.id, name: p.name, status: null, reason: 'decrypt', detail: 'API Key 密文无法解密（可能曾手动改动或被篡改），请到「规则与名单」重新填写。' });
              continue;
            }
          }
          try {
            const r = await p.query(host, key, msg.url || '');
            if (r && r.malicious) {
              results.push({ id: p.id, name: p.name, hasScore: !!p.hasScore, soft: !!r.soft, score: r.score, scoreMax: r.scoreMax, detail: r.detail, src: r.src, vtLevel: r.vtLevel || '', verdictText: r.verdictText || '', engines: Array.isArray(r.engines) ? r.engines : [], stale: !!r.stale, facts: Array.isArray(r.facts) ? r.facts : [], order: (p.order || 0) });
            } else if (r && r.error) {
              errors.push({ id: p.id, name: p.name, status: (r.status || null), reason: (r.reason || 'unknown'), detail: (r.detail || '') });
            }
          } catch (e) {}
        }
        results.sort(function (a, b) { return (a.order || 0) - (b.order || 0); });
        _intelCache[cacheKey] = { t: Date.now(), r: results, e: errors };
        try { sendResponse({ enabled: true, results: results, errors: errors }); } catch (e) {}
      } catch (e) {
      try { sendResponse({ enabled: false, results: [] }); } catch (e2) {}
    }
  })();
  return true; // 异步 sendResponse
  }

  // ===== OpenPhish 本地钓鱼黑名单 =====
  if (msg.type === 'sf-openphish-update') {
    // 解耦长任务：立即 ACK，真正的抓取交给一次性 alarm（alarm 回调期间 Chrome 保证 SW 存活），
    // 抓取结果通过单向消息 sf-openphish-updated 推送给设置页——避免「长连接 + 后台被回收」导致 port closed。
    // ★ 2026-11-26：设置页点「立即更新」会先把开关写进 storage.sync 再发这条消息；
    //   sync 的 onChanged 与 message 之间没有先后保证，这里直接丢一次设置缓存，
    //   确保本次抓取与「是否参与拦截」的判定用的是刚保存的开关值。
    _settingsCache = null;
    try { chrome.alarms.create('sfOpenPhishManual', { when: Date.now() + 200 }); } catch (e) {}
    try { sendResponse({ started: true }); } catch (e) {}
    return true;
  }
  if (msg.type === 'sf-openphish-check') {
    // 内容脚本访问网站时调用：与本地静态名单（域名集合）比对（精确 + 父域回溯）
    (async () => {
      try {
        if (!(await communityListsOn())) { try { sendResponse({ listed: false, count: 0, updated: 0, disabled: true }); } catch (_) {} return; }
        if (!_opDomains) await loadOpenPhishDomains();
        const host = (msg.hostname || '').toLowerCase();
        const listed = openPhishHit(host);
        // meta 已常驻内存，不再每次导航都读一次 storage.local（原实现多花 1~2ms 且推迟横幅）
        if (!_opMeta) { try { _opMeta = await new Promise((res) => chrome.storage.local.get({ [SF_OP_META_KEY]: { updated: 0 } }, (o) => res(o[SF_OP_META_KEY] || { updated: 0 }))); } catch (e) {} }
        try { sendResponse({ listed: listed, count: (_opDomains ? _opDomains.size : 0), updated: ((_opMeta && _opMeta.updated) || 0) }); } catch (e) {}
      } catch (e) { try { sendResponse({ listed: false, count: 0, updated: 0 }); } catch (_) {} }
    })();
    return true;
  }

  // ===== PhishDestroy 本地钓鱼黑名单 =====
  if (msg.type === 'sf-phishdestroy-update') {
    // 与 OpenPhish 相同：立即 ACK，抓取交给一次性 alarm，结果用单向消息回推设置页
    // ★ 2026-11-26：设置页点「立即更新」会先把开关写进 storage.sync 再发这条消息；
    //   sync 的 onChanged 与 message 之间没有先后保证，这里直接丢一次设置缓存，
    //   确保本次抓取与「是否参与拦截」的判定用的是刚保存的开关值。
    _settingsCache = null;
    try { chrome.alarms.create('sfPhishDestroyManual', { when: Date.now() + 200 }); } catch (e) {}
    try { sendResponse({ started: true }); } catch (e) {}
    return true;
  }
  if (msg.type === 'sf-phishdestroy-check') {
    // 内容脚本访问网站时调用：与常驻内存的 Set 比对（精确 + 父域回溯），不读 storage.local
    (async () => {
      try {
        if (!(await communityListsOn())) { try { sendResponse({ listed: false, count: 0, updated: 0, disabled: true }); } catch (_) {} return; }
        if (!_pdDomains) await loadPhishDestroyDomains();
        const host = (msg.hostname || '').toLowerCase();
        const listed = phishDestroyHit(host);
        if (!_pdMeta) { try { _pdMeta = await new Promise((res) => chrome.storage.local.get({ [PD_META_KEY]: { updated: 0 } }, (o) => res(o[PD_META_KEY] || { updated: 0 }))); } catch (e) {} }
        try { sendResponse({ listed: listed, count: (_pdDomains ? _pdDomains.size : 0), updated: ((_pdMeta && _pdMeta.updated) || 0) }); } catch (e) {}
      } catch (e) { try { sendResponse({ listed: false, count: 0, updated: 0 }); } catch (_) {} }
    })();
    return true;
  }
  // ===== HaGeZi's TIF 本地威胁情报黑名单 =====
  if (msg.type === 'sf-hagezi-update') {
    // 同 OpenPhish / PhishDestroy：立即 ACK，抓取交给一次性 alarm（完整版约 36MB，下载耗时较长，避免长连接被回收）
    // ★ 2026-11-26：设置页点「立即更新」会先把开关写进 storage.sync 再发这条消息；
    //   sync 的 onChanged 与 message 之间没有先后保证，这里直接丢一次设置缓存，
    //   确保本次抓取与「是否参与拦截」的判定用的是刚保存的开关值。
    _settingsCache = null;
    try { chrome.alarms.create('sfHaGeZiManual', { when: Date.now() + 200 }); } catch (e) {}
    try { sendResponse({ started: true }); } catch (e) {}
    return true;
  }
  if (msg.type === 'sf-hagezi-check') {
    (async () => {
      try {
        if (!(await communityListsOn())) { try { sendResponse({ listed: false, count: 0, updated: 0, disabled: true }); } catch (_) {} return; }
        if (!_hgBits) await loadHaGeZiFilter();
        const host = (msg.hostname || '').toLowerCase();
        const listed = haGeZiHit(host);
        if (!_hgMeta) {
          try { _hgMeta = await new Promise((res) => chrome.storage.local.get({ [HG_META_KEY]: { updated: 0 } }, (o) => res(o[HG_META_KEY] || { updated: 0 }))); } catch (e) {}
        }
        try { sendResponse({ listed: listed, count: _hgCount, updated: ((_hgMeta && _hgMeta.updated) || 0) }); } catch (e) {}
      } catch (e) { try { sendResponse({ listed: false, count: 0, updated: 0 }); } catch (_) {} }
    })();
    return true;
  }
  // ===== 社区 AdBlock 风险名单（uBlock Badware risks / Dandelion Sprout）=====
  if (msg.type === 'sf-adlist-update') {
    const id = String(msg.id || '');
    if (!ADL_LISTS[id]) { try { sendResponse({ started: false, error: '未知名单' }); } catch (e) {}
      return true; }
    // ★ 2026-11-26：设置页点「立即更新」会先把开关写进 storage.sync 再发这条消息；
    //   sync 的 onChanged 与 message 之间没有先后保证，这里直接丢一次设置缓存，
    //   确保本次抓取与「是否参与拦截」的判定用的是刚保存的开关值。
    _settingsCache = null;
    try { chrome.alarms.create('sfAdlManual_' + id, { when: Date.now() + 200 }); } catch (e) {}
    try { sendResponse({ started: true }); } catch (e) {}
    return true;
  }
  if (msg.type === 'sf-adlist-check') {
    const id = String(msg.id || '');
    (async () => {
      try {
        if (!ADL_LISTS[id] || !(await communityListsOn())) {
          try { sendResponse({ listed: false, count: 0, updated: 0, disabled: true }); } catch (_) {}
          return;
        }
        const st = _adl[id];
        if (!st.bits) await loadAdl(id);
        if (!st.meta) {
          try {
            st.meta = await new Promise((res) => chrome.storage.local.get({ [ADL_LISTS[id].metaKey]: { updated: 0 } }, (o) => res(o[ADL_LISTS[id].metaKey] || { updated: 0 })));
          } catch (e) {}
        }
        const listed = adlHit(id, (msg.hostname || '').toLowerCase());
        try { sendResponse({ listed: listed, count: st.count, updated: ((st.meta && st.meta.updated) || 0) }); } catch (e) {}
      } catch (e) { try { sendResponse({ listed: false, count: 0, updated: 0 }); } catch (_) {} }
    })();
    return true;
  }
  // ===== 银狐防护云端名单（FoxAPI）=====
  // 只回传结构化判定，**不触发任何横幅**；内容脚本把它并入本地评分。
  if (msg.type === 'sf-foxapi-lookup') {
    (async () => {
      try {
        const r = await foxApiLookup(msg.hostname || '');
        try { sendResponse(r); } catch (e) {}
      } catch (e) {
        try { sendResponse({ ok: false, reason: 'error' }); } catch (_) {}
      }
    })();
    return true;
  }
});

// ★★ 2026-10-15 修（赞助者反馈：「拦截记录一直是『未知域名』和 NaN/NaN NaN:NaN」）
//   根因是**发信方与收信方对字段位置的理解不一致**：
//     内容脚本发的是 `{ type:'sf-detected', hostname: location.hostname, data: result }`
//     —— hostname 在**信封顶层**；而这里调的是 `updateStats(msg.data)`
//     ⇒ `data.hostname` 恒为 undefined。
//   再叠加第二处：`analyze()` 返回的是 `{score,level,detected,official,spoof,reasons}`，
//     **根本没有 time 字段** ⇒ 记录的时间也是 undefined ⇒ 弹窗里
//     `new Date(undefined)` 渲染出「NaN/NaN NaN:NaN」（Invalid Date 不抛异常，
//     靠 try/catch 兜不住，见 popup.js 的 fmtTime）。
//   修法：① hostname 从信封传进来（保留 data 内字段作兼容）；② 时间一律由**后台盖章** ——
//   「记录时刻」本来就该是写这条记录的瞬间，不该依赖上报方给不给。
// ★★ 2026-10-28 修（抚州职院信息安全公告被「两次检测 / 拦截 2 次」）：
//   ① **去重**：同一标签页 15 秒窗口内的重复上报（首屏快判 + 异步补强重判）只保留一条记录，
//      以最后一次为准，绝不重复计数；
//   ② **仅 danger 计入「拦截风险网站」**（stats.warnings）：warn 只做页面内温和提示，
//      不计入拦截数、也不写拦截记录（content 端已不再为 warn 上报 sf-detected）。
function updateStats(data, hostnameFromMsg, sender) {
  chrome.storage.local.get({ stats: { warnings: 0, blocks: 0, recent: [], suspicious: [], blockedTabs: {} } }, function (r) {
    const stats = r.stats || { warnings: 0, blocks: 0, recent: [], suspicious: [], blockedTabs: {} };
    const d = data || {};
    const host = String(d.hostname || d.host || hostnameFromMsg || '').toLowerCase();
    const level = d.level || 'safe';
    const now = Date.now();
    const tabId = (sender && sender.tab && typeof sender.tab.id === 'number') ? sender.tab.id : null;

    // ── 去重：定位同标签近期记录 ──
    const recent = stats.recent || [];
    let idx = -1;
    if (tabId != null) {
      for (let i = recent.length - 1; i >= 0; i--) {
        if (recent[i].tabId === tabId && (now - recent[i].time) < 15000) { idx = i; break; }
      }
    }

    const entry = {
      hostname: host,
      score: (typeof d.score === 'number') ? d.score : null,
      level: level,
      time: now,                 // ★ 后台盖章，不以上报方为准
      tabId: (tabId != null) ? tabId : undefined
    };
    if (idx >= 0) recent[idx] = entry;   // 覆盖同标签旧记录（防重复）
    else recent.unshift(entry);            // 新记录
    stats.recent = recent.slice(0, 30);

    // ── 计数：仅 danger 计入「拦截风险网站」，且同一标签只计一次 ──
    if (level === 'danger') {
      const blockedTabs = stats.blockedTabs || {};
      // 清理 24h 前的陈旧标记，避免 blockedTabs 无限增长
      const DAY = 24 * 60 * 60 * 1000;
      for (const k in blockedTabs) { if ((now - (blockedTabs[k] || 0)) > DAY) delete blockedTabs[k]; }
      if (tabId != null) {
        if (!blockedTabs[tabId]) { stats.warnings += 1; blockedTabs[tabId] = now; }
      } else if (idx < 0) {
        stats.warnings += 1;     // 无 tabId 时退化为「无旧记录才 +1」
      }
      stats.blockedTabs = blockedTabs;
      // 同一域名若已记入「高危」（recent 的 danger 记录），则从「可疑」列表中剔除，
      // 避免「同一域名同时出现在高危与可疑」（如 huorongsafe.com.cn 根页判危、子页曾判可疑）。
      if (host && stats.suspicious && stats.suspicious.length) {
        const before = stats.suspicious.length;
        stats.suspicious = stats.suspicious.filter(function (s) { return (s.hostname || '').toLowerCase() !== host; });
        if (stats.suspicious.length !== before) { /* 已剔除同名可疑记录 */ }
      }
    } else if (level === 'warn') {
      // 可疑域名（warn）：记入「近期可疑域名记录」，不计入「拦截风险网站」计数、不触发下载拦截。
      // 同一标签 15s 内不重复写入。
      const suspicious = stats.suspicious || [];
      let sIdx = -1;
      if (tabId != null) {
        for (let i = suspicious.length - 1; i >= 0; i--) {
          if (suspicious[i].tabId === tabId && (now - suspicious[i].time) < 15000) { sIdx = i; break; }
        }
      }
      const sEntry = {
        hostname: host,
        score: (typeof d.score === 'number') ? d.score : null,
        level: 'warn',
        time: now,
        tabId: (tabId != null) ? tabId : undefined
      };
      if (sIdx >= 0) suspicious[sIdx] = sEntry;   // 覆盖同标签旧记录（防重复）
      else suspicious.unshift(sEntry);            // 新记录
      stats.suspicious = suspicious.slice(0, 50);
    }
    // 其它 level（safe / official / unknown）不计入任何统计。

    chrome.storage.local.set({ stats });
  });
}

// ===== 分析闸门：默认拒绝（检测未出前先堵死该标签全部下载）=====
// ★ 2026-11-22：tabId 缺失时（网页 JS 匿名触发 / window.open / 新窗口下载常为 -1），
//   用 initiator / referrer 反查「当前正在分析」的标签页，避免这段窗口期被绕过。
//   命中多个时取第一个匹配的（同一 host 多标签同时分析的情形极少，且挂起只会更保守）。
function _analyzingTabBySource(item) {
  try {
    const src = (item && (item.initiator || item.referrer)) || '';
    if (!src) return null;
    let h = '';
    try { h = new URL(src).hostname.toLowerCase(); } catch (e) { return null; }
    if (!h) return null;
    for (const id in analysisState) {
      if (analysisState[id] !== 'analyzing') continue;
      const top = lastTopUrl[id] ? parseHost(lastTopUrl[id]) : '';
      if (top && top === h) return Number(id);
    }
  } catch (e) {}
  return null;
}
function holdDownload(tabId, item) {
  if (!heldDownloads[tabId]) heldDownloads[tabId] = [];
  heldDownloads[tabId].push({ id: item.id, url: item.url, filename: item.filename });
  // 静默取消并擦除，避免下载栏出现「已取消」残影；判安后再静默重下
  // ★ 2026-11-22：判安后**不再**静默重下（见 dropHeld）。取消 + 擦除就是最终结果，
  //   用户若要这个文件，必须自己回到页面重新点一次。
  // ★ 2026-11-23：擦除改为延迟重试（_cancelAndErase），否则条目还在取消中会留下「已中断」残影。
  // try { chrome.downloads.cancel(item.id); } catch (e) {}
  // try { chrome.downloads.erase(item.id); } catch (e) {}
  _cancelAndErase(item.id);
}
function flushHeld(tabId) {
  const held = heldDownloads[tabId];
  if (!held || !held.length) return;
  delete heldDownloads[tabId];
  held.forEach(function (h) {
    if (!h.url) return;
    // blob:/data: 无法用 URL 静默重下 → 提示用户手动重新点击
    if (/^(blob:|data:)/i.test(h.url)) {
      try { safeTabMsg(tabId, { type: 'sf-download-allow-failed', url: h.url }); } catch (e2) {}
      return;
    }
    reissuedUrls.add(h.url);
    try { chrome.downloads.download({ url: h.url, filename: h.filename || '', saveAs: false }); } catch (e) {}
  });
}

// ★ 2026-11-22：放弃已挂起的下载（不再自动重下）。
//   用户要求：分析期间被取消的下载，即使判定为 safe 也不许后台偷偷补下 —— 必须由用户重新点击。
//   原因：静默重下等于「用户没确认、扩展替他把文件拉下来」，与「默认不信任」的定位相悖；
//   而且自动重下会绕过用户刚刚看到的拦截提示（用户可能正是想放弃这次下载）。
//   行为：记录数 >0 时给该标签一条提示，让用户知道要重新点。
function dropHeld(tabId, reason) {
  const held = heldDownloads[tabId];
  if (!held || !held.length) { delete heldDownloads[tabId]; return 0; }
  const n = held.length;
  delete heldDownloads[tabId];
  try { safeTabMsg(tabId, { type: 'sf-held-dropped', count: n, reason: reason || '' }); } catch (e) {}
  return n;
}
function resolveAnalysis(tabId, level) {
  if (analysisTimers[tabId]) { clearTimeout(analysisTimers[tabId]); delete analysisTimers[tabId]; }
  const danger = (level === 'danger');
  analysisState[tabId] = danger ? 'danger' : 'safe';
  if (danger) {
    // 危险：保持取消已挂起下载，并向该标签弹警告
    const held = heldDownloads[tabId];
    if (held && held.length) {
      held.forEach(function (h) {
        // 闸门挂起期间的下载在判危后等同于「已拦截」，其载荷域名同样入库（#16）
        try { dlBlacklistAdd(parseHost(h.url), { filename: h.filename, from: lastTopUrl[tabId] ? parseHost(lastTopUrl[tabId]) : '' }); } catch (e) {}
        try { safeTabMsg(tabId, { type: 'sf-download-blocked', host: parseHost(h.url), url: h.url, filename: h.filename }); } catch (e) {}
      });
    }
    delete heldDownloads[tabId];
  } else {
    // flushHeld(tabId); // 安全：静默重下挂起下载
    // ★ 2026-11-22：改为「只丢弃、不重下」。判定 safe 也不恢复分析期间被取消的下载，
    //   用户必须重新点击才能触发（旧行为见上一行注释）。
    dropHeld(tabId, 'safe');
  }
}
function armAnalysis(tabId) {
  analysisState[tabId] = 'analyzing';
  if (analysisTimers[tabId]) clearTimeout(analysisTimers[tabId]);
  analysisTimers[tabId] = setTimeout(function () {
    if (analysisState[tabId] === 'analyzing') {
      analysisState[tabId] = 'safe';
      // flushHeld(tabId); // 失效开放：内容脚本无回应也按安全放行挂起下载
      // ★ 2026-11-22：超时同样不自动重下，只提示用户重新点击（理由见 dropHeld 注释）。
      dropHeld(tabId, 'timeout');
    }
    delete analysisTimers[tabId];
  }, ANALYSIS_TIMEOUT_MS);
}

// ===== 拦截下载：仅拦「危险且未放行站点」发起的下载 =====
if (chrome.downloads && chrome.downloads.onCreated) {
  chrome.downloads.onCreated.addListener(function (item) {
    if (!item || !item.url) return;
    // ★ 2026-11-20：解析器探测标签页触发的下载一律不落地。
    //   探测只需读到「跳到哪个域名」，文件本身必须当场取消并擦除，避免为抓情报反而把木马存到磁盘。
    try {
      if (item.tabId != null && item.tabId >= 0 && _resolverProbes.has(item.tabId)) {
        _resolverEnd(item.tabId, parseHost(item.url), item.url, 'download-blocked');
        // try { chrome.downloads.cancel(item.id); } catch (e) {}
        // try { chrome.downloads.erase(item.id); } catch (e) {}
        // ★ 2026-11-23：erase 必须传 { id } 查询对象（传数字会同步抛 No matching signature），
        //   且要延迟重试；统一走 _cancelAndErase。
        _cancelAndErase(item.id);
        return;
      }
    } catch (e) {}
    // 判安后静默重下的下载（原被闸门挂起者）→ 直接放行，不再二次闸控
    if (reissuedUrls.has(item.url)) { reissuedUrls.delete(item.url); return; }
    // 本次下载用户已明确「仍要下载」→ 直接放行（避免重复拦截）
    if (isAllowedDownload(item.url)) return;
  // ★ 由扩展发起（byExtensionId）的下载：仅「本扩展自身」（静默重下/保存）直接放行；
  //   其它扩展（迅雷/下载器接管类）发起的下载落入后续风险判定——凡是走 downloads API
  //   才能转交外部下载器的，在这里掐断即可阻止其绕过浏览器的下载。
  //   ⚠️ 2026-11-13 实测：**IDM 不受这条约束**。IDM Integration Module（6.43.x）的路径是
  //   「document_start 内容脚本在 window 捕获阶段监听 mousedown/mouseup 抢走 URL →
  //   runtime.connectNative('com.tonec.idm') → IDMMsgHost.exe / IDM.exe 自己发 HTTP 请求」，
  //   真正的下载字节根本不经过浏览器下载栈，chrome.downloads.onCreated 要么不触发、
  //   要么触发时 IDM 自己的 onCreated(cancel) 监听器已把 URL 交给原生进程了。
  //   我们的页面级守卫挂 document（捕获）比 IDM 的 window（捕获）晚一拍，抢不过它；
  //   MV3 又拿不到 webRequestBlocking，无法在网络层取消它的请求。
  //   ⇒ 结论：**本扩展无法可靠拦截 IDM / 迅雷这类原生下载器**，只能在判定为高风险时
  //   尽量移除 href / 置 pointer-events:none 并提示用户临时关闭「浏览器接管」。
  //   这段逻辑保留，是为了兜住「用 downloads API 转交」的那类下载器，别当成 IDM 防线。
  if (item.byExtensionId && item.byExtensionId === chrome.runtime.id) return;
  // ★ 来源标签页已被「完全放行」(releasedHosts) 或处于「仍要下载」临时放行窗口 → 直接放过本次下载，
  //   让没有 IDM 的用户也能通过浏览器自身完成下载（含自动学习的下载黑名单域）。
  if (isTabTempAllowed(item.tabId)) return;
  if (isSourceReleased(item)) return;
      const host = parseHost(item.url);
      // 先等云端名单就绪再取设置判定（见文件顶部 cloudReady 的说明）
      // ★ 2026-11-23（授权模型）：第三个参数是「授权表已从 storage.session 恢复」。
      //   后台被 MV3 休眠后再唤醒时内存是空的，不等这一步就判，会把用户刚授权过的页面
      //   又当成「首次下载」重问一遍（状态读不到 → 误判）。
      Promise.all([getSettings(), cloudReady(), _sfAuth.ready || Promise.resolve(), _sfSite.ready || Promise.resolve()]).then(function (r) {
      const settings = r[0];
      // ★ 2026-11-23：先判「自动下载」（没有用户手势却自己开始）。
      //   放到挂起逻辑之前，是因为它专门覆盖 tabId / referrer / initiator 全空的导航型下载
      //   （meta refresh、直接跳文件、服务端强推），那种下载根本无从挂起。
      if (checkAutoDownload(item, settings, item.tabId)) return;
      // ★ 分析闸门（2026-11-11：与「自动拦截下载」开关解耦）
      //   判定未出结论前一律先挂起该标签的全部下载 —— 这是「默认拒绝」，不是「命中危险后的拦截」。
      //   原实现把这段放在 settings.autoBlockDownloads 之后，用户一关那个开关，
      //   木马就能在检测的 1–10 秒窗口里直接落地。现在只要求「扩展启用」。
      // if (settings.enabledGlobal && item.tabId && item.tabId >= 0 &&
      //     analysisState[item.tabId] === 'analyzing') {
      //   holdDownload(item.tabId, item);
      //   return;
      // }
      // ★ 2026-11-22：旧实现只认 item.tabId >= 0，网页 JS 匿名触发 / window.open 的下载
      //   （tabId 常为 -1）会直接穿过这段窗口期。现在先按 tabId 判，缺失时按来源反查。
      const _holdTabId = (item.tabId != null && item.tabId >= 0)
        ? item.tabId
        : _analyzingTabBySource(item);
      if (settings.enabledGlobal && _holdTabId != null && _holdTabId >= 0 &&
          analysisState[_holdTabId] === 'analyzing' && !_authPassIds.has(item.id)) {
        holdDownload(_holdTabId, item);
        return;
      }
      // 已按用户意图放行过 → 清掉标记，不再重复放行同一个 id
      if (_authPassIds.has(item.id)) _authPassIds.delete(item.id);
      if (!settings.enabledGlobal || !settings.autoBlockDownloads) return;
      // ★ 免费加成：Chrome 自带 Safe Browsing 已将该下载标记为恶意
      //   （content=文件已知恶意 / url=网址已知恶意 / host=来源主机已知分发恶意二进制）
      //   此判定常在 onCreated 时仍为 safe，云查完成后经 onChanged 返回，见下方 onChanged 兜底。
      if (isMaliciousDanger(item.danger)) {
        cancelDownload(item.id, host, item.tabId >= 0 ? [item.tabId] : [], item.url, item.filename);
        return;
      }
      // ★ 名单判定顺序（2026-11-09 定版）：**任意黑名单 > 任意白名单**；
      //   同色内部按「云端 > 扩展内置 > 自定义」归因（此处只影响提示，不影响是否取消）。
      //   冲突时一律拦：云端白名单是远端可变数据，一旦误加/被投毒，不能让它开出一条
      //   绕过样本 IOC 的下载通道。故黑名单**不再被任何白名单豁免**。
      const srcHost = downloadSourceHost(item);
      const srcUrl = downloadSourceUrl(item);
      // 旧（2026-11-09 定版）：黑名单逐条判，命中即取消；没有「例外」这一层。
      /*
      // 1) 云端黑名单（含通配 / 路径）：下载地址或来源页链接命中即拦
      if (isCloudBadHost(host) || isCloudBadUrl(item.url) || (srcHost && isCloudBadUrl(srcUrl))) {
        cancelDownload(item.id, host, item.tabId >= 0 ? [item.tabId] : [], item.url, item.filename);
        return;
      }
      if (srcHost && isCloudBadHost(srcHost)) {
        cancelDownload(item.id, srcHost, item.tabId >= 0 ? [item.tabId] : [], item.url, item.filename);
        return;
      }
      // 2) 扩展内置黑名单（样本 IOC）
      if (isBuiltinBadHost(host)) {
        cancelDownload(item.id, host, item.tabId >= 0 ? [item.tabId] : [], item.url, item.filename);
        return;
      }
      if (srcHost && isBuiltinBadHost(srcHost)) {
        cancelDownload(item.id, srcHost, item.tabId >= 0 ? [item.tabId] : [], item.url, item.filename);
        return;
      }
      // 3) 自定义黑名单（用户本机「规则与名单」）
      if (hostMatch(host, settings.customBadDomains)) {
        cancelDownload(item.id, host, item.tabId >= 0 ? [item.tabId] : [], item.url, item.filename);
        return;
      }
      if (srcHost && hostMatch(srcHost, settings.customBadDomains)) {
        cancelDownload(item.id, srcHost, item.tabId >= 0 ? [item.tabId] : [], item.url, item.filename);
        return;
      }
      */
      // ★ 新（2026-11-23）：按「例外优先矩阵」逐主机判定（云端例外 > 云端黑名单 > 内置例外 >
      //   内置黑名单 > 用户例外 > 用户黑名单）。命中例外的那一侧不再进入黑名单取消分支，
      //   另一侧仍独立判定；下面的文件名 IOC / 白名单 / 下载黑名单逻辑保持原样。
      const _tierMain = _dlListTier(host, item.url, settings);
      const _tierSrc = srcHost ? _dlListTier(srcHost, srcUrl, settings) : '';
      if (_tierMain === 'bad' || _tierSrc === 'bad') {
        const _badHost = (_tierMain === 'bad') ? host : srcHost;
        cancelDownload(item.id, _badHost, item.tabId >= 0 ? [item.tabId] : [], item.url, item.filename);
        return;
      }
      // 3.5) ★ 已知木马化投递物文件名（样本静态分析 IOC）：bzy.exe / shanlian_VPN_64.exe 等
      //   命中即强制取消下载，不受「来源页是否判危」影响（无法读下载字节，文件名是最稳锚点）。
      //   ★ 2026-11-09：从白名单之后提到白名单之前——白名单一旦命中就 return，原先排在
      //   后面等于对所有放行站点（含云端「整站白名单」条目）彻底失效，这正是按主机放行
      //   蓝奏云分发渠道后最需要补上的一道静态防线。IOC 是极小固定列表、误伤概率极低，
      //   所以即使在白名单站点上也照拦；下面三处白名单 return（此处 / byExtensionId 分支 /
      //   自动下载兜底）因此都自动受本检查约束。
      if (isKnownBadFilename(item.filename) || isKnownBadFilename(item.url)) {
        cancelDownload(item.id, host || srcHost || '', item.tabId >= 0 ? [item.tabId] : [], item.url, item.filename);
        return;
      }
      // 4) 白名单放行：只有黑名单全不命中后才看（云端 / 内置 / 自定义，效果一致）
      //    ★ 2026-11-09：路径白名单（主机名/路径）在这里生效——下载地址本身或来源页链接
      //    命中路径条目即放行。它只覆盖那一个链接，不会让整个主机变成「可信下载源」，
      //    所以没有并入 isTrustedDownloadHost / _dlBlProtected（那两处只认 host）。
      if (isTrustedDownloadHost(host, settings)) return;
      if (isCloudWhiteUrl(item.url) || (srcHost && isCloudWhiteUrl(srcUrl))) return;
      // ★ 下载黑名单跨站复用（#16）：该载荷域名此前已因投递木马被拦过 → 直接取消。
      //   不必等新落地页重新走一遍判危流程（银狐换落地页远比换载荷 CDN 勤快）。
      //   受保护域名（GitHub/微软/官方/用户白名单）永不入库，故此处不会误伤正规下载源。
      if (dlBlacklistHas(host)) {
        cancelDownload(item.id, host, item.tabId >= 0 ? [item.tabId] : [], item.url, item.filename);
        return;
      }
      // ★ 下载器/接管类扩展（byExtensionId 且非本扩展）发起的下载：
      //   白名单 / 官方域名 / 可信下载源照常放行；其余高危文件（exe/zip/rar/网盘/脚本）
      //   一律拦截并弹「询问放行」窗——这是对「迅雷/IDM 等绕过浏览器直接下载」的兜底拦截。
      if (item.byExtensionId) {
        if (hostMatch(host, settings.allowlist, 'customWhite')) return;
        if (isCloudWhiteUrl(item.url) || (srcHost && isCloudWhiteUrl(srcUrl))) return;  // 路径白名单
        if (srcHost && (SF.isOfficialDomain(srcHost) || hostMatch(srcHost, settings.allowlist, 'customWhite'))) return;
        if (_dlBlProtected(host, settings)) return;   // TRUSTED_DOWNLOAD_HOSTS / 官方 / 用户白名单
        if (isHighRiskFile(item.url)) {
          cancelDownload(item.id, host || srcHost || '', item.tabId >= 0 ? [item.tabId] : [], item.url, item.filename, true);
          return;
        }
        return;   // 非高危文件（视频/图片等）：交给下载器接管，不打扰
      }

      // ★ 核心：只有当「发起下载的页面」被判定危险且未放行时才拦，否则一律放行
      loadState().then(function (state) {
        const src = sourceHostOf(item, state);
        if (src.host) { cancelDownload(item.id, src.host, src.tabIds, item.url, item.filename); return; }
        // ★ 跳转链兜底：本标签页曾由危险站跳转而来，且本次下载是可执行/网盘类 → 直接拦
        //   （覆盖「B 站自身没独立判危、但其下载仍从被污染标签发起」的场景）
        if (isTainted(state, item.tabId)) {
          const t = SF.classifyLink(item.url);
          if (t === 'exec' || t === 'cloud' || t === 'archive' || t === 'download') {
            cancelDownload(item.id, host, [item.tabId], item.url, item.filename);
            return;
          }
        }
        // ★ 自动下载兜底：下载在内容脚本「判定→标记危险」之前就已触发
        //   （覆盖「点进网站就下载」「服务端 Content-Disposition 强制下载」等抢跑场景）
        // 文件本身在白名单 / 来源是可信官方域名 → 放行
        if (hostMatch(host, settings.allowlist, 'customWhite')) return;
        if (isCloudWhiteUrl(item.url) || (srcHost && isCloudWhiteUrl(srcUrl))) return;  // 路径白名单
        if (srcHost && (SF.isOfficialDomain(srcHost) || hostMatch(srcHost, settings.allowlist, 'customWhite'))) return;
        if (isHighRiskFile(item.url)) {
          // 1) 来源域名自身像品牌仿冒（非官方）→ 直接拦，不依赖内容脚本判定
          //    注意：必须先排除官方域名，否则 qq.com / www.moonshot.cn 等含品牌词的官网会被误判仿冒而误拦下载
          if (srcHost && !SF.isOfficialDomain(srcHost) && SF.detectSpoof(srcHost)) {
            markTainted(item, srcHost, state);
            cancelDownload(item.id, srcHost, [item.tabId], item.url, item.filename);
            return;
          }
          // 2) 页面刚载入（≤ 窗口期）就自动下高危文件 → 视为「自动下载」，直接拦
          const t0 = (item.tabId && item.tabId >= 0) ? navCommitTime[item.tabId] : 0;
          if (t0 && (Date.now() - t0) <= AUTO_WINDOW_MS) {
            markTainted(item, srcHost || host, state);
            cancelDownload(item.id, srcHost || host, [item.tabId], item.url, item.filename);
            return;
          }
        }
      });
    });
  });
}

// ===== Chrome 自带 Safe Browsing 兜底：danger 常在下载「创建后」才经云查返回 =====
//   例如 onCreated 时 danger 仍为 safe，数秒后 onChanged 才变为 content/url/host。
//   这里监听 danger 变化，命中恶意判定时取消（未完成）或弹窗警告（已落地无法撤回）。
if (chrome.downloads && chrome.downloads.onChanged) {
  chrome.downloads.onChanged.addListener(function (delta) {
    if (!delta || delta.id == null) return;
    if (!(delta.danger && delta.danger.current) || !isMaliciousDanger(delta.danger.current)) return;
    const id = delta.id;
    getSettings().then(function (settings) {
      if (!settings.enabledGlobal || !settings.autoBlockDownloads) return;
      chrome.downloads.search({ id: id }, function (items) {
        if (!items || !items.length) return;
        const it = items[0];
        if (isAllowedDownload(it.url) || it.byExtensionId) return; // 用户已明确放行 / 扩展自身发起
        // 「仍要下载」临时放行窗口 / 「完全放行」来源页：同样放过，避免 Safe Browsing 延迟判定又取消它
        if (isTabTempAllowed(it.tabId)) return;
        if (it.tabId && it.tabId >= 0 && lastTopUrl[it.tabId]) {
          const hh = parseHost(lastTopUrl[it.tabId]);
          if (hh && releasedHostsCache[hh]) return;
        }
        const tabIds = it.tabId >= 0 ? [it.tabId] : [];
        const h = parseHost(it.url);
        if (it.state === 'complete') {
          // 已落地到磁盘：cancel 无效，但仍弹窗警告用户文件可疑
          tabIds.forEach(function (tid) {
            if (tid != null) {
              try { safeTabMsg(tid, { type: 'sf-download-blocked', host: h, url: it.url, filename: it.filename }); } catch (e) {}
            }
          });
          return;
        }
        if (it.state === 'interrupted') return; // 已中断，无需再处理
        cancelDownload(it.id, h, tabIds, it.url, it.filename);
      });
    });
  });
}

// ===== 检测银狐「跳转链」：危险站 A 自动跳转到新站 B 时，把 B 标记为污染 =====
if (chrome.webNavigation && chrome.webNavigation.onCommitted) {
  chrome.webNavigation.onCommitted.addListener(function (details) {
    if (details.frameId !== 0) return; // 只处理顶级框架
    const _navUrl = details.url || '';
    let _navProto = '';
    try { _navProto = new URL(_navUrl).protocol; } catch (e) {}
    if (_navProto !== 'http:' && _navProto !== 'https:') return; // 仅对 http(s) 网页起闸；浏览器内部页/扩展页不闸
    const tabId = details.tabId;
    // ★ 分析闸门：页面提交即进入「检测中」状态，该标签下载先默认拒绝（内容脚本回传判定后解除）
    armAnalysis(tabId);
    // ★ 2026-11-23：记「跳转下载意图」——3s 内这个 tab 刚点过带下载语义的链接，
    //   说明这次跳转是用户点下载带过来的（随后新页面自己开始下载属正常链路）。
    try {
      const _now = Date.now();
      for (let i = _strongGestures.length - 1; i >= 0; i--) {
        const g = _strongGestures[i];
        if (_now - g.at > 3000) break;
        if (g.dl && g.tabId === tabId) { _sfAuth.navIntent[tabId] = { at: _now, left: 2 }; break; }
      }
    } catch (e) {}
    const url = _navUrl;
    let host = '';
    try { host = new URL(url).hostname.toLowerCase(); } catch (e) {}
    const prev = lastTopUrl[tabId] || '';
    let prevHost = '';
    try { prevHost = new URL(prev).hostname.toLowerCase(); } catch (e) {}
    navCommitTime[tabId] = Date.now(); // 记录本次导航提交时间，供自动下载竞速判定使用
    prevTopUrl[tabId] = prev; // 记下「上一跳」页面，供下载来源归属回退使用
    loadState().then(function (state) {
      const tab = state.dangerTabs[tabId];
      const prevWasDanger = tab && !tab.released && tab.hostname && tab.hostname === prevHost;
      // A(危险) → B(新域名)：标记 B 为跳转链污染（高风险）
      if (prevWasDanger && host && host !== prevHost) {
        state.dangerTabs[tabId] = { hostname: host, released: false, chained: true };
        saveState(state);
      }
      lastTopUrl[tabId] = url;
    });
  });
}

// ===== SPA 路由变化（pushState / replaceState）也要重新起闸（2026-11-11 新增）=====
//   为什么必须单独监听：上面的 onCommitted 只在「真实导航」（整页加载、前进后退）时触发。
//   SPA 用 history.pushState 换路由时既不重载文档、也不再触发 onCommitted，内容脚本也不会
//   重新注入 —— 结果是第二个路由起 analysisState 永远停在上一个页面的结论：
//     · 上一页 safe → 新路由完全没有「判定前默认拒绝」窗口，下载直接落到名单判定；
//     · 上一页 danger → 新路由被上一页的判危状态按住，连「仍要下载」的释放对象都是旧 host。
//   内容脚本侧另有 popstate/hashchange + URL 轮询做重判（见 content.js 的 installSpaRouteWatch），
//   这里只负责后台闸门与 URL 记账，两边互为双保险。
//   注：不在这里复刻「A(危险)→B(新域名) 跳转链污染」逻辑 —— SPA 路由通常同域内切换，
//       跨域 pushState 会被浏览器拒绝，链污染只在整页跳转时才有意义。
if (chrome.webNavigation && chrome.webNavigation.onHistoryStateUpdated) {
  chrome.webNavigation.onHistoryStateUpdated.addListener(function (details) {
    if (details.frameId !== 0) return;                 // 只处理顶级框架
    const _sUrl = details.url || '';
    let _sProto = '';
    try { _sProto = new URL(_sUrl).protocol; } catch (e) {}
    if (_sProto !== 'http:' && _sProto !== 'https:') return;
    const tabId = details.tabId;
    if (tabId == null || tabId < 0) return;
    let host = '';
    try { host = new URL(_sUrl).hostname.toLowerCase(); } catch (e) {}
    // ★ 同 URL / 仅锚点变化 → 不是换路由，直接跳过。
    //   必须跳过：很多框架每次 setState 都会 replaceState 一次，若每次都重新 armAnalysis，
    //   就会出现「页面早已判安全、闸门却又被关 11s」的假拦截（下载被取消再静默重下）。
    const _prevNavUrl = lastTopUrl[tabId] || '';
    const _noHash = function (s) { const i = String(s).indexOf('#'); return i === -1 ? String(s) : String(s).slice(0, i); };
    if (_prevNavUrl && _noHash(_prevNavUrl) === _noHash(_sUrl)) return;
    // 与 onCommitted 同语义：进入「检测中」，该标签的下载先默认拒绝
    armAnalysis(tabId);
    // URL 记账必须同步更新：下载来源归属（downloadSourceHost/Url）、自动下载竞速、
    // 以及 URL 级云端名单（cloudBlackPath/cloudWhitePath）全都读这几个变量。
    navCommitTime[tabId] = Date.now();
    prevTopUrl[tabId] = lastTopUrl[tabId] || '';
    lastTopUrl[tabId] = _sUrl;
    // 同一标签换了 host（少见：SPA 内二次跳转到别的域）→ 上一页的判危/放行状态作废，
    // 否则「仍要下载」的临时放行窗口会把新域也一并放开。
    loadState().then(function (state) {
      const tab = state.dangerTabs[tabId];
      if (!tab) return;
      const tabHost = String(tab.hostname || '').toLowerCase();
      if (tabHost && host && tabHost !== host) {
        delete state.dangerTabs[tabId];
        saveState(state);
      }
    });
  });
}


function cancelDownload(id, host, tabIds, url, filename, extBlock) {
  // ★ 自动入库（#16）：把本次被拦下载的「载荷域名」记进下载黑名单，供后续跨站复用识别。
  //   host 参数是「落地页/来源域名」，真正要记的是文件所在域名（parseHost(url)），
  //   落地页只作来源元数据留档 —— 银狐换落地页比换载荷 CDN 勤快得多。
  try { dlBlacklistAdd(parseHost(url), { filename: filename, from: host }); } catch (e) {}
  chrome.downloads.cancel(id, function () {
    chrome.storage.local.get({ stats: { warnings: 0, blocks: 0, recent: [] } }, function (r) {
      const stats = r.stats || { warnings: 0, blocks: 0, recent: [] };
      stats.blocks += 1;
      chrome.storage.local.set({ stats });
    });
    // 不再使用系统通知（关掉浏览器后仍会在系统通知中心弹出）；改为在网页内「大弹窗」提示
    // 把提示发到「发起下载的危险页面」对应的所有标签页（解决 item.tabId 为 -1 收不到提示的问题）
    (tabIds || []).forEach(function (tid) {
      if (tid != null && tid >= 0) {
        try { safeTabMsg(tid, { type: extBlock ? 'sf-dl-ext-blocked' : 'sf-download-blocked', host: host, url: url, filename: filename }); } catch (e) {}
      }
    });
  });
}

// 标签页关掉后清理其危险状态
if (chrome.tabs && chrome.tabs.onRemoved) {
  chrome.tabs.onRemoved.addListener(function (tabId) {
    if (lastTopUrl[tabId]) delete lastTopUrl[tabId];
    if (prevTopUrl[tabId]) delete prevTopUrl[tabId];
    if (navCommitTime[tabId]) delete navCommitTime[tabId];
    if (analysisState[tabId]) delete analysisState[tabId];
    if (analysisTimers[tabId]) { clearTimeout(analysisTimers[tabId]); delete analysisTimers[tabId]; }
    if (heldDownloads[tabId]) delete heldDownloads[tabId];
    loadState().then(function (state) {
      if (state.dangerTabs[tabId]) { delete state.dangerTabs[tabId]; saveState(state); }
    });
  });
}

