/*
 * background.js — 银狐防护后台 service worker
 * 职责：
 *   1) 初始化默认设置
 *   2) 接收内容脚本的「检测上报」，记录「被判定为危险的标签页」(dangerTabs) 与「用户已放行的站点」(releasedHosts)
 *   3) 拦截下载：★ 只有「发起下载的页面」本身被判定为危险且用户未放行时才拦，绝不全局误拦
 *   4) 接收「离开此网站」指令，直接关闭该标签页（不再跳百度）
 * 状态保存在 chrome.storage.session，可在 service worker 重启后存活（同一浏览器会话内有效）。
 */
'use strict';

importScripts('rules/iocs.js', 'rules/analyzer.js');

// 兼容 service worker（self，无 window）与内容脚本（window 隔离世界）两种上下文：
// iocs.js / analyzer.js 已同时挂到 self 与 window。兜底 stub 防止依赖缺失时崩溃。
const SF = self.SF_ANALYZER || (typeof window !== 'undefined' ? window.SF_ANALYZER : null) || {
  classifyLink: function () { return 'other'; },
  isOfficialDomain: function () { return false; },
  detectSpoof: function () { return null; }
};

// 用户在当前会话里「仍要下载」明确放行的下载 URL（避免重复拦截；SW 重启后清空，会重新询问，安全）
const allowedDownloads = new Set();

// 记录每个标签页最近一次「顶级导航」的 URL，用于检测「危险站 → 跳转新站」的银狐跳转链
const lastTopUrl = {};
// 记录每个标签页「本次导航前的上一跳」页面 URL（用于下载来源归属回退：
// 当跳转下载的 referrer/initiator 为空时，用上一跳页面定位真实来源，避免秒跳下载漏归）
const prevTopUrl = {};
// 记录每次顶级导航「提交完成」的时间戳，用于识别「点进即下载 / 服务端强制下载」的自动下载竞速
const navCommitTime = {};
// 自动下载判定窗口：页面提交后该时间窗内发起的高危文件下载，视为「自动下载」而非用户手动点击
const AUTO_WINDOW_MS = 1500;

// 云端官网库（#384，#420 病毒库式改造）：独立、低调托管的公开域名清单，仅作本地 OFFICIAL_DOMAINS 的补充。
// 病毒库式：SW 启动从 storage.local 秒级载入整库到内存 set（检测不再阻塞网络）；
// 后台异步轮询极小的 version.json，仅云端版本号变化才重新下载整库并落本地缓存。
// 绝不接收用户域名 → 零隐私上报。
const CLOUD_OFFICIAL_URL = 'https://site-directory-cache.pages.dev/official-domains.json';
const CLOUD_CACHE_KEY = 'sf_cloud_official';
let _cloudOfficialSet = null;
let _cloudOfficialLoading = null;
let _cloudOfficialMeta = { version: null, count: 0, updated: null, etag: null, cachedAt: 0 };

// 分析闸门：标签页「检测未出结果前默认拒绝下载」的状态机
//   analyzing = 已加载、内容脚本尚未回传判定 → 该标签全部下载先取消挂起
//   safe      = 已判定安全 → 挂起下载静默重下，后续下载直接放行
//   danger    = 已判定危险 → 挂起下载保持取消并弹警告，后续下载按危险拦截
const analysisState = {};
const heldDownloads = {};       // tabId -> [{id,url,filename}]
const reissuedUrls = new Set(); // 判安后已静默重下的 URL，避免 onCreated 二次闸控
const analysisTimers = {};      // tabId -> 超时兜底句柄
const ANALYSIS_TIMEOUT_MS = 4000; // 内容脚本异常/畸形页时失效开放，按安全放行

// 性能优化：模块级复用正则，避免重复编译
const WWW_RE = /^www\./;

const DEFAULTS = {
  enabledGlobal: true, showWarning: true, autoBlockDownloads: true, notify: true, sensitivity: 'medium',
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
  allowlist: [], customKeywords: [], customBadDomains: []
};

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

// 内存缓存：下载拦截等高频路径每次都读 storage.sync，service worker 冷启动后首次读即缓存，
// 之后同步返回；监听 storage.onChanged 在设置变更时失效，确保 options 页改动即时生效。
let _settingsCache = null;
function getSettings() {
  if (_settingsCache) return Promise.resolve(_settingsCache);
  return new Promise(function (resolve) {
    chrome.storage.sync.get(DEFAULTS, function (s) {
      _settingsCache = Object.assign({}, DEFAULTS, s || {});
      resolve(_settingsCache);
    });
  });
}
if (chrome.storage && chrome.storage.onChanged) {
  chrome.storage.onChanged.addListener(function (changes, area) {
    if (area === 'sync' && _settingsCache) _settingsCache = null; // 任意 sync 设置变更 → 下次 getSettings 重新拉取
  });
}

function parseHost(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch (e) { return ''; }
}

function hostMatch(host, list) {
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

// 硬编码银狐木马投递站黑名单（与页面级「已知银狐木马站点」判定同源，来自 iocs.js KNOWN_BAD_DOMAINS）。
// 专门用于下载拦截：命中「下载 URL 域名」或「来源/referrer 域名」即视为已知恶意，下载须强制取消（永不豁免）。
// 背景：此前 onCreated 只查用户自定义黑名单 customBadDomains，漏掉了硬编码名单里的投递站，
//       导致这类站点的 ZIP/EXE 在被页面级标记危险后，下载仍可能放行。
const _KNOWN_BAD_HOSTS = (function () {
  const list = (self.SF_IOCS && self.SF_IOCS.KNOWN_BAD_DOMAINS) || [];
  return list.map(function (d) { return String(d).trim().toLowerCase(); });
})();
function isKnownBadHost(h) {
  h = (h || '').toLowerCase();
  return _KNOWN_BAD_HOSTS.some(function (d) { return d && (h === d || h.endsWith('.' + d)); });
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

chrome.runtime.onInstalled.addListener(function (details) {
  chrome.storage.sync.get(DEFAULTS, function (s) {
    chrome.storage.sync.set(Object.assign({}, DEFAULTS, s || {}));
  });
  chrome.storage.local.get({ stats: { warnings: 0, blocks: 0, recent: [] } }, function (r) {
    if (!r.stats) chrome.storage.local.set({ stats: { warnings: 0, blocks: 0, recent: [] } });
  });
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

// 浏览器启动 → 强制同步云端库缓存（用户要求：每次打开浏览器自动从云端拉取并缓存）
chrome.runtime.onStartup.addListener(function () {
  syncCloudOfficial(true);
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
    const timer = setTimeout(function () { try { ctrl.abort(); } catch (e) {} }, 6000);
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
    if (!e || !e.last || (now - e.last) > DL_BL_TTL) { delete _dlBl[d]; changed = true; }
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
function _dlBlProtected(host, settings) {
  const h = (host || '').toLowerCase();
  if (!h) return true;
  const trusted = (self.SF_IOCS && self.SF_IOCS.TRUSTED_DOWNLOAD_HOSTS) || [];
  if (hostMatch(h, trusted)) return true;
  try { if (SF && SF.isOfficialDomain && SF.isOfficialDomain(h)) return true; } catch (e) {}
  if (settings && hostMatch(h, settings.allowlist)) return true;
  return false;
}
// 记一次拦截：只记「下载文件所在的注册域名」（载荷域名），落地页域名仅作来源元数据留档
function dlBlacklistAdd(downloadHost, meta) {
  const h = (downloadHost || '').toLowerCase();
  if (!h) return;
  return Promise.all([_dlBlLoad(), getSettings()]).then(function (arr) {
    const settings = arr[1];
    if (_dlBlProtected(h, settings)) return;
    const dom = _regDomain(h);
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
        from: (meta && meta.from) ? String(meta.from).slice(0, 120) : ''
      };
    }
    _dlBlPrune();
    _dlBlSave();
  }).catch(function () {});
}
// 命中查询（按注册域名匹配，含全部子域名）
function dlBlacklistHas(host) {
  if (!_dlBl) return false;                 // 未加载完成时保守返回 false（不误拦）
  const dom = _regDomain((host || '').toLowerCase());
  return !!(dom && _dlBl[dom]);
}
function dlBlacklistDomains() {
  return _dlBlLoad().then(function () { return Object.keys(_dlBl || {}); });
}
// service worker 一启动就预热，保证 downloads.onCreated（同步判断）能立即查到黑名单
try { _dlBlLoad(); } catch (e) {}

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
    buildUrl: function (d) { return 'https://uapis.cn/api/v1/network/icp?domain=' + encodeURIComponent(d); },
    // 有备案：{"code":200,"serviceLicence":"京ICP备xxxxxxx号","unitName":"..."}
    // 无备案：{"code":200,"serviceLicence":"查询失败","unitName":"查询失败"}
    // ⚠️ 查不到时它仍返回 code:200，必须靠「是否含 ICP备/ICP证」区分真实备案号与失败文案，
    //    否则会把无备案的外国站误判成 hasIcp:true，直接放行造成漏检。
    parse: function (d) {
      const lic = (d && typeof d.serviceLicence === 'string') ? d.serviceLicence.trim() : '';
      if (d && (d.code === 200 || d.code === '200') && /ICP[备证]/.test(lic)) {
        return { hasIcp: true, icpNumber: lic, unitName: (d.unitName && d.unitName !== '查询失败') ? d.unitName : '' };
      }
      return { hasIcp: false };
    }
  },
  {
    // 公开 demo 凭据，上游可能随时撤销；撤销后本源静默失败并回退首源/页面扫描，不影响判定安全性
    name: 'apihz', rateLimitPerMin: 10, id: '88888888', key: '88888888',
    buildUrl: function (d, c) {
      return 'https://cn.apihz.cn/api/wangzhan/icp.php?id=' + encodeURIComponent(c.id) +
             '&key=' + encodeURIComponent(c.key) + '&domain=' + encodeURIComponent(d);
    },
    // 有备案：{"code":200,"icp":"蜀ICP备xxx号","unit":"..."} / 无备案：{"code":400,"msg":"查询失败或没有备案。"}
    parse: function (d) {
      const lic = (d && typeof d.icp === 'string') ? d.icp.trim() : '';
      if (d && (d.code === 200 || d.code === '200') && /ICP[备证]/.test(lic)) {
        return { hasIcp: true, icpNumber: lic, unitName: (d.unit && d.unit !== '查询失败') ? d.unit : '' };
      }
      return { hasIcp: false };
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

  for (const p of ICP_PROVIDERS) {
    if (!_icpAcquire(p)) continue;
    try {
      const ctrl = new AbortController();
      const timer = setTimeout(function () { try { ctrl.abort(); } catch (e) {} }, 8000);
      const resp = await fetch(p.buildUrl(domain, p), { signal: ctrl.signal, cache: 'no-store' });
      clearTimeout(timer);
      if (!resp.ok) continue;
      const text = await resp.text();
      if (!text) continue;
      let data;
      try { data = JSON.parse(text); } catch (e) { continue; } // 非 JSON（如接口改版/返回 HTML）→ 换下一源
      const parsed = p.parse(data) || { hasIcp: false };
      const result = {
        queried: true,
        hasIcp: !!parsed.hasIcp,
        icpNumber: parsed.icpNumber || null,
        unitName: parsed.unitName || null,
        service: p.name
      };
      _icpCacheSet(domain, result);
      return result;
    } catch (e) { continue; } // 超时/网络错误 → 换下一源
  }
  const failed = { queried: false, hasIcp: false };
  _icpCacheSet(domain, failed); // 失败按 _ICP_FAIL_TTL 短缓存
  return failed;
}


// ===== 云端官网库（按需拉取 + 内存缓存 + 标签对齐后缀匹配）=====
function _cloudSuffixHit(set, hostname) {
  const h = (hostname || '').toLowerCase().replace(WWW_RE, '');
  if (!h) return null;
  if (set.has(h)) return h;
  let idx = h.indexOf('.');
  while (idx !== -1) {
    const suf = h.slice(idx + 1);
    if (set.has(suf)) return suf;
    idx = h.indexOf('.', idx + 1);
  }
  return null;
}

async function ensureCloudOfficialSet() {
  if (_cloudOfficialSet) return _cloudOfficialSet;
  if (_cloudOfficialLoading) return _cloudOfficialLoading;
  _cloudOfficialLoading = (async () => {
    try {
      const resp = await fetch(CLOUD_OFFICIAL_URL, { cache: 'force-cache' });
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      const j = await resp.json();
      const arr = (j && j.domains) || [];
      if (!Array.isArray(arr)) throw new Error('bad payload');
      const set = _buildCloudSet(arr);
      _cloudOfficialSet = set;
      _cloudOfficialMeta = {
        version: (j && j.version) || null,
        count: arr.length,
        updated: (j && j.updated) || null,
        cachedAt: Date.now()
      };
      await _persistCloudFull({ version: _cloudOfficialMeta.version, domains: arr, updated: _cloudOfficialMeta.updated, cachedAt: Date.now() });
    } catch (e) {
      _cloudOfficialSet = new Set();
    } finally {
      _cloudOfficialLoading = null;
    }
    return _cloudOfficialSet;
  })();
  return _cloudOfficialLoading;
}

// 从 domains 数组构建 Set（含校验防篡改注入）
function _buildCloudSet(arr) {
  const set = new Set();
  if (!Array.isArray(arr)) return set;
  for (const d of arr) {
    if (typeof d === 'string' && d.indexOf(' ') === -1 && d.indexOf('/') === -1 && d.indexOf('..') === -1) set.add(d.toLowerCase());
  }
  return set;
}

// SW 每次唤醒都会重新执行顶层代码，故在文件末尾顶层调用 syncCloudOfficial() 即可保证后台内存常驻云端库：
// ① 优先从 storage.local 秒级载入已缓存的整库到内存 Set（检测不阻塞网络）；
// ② 异步用极小的 HEAD 请求比对远端 ETag / Last-Modified，仅当云端变化（或本地为空 / 强制）才下载整库并落本地缓存；
// ③ 设置页（纯前端）直接 fetch CDN 公开名单、写 storage.local，后台通过 storage.onChanged 同步内存 Set，零消息端口、零隐私上报。
// 全程纯前端消费 CDN 静态 JSON，绝不接收用户域名 → 零隐私上报。
const CLOUD_SYNC_THROTTLE_MS = 6 * 60 * 60 * 1000; // 非启动场景下 6 小时节流，避免每次导航都拉 3.9MB

// SW 每次唤醒执行：先同步载入内存，再异步决定是否需要从云端刷新缓存
function syncCloudOfficial(force) {
  // ① 同步从 storage.local 载入内存（检测不阻塞）
  chrome.storage.local.get(CLOUD_CACHE_KEY, function (res) {
    const data = res && res[CLOUD_CACHE_KEY];
    if (data && Array.isArray(data.domains) && data.domains.length) {
      _cloudOfficialSet = _buildCloudSet(data.domains);
      _cloudOfficialMeta = {
        version: data.version || null,
        count: data.domains.length,
        updated: data.updated || null,
        etag: data.etag || null,
        cachedAt: data.cachedAt || 0
      };
    }
    // ② 节流：非强制（非启动 / 非升级）且距上次成功同步不足 6h → 跳过联网检查
    if (!force && _cloudOfficialMeta.cachedAt && (Date.now() - _cloudOfficialMeta.cachedAt) < CLOUD_SYNC_THROTTLE_MS) {
      return;
    }
    // ③ 异步检查远端是否变化，必要时拉取整库
    refreshCloudOfficialCache(force);
  });
}

// 用 HEAD 比对远端变更；仅变化 / 本地为空 / 强制时才下载整库并写 storage.local
function refreshCloudOfficialCache(force) {
  // MV3 保活心跳：HEAD 很快，但随后的 GET 整库（3.9MB）较慢，期间用定时器维持 SW 运行直到完成
  const keepAlive = setInterval(function () {}, 20000);
  const finish = function () { try { clearInterval(keepAlive); } catch (e) {} };
  fetch(CLOUD_OFFICIAL_URL, { method: 'HEAD', cache: 'no-store' })
    .then(function (head) {
      if (!head.ok) throw new Error('HEAD ' + head.status);
      const remoteEtag = head.headers.get('etag');
      const remoteLM = head.headers.get('last-modified');
      const changed = !_cloudOfficialMeta.etag ||
        (remoteEtag && remoteEtag !== _cloudOfficialMeta.etag) ||
        (remoteLM && _cloudOfficialMeta.updated && remoteLM !== _cloudOfficialMeta.updated);
      if (!changed && !force) {
        // 未变化：仅刷新 cachedAt，避免重复写整库
        _cloudOfficialMeta.cachedAt = Date.now();
        _persistCloudMeta();
        return;
      }
      return fetch(CLOUD_OFFICIAL_URL, { cache: 'no-store' })
        .then(function (r) { if (!r.ok) throw new Error('GET ' + r.status); return r.json(); })
        .then(function (j) {
          const arr = (j && j.domains) || [];
          if (!Array.isArray(arr)) throw new Error('bad payload');
          _cloudOfficialSet = _buildCloudSet(arr);
          _cloudOfficialMeta = {
            version: (j && j.version) || null,
            count: arr.length,
            updated: (j && j.updated) || remoteLM || null,
            etag: remoteEtag || null,
            cachedAt: Date.now()
          };
          return _persistCloudFull({ version: _cloudOfficialMeta.version, domains: arr, updated: _cloudOfficialMeta.updated, etag: remoteEtag || null, cachedAt: Date.now() });
        });
    })
    .catch(function () { /* 失败静默，保留旧缓存 */ })
    .then(finish, finish);
}

// 设置页（纯前端）更新了云端库缓存 → 同步内存 Set，无需任何消息端口
chrome.storage.onChanged.addListener(function (changes, area) {
  if (area !== 'local' || !changes[CLOUD_CACHE_KEY]) return;
  const data = changes[CLOUD_CACHE_KEY].newValue;
  if (data && Array.isArray(data.domains)) {
    _cloudOfficialSet = _buildCloudSet(data.domains);
    _cloudOfficialMeta = {
      version: data.version || null,
      count: data.domains.length,
      updated: data.updated || null,
      etag: data.etag || null,
      cachedAt: data.cachedAt || Date.now()
    };
  }
});

// SW 每次唤醒都执行本顶层调用（MV3 Service Worker 无传统全局单例，靠顶层代码保证初始化）
syncCloudOfficial(false);

function _persistCloudFull(data) {
  return new Promise(function (resolve) {
    chrome.storage.local.set({ [CLOUD_CACHE_KEY]: data }, resolve);
  });
}

// 轻量更新 meta（仅 cachedAt 等），不重写整库
function _persistCloudMeta() {
  chrome.storage.local.get(CLOUD_CACHE_KEY, function (res) {
    const data = res && res[CLOUD_CACHE_KEY];
    if (!data) return;
    data.cachedAt = _cloudOfficialMeta.cachedAt;
    chrome.storage.local.set({ [CLOUD_CACHE_KEY]: data });
  });
}

function getCloudOfficialMeta() { return _cloudOfficialMeta; }


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

  if (msg.type === 'sf-cloud-official') {
    // 内容脚本问「本页域名是否命中云端官网库」。后台拉取云端公开名单（仅内存），
    // 用标签对齐后缀匹配（与 isOfficialDomain 同语义）；不接收任何用户域名 → 零隐私上报。
    const host = (msg.host || '').toLowerCase().replace(WWW_RE, '');
    ensureCloudOfficialSet().then(function (set) {
      const hit = _cloudSuffixHit(set, host);
      try { sendResponse({ official: !!hit, matched: hit || '' }); } catch (e) {}
    }).catch(function () {
      try { sendResponse({ official: false, matched: '' }); } catch (e) {}
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
  } else if (msg.type === 'sf-allow-download') {
    // 用户选择「仍要下载」：将该 URL 加入本次会话放行名单（避免重复拦截）
    const url = msg && msg.url;
    if (url) {
      allowedDownloads.add(url);
      // 仅当来自「后台大弹窗」(下载已被取消) 时才由后台重新触发下载；
      // 来自「页面内钩子」(fromPage) 时由页面自身执行下载，后台不必重下，避免双下载。
      if (!msg.fromPage && chrome.downloads && chrome.downloads.download) {
        chrome.downloads.download({ url: url }, function () {
          if (chrome.runtime.lastError) {
            // 无法直接重下（如 blob / 需站内鉴权），提示前台让用户手动在站内下载
            try {
              if (sender.tab && sender.tab.id != null && chrome.tabs && chrome.tabs.sendMessage)
                chrome.tabs.sendMessage(sender.tab.id, { type: 'sf-download-allow-failed', url });
            } catch (e2) {}
          }
        });
      }
    }
  } else if (msg.type === 'sf-notify') {
    // 危险弹窗系统通知（Windows 右下角 toast）：内容脚本转发，后台创建原生通知
    try {
      if (chrome.notifications && chrome.notifications.create) {
        const nid = 'sf-' + Date.now();
        chrome.notifications.create(nid, {
          type: 'basic',
          iconUrl: chrome.runtime.getURL('icons/icon128.png'),
          title: (msg.title || '⚠️ 银狐防护提醒'),
          message: (msg.message || '发现高风险网站'),
          priority: 1,
          requireInteraction: false
        }, function () {});
        // 兜底：无论系统通知设置如何，10 秒后强制清除，避免 toast 常驻右下角
        setTimeout(function () {
          try { chrome.notifications.clear(nid, function () {}); } catch (e) {}
        }, 10000);
      }
    } catch (e) {}
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
  chrome.storage.local.get({ stats: { warnings: 0, blocks: 0, recent: [], blockedTabs: {} } }, function (r) {
    const stats = r.stats || { warnings: 0, blocks: 0, recent: [], blockedTabs: {} };
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
    }
    // warn 不计入任何拦截计数（也不应到达此处，content 端已不上报 warn）。

    chrome.storage.local.set({ stats });
  });
}

// ===== 分析闸门：默认拒绝（检测未出前先堵死该标签全部下载）=====
function holdDownload(tabId, item) {
  if (!heldDownloads[tabId]) heldDownloads[tabId] = [];
  heldDownloads[tabId].push({ id: item.id, url: item.url, filename: item.filename });
  // 静默取消并擦除，避免下载栏出现「已取消」残影；判安后再静默重下
  try { chrome.downloads.cancel(item.id); } catch (e) {}
  try { chrome.downloads.erase(item.id); } catch (e) {}
}
function flushHeld(tabId) {
  const held = heldDownloads[tabId];
  if (!held || !held.length) return;
  delete heldDownloads[tabId];
  held.forEach(function (h) {
    if (!h.url) return;
    // blob:/data: 无法用 URL 静默重下 → 提示用户手动重新点击
    if (/^(blob:|data:)/i.test(h.url)) {
      try { if (chrome.tabs && chrome.tabs.sendMessage) chrome.tabs.sendMessage(tabId, { type: 'sf-download-allow-failed', url: h.url }); } catch (e2) {}
      return;
    }
    reissuedUrls.add(h.url);
    try { chrome.downloads.download({ url: h.url, filename: h.filename || '', saveAs: false }); } catch (e) {}
  });
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
        try { if (chrome.tabs && chrome.tabs.sendMessage) chrome.tabs.sendMessage(tabId, { type: 'sf-download-blocked', host: parseHost(h.url), url: h.url, filename: h.filename }); } catch (e) {}
      });
    }
    delete heldDownloads[tabId];
  } else {
    flushHeld(tabId); // 安全：静默重下挂起下载
  }
}
function armAnalysis(tabId) {
  analysisState[tabId] = 'analyzing';
  if (analysisTimers[tabId]) clearTimeout(analysisTimers[tabId]);
  analysisTimers[tabId] = setTimeout(function () {
    if (analysisState[tabId] === 'analyzing') {
      analysisState[tabId] = 'safe';
      flushHeld(tabId); // 失效开放：内容脚本无回应也按安全放行挂起下载
    }
    delete analysisTimers[tabId];
  }, ANALYSIS_TIMEOUT_MS);
}

// ===== 拦截下载：仅拦「危险且未放行站点」发起的下载 =====
if (chrome.downloads && chrome.downloads.onCreated) {
  chrome.downloads.onCreated.addListener(function (item) {
    if (!item || !item.url) return;
    // 判安后静默重下的下载（原被闸门挂起者）→ 直接放行，不再二次闸控
    if (reissuedUrls.has(item.url)) { reissuedUrls.delete(item.url); return; }
    // 本次下载用户已明确「仍要下载」→ 直接放行（避免重复拦截）
    if (allowedDownloads.has(item.url)) return;
  // ★ 由扩展发起（byExtensionId）的下载：仅「本扩展自身」（静默重下/保存）直接放行；
  //   其它扩展（迅雷/IDM/下载器接管类）发起的下载落入后续风险判定——它们必须先经
  //   downloads API 才能转交外部下载器，在这里掐断即可阻止其绕过浏览器的下载。
  if (item.byExtensionId && item.byExtensionId === chrome.runtime.id) return;
      const host = parseHost(item.url);
      getSettings().then(function (settings) {
      if (!settings.enabledGlobal || !settings.autoBlockDownloads) return;
      // ★ 免费加成：Chrome 自带 Safe Browsing 已将该下载标记为恶意
      //   （content=文件已知恶意 / url=网址已知恶意 / host=来源主机已知分发恶意二进制）
      //   此判定常在 onCreated 时仍为 safe，云查完成后经 onChanged 返回，见下方 onChanged 兜底。
      if (isMaliciousDanger(item.danger)) {
        cancelDownload(item.id, host, item.tabId >= 0 ? [item.tabId] : [], item.url, item.filename);
        return;
      }
      // ★ 分析闸门：来源标签页仍在检测中 → 默认拒绝，先堵死全部下载并挂起，待判定后处理
      if (item.tabId && item.tabId >= 0 && analysisState[item.tabId] === 'analyzing') {
        holdDownload(item.tabId, item);
        return;
      }
      // 白名单站点（按下载文件所在域名放行）
      if (hostMatch(host, settings.allowlist)) return;
      // 用户自定义黑名单域名 → 拦（提示发到当前标签页）
      if (hostMatch(host, settings.customBadDomains)) {
        cancelDownload(item.id, host, item.tabId >= 0 ? [item.tabId] : [], item.url, item.filename);
        return;
      }
      // ★ 硬编码银狐木马投递站黑名单（与页面级判定同源）：命中下载 URL 或来源域即强制取消，永不豁免
      if (isKnownBadHost(host)) {
        cancelDownload(item.id, host, item.tabId >= 0 ? [item.tabId] : [], item.url, item.filename);
        return;
      }
      const srcHost = downloadSourceHost(item);
      if (srcHost && isKnownBadHost(srcHost)) {
        cancelDownload(item.id, srcHost, item.tabId >= 0 ? [item.tabId] : [], item.url, item.filename);
        return;
      }
      // ★ 已知木马化投递物文件名（样本静态分析 IOC）：bzy.exe / shanlian_VPN_64.exe 等
      //   命中即强制取消下载，不受「来源页是否判危」影响（无法读下载字节，文件名是最稳锚点）。
      if (isKnownBadFilename(item.filename) || isKnownBadFilename(item.url)) {
        cancelDownload(item.id, host || srcHost || '', item.tabId >= 0 ? [item.tabId] : [], item.url, item.filename);
        return;
      }
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
        if (hostMatch(host, settings.allowlist)) return;
        if (srcHost && (SF.isOfficialDomain(srcHost) || hostMatch(srcHost, settings.allowlist))) return;
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
        if (hostMatch(host, settings.allowlist)) return;
        if (srcHost && (SF.isOfficialDomain(srcHost) || hostMatch(srcHost, settings.allowlist))) return;
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
        if (allowedDownloads.has(it.url) || it.byExtensionId) return; // 用户已明确放行 / 扩展自身发起
        const tabIds = it.tabId >= 0 ? [it.tabId] : [];
        const h = parseHost(it.url);
        if (it.state === 'complete') {
          // 已落地到磁盘：cancel 无效，但仍弹窗警告用户文件可疑
          tabIds.forEach(function (tid) {
            if (tid != null && chrome.tabs && chrome.tabs.sendMessage) {
              try { chrome.tabs.sendMessage(tid, { type: 'sf-download-blocked', host: h, url: it.url, filename: it.filename }); } catch (e) {}
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
      if (tid != null && tid >= 0 && chrome.tabs && chrome.tabs.sendMessage) {
        try { chrome.tabs.sendMessage(tid, { type: extBlock ? 'sf-dl-ext-blocked' : 'sf-download-blocked', host: host, url: url, filename: filename }); } catch (e) {}
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

