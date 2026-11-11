/* options.js — SilverFoxBlocker 设置控制面板逻辑（侧边栏分类版） */
'use strict';

// 360 系统急救箱官方下载直链。现为「备用直链」：点击按钮时会自动抓取
// 官网/软件宝库的最新 64 位独立版直链；仅当自动抓取失败时才回退到此处。
const RESCUE_DOWNLOAD_URL = 'https://dl.360safe.com/360c0mpkill_5.1.64.1289-0701.zip';

// 火绒专杀工具（无签名版）官方下载直链（备用种子）。点击按钮时会自动探测火绒 CDN 的最新无签名版；
// 该工具可解除银狐木马对常规杀毒软件的打开限制；因无签名，Windows Defender 与安全下载检测会拦截——属正常现象，用户放行即可。
// 有签名版同样会被银狐类病毒拦截，故只提供无签名版。自动抓取失败时才回退到此种子直链。
const HRKILL_DOWNLOAD_URL = 'https://down7.huorong.cn/hrkill/hrkill_unsign-1.0.0.200.exe';

// Kaspersky Virus Removal Tool（KVRT）官方直链：固定地址、始终指向最新版，
// 所以不需要像 360 / 火绒那样去探测版本号（桌面 KVRT 目录里的 update_by_aria2.bat
// 抓的也是这一条）。每次点击都是「重新下载最新版」。
const KVRT_DOWNLOAD_URL = 'https://devbuilds.s.kaspersky-labs.com/kvrt/latest/full/kvrt.exe';

// AdwCleaner 官方 release 直链：与 KVRT 一样是「固定地址、始终指向最新版」，
// 所以不需要探测版本号，每次点击都是重新下载最新版。该地址取自
// D:\Users\18926\Desktop\AdwCleaner\update_by_aria2.bat 的 DOWNLOAD_URL。
// ⚠️ URL 末段是 "adwcleaner?channel=release"，不能直接拿来当文件名：
//    必须用 filename:'adwcleaner.exe'（脚本里 aria2 的 -o 参数也是这个名字）。
const ADWCLEANER_DOWNLOAD_URL = 'https://adwcleaner.malwarebytes.com/adwcleaner?channel=release';

// 急救 / 清除工具的 DOM 映射，供下载与复制直链共用。
// direct:true = 直链固定，点按钮直接下载，不经后台探测（见 sfRescueDownload）。
// filename（可选）= chrome.downloads 保存时使用的文件名，URL 末段不是文件名时必须指定。
const SF_RESCUE_TOOLS = {
  '360': { btn: 'rescueBtn', url: 'rescueUrl', fallback: RESCUE_DOWNLOAD_URL, store: 'rescue360Url', direct: false },
  hrkill: { btn: 'hrkillBtn', url: 'hrkillUrl', fallback: HRKILL_DOWNLOAD_URL, store: 'hrkillUrl', direct: false },
  kvrt: { btn: 'kvrtBtn', url: 'kvrtUrl', fallback: KVRT_DOWNLOAD_URL, store: 'kvrtUrl', direct: true },
  adwcleaner: { btn: 'adwBtn', url: 'adwUrl', fallback: ADWCLEANER_DOWNLOAD_URL, store: 'adwcleanerUrl', direct: true, filename: 'adwcleaner.exe' }
};

// （银狐系统解锁工具已停止维护并下架，此处不再提供下载入口。）

const DEFAULTS = {
  enabledGlobal: true,
  showWarning: true,
  autoBlockDownloads: true,
  notify: true,
  icpApiVerify: true,   // ICP 备案权威核验（只发域名给公开备案接口，且仅在核验有价值时发起）
  // 敏感度：设置页已无对应控件（2026-11-11），固定 'medium'；引擎仍读它做阈值/组合升级分档
  sensitivity: 'medium',
  fontMode: 'system',   // 'system' | 'smiley'
  theme: 'dark',        // 'dark' | 'light'（旧字段，兼容升级；新逻辑以 themePalette + themeLight 为准）
  themePalette: 'classic', // 'classic' | 'gold' | 'neon' | 'mist' | 'space' | 'pixel'(隐藏彩蛋)
  pixelUnlocked: false,   // Pixel 主题为隐藏彩蛋，解锁后才在主题网格显示/生效
  material: 'frosted',  // 'frosted'(磨砂玻璃，默认) | 'liquid'(琉声液态玻璃)；Pixel 主题下强制 frosted
  bgImage: '',          // 自定义背景 dataURL（空=使用主题默认背景）
  sidebar: 'attached',   // 'attached'(贴合) | 'floating'(浮空)；自定义主题可携带，用户后续可切换
  control: 'normal',     // 'normal'(普通) | 'skeuomorphic'(拟物)
  bgType: 'gradient',    // 'gradient' | 'solid' | 'image'（背景类型，自定义主题与背景设置共享）
  customThemes: [],     // 用户导入的自定义主题数组 [{id,name,theme}]
  aiMaxMode: false,         // Max 模式：开启后云端模型优先辅助，自动关闭本地引擎与云端增强开关，仅保留云端 AI 模型辅助；云端处理不了时回退本地
  aiCloudWebAnalyse: false, // 子开关「借助云端AI分析网页」（Max 下，后台自动分析网页）
  aiScanFileAnalyse: false, // 子开关「借助云端AI分析扫描文件」（Max 下，银狐扫描可疑文件时发特征摘要给 AI 辅助研判）
  remindMode: 'normal',    // 扩展整体报毒识别/提醒偏好：'normal' 正常 | 'quiet' 安静（仅危险告警，不弹软提示卡）
  fontScale: 1,         // 0.85 ~ 1.40，界面字号缩放系数
  // 威胁情报 API（可选）：默认关闭；启用后扩展实时查询当前域名在第三方情报库的判定。
  // VirusTotal 需用户自有 Key；URLhaus / NetAPI 无需 Key（免费公开接口）。
  threatIntel: {
    enabled: false,
    providers: {
      // VirusTotal / Google Safe Browsing 的 Key 一律以 AES-GCM 密文存储（crypto-helper 加解密），
      // settings 里读到的 apiKey 是密文；明文只存在于用户输入的瞬间与后台 SW 解密后的内存里。
      virustotal: { enabled: false, apiKey: '' },
      urlhaus: { enabled: false },
      netapi: { enabled: false },
      googlesafebrowsing: { enabled: false, apiKey: '' }
    }
  },
  // 社区维护的本地黑名单总开关（默认关闭）：关闭时三个名单不加载、不更新、不参与比对；
  // 开启后各名单再按自己的 enabled 开关决定是否参与。后续新增名单只需在此结构下追加。
  communityLists: { enabled: false },
  // OpenPhish 本地钓鱼黑名单：免费 feed，无需 Key；默认每天自动更新，名单存于 storage.local
  openphish: { enabled: false, lastUpdated: 0 },
  // PhishDestroy 本地钓鱼黑名单：第二个静态名单源（约 14 万条域名），机制与 OpenPhish 完全一致
  phishdestroy: { enabled: false, lastUpdated: 0 },
  // HaGeZi's Threat Intelligence Feeds：第三个静态名单源（约 181 万条），本地以哈希索引保存
  hagezi: { enabled: false, lastUpdated: 0, variant: 'full' },
  customTheme: null,    // 用户导入的自定义主题：{ name, theme:{ bgPrimary,bgSecondary,accent,accent2,text,surface,border,material,sidebar,control } }
  reduceMotion: false,  // 减弱动画效果：关闭全部过渡与动画
  layout: 'new',        // 设置页布局：'new'(新版 8 项分组导航，默认) | 'old'(旧版 11 项平铺导航)
  enabled: {
    domainImpersonation: true, icpMissing: true, lowQuality: true,
    execDownload: true, cloudDiskDist: true, obfuscatedJs: true, vmDetection: true,
    socialEngineering: true, fakeOfficial: true, redirectIframe: true, domainStructure: true
  },
  allowlist: [], customKeywords: [], customBadDomains: []
};

// Google Safe Browsing Key 加密存储相关 UI 状态
let _gsKeySet = false;       // 设置页打开时是否已存在密文 Key（用户未改动则保留原密文）
let _gsSavedCipher = '';     // 已保存的密文，用户留空时原样保留，避免误清空
let _gsEncryptFailed = false;// 本次保存时加密是否失败（首次填写却加密失败 → 不存明文，提示用户重试）
let _gsFieldDirty = false;   // 用户是否修改过 Key 输入框（聚焦后输入过）→ 决定保存时是否重新加密
// 已保存 Key 的掩码显示：约 40 个圆点（贴近 Google API Key 的正常长度 ~39 位），
// 既不像密文那样看起来像「乱码」，也不会短得只剩十几个点显得没存上；保存前后长度完全一致。
const GSB_MASK_CHAR = '•';
const GSB_MASK = new Array(39 + 1).join(GSB_MASK_CHAR);  // 已保存 Key 的掩码（39 点 = Google API Key 典型长度）；未保存时输入框为空

// VirusTotal Key 加密存储相关 UI 状态（与 GSB 共用 crypto-helper，但状态彼此独立）
let _vtKeySet = false;       // 设置页打开时是否已存在密文 Key
let _vtSavedCipher = '';     // 已保存的密文，用户未改动输入框时原样保留
let _vtEncryptFailed = false;// 本次保存加密是否失败（首次填写失败 → 不存明文，提示重试）
let _vtFieldDirty = false;   // 用户是否改动过 Key 输入框
const VT_MASK = new Array(64 + 1).join(GSB_MASK_CHAR);   // VT v3 API Key 典型长度 64 位

function $(id) { return document.getElementById(id); }
// 扩展环境才有 chrome.storage；浏览器直接预览时优雅退回默认值，不影响真实行为
function hasStorage() { return (typeof chrome !== 'undefined') && chrome.storage && chrome.storage.sync; }
function hasStorageLocal() { return (typeof chrome !== 'undefined') && chrome.storage && chrome.storage.local; }
function getSettings() {
  if (!hasStorage()) return Promise.resolve(Object.assign({}, DEFAULTS));
  return new Promise((resolve) => chrome.storage.sync.get(DEFAULTS, (s) => resolve(Object.assign({}, DEFAULTS, s || {}))));
}

// ===== 旧版明文 VirusTotal Key → AES-GCM 密文自动迁移 =====
// v1.6.1 及更早版本把 VT Key 明文写进 storage.sync。升级后打开一次设置页即完成迁移，
// 用户无需重新粘贴；迁移失败则保留明文（后台仍兼容），绝不把 Key 弄丢或写成半截密文。
async function migrateVtPlainKey(settings) {
  try {
    const ti = settings && settings.threatIntel;
    const vt = ti && ti.providers && ti.providers.virustotal;
    const raw = (vt && typeof vt.apiKey === 'string') ? vt.apiKey.trim() : '';
    if (!raw || typeof sfLooksEncrypted !== 'function' || sfLooksEncrypted(raw)) return;
    if (typeof sfEncryptKey !== 'function' || !hasStorage()) return;
    const enc = await sfEncryptKey(raw);
    if (!enc) return;   // Web Crypto 不可用：保留明文，后台兼容路径仍可正常查询
    // 深拷贝，避免改到 DEFAULTS.threatIntel 的共享引用（getSettings 是浅合并）
    const nextTi = JSON.parse(JSON.stringify(ti));
    nextTi.providers = nextTi.providers || {};
    nextTi.providers.virustotal = Object.assign({}, nextTi.providers.virustotal || {}, { apiKey: enc });
    const ok = await new Promise((resolve) => {
      try {
        chrome.storage.sync.set({ threatIntel: nextTi }, function () {
          resolve(!(chrome.runtime && chrome.runtime.lastError));
        });
      } catch (e) { resolve(false); }
    });
    if (!ok) return;
    settings.threatIntel = nextTi;   // 让 bindControls 直接拿到密文态
    console.log('[SilverFoxBlocker][设置] 已将旧的明文 VirusTotal API Key 迁移为 AES-GCM 密文');
  } catch (e) {
    console.warn('[SilverFoxBlocker][设置] VT Key 迁移失败，保留原配置：', e);
  }
}

/* 字号弹性弹簧：用 requestAnimationFrame 逐帧把 --sf-scale 逼近目标值，带明显过冲回弹（弹性十足）。
   拖动时目标实时跟随（跟手不滞后），松手 / 重置 / 切换字体时呈现 Q 弹回弹。 */
let _scCur = 1, _scTar = 1, _scVel = 0, _scRAF = null;
const _scRoot = document.documentElement;
function _scTick() {
  const diff = _scTar - _scCur;
  _scVel += diff * 0.16;   // 刚度
  _scVel *= 0.74;          // 阻尼（<1 即欠阻尼，产生过冲回弹）
  _scCur += _scVel;
  if (Math.abs(diff) < 0.0006 && Math.abs(_scVel) < 0.0006) {
    _scCur = _scTar; _scVel = 0;
    _scRoot.style.setProperty('--sf-scale', _scCur.toFixed(4));
    _scRAF = null;
    return;
  }
  _scRoot.style.setProperty('--sf-scale', _scCur.toFixed(4));
  _scRAF = requestAnimationFrame(_scTick);
}
function setScale(target, instant) {
  _scTar = target;
  if (instant) {
    _scCur = target; _scVel = 0;
    if (_scRAF) { cancelAnimationFrame(_scRAF); _scRAF = null; }
    _scRoot.style.setProperty('--sf-scale', target.toFixed(4));
    return;
  }
  if (!_scRAF) _scRAF = requestAnimationFrame(_scTick);
}

/* 立即把字体/主题偏好应用到当前文档（设置页实时预览） */
function applyAppearance(instant) {
  const root = document.documentElement;
  const activeFont = (document.querySelector('.font-opt.active') || {}).dataset;
  const fontMode = (activeFont && activeFont.font) || 'system';
  let themeLight = ($('themeLight') && $('themeLight').checked) || false;
  // 外观主题：经典保持无额外类（沿用 :root 默认配色）；其余调色板挂对应 html.theme-* 类
  const activeTheme = (document.querySelector('.theme-opt.active') || { dataset: {} }).dataset;
  const palette = (activeTheme && activeTheme.palette) || 'classic';
  // 材质与背景从全局设置缓存读取（init 时写入 window.__sfSettings），保证切换主题时也能正确应用
  const settings = (typeof window !== 'undefined' && window.__sfSettings) || {};
  // 自定义主题：用户导入，支持多主题（themePalette 形如 'custom:<id>'）
  const customMatch = typeof palette === 'string' && palette.startsWith('custom:') ? palette.slice(7) : '';
  const customThemes = Array.isArray(settings.customThemes) ? settings.customThemes : (settings.customTheme ? [settings.customTheme] : []);
  const customTheme = customMatch ? customThemes.find(function (x) { return String(x.id) === customMatch; }) : null;
  const ct = (customTheme && customTheme.theme) ? customTheme.theme : null;
  root.classList.toggle('font-smiley', fontMode === 'smiley');
  root.classList.toggle('theme-light', themeLight || (ct && !!ct.themeLight));
  root.classList.toggle('theme-gold', palette === 'gold');
  root.classList.toggle('theme-neon', palette === 'neon');
  root.classList.toggle('theme-mist', palette === 'mist');
  root.classList.toggle('theme-space', palette === 'space');
  root.classList.toggle('theme-glass', palette === 'glass');
  root.classList.toggle('theme-pixel', palette === 'pixel');
  // 界面材质：默认磨砂玻璃；琉声液态玻璃仅在非 Pixel 主题下生效（Pixel 锁定磨砂玻璃）。
  // 自定义主题不再锁死材质——material 统一从 settings 读取（导入时已写入），用户后期可在 UI 自由切换。
  const matBtn = (document.querySelector('#materialSeg button.active') || { dataset: {} });
  const material = (matBtn && matBtn.dataset && matBtn.dataset.material) || (settings && settings.material) || (ct && ct.material) || 'frosted';
  root.classList.toggle('material-liquid', material === 'liquid' && palette !== 'pixel');
  root.classList.toggle('material-flat', material === 'flat');
  // 自定义背景：写入 body 固定背景层（Pinned 背景，模糊压暗保证文字可读；Pixel 主题下也生效）
  const bg = (settings && settings.bgImage) || '';
  if (bg) {
    document.body.style.backgroundImage = 'linear-gradient(rgba(8,12,24,.55), rgba(8,12,24,.55)), url(' + bg + ')';
    document.body.style.backgroundSize = 'cover';
    document.body.style.backgroundPosition = 'center';
    document.body.style.backgroundAttachment = 'fixed';
  } else {
    document.body.style.backgroundImage = '';
  }
  // 字号缩放：由「字体大小」滑块控制，作用于全部界面文本。
  // 得意黑(SmileySans)字重偏小，内置 110% 基准系数，使其观感与其他字体一致（这是用户实测的最佳值）。
  const fsEl = $('fontScale');
  const fs = (fsEl && parseFloat(fsEl.value)) || 100;
  let scale = fs / 100;
  const effectiveFontMode = fontMode;
  if (effectiveFontMode === 'smiley') scale *= 1.10;
  // 自定义主题：仅注入「配色」变量（accent/bgPrimary 等无独立 UI 入口，由主题携带，保持主题观感）；
  // 材质 / 侧边栏 / 控件 / 背景图片 一律从 settings 读取（导入时已一次性写入，用户后续可在 UI 自由修改，不锁死）。
  if (ct) {
    root.classList.add('theme-custom');
    root.style.setProperty('--sf-accent', ct.accent);
    root.style.setProperty('--sf-accent-2', ct.accent2);
    root.style.setProperty('--sf-text', ct.text);
    root.style.setProperty('--sf-surface-solid', ct.surface);
    root.style.setProperty('--sf-border', ct.border);
    root.style.setProperty('--sf-accent-grad-soft', hexToRgbaSoft(ct.accent));
    // 背景：优先用用户后期设置的图片背景（settings.bgImage），否则回退主题自带渐变/纯色
    if (!bg) {
      const bgType = ct.bgType || 'gradient';
      if (bgType === 'solid') {
        document.body.style.background = ct.bgSolid || ct.bgPrimary;
      } else {
        document.body.style.background = 'linear-gradient(' + (ct.bgDirection || '160deg') + ', ' + ct.bgPrimary + ', ' + ct.bgSecondary + ')';
      }
    }
    // 侧边栏 / 控件：从 settings 读取，不再硬读主题
    const sidebar = (settings && settings.sidebar) || ct.sidebar || 'attached';
    root.classList.toggle('sidebar-floating', sidebar === 'floating');
    root.classList.toggle('sidebar-attached', sidebar === 'attached');
    const control = (settings && settings.control) || ct.control || 'normal';
    root.classList.toggle('control-skeuo', control === 'skeuomorphic');
  } else {
    root.classList.remove('theme-custom', 'material-flat', 'sidebar-floating', 'sidebar-attached', 'control-skeuo');
    ['--sf-accent', '--sf-accent-2', '--sf-text', '--sf-surface-solid', '--sf-border', '--sf-accent-grad-soft']
      .forEach(function (p) { root.style.removeProperty(p); });
    if (!settings.bgImage) document.body.style.background = '';
  }
  const reduce = document.documentElement.classList.contains('reduce-motion');
  setScale(scale, instant || reduce);
}

// 将 hex 颜色转成带透明度的 rgba（用于自定义主题的 accent-grad-soft 软底色）
function hexToRgbaSoft(hex) {
  hex = (hex || '').replace('#', '');
  if (hex.length === 3) hex = hex.split('').map(function (c) { return c + c; }).join('');
  const n = parseInt(hex, 16);
  return 'rgba(' + ((n >> 16) & 255) + ',' + ((n >> 8) & 255) + ',' + (n & 255) + ',.16)';
}

// 在主题网格中重建所有「自定义」主题卡片（位于导入卡片之前）。selectId 传入时选中对应主题。
function ensureCustomThemeCards(selectId) {
  const grid = $('themeGrid'); if (!grid) return;
  grid.querySelectorAll('.theme-opt.theme-custom').forEach(function (n) { n.remove(); });
  const settings = window.__sfSettings || {};
  let list = Array.isArray(settings.customThemes) ? settings.customThemes : (settings.customTheme ? [settings.customTheme] : []);
  const imp = $('themeImportCard');
  list.forEach(function (ct) {
    if (!ct || !ct.theme) return;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'theme-opt theme-custom';
    btn.dataset.palette = 'custom:' + ct.id;
    btn.dataset.cid = ct.id;
    const a = ct.theme.accent || '#7db4ff';
    const a2 = ct.theme.accent2 || '#a08cff';
    // 重名时显示序号，避免两张同名卡无法区分（底层仍以唯一 id 操作，不会只留一个）
    const nm = ct.name || '自定义主题';
    const same = list.filter(function (x) { return (x.name || '自定义主题') === nm; });
    const label = same.length > 1 ? nm + ' (' + (same.indexOf(ct) + 1) + ')' : nm;
    btn.innerHTML = '<span class="theme-swatch" style="background:linear-gradient(135deg,' + a + ',' + a2 + ')"></span>' +
                    '<span class="theme-name">' + label + '</span>';
    if (imp) grid.insertBefore(btn, imp); else grid.appendChild(btn);
  });
  if (selectId) {
    grid.querySelectorAll('.theme-opt').forEach(function (x) { x.classList.remove('active'); });
    const target = grid.querySelector('.theme-opt[data-palette="custom:' + selectId + '"]');
    if (target) target.classList.add('active');
  }
}

/* 主题切换过场：给 <html> 挂 .theme-anim 一阵子（CSS 收尾后自动移除，避免拖累日常交互） */
function flashThemeAnim() {
  if (document.documentElement.classList.contains('reduce-motion')) return;
  const root = document.documentElement;
  root.classList.add('theme-anim');
  clearTimeout(window.__themeAnimT);
  window.__themeAnimT = setTimeout(function () { root.classList.remove('theme-anim'); }, 480);
}

/* Pixel 主题彩蛋：默认在主题网格隐藏；连点左上角标志 3 下 → 口令框；口令正确则解锁并显示/应用该主题。
   口令本身不出现在任何界面文案，仅以「Google 类原生安卓英文名」作暗示。 */
function setupPixelEgg() {
  const brand = $('brandEgg');
  const overlay = $('eggOverlay');
  const input = $('eggInput');
  const okEl = $('eggOk');
  const confirmBtn = $('eggConfirm');
  const cancelBtn = $('eggCancel');
  if (!brand || !overlay || !input) return;

  const KEYWORD = 'pixel';
  let clicks = 0, clickT = null;

  function openEgg() {
    overlay.classList.add('show');
    input.value = '';
    input.classList.remove('err');
    okEl.classList.remove('show');
    setTimeout(() => input.focus(), 60);
  }
  function closeEgg() { overlay.classList.remove('show'); }

  function tryUnlock() {
    if ((input.value || '').trim().toLowerCase() === KEYWORD) {
      document.documentElement.classList.add('pixel-unlocked');
      okEl.classList.add('show');
      if (hasStorage()) chrome.storage.sync.set({ pixelUnlocked: true });
      const opt = document.querySelector('.theme-opt[data-palette="pixel"]');
      if (opt) {
        document.querySelectorAll('.theme-opt').forEach((x) => x.classList.remove('active'));
        opt.classList.add('active');
        const tc = $('themeCurrent'); if (tc) tc.textContent = (opt.querySelector('.theme-name') || {}).textContent || 'Pixel';
        applyAppearance();
        flashThemeAnim();
        if (hasStorage()) chrome.storage.sync.set({ themePalette: 'pixel' });
      }
      setTimeout(closeEgg, 700);
    } else {
      input.classList.add('err');
      input.value = '';
      setTimeout(() => input.classList.remove('err'), 360);
    }
  }

  brand.addEventListener('click', () => {
    const now = Date.now();
    if (!clickT || now - clickT > 1200) clicks = 0;
    clickT = now; clicks++;
    if (clicks >= 3) { clicks = 0; openEgg(); }
  });
  brand.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); brand.click(); }
  });
  confirmBtn && confirmBtn.addEventListener('click', tryUnlock);
  cancelBtn && cancelBtn.addEventListener('click', closeEgg);
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') tryUnlock(); });
  overlay.addEventListener('click', (e) => { if (e.target === overlay) closeEgg(); });
}

/* 扩展自动更新提示：仅「版本升级」时弹出；首次安装与降级均不弹（修复误弹 bug） */

function setupUpdateToast() {
  const box = $('updToast');
  const close = $('updClose');
  if (!box) return;

  function hide() {
    box.classList.add('is-hiding');
    setTimeout(() => { box.hidden = true; box.classList.remove('is-hiding'); }, 280);
  }
  if (close) close.addEventListener('click', hide);

  let curVer = '0';
  try { curVer = (chrome.runtime && chrome.runtime.getManifest && chrome.runtime.getManifest().version) || '0'; } catch (e) {}
  const vt = $('updVer'); if (vt) vt.textContent = 'v' + curVer;
  // 本次更新要点（发布新版时更新此数组；第三人称客观语气，禁止提及用户）
  const UPD_HIGHLIGHTS = [
    '扫描算法重构，误报率大幅下降，知名官网不再被误拦',
    '官网白名单扩容至千余条法人站点，下载站与论坛社区免于误报',
    '扩展性能优化，大页面扫描耗时不升反降',
    '压缩包解压扫描修复，自解压包内木马投递物可被识别',
    '新增一键加入白名单，误拦站点可即时拉黑放行'
  ];
  const ul = $('updPoints');
  if (ul) ul.innerHTML = UPD_HIGHLIGHTS.map(function (h) { return '<li>' + h + '</li>'; }).join('');

  if (!hasStorage()) return;   // 非扩展环境（直接预览）不弹，避免误报
  chrome.storage.local.get({ sfLastVer: '' }, (r) => {
    const last = r.sfLastVer || '';
    if (!last) {
      // 首次安装：记下当前版本，不弹「更新成功」
      chrome.storage.local.set({ sfLastVer: curVer });
      return;
    }
    if (cmpVer(last, curVer) < 0) {
      // 升级：弹出更新成功，并写回新版本
      chrome.storage.local.set({ sfLastVer: curVer });
      setTimeout(() => { box.hidden = false; }, 900);
    }
    // 相等或降级：不弹
  });
}

/* 读取打包内的 sponsors.json 显示鸣谢名单（无名单则隐藏区块）
   ---------------------------------------------------------------------
   ★ 文件格式：`[ { "name": "爱发电用户 <用户名>" }, … ]`
     —— name 就是要显示的文字，用「爱发电用户 + 用户名」的写法（银泊 2026-10-15 定）。
     数组为空 / 文件缺失 ⇒ 整个鸣谢区块隐藏（不显示空的「以下赞助者」标题）。
   ★★ 两个容易忘的坑：
     ① `sponsors.json` **必须同时写进 manifest 的 `web_accessible_resources`** ——
        否则 options 页 fetch 它会被 Chrome 拦（403），静默走 catch，区块永远是隐藏的
        （2026-10-15 实测：文件里明明有名有姓，界面上就是不显示）。
     ② 该文件**只在扩展里用**（银泊定：主防 GUI 不放赞助区）。 */
function renderSponsors() {
  const wrap = $('sponsorList');
  const ul = $('sponsorNames');
  if (!wrap || !ul) return;
  if (!chrome.runtime || !chrome.runtime.getURL) { wrap.hidden = true; return; }
  fetch(chrome.runtime.getURL('sponsors.json'))
    .then(function (r) { return r.ok ? r.json() : []; })
    .then(function (list) {
      if (!Array.isArray(list) || !list.length) { wrap.hidden = true; return; }
      ul.textContent = '';
      list.forEach(function (s) {
        const name = (typeof s === 'string') ? s : (s && s.name) || '';
        if (!name) return;
        const li = document.createElement('li');
        li.textContent = name;   // 用 textContent 防 XSS，名单即使被改也只是纯文本
        ul.appendChild(li);
      });
      wrap.hidden = false;
    })
    .catch(function () { wrap.hidden = true; });
}

/* 版本号比较：a<b 返回 -1，a>b 返回 1，相等返回 0（逢11进一规则下逐段比较即可） */
function cmpVer(a, b) {
  const pa = String(a).split('.').map((n) => parseInt(n, 10) || 0);
  const pb = String(b).split('.').map((n) => parseInt(n, 10) || 0);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const x = pa[i] || 0, y = pb[i] || 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

/* ================= 设置页双布局导航（新版 8 项分组 / 旧版 11 项平铺） =================
   默认新版；切换入口在「个性化」→「界面布局」。切换动画：旧项自然分离（淡出+右滑+塌缩），
   新项自然融合（错峰淡入+左滑+展开）。仅重绘 #nav 内部，不改任何 section 结构。 */
const NAV_ICONS = {
  gear: '<path d="M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z"/><path d="M19.4 13a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-2.9 1.2V21a2 2 0 0 1-4 0v-.1A1.7 1.7 0 0 0 7 19.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0-1.2-2.9H3a2 2 0 0 1 0-4h.1A1.7 1.7 0 0 0 4.7 7l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 2.9-1.2V3a2 2 0 0 1 4 0v.1A1.7 1.7 0 0 0 17 4.7l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0 1.2 2.9H21a2 2 0 0 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1Z" opacity=".9"/>',
  grid: '<path d="M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z"/>',
  shield: '<path d="M12 3 4 6v6c0 5 3.4 8.5 8 9 4.6-.5 8-4 8-9V6l-8-3Z"/><path d="M9 12l2 2 4-4" stroke-width="2" fill="none"/>',
  doc: '<path d="M5 4h11l3 3v13H5z"/><path d="M8 11h8M8 15h8M8 7h4" stroke-width="1.8" fill="none"/>',
  chart: '<path d="M5 19V5M5 19h14M9 15v-4M13 15V8M17 15v-7"/>',
  cross: '<path d="M12 3 4 6v6c0 5 3.4 8.5 8 9 4.6-.5 8-4 8-9V6l-8-3Z"/><path d="M12 8v8M8 12h8" stroke-width="2" fill="none" stroke-linecap="round"/>',
  upload: '<path d="M12 16V4m0 0L7 9m5-5l5 5" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2" fill="none" stroke-width="1.8" stroke-linecap="round"/>',
  globe: '<path d="M12 3a9 9 0 0 0 0 18c1.7 0 2-1.3 1.2-2.2-.8-.9-.3-2.1.9-2.1H15a3 3 0 0 0 0-6h-1.9c-1.2 0-1.7-1.4-.9-2.1.8-.9.5-2.2-1.2-2.2Z" opacity=".9"/><circle cx="12" cy="12" r="9" fill="none"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01" stroke-width="2" fill="none" stroke-linecap="round"/>'
};
// 旧版（11 项平铺，保持历史行为）
const NAV_OLD = [
  { targets: ['detect'],  label: '检测维度', title: '检测维度', desc: '独立评分的检测项，可逐项开关', icon: 'grid' },
  { targets: ['behavior'], label: '拦截行为',title: '拦截行为', desc: '命中风险时如何提醒与处置',   icon: 'shield' },
  { targets: ['rules'],   label: '规则与名单',title: '规则与名单', desc: '信任域名、自定义关键词与黑名单', icon: 'doc' },
  { targets: ['stats'],   label: '防护统计', title: '防护统计', desc: '已拦截风险与下载次数',       icon: 'chart' },
  { targets: ['rescue'],  label: '银狐急救', title: '银狐急救', desc: '中招后的下载与查杀引导',     icon: 'cross' },
  { targets: ['about'],   label: '关于',     title: '关于',     desc: '版本信息与说明',             icon: 'info' }
];
// 新版（8 项分组导航，默认）：同类合并、语义归类
const NAV_NEW_GROUPS = [
  {
    label: '防护', items: [
      { targets: ['detect', 'behavior'], label: '检测拦截', title: '检测与拦截', desc: '检测维度与命中后的处置方式', icon: 'shield' },
      { targets: ['rules'],              label: '规则与名单', title: '规则与名单', desc: '信任域名、关键词与黑名单', icon: 'doc' },
      { targets: ['stats'],              label: '防护统计', title: '防护统计', desc: '已拦截风险与下载次数', icon: 'chart' }
    ]
  },
  {
    label: '工具', items: [
      { targets: ['tools'], label: '急救与工具', title: '急救与工具', desc: '中招后的下载与查杀引导', icon: 'cross' }
    ]
  },
  {
    label: '设置', items: [
      { targets: ['about'],    label: '关于',     title: '关于',     desc: '版本信息与说明',           icon: 'info' }
    ]
  }
];

function renderNav(layout) {
  const nav = document.getElementById('nav');
  if (!nav) return;
  const old = layout === 'old';
  let html = '';
  if (old) {
    NAV_OLD.forEach(function (it) {
      html += '<button class="nav-item" data-targets="' + it.targets.join(' ') + '" data-title="' + it.title + '" data-desc="' + it.desc + '">' +
        '<svg viewBox="0 0 24 24">' + NAV_ICONS[it.icon] + '</svg><span>' + it.label + '</span></button>';
    });
  } else {
    NAV_NEW_GROUPS.forEach(function (g) {
      html += '<div class="nav-group-label">' + g.label + '</div>';
      g.items.forEach(function (it) {
        html += '<button class="nav-item" data-targets="' + it.targets.join(' ') + '" data-title="' + it.title + '" data-desc="' + it.desc + '">' +
          '<svg viewBox="0 0 24 24">' + NAV_ICONS[it.icon] + '</svg><span>' + it.label + '</span></button>';
      });
    });
  }
  nav.innerHTML = html;
  nav.setAttribute('data-layout', old ? 'old' : 'new');
  // 恢复当前激活项高亮（重建后没有 active，侧边栏会失去高亮；跟随当前显示的 section）
  const curSec = document.querySelector('.sec.active');
  const curId = curSec ? curSec.id : 'general';
  const curNav = findNavForTarget(curId);
  if (curNav) curNav.classList.add('active');
  else {
    const first = nav.querySelector('.nav-item');
    if (first) first.classList.add('active');
  }
}

/* ================= 布局切换「非线性重组动画」 =================
   ① 分离：旧导航全部项向整体质心收拢（塌缩式汇聚，非线性 easing），像被吸回一点再消失；
   ② 融合：渲染新导航后，每个新项从质心弹出、非线性地飞回自己的位置铺展开来（错峰 stagger）。
   整体观感是「旧布局溶解 → 新布局从同一点重组长出来」。 */
function applyLayout(layout, animate) {
  const nav = document.getElementById('nav');
  if (!nav) return;
  const reduce = document.documentElement.classList.contains('reduce-motion');
  const curLayout = nav.getAttribute('data-layout');
  if (!animate || reduce || curLayout === layout || (curLayout !== 'new' && curLayout !== 'old')) {
    renderNav(layout); setupNav(); return;
  }
  // ========== ① 分离：旧项向质心收拢 ==========
  const items = Array.prototype.slice.call(nav.querySelectorAll('.nav-item, .nav-group-label'));
  if (!items.length) { renderNav(layout); setupNav(); return; }
  const rects = items.map(function (it) { return it.getBoundingClientRect(); });
  // 质心 = 全部导航项包围盒中心（重组锚点）
  let minL = 1e9, minT = 1e9, maxR = -1e9, maxB = -1e9;
  rects.forEach(function (r) {
    minL = Math.min(minL, r.left); minT = Math.min(minT, r.top);
    maxR = Math.max(maxR, r.right); maxB = Math.max(maxB, r.bottom);
  });
  const cx = (minL + maxR) / 2, cy = (minT + maxB) / 2;
  const leave = items.map(function (it, i) {
    const r = rects[i];
    const dx = cx - (r.left + r.width / 2), dy = cy - (r.top + r.height / 2);
    return it.animate([
      { opacity: 1, transform: 'translate(0,0) scale(1)' },
      { opacity: 0, transform: 'translate(' + dx + 'px,' + dy + 'px) scale(.6)' }
    ], { duration: 320, easing: 'cubic-bezier(.6,0,.8,.4)', delay: i * 10, fill: 'forwards' });
  });
  Promise.all(leave.map(function (a) { return a.finished.catch(function () {}); })).then(function () {
    // ========== ② 融合：新项从质心弹出、飞回原位铺展 ==========
    renderNav(layout);
    setupNav();
    const fresh = Array.prototype.slice.call(nav.querySelectorAll('.nav-item, .nav-group-label'));
    fresh.forEach(function (el, i) {
      const r = el.getBoundingClientRect();
      const dx = cx - (r.left + r.width / 2), dy = cy - (r.top + r.height / 2);
      el.animate([
        { opacity: 0, transform: 'translate(' + dx + 'px,' + dy + 'px) scale(.5)' },
        { opacity: 1, transform: 'translate(0,0) scale(1)' }
      ], { duration: 500, easing: 'cubic-bezier(.24,1.4,.36,1)', delay: i * 34, fill: 'backwards' });
    });
  });
}

// 「个性化 → 界面布局」切换控件初始化（即时生效并持久化）
function bindLayoutSwitch() {
  const cur = (window.__sfSettings && window.__sfSettings.layout) || 'new';
  // 始终渲染导航（个性化页移除后可能不再有布局切换控件，仍保留默认新版导航）
  renderNav(cur);
  const seg = document.getElementById('layoutSeg');
  if (!seg) return;
  seg.querySelectorAll('button').forEach(function (b) {
    b.classList.toggle('active', b.dataset.layout === cur);
  });

  // seg 滑块定位（与灵敏度 seg 同款）
  function layoutGlider() {
    const active = seg.querySelector('button.active') || seg.querySelector('button');
    const glider = seg.querySelector('.seg-glider');
    if (!active || !glider) return;
    const sg = seg.getBoundingClientRect();
    const ar = active.getBoundingClientRect();
    glider.style.width = ar.width + 'px';
    glider.style.transform = 'translateX(' + (ar.left - sg.left) + 'px)';
  }
  requestAnimationFrame(layoutGlider);
  let lzTimer;
  window.addEventListener('resize', function () { clearTimeout(lzTimer); lzTimer = setTimeout(layoutGlider, 100); });

  seg.addEventListener('click', function (e) {
    const btn = e.target.closest('button');
    if (!btn || btn.classList.contains('active')) return;
    seg.querySelectorAll('button').forEach(function (x) { x.classList.remove('active'); });
    btn.classList.add('active');
    layoutGlider();
    const layout = btn.dataset.layout;
    if (window.__sfSettings) window.__sfSettings.layout = layout;
    if (hasStorage()) chrome.storage.sync.set({ layout: layout });
    applyLayout(layout, true);
  });
}

/* 按 section id 找到对应导航项：兼容新版 data-targets（"rescue"）与旧版 data-target */
function findNavForTarget(id) {
  if (!id) return null;
  const items = document.querySelectorAll('.nav-item');
  for (let i = 0; i < items.length; i++) {
    const it = items[i];
    const list = ((it.dataset.targets || '') + ' ' + (it.dataset.target || '')).trim().split(/\s+/);
    if (list.indexOf(id) >= 0) return it;
  }
  return null;
}

/* 侧边栏导航：点击分类切换右侧内容，并更新标题/描述 */
function setupNav() {
  const navItems = document.querySelectorAll('.nav-item');
  const secTitle = $('secTitle');
  const secDesc = $('secDesc');

  // 侧边栏滑动指示：高亮块跟随 active 项丝滑滑动（不是瞬间跳变）
  function moveNavIndicator(item, showNow) {
    const nav = document.getElementById('nav');
    if (!nav || !item) return;
    let ind = nav.querySelector('.nav-indicator');
    if (!ind) {
      ind = document.createElement('span');
      ind.className = 'nav-indicator';
      ind.setAttribute('aria-hidden', 'true');
      nav.insertBefore(ind, nav.firstChild);
    }
    const navRect = nav.getBoundingClientRect();
    const r = item.getBoundingClientRect();
    ind.style.height = r.height + 'px';
    ind.style.transform = 'translateY(' + (r.top - navRect.top) + 'px)';
    if (showNow !== false) {
      ind.classList.add('show');
      clearTimeout(nav.__indT);
      nav.__indT = setTimeout(function () { ind.classList.remove('show'); }, 620);
    }
  }

  navItems.forEach((item) => {
    item.addEventListener('click', () => {
      // 一个入口可能对应多个 section（data-targets="detect behavior"）；
      // 旧版为单个（data-target="rescue"），统一按空格拆分取第一个作主区。
      const targets = (item.dataset.targets || item.dataset.target || '').trim().split(/\s+/).filter(Boolean);
      navItems.forEach((n) => n.classList.toggle('active', n === item));
      document.querySelectorAll('.sec').forEach((s) => { s.classList.remove('active'); s.classList.remove('sec-in'); });
      let firstSec = null;
      targets.forEach((t, i) => {
        const sec = document.getElementById(t);
        if (sec) {
          sec.classList.add('active');
          if (i === 0) { void sec.offsetWidth; sec.classList.add('sec-in'); }
          if (!firstSec) firstSec = sec;
        }
      });
      secTitle.textContent = item.dataset.title || '';
      secDesc.textContent = item.dataset.desc || '';
      const bb = $('backBtn'); if (bb) bb.hidden = true;   // 切到一级分类时退出子页面
      moveNavIndicator(item);
    });

    // 鼠标悬停追踪光晕
    item.addEventListener('mousemove', (e) => {
      const r = item.getBoundingClientRect();
      item.style.setProperty('--mx', (e.clientX - r.left) + 'px');
      item.style.setProperty('--my', (e.clientY - r.top) + 'px');
    });
  });

  // 初始定位到默认 active 项（静默归位，不闪现）
  const defItem = document.querySelector('.nav-item.active');
  if (defItem) moveNavIndicator(defItem, false);
}

function renderCategories(settings) {
  const list = $('catList');
  const cats = (window.SF_ANALYZER && window.SF_ANALYZER.CATEGORIES) || [];
  const weights = settings.weights || {};
  list.innerHTML = cats.map((c) => {
    const on = settings.enabled[c.id] !== false;
    // 用户自定义权重优先；否则用内置默认权重
    const w = (typeof weights[c.id] === 'number') ? weights[c.id] : c.weight;
    // 当前加载出来的权重即视为该项「默认」，供「恢复默认」按钮回退（data-default）
    const defW = w;
    return '<div class="row cat-row">' +
      '<div class="rl"><div class="rt">' + c.label + '<span class="weight">权重 ' + w + '</span></div>' +
      '<div class="rd">' + (c.desc || '') + '</div></div>' +
      '<div class="cat-ctl">' +
        '<div class="wedit" title="调整权重：保存设置后该维度的评分权重即按此值生效">' +
          '<span class="wlabel">调整权重</span>' +
          '<div class="wstepper">' +
            '<button type="button" class="wstep" data-d="-1" aria-label="减少权重">−</button>' +
            '<input type="number" class="winput" data-weight="' + c.id + '" data-default="' + defW + '" value="' + w + '" min="0" max="200" step="1" aria-label="' + c.label + ' 权重">' +
            '<button type="button" class="wstep" data-d="1" aria-label="增加权重">+</button>' +
          '</div>' +
        '</div>' +
        '<button type="button" class="wreset" data-reset="' + c.id + '" title="恢复为本项当前权重默认值">恢复默认</button>' +
        '<label class="switch"><input type="checkbox" data-cat="' + c.id + '"' + (on ? ' checked' : '') + '><span class="slider"></span></label>' +
      '</div>' +
      '</div>';
  }).join('');

  // 权重编辑：步进按钮(±1) + 输入框实时联动，并同步更新同一行的「权重 XX」标签；「恢复默认」回退到加载值
  list.querySelectorAll('.cat-row').forEach((row) => {
    const inp = row.querySelector('.winput');
    const pill = row.querySelector('.weight');
    const stepper = row.querySelector('.wstepper');
    const resetBtn = row.querySelector('.wreset');
    if (!inp || !pill) return;
    const clamp = (v) => Math.max(0, Math.min(200, isNaN(v) ? 0 : v));
    const sync = () => { pill.textContent = '权重 ' + clamp(parseInt(inp.value, 10)); };
    inp.addEventListener('input', sync);
    stepper.querySelectorAll('.wstep').forEach((btn) => {
      btn.addEventListener('click', () => {
        const d = parseInt(btn.dataset.d, 10) || 0;
        inp.value = clamp(parseInt(inp.value, 10) + d);
        sync();
      });
    });
    if (resetBtn) {
      resetBtn.addEventListener('click', () => {
        const def = parseInt(inp.dataset.default, 10) || 0;
        inp.value = def;
        sync();
      });
    }
  });
}

// 手动/自动触发 OpenPhish 名单更新：发指令后即返回，真正结果与状态由后台单向推送（见下方 onMessage 监听），
// 避免「长连接 + MV3 后台被回收」导致的“消息端口已关闭”错误。
function updateOpenPhish(statusEl) {
  try {
    const btn = $('openphishUpdateBtn');
    if (btn) { btn.disabled = true; btn.textContent = '更新中…'; }
    if (statusEl) statusEl.textContent = '正在抓取 OpenPhish 名单…';
    chrome.runtime.sendMessage({ type: 'sf-openphish-update' }, function () {
      // 此处仅收到后台 ACK（{started:true}）或端口异常；真正结果在 sf-openphish-updated 推送里
      if (chrome.runtime.lastError) {
        if (btn) { btn.disabled = false; btn.textContent = '立即更新'; }
        if (statusEl) { statusEl.textContent = '启动更新失败：' + (chrome.runtime.lastError.message || '后台未响应') + '（请确认扩展已重载且后台在运行）'; statusEl.style.color = '#c0392b'; }
      }
    });
  } catch (e) {
    if (statusEl) statusEl.textContent = '更新请求发送失败：' + ((e && e.message) || e);
  }
}

function updatePhishDestroy(statusEl) {
  try {
    const btn = $('phishdestroyUpdateBtn');
    if (btn) { btn.disabled = true; btn.textContent = '更新中…'; }
    if (statusEl) statusEl.textContent = '正在抓取 PhishDestroy 名单（约 14 万条，首次略慢）…';
    chrome.runtime.sendMessage({ type: 'sf-phishdestroy-update' }, function () {
      // 仅收到后台 ACK；真正结果在 sf-phishdestroy-updated 推送里
      if (chrome.runtime.lastError) {
        if (btn) { btn.disabled = false; btn.textContent = '立即更新'; }
        if (statusEl) { statusEl.textContent = '启动更新失败：' + (chrome.runtime.lastError.message || '后台未响应') + '（请确认扩展已重载且后台在运行）'; statusEl.style.color = '#c0392b'; }
      }
    });
  } catch (e) {
    if (statusEl) statusEl.textContent = '更新请求发送失败：' + ((e && e.message) || e);
  }
}

function updateHaGeZi(statusEl) {
  try {
    const btn = $('hageziUpdateBtn');
    if (btn) { btn.disabled = true; btn.textContent = '更新中…'; }
    if (statusEl) statusEl.textContent = '正在抓取 HaGeZi TIF 名单（约 181 万条、36MB，首次约需 10~60 秒）…';
    chrome.runtime.sendMessage({ type: 'sf-hagezi-update' }, function () {
      // 仅收到后台 ACK；真正结果在 sf-hagezi-updated 推送里
      if (chrome.runtime.lastError) {
        if (btn) { btn.disabled = false; btn.textContent = '立即更新'; }
        if (statusEl) { statusEl.textContent = '启动更新失败：' + (chrome.runtime.lastError.message || '后台未响应') + '（请确认扩展已重载且后台在运行）'; statusEl.style.color = '#c0392b'; }
      }
    });
  } catch (e) {
    if (statusEl) statusEl.textContent = '更新请求发送失败：' + ((e && e.message) || e);
  }
}

// 下载进度（后台流式读取时每 4MB 回推一次），让「更新中」有可见进展而不是像卡死
chrome.runtime.onMessage.addListener(function (msg) {
  try {
    if (!msg || msg.type !== 'sf-hagezi-progress') return;
    const statusEl = $('hageziStatus');
    const btn = $('hageziUpdateBtn');
    if (btn) { btn.disabled = true; btn.textContent = '更新中…'; }
    if (!statusEl) return;
    const got = msg.received || 0;
    // total：服务端 content-length，仅在「未压缩传输」时才可信（压缩传输时是压缩后大小，
    // 与后台实际收到的解压字节不可比，后台会置 0）；expected：该名单版本的参考体积。
    const total = msg.total || 0;
    const expected = msg.expected || 0;
    const mb = function (n) { return (n / 1048576).toFixed(1) + 'MB'; };
    if (msg.stage === 'build') {
      statusEl.textContent = '名单已下载（' + mb(got) + '），正在建立索引…';
    } else if (!got) {
      statusEl.textContent = '正在连接下载源…';
    } else if (total && got <= total * 1.02) {
      const pct = Math.min(100, Math.round(got / total * 100));
      statusEl.textContent = '正在下载名单：' + mb(got) + ' / ' + mb(total) + '（' + pct + '%）';
    } else if (expected) {
      // 压缩传输 / 无 content-length：按参考体积估算，分母不小于实际值，百分比封顶 99%
      const denom = Math.max(expected, got);
      const pct = Math.min(99, Math.round(got / denom * 100));
      statusEl.textContent = '正在下载名单：' + mb(got) + ' / 约 ' + mb(denom) + '（' + pct + '%）';
    } else {
      statusEl.textContent = '正在下载名单：已接收 ' + mb(got);
    }
    statusEl.style.color = '';
  } catch (e) {}
});

// 接收后台抓取完成后的单向推送（无长连接，不受 MV3 SW 回收影响）。
// OpenPhish 与 PhishDestroy 共用同一套渲染逻辑，只按来源切换元素与文案。
chrome.runtime.onMessage.addListener(function (msg, _sender, _sendResponse) {
  try {
    if (!msg) return;
    const isOp = msg.type === 'sf-openphish-updated';
    const isPd = msg.type === 'sf-phishdestroy-updated';
    if (!isOp && !isPd) return;
    const r = msg.result || {};
    const name = isOp ? 'OpenPhish' : 'PhishDestroy';
    const statusEl = $(isOp ? 'openphishStatus' : 'phishdestroyStatus');
    const btn = $(isOp ? 'openphishUpdateBtn' : 'phishdestroyUpdateBtn');
    if (btn) { btn.disabled = false; btn.textContent = '立即更新'; }
    if (!statusEl) return;
    if (r.ok) {
      const d = new Date();
      const ds = d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0') + ' ' + String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0');
      const s = r.source || '';
      const srcNote = s ? ('，源：' + (s.indexOf('gh-proxy') >= 0 ? 'GitHub 反代' : (s.indexOf('jsdelivr') >= 0 ? 'jsDelivr 镜像' : (s.indexOf('raw.githubusercontent') >= 0 ? 'GitHub raw' : name + ' 官方')))) : '';
      statusEl.textContent = '更新成功：' + ds + '（共 ' + (r.count || 0) + ' 条域名' + srcNote + '）';
      statusEl.style.color = '';
    } else if (r.skipped) {
      statusEl.textContent = '更新跳过（24 小时内已更新，共 ' + (r.count || 0) + ' 条域名）';
      statusEl.style.color = '';
    } else {
      statusEl.textContent = '更新失败（全部源均不可达）：' + (r.error || '未知错误');
      statusEl.style.color = '#c0392b';
    }
  } catch (e) {}
});

// HaGeZi TIF 的更新结果推送（抓取体量大、耗时长，同样走单向消息）
chrome.runtime.onMessage.addListener(function (msg) {
  try {
    if (!msg || msg.type !== 'sf-hagezi-updated') return;
    const r = msg.result || {};
    const statusEl = $('hageziStatus');
    const btn = $('hageziUpdateBtn');
    if (btn) { btn.disabled = false; btn.textContent = '立即更新'; }
    if (!statusEl) return;
    const fmt = function (ts) {
      const d = new Date(ts);
      return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0') + ' ' + String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0');
    };
    if (r.ok) {
      const s = r.source || '';
      const srcNote = s ? ('，源：' + (s.indexOf('gh-proxy') >= 0 ? 'GitHub 反代' : (s.indexOf('jsdelivr') >= 0 ? 'jsDelivr 镜像' : (s.indexOf('raw.githubusercontent') >= 0 ? 'GitHub raw' : '官方源')))) : '';
      statusEl.textContent = '更新成功：' + fmt(Date.now()) + '（共 ' + (r.count || 0) + ' 条域名' + srcNote + '）';
      statusEl.style.color = '';
    } else if (r.busy) {
      statusEl.textContent = '已有更新任务正在进行，请等它结束（状态行会实时显示下载进度）';
      statusEl.style.color = '';
    } else if (r.skipped) {
      statusEl.textContent = '更新跳过（24 小时内已成功更新，或距上次失败不足 30 分钟）';
      statusEl.style.color = '';
    } else {
      statusEl.textContent = '更新失败（全部源均不可达，已保留本地旧名单）：' + (r.error || '未知错误');
      statusEl.style.color = '#c0392b';
    }
  } catch (e) {}
});

function bindControls(settings) {
  // 防护总览页已移除：不再绑定总开关 UI（底层 enabledGlobal 存储键保持默认开启，不影响防护）
  const egEl = $('enabledGlobal');
  if (egEl) {
    egEl.checked = !!settings.enabledGlobal;
    egEl.addEventListener('change', (e) => updateMasterPill(e.target.checked));
  }
  updateMasterPill(settings.enabledGlobal);

  $('showWarning').checked = !!settings.showWarning;
  $('autoBlockDownloads').checked = !!settings.autoBlockDownloads;
  $('notify').checked = !!settings.notify;
  if ($('icpApiVerify')) $('icpApiVerify').checked = settings.icpApiVerify !== false;

  // 威胁情报 API：主开关默认不勾选；勾选才展开 provider 列表，再勾选具体情报源才出现 Key 输入框
  const tiEnabled = $('tiEnabled');
  if (tiEnabled) {
    const ti = settings.threatIntel || { enabled: false, providers: {} };
    const vt = (ti.providers && ti.providers.virustotal) || { enabled: false, apiKey: '' };
    const tiProviders = $('tiProviders');
    const tiVtEnabled = $('tiVtEnabled');
    const tiVtKey = $('tiVtKey');
    const tiVtKeyWrap = $('tiVtKeyWrap');
    const tiVtKeyHint = $('tiVtKeyHint');
    tiEnabled.checked = !!ti.enabled;
    if (tiProviders) tiProviders.style.display = tiEnabled.checked ? '' : 'none';
    if (tiVtEnabled) tiVtEnabled.checked = !!vt.enabled;
    // VT Key 与 GSB 同为 AES-GCM 密文存储：明文永不落盘、永不回显，已配置时只显示圆点掩码。
    _vtKeySet = false; _vtSavedCipher = ''; _vtFieldDirty = false;
    if (tiVtKey) {
      tiVtKey.value = '';
      tiVtKey.type = 'password';
      tiVtKey.onfocus = null;
      // 无条件绑定：首次填写（原本没有 Key）也必须能把新 Key 送进 collectSettings 加密，
      // 不能只在「已存在密文」时绑定，否则第一次粘贴的 Key 会被静默丢弃。
      tiVtKey.oninput = function () { _vtFieldDirty = true; };
      tiVtKey.placeholder = '粘贴你的 VirusTotal API Key（保存时自动加密）';
    }
    if (tiVtKeyWrap) tiVtKeyWrap.style.display = (tiVtEnabled && tiVtEnabled.checked) ? '' : 'none';
    if (tiVtKeyHint) { tiVtKeyHint.textContent = ''; tiVtKeyHint.style.color = ''; }
    if (vt.apiKey && sfLooksEncrypted(vt.apiKey)) {
      _vtKeySet = true; _vtSavedCipher = vt.apiKey; _vtFieldDirty = false;
      if (tiVtKey) {
        tiVtKey.value = VT_MASK;
        tiVtKey.placeholder = '已加密保存（显示为圆点）。点击可输入新 Key 替换；留空保存则保留原 Key。';
        tiVtKey.onfocus = function () {
          if (tiVtKey.value === VT_MASK) { try { tiVtKey.select(); } catch (_) {} }
        };
      }
      if (tiVtKeyHint) {
        tiVtKeyHint.textContent = '✓ 已配置并加密保存（圆点仅为掩码，不可还原为明文）。如需更换，直接输入新的 Key 再保存；留空保存则保留原 Key。';
        tiVtKeyHint.style.color = '#2e9e6b';
      }
    } else if (vt.apiKey) {
      // 自动迁移失败等极端情况下残留的旧明文：绝不回显，提示重新输入，下次保存即加密落盘
      if (tiVtKey) tiVtKey.value = '';
      if (tiVtKeyHint) {
        tiVtKeyHint.textContent = '检测到旧格式 Key（未加密），请重新输入以重新加密保存。';
        tiVtKeyHint.style.color = '#c0392b';
      }
    }
    tiEnabled.addEventListener('change', function () {
      if (tiProviders) tiProviders.style.display = tiEnabled.checked ? '' : 'none';
    });
    if (tiVtEnabled) tiVtEnabled.addEventListener('change', function () {
      if (tiVtKeyWrap) tiVtKeyWrap.style.display = tiVtEnabled.checked ? '' : 'none';
    });
    const tiUrlhausEnabled = $('tiUrlhausEnabled');
    if (tiUrlhausEnabled) tiUrlhausEnabled.checked = !!(ti.providers && ti.providers.urlhaus && ti.providers.urlhaus.enabled);
    const tiNetapiEnabled = $('tiNetapiEnabled');
    if (tiNetapiEnabled) tiNetapiEnabled.checked = !!(ti.providers && ti.providers.netapi && ti.providers.netapi.enabled);

    // Google Safe Browsing：Key 以密文存储；已配置则在输入框「显示密文」（像 VirusTotal 显示已存 Key 一样），
    // 让用户一眼可见「已保存」，而非留空造成「没存上」的误判；明文 Key 永不回显。
    const gs = (ti.providers && ti.providers.googlesafebrowsing) || { enabled: false, apiKey: '' };
    const tiGsEnabled = $('tiGsEnabled');
    const tiGsKey = $('tiGsKey');
    const tiGsKeyWrap = $('tiGsKeyWrap');
    const tiGsKeyHint = $('tiGsKeyHint');
    _gsKeySet = false; _gsSavedCipher = ''; _gsFieldDirty = false;
    if (tiGsEnabled) tiGsEnabled.checked = !!gs.enabled;
    if (tiGsKey) {
      tiGsKey.value = '';
      tiGsKey.type = 'password';
      tiGsKey.onfocus = null;
      // 与 VT 一致改为无条件绑定：修复首次填写 GSB Key 时因 _gsFieldDirty 恒为 false 而静默丢失的问题
      tiGsKey.oninput = function () { _gsFieldDirty = true; };
      tiGsKey.placeholder = '粘贴你的 Google Safe Browsing API Key（保存时自动加密）';
    }
    if (tiGsKeyWrap) tiGsKeyWrap.style.display = (tiGsEnabled && tiGsEnabled.checked) ? '' : 'none';
    if (tiGsKeyHint) { tiGsKeyHint.textContent = ''; tiGsKeyHint.style.color = ''; }
    if (gs.apiKey && sfLooksEncrypted(gs.apiKey)) {
      // 已加密保存：输入框显示「39 个圆点」掩码（对应 Google API Key 的真实长度），
      // 未配置时输入框为空——一眼可辨「有没有存过 Key」。明文 Key 永不回显。
      // 点击不消失（仅全选），直接打字即替换；留空保存 = 保留原 Key（靠 _gsFieldDirty 判断）。
      _gsKeySet = true; _gsSavedCipher = gs.apiKey; _gsFieldDirty = false;
      if (tiGsKey) {
        tiGsKey.type = 'password';
        tiGsKey.value = GSB_MASK;
        tiGsKey.placeholder = '已加密保存（显示为圆点）。点击可输入新 Key 替换；留空保存则保留原 Key。';
        tiGsKey.onfocus = function () {
          if (tiGsKey.value === GSB_MASK) { try { tiGsKey.select(); } catch (_) {} }
        };
      }
      if (tiGsKeyHint) {
        tiGsKeyHint.textContent = '✓ 已配置并加密保存（圆点仅为掩码，不可还原为明文）。如需更换，直接输入新的 Key 再保存；留空保存则保留原 Key。';
        tiGsKeyHint.style.color = '#2e9e6b';
      }
    } else if (gs.apiKey) {
      // 兼容：若意外存了非密文（理论不会发生），不回显明文，仅提示重新输入以重新加密
      if (tiGsKey) { tiGsKey.type = 'password'; tiGsKey.value = ''; }
      if (tiGsKeyHint) {
        tiGsKeyHint.textContent = '检测到旧格式 Key（未加密），请重新输入以重新加密保存。';
        tiGsKeyHint.style.color = '#c0392b';
      }
    }
    if (tiGsEnabled) tiGsEnabled.addEventListener('change', function () {
      if (tiGsKeyWrap) tiGsKeyWrap.style.display = tiGsEnabled.checked ? '' : 'none';
    });
  }

  // 社区维护的本地黑名单：主开关默认不勾选；勾选后才展开三个名单子项（各自还有独立开关）
  const clEnabled = $('communityListsEnabled');
  if (clEnabled) {
    const clProviders = $('communityProviders');
    clEnabled.checked = !!(settings.communityLists && settings.communityLists.enabled);
    if (clProviders) clProviders.style.display = clEnabled.checked ? '' : 'none';
    clEnabled.addEventListener('change', function () {
      if (clProviders) clProviders.style.display = clEnabled.checked ? '' : 'none';
    });
  }

  // 以下三个名单的初始化不依赖主开关：即使总开关关闭也要回填各自状态（下次开启即生效）
  // OpenPhish 本地钓鱼黑名单：开关 + 立即更新按钮 + 状态显示
  const opEnabled = $('openphishEnabled');
  const opUpdateBtn = $('openphishUpdateBtn');
  const opStatus = $('openphishStatus');
  if (opEnabled) opEnabled.checked = !!(settings.openphish && settings.openphish.enabled);
  // 读取本地名单元信息，显示「上次更新 / 条目数」
  try {
    chrome.storage.local.get({ sfOpenPhishMeta: { updated: 0, count: 0, error: '' } }, function (r) {
      const m = r.sfOpenPhishMeta || {};
      if (opStatus) {
        if (m.updated) {
          const d = new Date(m.updated);
          const ds = d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0') + ' ' + String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0');
          opStatus.textContent = '本地名单已更新：' + ds + '（共 ' + (m.count || 0) + ' 条域名）' + (m.error ? '；上次更新出错：' + m.error : '');
          opStatus.style.color = m.error ? '#c0392b' : '';
        } else {
          opStatus.textContent = '本地名单尚未更新（启用后点击「立即更新」抓取，或等待每日自动更新）';
        }
      }
    });
  } catch (e) {}
  if (opUpdateBtn) opUpdateBtn.addEventListener('click', function () { updateOpenPhish(opStatus); });

  // PhishDestroy 本地钓鱼黑名单：与 OpenPhish 完全同构的「开关 + 立即更新 + 状态」
  const pdEnabled = $('phishdestroyEnabled');
  const pdUpdateBtn = $('phishdestroyUpdateBtn');
  const pdStatus = $('phishdestroyStatus');
  if (pdEnabled) pdEnabled.checked = !!(settings.phishdestroy && settings.phishdestroy.enabled);
  try {
    chrome.storage.local.get({ sfPhishDestroyMeta: { updated: 0, count: 0, error: '' } }, function (r) {
      const m = r.sfPhishDestroyMeta || {};
      if (!pdStatus) return;
      if (m.updated) {
        const d = new Date(m.updated);
        const ds = d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0') + ' ' + String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0');
        pdStatus.textContent = '本地名单已更新：' + ds + '（共 ' + (m.count || 0) + ' 条域名）' + (m.error ? '；上次更新出错：' + m.error : '');
        pdStatus.style.color = m.error ? '#c0392b' : '';
      } else {
        pdStatus.textContent = '本地名单尚未更新（启用后点击「立即更新」抓取，或等待每日自动更新）';
      }
    });
  } catch (e) {}
  if (pdUpdateBtn) pdUpdateBtn.addEventListener('click', function () { updatePhishDestroy(pdStatus); });

  // HaGeZi's TIF：与前两者同构的「开关 + 立即更新 + 状态」
  const hgEnabled = $('hageziEnabled');
  const hgUpdateBtn = $('hageziUpdateBtn');
  const hgStatus = $('hageziStatus');
  if (hgEnabled) hgEnabled.checked = !!(settings.hagezi && settings.hagezi.enabled);
  const hgVariant = $('hageziVariant');
  if (hgVariant) hgVariant.value = (settings.hagezi && settings.hagezi.variant === 'medium') ? 'medium' : 'full';
  try {
    chrome.storage.local.get({ sfHaGeZiTifMeta: { updated: 0, count: 0, error: '' } }, function (r) {
      const m = r.sfHaGeZiTifMeta || {};
      if (!hgStatus) return;
      if (m.updated) {
        const d = new Date(m.updated);
        const ds = d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0') + ' ' + String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0');
        hgStatus.textContent = '本地名单已更新：' + ds + '（共 ' + (m.count || 0) + ' 条域名）' + (m.error ? '；上次更新出错：' + m.error : '');
        hgStatus.style.color = m.error ? '#c0392b' : '';
      } else if (m.error) {
        hgStatus.textContent = '本地名单尚未更新；上次更新失败：' + m.error;
        hgStatus.style.color = '#c0392b';
      } else {
        hgStatus.textContent = '本地名单尚未更新（启用后点击「立即更新」抓取，或等待每日自动更新）';
      }
    });
  } catch (e) {}
  if (hgUpdateBtn) hgUpdateBtn.addEventListener('click', function () { updateHaGeZi(hgStatus); });

  // ===== 灵敏度（low/medium/high）控件已不存在 —— 2026-11-11 注释保留，便于日后恢复 =====
  //   实情：options.html 里已经没有 id="sensitivity" 的控件（防护总览页重构时被删除），
  //   所以 $('sensitivity') 恒为 null，下面整段绑定是死代码：既不执行，也不会把点击写回设置。
  //   引擎侧不受影响：settings.sensitivity 缺省即 'medium'（阈值 35/70、组合升级 3 项中风险），
  //   与本段被注释前后完全一致 —— 注释它只是去掉「永远不成立的分支」，不改变任何判定。
  //   恢复方式：设置页加回 <div id="sensitivity"><button data-v="low|medium|high">…</button></div>，
  //            再取消下面的注释即可。
  /*
  const seg = $('sensitivity');
  if (seg) {
    function updateSegGlider() {
      const active = seg.querySelector('button.active') || seg.querySelector('button');
      const glider = seg.querySelector('.seg-glider');
      if (!active || !glider) return;
      const segRect = seg.getBoundingClientRect();
      const btnRect = active.getBoundingClientRect();
      glider.style.width = btnRect.width + 'px';
      glider.style.transform = `translateX(${btnRect.left - segRect.left}px)`;
    }
    seg.querySelectorAll('button').forEach((b) => {
      b.classList.toggle('active', b.dataset.v === settings.sensitivity);
      b.addEventListener('click', () => {
        seg.querySelectorAll('button').forEach((x) => x.classList.remove('active'));
        b.classList.add('active');
        updateSegGlider();
        if (window.__sfSettings) window.__sfSettings.sensitivity = b.dataset.v;
      });
    });
    requestAnimationFrame(updateSegGlider);
    let segResizeTimer;
    window.addEventListener('resize', () => { clearTimeout(segResizeTimer); segResizeTimer = setTimeout(updateSegGlider, 100); });
  }
  */

  $('allowlist').value = (settings.allowlist || []).join('\n');
  $('customKeywords').value = (settings.customKeywords || []).join('\n');
  $('customBadDomains').value = (settings.customBadDomains || []).join('\n');

  applyAppearance(true);
}

function updateMasterPill(on) {
  const p = $('masterPill');
  if (!p) return;
  p.textContent = on ? '防护中' : '已关闭';
  p.className = 'mini-pill ' + (on ? 'on' : 'off');
}

// 「银狐急救」分类：展示官方直链 + 点击按钮直接下载 360 系统急救箱
/* 下钻导航：枢纽页卡片 → 独立子页面，返回时回到来源枢纽页（规则与名单 + 工具中心 + 个性化主题共用）。
   支持多级嵌套返回（如「工具中心 → 银狐急救」），栈记录每层「从哪进来」。 */
function setupSubNav() {
  const backBtn = $('backBtn');
  const secTitle = $('secTitle');
  const secDesc = $('secDesc');
  // 子页导航栈：每个元素 { hub, title, desc } —— hub 为上一级页面 id
  window.__sfSubStack = [];

  function pushEntry(hubId, title, desc) {
    window.__sfSubStack.push({ hub: hubId, title: title, desc: desc });
  }


  document.querySelectorAll('[data-sub]').forEach((card) => {
    card.addEventListener('click', () => {
      const sub = $(card.dataset.sub);
      if (!sub) return;
      const hubSec = card.closest('.sec');
      // 记录「当前所在页」作为返回目标（返回时回到来源枢纽页）
      pushEntry(hubSec ? hubSec.id : 'rules', secTitle.textContent, secDesc.textContent);
      document.querySelectorAll('.sec').forEach((s) => s.classList.remove('active'));
      sub.classList.add('active');
      const t = card.dataset.subTitle || ((card.querySelector('.rc-t') || {}).textContent || '');
      const d = card.dataset.subDesc || ((card.querySelector('.rc-d') || {}).textContent || '');
      secTitle.textContent = t;
      secDesc.textContent = d;
      if (backBtn) backBtn.hidden = false;
    });
  });

  if (backBtn) {
    backBtn.addEventListener('click', () => {
      window.__sfReturnHub = null;
      const stack = window.__sfSubStack;
      if (!stack || !stack.length) { backBtn.hidden = true; return; }
      const last = stack.pop();
      const hub = last.hub;
      const hubNav = findNavForTarget(hub);
      if (hubNav) {
        // 返回一级导航项：模拟点击统一处理分组高亮，返回即退出子页模式
        hubNav.click();
        backBtn.hidden = true;
        stack.length = 0;   // 已回到一级分类，清空残留栈
      } else {
        // 中间层级：继续留在子页模式，还可再返回
        document.querySelectorAll('.sec').forEach((s) => s.classList.remove('active'));
        const h = $(hub);
        if (h) h.classList.add('active');
        secTitle.textContent = last.title || '';
        secDesc.textContent = last.desc || '';
        backBtn.hidden = stack.length === 0;
      }
    });
  }
}

// 打开一个子页（#sec= 直达时）：找到对应 data-sub 卡片模拟点击，走统一子页激活逻辑
function openSubById(id) {
  const sec = document.getElementById(id);
  const card = document.querySelector('[data-sub="' + id + '"]');
  if (!sec) return false;
  if (card && typeof card.click === 'function') { card.click(); return true; }
  return false;
}

function sfRescueDirect(btn, urlEl, url, originalText, safety, filename) {
  if (safety) clearTimeout(safety);
  if (btn) { btn.disabled = false; btn.textContent = originalText; }
  if (urlEl) urlEl.textContent = url;
  // 默认用 URL 末段当文件名；带查询串的直链（AdwCleaner 的 ?channel=release）
  // 由配置显式给出 filename，避免把 "adwcleaner?channel=release" 当成文件名。
  const fname = filename || (url.split('/').pop() || 'rescue.bin').split('?')[0];
  if (typeof chrome !== 'undefined' && chrome.downloads && chrome.downloads.download) {
    chrome.downloads.download({ url: url, filename: fname, conflictAction: 'uniquify' });
  } else {
    window.open(url, '_blank', 'noopener');
  }
}

function sfRescueDownload(tool) {
  const cfg = SF_RESCUE_TOOLS[tool];
  if (!cfg) return;
  const btn = $(cfg.btn);
  const urlEl = $(cfg.url);
  if (!btn) return;
  const originalText = btn.textContent;
  // KVRT / AdwCleaner：直链本身就是「最新版」，没有版本探测这一步，直接走下载。
  // 复用同一套 sfRescueDirect（写直链、调 chrome.downloads、无权限时退化为新标签打开）。
  if (cfg.direct) {
    sfRescueDirect(btn, urlEl, cfg.fallback, originalText, null, cfg.filename);
    try {
      const kv = {};
      kv[cfg.store] = cfg.fallback;
      if (chrome.storage && chrome.storage.local) chrome.storage.local.set(kv);
    } catch (e) {}
    showToast('已开始下载：' + (cfg.filename || cfg.fallback.split('/').pop() || 'tool.exe'));
    return;
  }
  const fallbackUrl = cfg.fallback;
  btn.disabled = true;
  btn.textContent = '正在获取最新直链…';
  // 安全兜底：60s 后恢复按钮，避免卡死
  const safety = setTimeout(function () {
    if (btn) { btn.disabled = false; btn.textContent = originalText; }
  }, 60000);
  if (typeof chrome === 'undefined' || !chrome.runtime || !chrome.runtime.sendMessage) {
    // 无后台通道：直接下载备用直链
    sfRescueDirect(btn, urlEl, fallbackUrl, originalText, safety);
    showToast('已开始下载（备用直链）');
    return;
  }
  chrome.runtime.sendMessage({ type: 'SF_FETCH_RESCUE', tool: tool, fallbackUrl: fallbackUrl }, function (res) {
    if (safety) clearTimeout(safety);
    if (btn) { btn.disabled = false; btn.textContent = originalText; }
    res = res || {};
    if (res.ok) {
      if (urlEl) { urlEl.textContent = res.url; urlEl.title = '点击复制'; }
      // 缓存到 storage.local，下次进入页面秒显最新直链
      try {
        const kv = {};
        kv[cfg.store] = res.url;
        chrome.storage.local.set(kv);
      } catch (e) {}
      showToast(res.fallback ? '自动获取失败，已用备用直链开始下载' : ('已开始下载：' + (res.filename || res.url)));
    } else {
      // 后台未触发下载：兜底直接下载备用直链
      sfRescueDirect(btn, urlEl, fallbackUrl, originalText, null);
      showToast('获取失败，已用备用直链开始下载');
    }
  });
}

// 直链卡片：点击复制（360 / 火绒 / KVRT / AdwCleaner 四张卡共用）
function bindRescueCopy(el, fallback) {
  if (!el) return;
  el.textContent = fallback;
  el.title = '点击复制';
  el.addEventListener('click', function () {
    const txt = el.textContent || fallback;
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(txt).then(function () { showToast(); }, function () { showToast(); });
      } else { showToast(); }
    } catch (e) { showToast(); }
  });
}

function bindRescue() {
  // 表驱动绑定：新增一个急救工具只需在 SF_RESCUE_TOOLS 里加一行，再在页面里放好
  // 同 id 的按钮 / 直链元素即可，不必再复制一遍下载与复制逻辑。
  Object.keys(SF_RESCUE_TOOLS).forEach(function (tool) {
    const cfg = SF_RESCUE_TOOLS[tool];
    bindRescueCopy($(cfg.url), cfg.fallback);
    const btn = $(cfg.btn);
    if (btn) btn.addEventListener('click', function () { sfRescueDownload(tool); });
  });

  // 优先显示上次抓取到的直链（秒显），没有再用内置备用直链
  try {
    if (chrome.storage && chrome.storage.local) {
      const keys = Object.keys(SF_RESCUE_TOOLS).map(function (t) { return SF_RESCUE_TOOLS[t].store; });
      chrome.storage.local.get(keys, function (kv) {
        kv = kv || {};
        Object.keys(SF_RESCUE_TOOLS).forEach(function (tool) {
          const cfg = SF_RESCUE_TOOLS[tool];
          const el = $(cfg.url);
          if (el && kv[cfg.store]) { el.textContent = kv[cfg.store]; el.title = '点击复制'; }
        });
      });
    }
  } catch (e) {}
}

async function collectSettings() {
  const enabled = {};
  document.querySelectorAll('input[data-cat]').forEach((cb) => { enabled[cb.dataset.cat] = cb.checked; });
  // 权重：仅保存与默认不同的覆盖值（避免锁死后续默认权重变更）；无覆盖则不留 key
  const defW = {};
  (window.SF_ANALYZER && window.SF_ANALYZER.CATEGORIES || []).forEach((c) => { defW[c.id] = c.weight; });
  const weights = {};
  document.querySelectorAll('input[data-weight]').forEach((inp) => {
    const id = inp.dataset.weight;
    let v = parseInt(inp.value, 10);
    if (isNaN(v)) v = (defW[id] != null) ? defW[id] : 0;
    v = Math.max(0, Math.min(200, v));
    if (defW[id] == null || v !== defW[id]) weights[id] = v;
  });
  // ===== 灵敏度：控件已移除（见上文注释），保存时固定写 'medium' =====
  //   原来这两行是 sensSeg/sensBtn 取值，因为 #sensitivity 不存在，sensBtn 恒为 null，
  //   下面的三元表达式实际也一直落到 'medium' —— 改成字面量后行为完全等价，少一次无意义的 DOM 查询。
  // const sensSeg = $('sensitivity');
  // const sensBtn = sensSeg ? sensSeg.querySelector('button.active') : null;
  const activeFont = (document.querySelector('.font-opt.active') || { dataset: {} }).dataset;
  // Google Safe Browsing：Key 加密后存储；用户未改动则保留原密文，绝不存明文/可识别密文
  // 先剥掉掩码圆点：防止用户把光标点在掩码末尾直接续写，导致「•••+新Key」被整体加密
  const gsRaw = ($('tiGsKey') ? ($('tiGsKey').value || '') : '');
  const gsInput = gsRaw.split(GSB_MASK_CHAR).join('').trim();
  let gsKeyEnc = '';
  _gsEncryptFailed = false;
  if (!_gsFieldDirty) {
    // 用户未改动输入框（仍是掩码）→ 直接保留原密文，不要对掩码二次加密
    gsKeyEnc = _gsSavedCipher || '';
  } else if (gsInput && gsInput !== _gsSavedCipher) {
    const enc = await sfEncryptKey(gsInput);   // 加密失败返回 null → 不回退明文
    if (enc) {
      gsKeyEnc = enc;
    } else if (_gsKeySet) {
      gsKeyEnc = _gsSavedCipher || '';          // 加密异常但曾有密文 → 保留旧密文，绝不回退明文
    } else {
      // 首次填写却加密失败：绝不能存明文，置空并标记，交由 save handler 提示用户重试
      gsKeyEnc = '';
      _gsEncryptFailed = true;
    }
  } else {
    // 用户清空或内容与原密文相同（未实质改动）→ 保留原密文，避免误清空
    gsKeyEnc = _gsSavedCipher || '';
  }
  // 保存后立即呈现「39 点掩码」态（有 Key）/ 空白（无 Key），与刷新后重新加载的显示完全一致
  try {
    const tiGsKeyEl = $('tiGsKey');
    if (tiGsKeyEl) { tiGsKeyEl.type = 'password'; tiGsKeyEl.value = gsKeyEnc ? GSB_MASK : ''; }
    _gsSavedCipher = gsKeyEnc; _gsFieldDirty = false;
    const tiGsKeyHintEl = $('tiGsKeyHint');
    if (tiGsKeyHintEl && gsKeyEnc) { tiGsKeyHintEl.textContent = '✓ 已配置并加密保存（圆点仅为掩码，不可还原为明文）。如需更换，直接输入新的 Key 再保存；留空保存则保留原 Key。'; tiGsKeyHintEl.style.color = '#2e9e6b'; }
  } catch (e) {}
  // VirusTotal：与 GSB 完全同机制，Key 加密后才写进 settings，明文绝不落盘
  const vtRaw = ($('tiVtKey') ? ($('tiVtKey').value || '') : '');
  const vtInput = vtRaw.split(GSB_MASK_CHAR).join('').trim();   // 剥掉掩码圆点，避免「圆点+新Key」被整体加密
  let vtKeyEnc = '';
  _vtEncryptFailed = false;
  if (!_vtFieldDirty) {
    vtKeyEnc = _vtSavedCipher || '';
  } else if (vtInput && vtInput !== _vtSavedCipher) {
    const enc = await sfEncryptKey(vtInput);
    if (enc) {
      vtKeyEnc = enc;
    } else if (_vtKeySet) {
      vtKeyEnc = _vtSavedCipher || '';        // 加密异常但已有密文 → 保留旧值，不回退明文
    } else {
      vtKeyEnc = ''; _vtEncryptFailed = true; // 首次填写却加密失败 → 绝不写明文
    }
  } else {
    vtKeyEnc = _vtSavedCipher || '';
  }
  try {
    const tiVtKeyEl = $('tiVtKey');
    if (tiVtKeyEl) { tiVtKeyEl.type = 'password'; tiVtKeyEl.value = vtKeyEnc ? VT_MASK : ''; }
    _vtSavedCipher = vtKeyEnc; _vtFieldDirty = false;
    const tiVtKeyHintEl = $('tiVtKeyHint');
    if (tiVtKeyHintEl && vtKeyEnc) {
      tiVtKeyHintEl.textContent = '✓ 已配置并加密保存（圆点仅为掩码，不可还原为明文）。如需更换，直接输入新的 Key 再保存；留空保存则保留原 Key。';
      tiVtKeyHintEl.style.color = '#2e9e6b';
    }
  } catch (e) {}
  return {
    enabledGlobal: (window.__sfSettings ? !!window.__sfSettings.enabledGlobal : true),
    showWarning: $('showWarning').checked,
    autoBlockDownloads: $('autoBlockDownloads').checked,
    notify: $('notify').checked,
    icpApiVerify: ($('icpApiVerify') ? $('icpApiVerify').checked : true),
    // 灵敏度：设置页已无对应控件，固定 medium（引擎阈值 35/70、组合升级 3 项中风险）。
    // 若日后恢复控件，把下行改回 `sensBtn ? sensBtn.dataset.v : 'medium'` 即可。
    sensitivity: 'medium',
    fontMode: (activeFont && activeFont.font) || 'system',
    theme: ($('themeLight') && $('themeLight').checked) ? 'light' : 'dark',
    themePalette: ((document.querySelector('.theme-opt.active') || { dataset: {} }).dataset.palette) || 'classic',
    material: ((document.querySelector('#materialSeg button.active') || { dataset: {} }).dataset.material) || 'frosted',
    sidebar: ((window.__sfSettings && window.__sfSettings.sidebar) || 'attached'),
    control: ((window.__sfSettings && window.__sfSettings.control) || 'normal'),
    bgType: ((window.__sfSettings && window.__sfSettings.bgType) || 'gradient'),
    // customThemes 已单独存 chrome.storage.local（见 save 处理），此处不再写入 sync 以免超 8KB 配额静默失败
    customTheme: null, // 旧单主题字段已废弃，显式清空
    fontScale: ($('fontScale') ? parseFloat($('fontScale').value) / 100 : 1),
    reduceMotion: ($('reduceMotion') ? $('reduceMotion').checked : false),
    layout: ((window.__sfSettings && window.__sfSettings.layout) || 'new'),   // 双布局：new(新版默认)/old(旧版)
    // 威胁情报 API：仅当主开关或任一 provider 启用时才写入真实配置；默认全关
    threatIntel: {
      enabled: ($('tiEnabled') ? $('tiEnabled').checked : false),
      providers: {
        virustotal: {
          enabled: ($('tiVtEnabled') ? $('tiVtEnabled').checked : false),
          apiKey: vtKeyEnc   // 密文（AES-GCM）；明文仅在后台 service worker 内解密
        },
        urlhaus: {
          enabled: ($('tiUrlhausEnabled') ? $('tiUrlhausEnabled').checked : false)
        },
        netapi: {
          enabled: ($('tiNetapiEnabled') ? $('tiNetapiEnabled').checked : false)
        },
        googlesafebrowsing: {
          enabled: ($('tiGsEnabled') ? $('tiGsEnabled').checked : false),
          apiKey: gsKeyEnc   // 密文（AES-GCM）；明文仅在后台 service worker 内解密
        }
      }
    },
    // 社区维护的本地黑名单总开关（默认关；关闭时后台不加载/不更新/不比对）
    communityLists: {
      enabled: ($('communityListsEnabled') ? $('communityListsEnabled').checked : false)
    },
    openphish: {
      enabled: ($('openphishEnabled') ? $('openphishEnabled').checked : false)
    },
    phishdestroy: {
      enabled: ($('phishdestroyEnabled') ? $('phishdestroyEnabled').checked : false)
    },
    hagezi: {
      enabled: ($('hageziEnabled') ? $('hageziEnabled').checked : false),
      variant: ($('hageziVariant') && $('hageziVariant').value === 'medium') ? 'medium' : 'full'
    },
    enabled,
    weights,
    allowlist: splitLines($('allowlist').value),
    customKeywords: splitLines($('customKeywords').value),
    customBadDomains: splitLines($('customBadDomains').value)
  };
}

function splitLines(s) {
  return String(s || '').split('\n').map((x) => x.trim()).filter(Boolean);
}

function showToast() {
  const t = $('toast');
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 1600);
}

function formatAbsTime(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  const p = (n) => String(n).padStart(2, '0');
  return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' +
         p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
}
// ★ 2026-11-08：最近拦截记录展示条数。background.js 的 updateStats 以
//   `stats.recent = recent.slice(0, 30)` 封顶，这里保持一致取 30——若只取 12，
//   等于把后台已经存下的记录白白藏掉一半；若要再多，需同时抬高后台的容量上限。
const RECENT_SHOW_LIMIT = 30;
const LEVEL_LABEL = { danger: '高危', warn: '可疑', safe: '放行' };
const LEVEL_COLOR = { danger: '#ff4d6d', warn: '#ffae42', safe: '#4be38b' };
function loadStats() {
  if (!hasStorage()) { if ($('stWarn')) $('stWarn').textContent = 0; if ($('stBlock')) $('stBlock').textContent = 0; return; }
  chrome.storage.local.get({ stats: { warnings: 0, blocks: 0, recent: [], suspicious: [] } }, (r) => {
    const st = r.stats || { warnings: 0, blocks: 0, recent: [] };
    if ($('stWarn')) $('stWarn').textContent = st.warnings || 0;
    if ($('stBlock')) $('stBlock').textContent = st.blocks || 0;
    const recent = Array.isArray(st.recent) ? st.recent : [];
    const counts = {};
    recent.forEach((x) => { const k = x.level || 'safe'; counts[k] = (counts[k] || 0) + 1; });
    const total = recent.length;
    const bar = $('dlBar');
    if (bar) {
      if (!total) bar.innerHTML = '<span class="dl-empty">暂无记录</span>';
      else {
        bar.innerHTML = '';
        // 固定顺序：高危(红) 在前(左)、可疑(黄) 在后(右)，保证统计图始终「左红右黄」
        const LEVEL_ORDER = ['danger', 'warn', 'safe', 'official', 'unknown'];
        const barKeys = LEVEL_ORDER.filter((k) => counts[k]).concat(Object.keys(counts).filter((k) => LEVEL_ORDER.indexOf(k) < 0));
        barKeys.forEach((k) => {
          const seg = document.createElement('span');
          seg.className = 'dl-seg';
          seg.style.width = (counts[k] / total * 100) + '%';
          seg.style.background = LEVEL_COLOR[k] || '#888';
          seg.title = (LEVEL_LABEL[k] || k) + '：' + counts[k];
          bar.appendChild(seg);
        });
      }
    }
    const legend = $('dlLegend');
    if (legend) {
      const items = Object.keys(LEVEL_LABEL).filter((k) => counts[k]).map((k) =>
        '<span class="dl-lg"><i style="background:' + (LEVEL_COLOR[k] || '#888') + '"></i>' + LEVEL_LABEL[k] + ' ' + (counts[k] || 0) + '</span>'
      );
      legend.innerHTML = items.join('') || '<span class="dl-empty">暂无记录</span>';
    }
    const rl = $('dlRecent');
    if (rl) {
      if (!total) { rl.innerHTML = '<div class="dl-empty">暂无记录</div>'; }
      else {
        rl.innerHTML = '';
        recent.slice(0, RECENT_SHOW_LIMIT).forEach((x) => {
          const lv = x.level || 'safe';
          const item = document.createElement('div');
          item.className = 'dl-item';
          const dot = document.createElement('span'); dot.className = 'dl-dot'; dot.style.background = LEVEL_COLOR[lv] || '#888';
          // ★ 2026-10-15：旧版本写下的记录里 hostname 为空（字段取错位置，见 background.js
          //   updateStats 的说明）⇒ 如实显示「未记录域名」，而不是一个看着像数据的占位词。
          const host = document.createElement('span'); host.className = 'dl-host'; host.textContent = x.hostname || '未记录域名';
          const lev = document.createElement('span'); lev.className = 'dl-lev'; lev.textContent = LEVEL_LABEL[lv] || lv;
          const time = document.createElement('span'); time.className = 'dl-time'; time.textContent = formatAbsTime(x.time);
          item.append(dot, host, lev, time);
          rl.appendChild(item);
        });
      }
    }
  });
}

// 白名单 / 规则 导入导出（JSON）
function bindRulesIO() {
  const expBtn = $('rulesExport');
  const impBtn = $('rulesImport');
  const impFile = $('rulesImportFile');
  if (expBtn) expBtn.addEventListener('click', () => {
    if (!hasStorage()) return;
    chrome.storage.sync.get({ allowlist: [], customKeywords: [], customBadDomains: [] }, (s) => {
      const payload = { app: 'silverfox-guard', type: 'rules', version: '1.5.3', exportedAt: Date.now(),
        allowlist: s.allowlist || [], customKeywords: s.customKeywords || [], customBadDomains: s.customBadDomains || [] };
      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = 'silverfox-rules-' + new Date().toISOString().slice(0, 10) + '.json';
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
  });
  if (impBtn && impFile) {
    impBtn.addEventListener('click', () => impFile.click());
    impFile.addEventListener('change', () => {
      const file = impFile.files && impFile.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = () => {
        try {
          const data = JSON.parse(reader.result);
          const patch = {};
          if (Array.isArray(data.allowlist)) patch.allowlist = data.allowlist;
          if (Array.isArray(data.customKeywords)) patch.customKeywords = data.customKeywords;
          if (Array.isArray(data.customBadDomains)) patch.customBadDomains = data.customBadDomains;
          if (!Object.keys(patch).length) { alert('文件中没有可导入的白名单 / 规则数据。'); return; }
          if (!confirm('导入将覆盖当前「自定义信任域名白名单 / 自定义风险关键词 / 自定义恶意域名黑名单」三项内容，确定继续？')) return;
          if (hasStorage()) chrome.storage.sync.set(patch, () => {
            if (window.__sfSettings) Object.assign(window.__sfSettings, patch);
            // 同步回填到对应文本框（若当前在编辑态）
            if ($('allowlist') && Array.isArray(patch.allowlist)) $('allowlist').value = patch.allowlist.join('\n');
            if ($('customKeywords') && Array.isArray(patch.customKeywords)) $('customKeywords').value = patch.customKeywords.join('\n');
            if ($('customBadDomains') && Array.isArray(patch.customBadDomains)) $('customBadDomains').value = patch.customBadDomains.join('\n');
            showToast();
          });
        } catch (e) {
          alert('文件解析失败，请确认是 SilverFoxBlocker 导出的 JSON 配置。');
        } finally {
          impFile.value = '';
        }
      };
      reader.readAsText(file);
    });
  }
}

/* ===== 自动学习的下载黑名单：展示 / 逐条删除 / 一键清空 =====
   条目由后台在真正取消一次可疑下载时自动写入（键为载荷域名的注册域名）。
   这里给用户完整的可见性与撤销能力——万一某个正规下载源被误记，删掉即可立刻恢复下载。 */
function sendBg(msg) {
  return new Promise((resolve) => {
    if (typeof chrome === 'undefined' || !chrome.runtime || !chrome.runtime.sendMessage) return resolve(null);
    try { chrome.runtime.sendMessage(msg, (r) => resolve(r || null)); } catch (e) { resolve(null); }
  });
}
function fmtDay(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
}
async function loadDlBlacklist() {
  const box = $('dlBlList');
  if (!box) return;
  const r = await sendBg({ type: 'sf-dl-bl-list' });
  const items = (r && r.items) || [];
  if ($('dlBlCount')) $('dlBlCount').textContent = '共 ' + items.length + ' 条';
  box.textContent = '';
  if (!items.length) {
    const e = document.createElement('div');
    e.className = 'dlbl-empty';
    e.textContent = '暂无记录';
    box.appendChild(e);
    return;
  }
  items.forEach((it) => {
    const row = document.createElement('div');
    row.className = 'dlbl-item';
    const d = document.createElement('div');
    d.className = 'd';
    const dn = document.createElement('div');
    dn.className = 'dn';
    dn.textContent = it.domain;
    const dm = document.createElement('div');
    dm.className = 'dm';
    const bits = [];
    bits.push('拦截 ' + (it.hits || 1) + ' 次');
    if (it.last) bits.push('最近 ' + fmtDay(it.last));
    if (it.from) bits.push('来源页 ' + it.from);
    if (it.sample) bits.push('文件 ' + it.sample);
    dm.textContent = bits.join(' · ');
    d.appendChild(dn); d.appendChild(dm);
    const x = document.createElement('button');
    x.className = 'dx';
    x.type = 'button';
    x.textContent = '移除';
    x.addEventListener('click', async () => {
      await sendBg({ type: 'sf-dl-bl-remove', domain: it.domain });
      loadDlBlacklist();
      showToast();
    });
    row.appendChild(d); row.appendChild(x);
    box.appendChild(row);
  });
}
function bindDlBlacklist() {
  const btn = $('dlBlClear');
  if (!btn) return;
  btn.addEventListener('click', async () => {
    if (!confirm('确定清空自动学习的下载黑名单吗？清空后这些域名将不再被自动拦截，需要重新学习。')) return;
    await sendBg({ type: 'sf-dl-bl-clear' });
    loadDlBlacklist();
    showToast();
  });
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}
async function init() {
  // 首次引导（OOBE）初始化设置向导已移除：直接加载设置页

  // 动态写入版本号（取自 manifest，避免硬编码遗漏导致内部页面版本滞后）
  try {
    const ver = (chrome.runtime && chrome.runtime.getManifest && chrome.runtime.getManifest().version) || '1.3.5';
    const vt = document.getElementById('verTop'); if (vt) vt.textContent = 'v' + ver;
    const va = document.getElementById('verAbout'); if (va) va.textContent = 'v' + ver;
  } catch (e) {}
  const settings = await getSettings();
  // 升级兼容：把旧版明文保存的 VirusTotal Key 就地加密后写回，之后按密文流程渲染
  await migrateVtPlainKey(settings);
  // 自定义背景图单独存 chrome.storage.local（dataURL 大，避免占 sync 配额），
  // 这里读回并合并进 settings.bgImage，使 applyAppearance / showBgThumb 走统一字段，退出重进不再丢失。
  if (hasStorageLocal()) {
    try {
      const bgRes = await new Promise((res) => chrome.storage.local.get({ sfBgImage: '' }, res));
      if (bgRes && bgRes.sfBgImage) settings.bgImage = bgRes.sfBgImage;
    } catch (e) {}
  }
  // —— 自定义主题存储策略 ——
  // 早期版本将自定义主题存 chrome.storage.sync，而主题常含 base64 背景图，易超 sync 单条 8192 字节上限，
  // 导致整条 set 静默失败（错误仅存于 chrome.runtime.lastError），刷新后主题从 storage 读不到而「消失」。
  // 现统一改存 chrome.storage.local（配额约 5MB，足以容纳背景图），init 启动时读回合并，彻底根治该问题。
  // 兼容迁移：sync 里残留的旧单主题 customTheme / 旧数组 customThemes 归一化后并入 local。
  if (hasStorageLocal()) {
    const ctRes = await new Promise((res) => chrome.storage.local.get({ sfCustomThemes: [] }, res));
    let merged = (ctRes && Array.isArray(ctRes.sfCustomThemes)) ? ctRes.sfCustomThemes.slice() : [];
    if (settings.customTheme && !Array.isArray(settings.customThemes)) {
      merged.push({ id: 'mig_' + Date.now().toString(36), name: settings.customTheme.name || '自定义主题', theme: settings.customTheme.theme });
      settings.customTheme = null;
    }
    if (Array.isArray(settings.customThemes)) {
      merged = merged.concat(settings.customThemes.filter(function (x) {
        return !merged.some(function (y) { return String(y.id) === String(x.id); });
      }));
    }
    if (merged.length) {
      settings.customThemes = merged;
      chrome.storage.local.set({ sfCustomThemes: merged });
    }
    if (settings.themePalette === 'custom' && merged.length) {
      settings.themePalette = 'custom:' + merged[0].id;
    }
  }
  if (settings.customTheme) settings.customTheme = null; // 旧单主题字段废弃
  if (hasStorage()) chrome.storage.sync.set({ customTheme: null });
  window.__sfSettings = settings;   // 缓存供 applyAppearance / 材质 / 背景读取
  if (settings.pixelUnlocked) document.documentElement.classList.add('pixel-unlocked');
  renderCategories(settings);
  bindControls(settings);
  loadStats();
  bindLayoutSwitch();   // 先渲染导航（默认新版），再绑定点击
  setupNav();
  setupSubNav();

  // AI 浮球 / 其他页面通过 #sec=<id> 锚点打开对应子页面（如 #sec=rescue）
  (function jumpFromHash() {
    try {
      const h = (location.hash || '').replace(/^#/, '');
      if (!h) return;
      const m = h.match(/sec=([^&]+)/);
      if (!m) return;
      const id = decodeURIComponent(m[1]);
      // 等 DOM / 导航就绪后再跳转，确保 section 元素与 nav 已绑定
      const doJump = function () {
        const sec = document.getElementById(id);
        const navItem = findNavForTarget(id);
        if (sec && navItem && typeof navItem.click === 'function') {
          navItem.click();
        } else if (openSubById(id)) {
          // 新版布局下 rescue 等子页无独立导航项，走卡片激活（含返回栈）
        } else if (sec) {
          // 兜底直接切（含 data-sub 子页面返回态）
          const card = document.querySelector('[data-sub="' + id + '"]');
          document.querySelectorAll('.sec').forEach((s) => { s.classList.remove('active'); s.classList.remove('sec-in'); });
          sec.classList.add('active'); void sec.offsetWidth; sec.classList.add('sec-in');
          if (navItem) navItem.classList.add('active');
          const bb = document.getElementById('backBtn'); if (bb) bb.hidden = !card;
        }
      };
      if (document.readyState === 'complete') setTimeout(doJump, 60);
      else window.addEventListener('load', function () { setTimeout(doJump, 60); });
    } catch (e) {}
  })();

  bindRescue();

  // 关于 / 版本更新：蓝奏云镜像入口。
  // 跳转完全复用 GitHub 按钮的原生 <a target="_blank" rel="noreferrer">，这里不拦截、不改写导航，
  // 只额外把提取码复制到剪贴板，方便用户在蓝奏云页面直接粘贴。
  // 复制失败时静默保持原提示（提取码仍可见，可手动输入），绝不假装已复制。
  (function bindLanzouUpdate() {
    const el = $('lanzouUpdate'), tip = $('lanzouPwdTip');
    if (!el) return;
    el.addEventListener('click', function () {
      try {
        if (!navigator.clipboard || !navigator.clipboard.writeText) return;
        navigator.clipboard.writeText('2hxh').then(function () {
          if (!tip) return;
          tip.textContent = '提取码 2hxh 已复制，请在蓝奏云页面粘贴';
          setTimeout(function () { tip.textContent = '提取码：2hxh'; }, 2200);
        }, function () {});
      } catch (e) {}
    });
  })();

  bindDlBlacklist();
  bindRulesIO();
  loadDlBlacklist();

  setupPixelEgg();
  setupUpdateToast();

  // 关于页：反馈与建议 —— 两个通道：GitHub Issues 预填新建页，或经自建 Worker 代发邮件到作者邮箱。
  // 邮件通道只在用户点击时发出（正文 + 选填联系方式）；失败绝不假装成功，短文本有最小长度校验。
  (function bindFeedback() {
    var btn = $('fbSend'), mailBtn = $('fbMail'), spin = $('fbSpin'), msg = $('fbMsg');

    // 分段控件：与项目其它 .seg 完全同款（glider 定位 + .active 切换），不用原生 select。
    // ★ 「关于」是子页面，初始很可能是 display:none ⇒ 量出来的宽度是 0；除了 rAF + resize，
    //   再用 IntersectionObserver 在卡片**真正可见时**补一次定位（否则滑块的宽度会一直是 0）。
    var seg = $('fbSeg');
    function layoutFbGlider() {
      if (!seg) return;
      var glider = seg.querySelector('.seg-glider');
      var act = seg.querySelector('button.active');
      if (!glider || !act) return;
      var sg = seg.getBoundingClientRect(), ar = act.getBoundingClientRect();
      if (!ar.width) return;                       // 还不可见：留到下次
      glider.style.width = ar.width + 'px';
      glider.style.transform = 'translateX(' + (ar.left - sg.left) + 'px)';
    }
    if (seg) {
      seg.addEventListener('click', function (e) {
        var b = e.target.closest('button');
        if (!b || b.classList.contains('active')) return;
        seg.querySelectorAll('button').forEach(function (x) { x.classList.remove('active'); });
        b.classList.add('active');
        layoutFbGlider();
      });
      requestAnimationFrame(layoutFbGlider);
      window.addEventListener('resize', function () { setTimeout(layoutFbGlider, 100); });
      if (window.IntersectionObserver) {
        try {
          new IntersectionObserver(function (es) {
            es.forEach(function (en) { if (en.isIntersecting) layoutFbGlider(); });
          }).observe(seg);
        } catch (e) {}
      }
    }
    function fbType() {
      var act = seg && seg.querySelector('button.active');
      return (act && act.dataset.v) || '其他';
    }

    function show(text, kind) {
      if (!msg) return;
      msg.hidden = !text;
      msg.textContent = text || '';
      msg.style.color = kind === 'ok' ? '#4be38b' : (kind === 'warn' ? '#ffae42' : '');
    }
    function prepare(cb) {
      var ta = $('fbText');
      var text = ((ta && ta.value) || '').trim();
      if (text.length < 5) { show('请用清晰的语言描述你遇到的问题，不少于5个字符。', 'warn'); if (ta) ta.focus(); cb(null); return; }
      if (text.length > 2000) { show('内容已超过 2000 字上限，请精简后再发送。', 'warn'); if (ta) ta.focus(); cb(null); return; }
      cb({ type: fbType(), message: text.slice(0, 2000) });
    }

    // 实时字数计数（上限 2000，与 Worker 端校验一致）
    var fbTextEl = $('fbText'), fbCountEl = $('fbCount');
    function updateFbCount() {
      if (!fbTextEl || !fbCountEl) return;
      var n = (fbTextEl.value || '').length;
      fbCountEl.textContent = n + ' / 2000';
      fbCountEl.classList.toggle('over', n >= 2000);
    }
    if (fbTextEl) { fbTextEl.addEventListener('input', updateFbCount); updateFbCount(); }

    var mailBusy = false; // 防重复发送：在「感谢您的反馈！」显示前/后都不允许重复点击
    var mailRestoreTimer = null; // 成功后 5 秒自动恢复计时器
    function runFeedback(viaMail) {
      var activeBtn = viaMail ? mailBtn : btn;
      if (viaMail) {
        // 已处于发送中（按钮禁用或忙碌标记）→ 直接忽略，避免重复发送
        if (mailBusy || (mailBtn && mailBtn.disabled)) return;
      }
      if (activeBtn) activeBtn.disabled = true;
      if (spin) spin.hidden = false;
      show('');
      prepare(function (p) {
        if (!p) { if (activeBtn) activeBtn.disabled = false; if (spin) spin.hidden = true; return; }
        var title = '[反馈] ' + p.type + '：' + p.message.slice(0, 40);
        var body = '问题类型：' + p.type + '\n\n' + p.message + '\n\n（以上反馈来自扩展内置「反馈与建议」）';
        if (viaMail) {
          // 直接发信：扩展把反馈 POST 到你的 Worker，由 Worker 代发邮件。
          // 不经过本地邮件客户端；域名也不在扩展源码以明文出现（见 feedback-config.js）。
          var cfg = window.SFB_FEEDBACK;
          var endpoint = (cfg && cfg.decode) ? cfg.decode(cfg.endpointCodes) : '';
          if (!cfg || !cfg.enabled || !endpoint) {
            show('邮件反馈尚未配置，暂时无法发送。', 'warn');
            if (mailBtn) mailBtn.disabled = false; if (spin) spin.hidden = true;
            return;
          }
          mailBusy = true; // 锁定，直到收到响应（含 5 秒自动恢复窗口）
          // 与 Worker 契约一致：{ message, contact }；类型信息并入正文，正文截断到 2000 字
          var payload = ('问题类型：' + p.type + '\n\n' + p.message).slice(0, 2000);
          var contactEl = $('fbContact');
          var contact = (contactEl && contactEl.value || '').trim();
          fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message: payload, contact: contact })
          })
            .then(function (res) {
              if (!res.ok) throw new Error('HTTP ' + res.status);
              show('感谢您的反馈！', 'ok');
              if ($('fbText')) { $('fbText').value = ''; updateFbCount(); }
              if ($('fbContact')) $('fbContact').value = '';
              // 成功后等待 5 秒自动恢复：先保持禁用，避免重复发送；5 秒后解禁
              if (mailBtn) mailBtn.disabled = true;
              if (spin) spin.hidden = true;
              if (mailRestoreTimer) clearTimeout(mailRestoreTimer);
              mailRestoreTimer = setTimeout(function () {
                if (mailBtn) mailBtn.disabled = false;
                mailBusy = false;
              }, 5000);
            })
            .catch(function () {
              show('发送失败，请稍后重试。', 'warn');
              if (mailRestoreTimer) clearTimeout(mailRestoreTimer);
              if (mailBtn) mailBtn.disabled = false; // 失败可重试
              mailBusy = false;
              if (spin) spin.hidden = true;
            });
        } else {
          // GitHub Issue：打开项目 Issues 新建页并预填内容
          var target = 'https://github.com/bbjj12345/SilverFoxBlocker/issues/new?title=' + encodeURIComponent(title) + '&body=' + encodeURIComponent(body);
          var opened = false, a;
          try {
            a = document.createElement('a'); a.href = target; a.target = '_blank'; a.rel = 'noreferrer'; a.style.display = 'none';
            document.body.appendChild(a); a.click(); document.body.removeChild(a); opened = true;
          } catch (e) {}
          if (!opened) { try { window.open(target, '_blank'); opened = true; } catch (e) {} }
          if (opened) show('感谢您的反馈！', 'ok');
          else show('未能打开 GitHub，请手动访问 https://github.com/bbjj12345/SilverFoxBlocker/issues 提交。', 'warn');
          if (activeBtn) activeBtn.disabled = false; if (spin) spin.hidden = true;
        }
      });
    }

    if (btn) btn.addEventListener('click', function () { runFeedback(false); });
    if (mailBtn) mailBtn.addEventListener('click', function () { runFeedback(true); });
  })();

  renderSponsors();

  $('saveBtn').addEventListener('click', async () => {
    try {
      const patch = await collectSettings();
      // 保存成功后同步回写缓存，保证 window.__sfSettings 与已落盘的 sync 一致，
      // 避免后续 applyAppearance / collectSettings 回退分支读到陈旧值。
      if (window.__sfSettings) Object.assign(window.__sfSettings, patch);
      // 诊断日志：确认两个需 Key 的源都写入了密文（用户在 DevTools 控制台可据此判断 Key 是否真的存上了）
      const gsProv = (patch.threatIntel && patch.threatIntel.providers && patch.threatIntel.providers.googlesafebrowsing) || {};
      const vtProv = (patch.threatIntel && patch.threatIntel.providers && patch.threatIntel.providers.virustotal) || {};
      console.log('[SilverFoxBlocker][设置] 保存威胁情报：'
        + 'VT 子开关=' + !!vtProv.enabled
        + '，VT 密文=' + (vtProv.apiKey ? '已加密(' + vtProv.apiKey.length + ')' : '空')
        + '，GSB 子开关=' + !!gsProv.enabled
        + '，GSB 密文长度=' + ((gsProv.apiKey || '').length)
        + (_gsEncryptFailed ? '，⚠ 本次 GSB Key 加密失败，未写入明文（已留空）' : '')
        + (_vtEncryptFailed ? '，⚠ 本次 VT Key 加密失败，未写入明文（已留空）' : ''));
      // 自定义主题可能含大体积背景图，单独存 chrome.storage.local，避免 sync 8KB 配额静默失败
      if (hasStorageLocal()) chrome.storage.local.set({ sfCustomThemes: (window.__sfSettings && Array.isArray(window.__sfSettings.customThemes)) ? window.__sfSettings.customThemes : [] });
      if (_gsEncryptFailed || _vtEncryptFailed) {
        const names = [
          _vtEncryptFailed ? 'VirusTotal' : '',
          _gsEncryptFailed ? 'Google Safe Browsing' : ''
        ].filter(Boolean).join('、');
        alert(names + ' 的 API Key 本次加密失败，未保存。请重试；如反复失败请检查浏览器是否支持 Web Crypto（chrome-extension:// 页面默认可用）。');
        return;
      }
      if (hasStorage()) {
        chrome.storage.sync.set(patch, () => {
          if (chrome.runtime.lastError) {
            console.error('[SilverFoxBlocker][设置] sync.set 失败：', chrome.runtime.lastError);
            alert('设置保存失败：' + (chrome.runtime.lastError && chrome.runtime.lastError.message || '未知错误') + '（常见于 sync 配额超限）');
          } else {
            showToast(); loadStats();
          }
        });
      } else {
        showToast();
      }
    } catch (e) {
      // collectSettings 抛错（如 sfEncryptKey 未定义）时，明确提示而非静默失败
      console.error('[SilverFoxBlocker][设置] 保存异常：', e);
      alert('保存设置时发生异常：' + (e && e.message || e) + '。设置未保存，请刷新设置页后重试。');
    }
  });

  $('resetBtn').addEventListener('click', () => {
    if (!confirm('确定要清空拦截统计吗？白名单与规则设置不会改动。')) return;
    if (hasStorage()) {
      chrome.storage.local.set({ stats: { warnings: 0, blocks: 0, recent: [], suspicious: [] } }, () => { loadStats(); showToast(); });
    } else {
      showToast();
    }
  });
}

init();

// 「如何获取 API？」折叠教程：事件委托，后续新增教程块无需再绑定
document.addEventListener('click', function (e) {
  const t = e.target;
  const btn = (t && t.closest) ? t.closest('.ti-guide-btn') : null;
  if (!btn) return;
  const wrap = btn.closest('.ti-guide');
  if (!wrap) return;
  const open = wrap.classList.toggle('open');
  btn.setAttribute('aria-expanded', open ? 'true' : 'false');
  btn.textContent = open ? '收起教程' : '如何获取 API？';
});

/* ============================================================================
 * GitHub 访问通道：直连 → 公共镜像
 * ----------------------------------------------------------------------------
 * 现象：大陆网络访问 github.com 经常 DNS 被污染、TLS 被重置，「前往 GitHub 查看更新」
 *   点下去就是长时间白屏，用户既看不到更新说明，也不知道还能换什么办法。
 * 做法：点按钮时先探测直连（HEAD + no-cors，1.5s 预算，不下载正文）；连不上就把刚
 *   打开的那个标签页重定向到能完整渲染网页的公共镜像（kkgithub / bgithub）；
 *   镜像也不通时退到最后一步——用文件反代读 releases/latest 的 JSON，只回答
 *   「最新版是哪个、有没有新版」，不再指望能打开网页。
 *
 * 按钮落点：/releases/latest（而不是仓库首页）。GitHub 会 301 到 /releases/tag/vX.Y.Z，
 *   用户点一次就落在更新说明上，少一次「进仓库 → 找 Release」的点击；镜像也带同一路径。
 *
 * 为什么「看网页」用全站镜像而不是 gh-proxy.com 这类「文件反代」：
 *   反代只转发 raw / releases / archive 这些文件请求，访问仓库网页时返回的是代理
 *   自己的首页（已实测），对「查看更新」没有任何意义。反代真正的用处是下面
 *   「云端名单同步」里抓 raw JSON，以及这里兜底读 api.github.com 的发布信息。
 * ========================================================================== */
const SF_GH_REPO_PATH = 'bbjj12345/SilverFoxBlocker';
const SF_GH_DIRECT_BASE = 'https://github.com/';
// 「查看更新」落点：直接指向 Releases 最新版，省掉在仓库页里找 Release 的一步
// （/releases/latest 会由 GitHub 301 到 /releases/tag/vX.Y.Z，镜像跟随同一跳转）
const SF_GH_UPDATE_PATH = '/releases/latest';
// 全站镜像：把 /用户名/仓库 直接拼在域名后面即可浏览（含 Releases / blob / issues）
// ⚠️ 这两家全站镜像存活率很低（kkgithub 已多次长时间 502/停止解析，bgithub 的
//    域名在部分网络被投毒到 Meta 的 IP），因此它们只是「尽力而为」的一层；
//    真正兜底的是走文件反代读 releases/latest 的 JSON（见 readReleaseViaProxy）。
const SF_GH_PAGE_MIRRORS = [
  { id: 'kkgithub', name: 'kkgithub 镜像', base: 'https://kkgithub.com/' },
  { id: 'bgithub', name: 'bgithub 镜像', base: 'https://bgithub.xyz/' }
];
const SF_GH_CHANNEL_KEY = 'sfGhChannel';   // storage.local: { id: 'direct'|'kkgithub'|..., at }

// 轻量可达性探测：TCP+TLS+HTTP 有响应就算通。
// no-cors 只能拿到 opaque 响应（分不清 200 与 404），但这里要回答的是「连得上吗」，
// 而不是「页面存不存在」，够用了；好处是不需要读正文、不占带宽、不受 CORS 影响。
function sfProbeUrl(url, ms) {
  return new Promise(function (resolve) {
    let done = false, ctrl = null;
    const finish = function (ok) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { if (ctrl) ctrl.abort(); } catch (e) {}
      resolve(ok);
    };
    const timer = setTimeout(function () { finish(false); }, ms || 1500);
    try {
      ctrl = new AbortController();
      fetch(url, { method: 'HEAD', mode: 'no-cors', cache: 'no-store', signal: ctrl.signal })
        .then(function () { finish(true); }, function () { finish(false); });
    } catch (e) { finish(false); }
  });
}

function loadGhChannel() {
  return new Promise(function (resolve) {
    // 400ms 兜底：扩展存储异常时不能让「改道」这一步无限等（否则标签页卡在报错页）
    const timer = setTimeout(function () { resolve(''); }, 400);
    const done = function (v) { clearTimeout(timer); resolve(v); };
    try {
      chrome.storage.local.get({ [SF_GH_CHANNEL_KEY]: null }, function (o) {
        done((o && o[SF_GH_CHANNEL_KEY] && o[SF_GH_CHANNEL_KEY].id) || '');
      });
    } catch (e) { done(''); }
  });
}
function saveGhChannel(id) {
  try { chrome.storage.local.set({ [SF_GH_CHANNEL_KEY]: { id: id, at: Date.now() } }, function () {}); } catch (e) {}
}

function setGhNote(text) {
  const el = $('ghChannelTip');
  if (!el) return;
  el.hidden = !text;
  el.textContent = text || '';
  if (text) el.title = '仅在打开 GitHub 网页时使用公共镜像，不涉及浏览记录或名单数据';
}

// 文件反代里支持 api.github.com 的极少（实测 ghproxy.net / geekertao 系返回 403），
// 这里只留确认可用的；列表形式方便以后加新通道。
const SF_GH_API_PROXIES = [
  { name: 'gh-proxy.com 代理', prefix: 'https://gh-proxy.com/' }
];
const SF_GH_RELEASE_API = 'https://api.github.com/repos/' + SF_GH_REPO_PATH + '/releases/latest';

/* ===== Gitee 镜像（第三个发布地）=========================================
 * 为什么有它：GitHub 直连超时、公共反代也挂的时候，国内用户还有一条完全独立的路。
 * 实测（2026-11-10）：
 *   GET https://gitee.com/bbjj12345/SilverFoxBlocker/releases/latest
 *       → 302 /releases/tag/v1.6.2（浏览器 UA 下正常渲染更新说明页）
 *   GET https://gitee.com/api/v5/repos/bbjj12345/SilverFoxBlocker/releases/latest
 *       → 200 JSON，tag_name=/published_at 齐全，且带 Access-Control-Allow-Origin: *
 *   ⚠️ 注意：无 UA 的裸请求访问 /releases/latest 会被 302 到仓库归档 zip，
 *      所以「读页面重定向」这条只在有 host 权限的扩展环境里可靠（浏览器会带 UA）。
 *      API 那条不依赖 UA，是首选。
 * ====================================================================== */
const SF_GITEE_REPO_PATH = 'bbjj12345/SilverFoxBlocker';
const SF_GITEE_BASE = 'https://gitee.com/';
const SF_GITEE_UPDATE_PATH = '/releases/latest';
const SF_GITEE_RELEASE_API = 'https://gitee.com/api/v5/repos/' + SF_GITEE_REPO_PATH + '/releases/latest';

function sfGiteeMirrorUrl() {
  return SF_GITEE_BASE + SF_GITEE_REPO_PATH + SF_GITEE_UPDATE_PATH;
}

// 读 Gitee 的最新发行版：先 API（JSON 最稳、不依赖 UA），再退回页面重定向解析 tag。
// 返回 { tag, at, source } 或 null；不下载任何安装包。
async function readReleaseViaGitee(ms) {
  const budget = ms || 5000;
  const t0 = Date.now();
  // 两段（API → 页面）共享同一份预算：否则一级失败后第二段又拿满 5s，总时长翻倍
  const leftIn = function () { return Math.max(600, budget - (Date.now() - t0)); };
  // 1) Gitee OpenAPI v5
  {
    const ctrl = new AbortController();
    const timer = setTimeout(function () { try { ctrl.abort(); } catch (e) {} }, leftIn());
    try {
      const res = await fetch(SF_GITEE_RELEASE_API + '?_=' + Date.now(), {
        cache: 'no-store', signal: ctrl.signal, headers: { Accept: 'application/json' }
      });
      if (res.ok) {
        const j = await res.json();
        if (j && j.tag_name) {
          return {
            tag: String(j.tag_name).replace(/^v/i, ''),
            at: j.published_at || j.created_at || '',
            source: 'Gitee 镜像'
          };
        }
      }
    } catch (e) {
      // API 不通（限流 403 / 超时）：交给下面的页面重定向
    } finally {
      clearTimeout(timer);
    }
  }
  // 2) 页面重定向：/releases/latest → /releases/tag/vX.Y.Z，读最终 URL 即得 tag
  {
    const ctrl = new AbortController();
    const timer = setTimeout(function () { try { ctrl.abort(); } catch (e) {} }, Math.min(4000, leftIn()));
    try {
      const res = await fetch(sfGiteeMirrorUrl() + '?_=' + Date.now(), {
        redirect: 'follow', cache: 'no-store', signal: ctrl.signal
      });
      // Gitee 的 tag 页 URL 形如 /releases/tag/v1.6.2；个别情况会落到
      // /releases/latest 不跳转，这时从正文里找一次
      let m = /\/releases\/tag\/([^\/?#]+)/.exec(res.url || '');
      if (!m && res.ok) {
        const html = await res.text();
        m = /\/releases\/tag\/([^\/?#"']+)/.exec(html || '');
      }
      if (m) {
        return { tag: decodeURIComponent(m[1]).replace(/^v/i, ''), at: '', source: 'Gitee 镜像' };
      }
    } catch (e) {
      // 两条都不通：由调用方报失败
    } finally {
      clearTimeout(timer);
    }
  }
  return null;
}

// 直连 github.com 打不开时的「退一步」：不打开网页，只问一句「有没有新版」。
// 走反代读 releases/latest 的 JSON（纯文件请求，反代能透传），4s 拿不到就放弃。
// 返回 { tag, at, source } 或 null；不下载任何安装包。
async function readReleaseViaProxy(ms) {
  const budget = ms || 4000;
  for (let i = 0; i < SF_GH_API_PROXIES.length; i++) {
    const p = SF_GH_API_PROXIES[i];
    const ctrl = new AbortController();
    const timer = setTimeout(function () { try { ctrl.abort(); } catch (e) {} }, budget);
    try {
      const res = await fetch(p.prefix + SF_GH_RELEASE_API, {
        cache: 'no-store', signal: ctrl.signal, headers: { Accept: 'application/vnd.github+json' }
      });
      if (!res.ok) continue;
      const j = await res.json();
      if (j && j.tag_name) {
        return { tag: String(j.tag_name).replace(/^v/i, ''), at: j.published_at || '', source: p.name };
      }
    } catch (e) {
      // 单通道失败不影响其它通道，静默换下一个
    } finally {
      clearTimeout(timer);
    }
  }
  return null;
}

// 打开仓库页/子页：直连优先，失败就把当前标签页改到镜像。
// 先 window.open 再判定，是为了「点了立刻有反应」——若先探测，网络差时要等 1.5s+ 才开页，
// 而且 await 之后 window.open 容易被当成非用户手势而拦掉。
async function openGithubSmart(path) {
  const sub = path || SF_GH_UPDATE_PATH;   // 不传路径时默认打开「最新 Release」
  const direct = SF_GH_DIRECT_BASE + SF_GH_REPO_PATH + sub;
  let win = null;
  try { win = window.open(direct, '_blank'); } catch (e) {}
  if (win) { try { win.opener = null; } catch (e) {} }
  // window.open 被弹窗拦截时（返回 null），退到 chrome.tabs.create，保证「点了总有反应」
  let tabId = -1;
  if (!win) {
    try {
      chrome.tabs.create({ url: direct }, function (t) { if (t && t.id != null) tabId = t.id; });
    } catch (e) {}
  }
  // 改道：优先改当前新标签页，其次改 chrome.tabs 建的那个，最后才新开一个
  const goTo = function (u) {
    if (win) { try { win.location.replace(u); return; } catch (e) {} }
    if (tabId >= 0 && chrome.tabs && chrome.tabs.update) {
      try { chrome.tabs.update(tabId, { url: u }); return; } catch (e) {}
    }
    try { window.open(u, '_blank'); } catch (e) {}
  };

  // 兜底路径用：把刚才抢开的那个空白/报错标签页收掉，免得用户面前留一个「无法访问」
  const dropPending = function () {
    if (win) { try { win.close(); return; } catch (e) {} }
    if (tabId >= 0 && chrome.tabs && chrome.tabs.remove) {
      try { chrome.tabs.remove(tabId); } catch (e) {}
    }
  };

  if (await sfProbeUrl(direct, 1500)) {
    saveGhChannel('direct');
    setGhNote('');
    return;
  }
  // 直连不通：优先用上次成功过的镜像，免得每次都在第一个镜像上再等一次超时
  const last = await loadGhChannel();
  const order = SF_GH_PAGE_MIRRORS.slice();
  if (last && last !== 'direct') {
    order.sort(function (a, b) { return (b.id === last ? 1 : 0) - (a.id === last ? 1 : 0); });
  }
  for (let i = 0; i < order.length; i++) {
    const m = order[i];
    const u = m.base + SF_GH_REPO_PATH + sub;
    if (!(await sfProbeUrl(u, 1800))) continue;
    goTo(u);
    saveGhChannel(m.id);
    setGhNote('直连 GitHub 超时，已改用 ' + m.name + '（内容与官网一致）。');
    console.log('[GitHub 通道] 直连失败 → ' + m.name + '：' + u);
    return;
  }
  // 最后兜底：网页确实打不开，但「有没有新版」仍然答得上来 —— 用文件反代读
  //   releases/latest 的 JSON（同样是文件请求，不依赖 github.com 网页能否渲染）。
  //   这样用户至少能看到最新版本号与发布日期，再决定去蓝奏云下载。
  setGhNote('直连与镜像均不可达，正在经代理查询最新版本…');
  dropPending();   // 网页最终打不开：别把用户扔在浏览器的「无法访问」页上
  const rel = await readReleaseViaProxy();
  let cur = '';
  try { cur = (chrome.runtime && chrome.runtime.getManifest) ? chrome.runtime.getManifest().version : ''; } catch (e) {}
  if (rel) {
    const date = rel.at ? '（' + rel.at.slice(0, 10) + '）' : '';
    const tail = !cur ? '。'
      : (rel.tag === cur ? '，与当前 v' + cur + ' 相同，无需更新。'
        : '，当前 v' + cur + '，可点右侧「前往 Gitee 查看更新」或「前往蓝奏云查看更新」下载。');
    setGhNote('GitHub 与镜像均不可达；经' + rel.source + '读到最新版 v' + rel.tag + date + tail);
    console.log('[GitHub 通道] 网页不可达，经 ' + rel.source + ' 读到最新版 v' + rel.tag);
  } else {
    setGhNote('直连与镜像均超时：可稍后重试，或改用「前往 Gitee 查看更新」/「前往蓝奏云查看更新」。');
    console.log('[GitHub 通道] 直连、镜像与反代均不可达：' + direct);
  }
}

(function initGithubSmartLink() {
  function bind() {
    const a = $('manualCheckUpdate');
    if (!a) return;
    a.setAttribute('title', '直连 github.com 不通时会自动改用公共镜像；镜像也不通时，经代理查询最新版本号；仍不行可改用「前往 Gitee 查看更新」');
    a.addEventListener('click', function (ev) {
      // 中键 / Ctrl+点击 / Cmd+点击 交给浏览器原生行为（新标签页打开 href），不做探测
      if (ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.altKey) return;
      ev.preventDefault();
      openGithubSmart('');
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', bind);
  else bind();
})();

/* ============================================================================
 * 「检查更新」按钮（版本行右侧）
 * ----------------------------------------------------------------------------
 * 与「前往 GitHub 查看更新」的区别：那个按钮是「把用户送到网页上自己看」，这个按钮
 * 是「只回答一句话」——所以这里从不打开标签页，只取回 tag_name 做比对。
 *
 * 取版本号的四级通道（前一级失败才走下一级，全程不下载安装包）：
 *   1) 直连 https://github.com/bbjj12345/SilverFoxBlocker/releases/latest
 *      GitHub 会 301 到 /releases/tag/vX.Y.Z，读 fetch 的最终 URL 即得 tag。
 *      扩展页有 <all_urls> host 权限，不受 CORS 限制；先 HEAD 再 GET，省流量。
 *   2) 直连 https://api.github.com/repos/…/releases/latest（JSON 更轻，
 *      网页侧偶发 5xx / 反爬时通常还能拿到）。
 *   3) 复用「前往 GitHub 查看更新」的兜底通道 readReleaseViaProxy()：
 *      gh-proxy.com 反代同一个 API。大陆网络下这一步基本是唯一能通的。
 *   4) Gitee 镜像 readReleaseViaGitee()：Gitee OpenAPI（带 CORS *）→ 页面重定向。
 *      与 GitHub 完全独立的线路，前三级全灭时仍能回答「有没有新版」。
 *
 * 比对语义（按用户要求「逐字节」）：先各去掉前导 v 与空白，两串完全相同就是
 *   同一版本；不同时再按 . - + 分段做数值比较，避免纯字典序把 1.6.10 判成比
 *   1.6.9 旧。线上版本号反而更低时仍提示「无可用更新」（多为本地是测试版）。
 * ========================================================================== */
function sfOwnVersion() {
  try { return String((chrome.runtime.getManifest() || {}).version || '').trim(); } catch (e) { return ''; }
}
function sfNormTag(t) {
  return String(t || '').trim().replace(/^v/i, '');
}
function sfCmpVersion(remote, local) {
  const a = sfNormTag(remote), b = sfNormTag(local);
  if (!a || !b) return 0;
  if (a === b) return 0;                      // 逐字节相同 → 同一版本
  const pa = a.split(/[.\-+]/), pb = b.split(/[.\-+]/);
  const n = Math.max(pa.length, pb.length);
  for (let i = 0; i < n; i++) {
    const x = pa[i] === undefined ? '0' : pa[i];
    const y = pb[i] === undefined ? '0' : pb[i];
    const nx = /^\d+$/.test(x) ? parseInt(x, 10) : NaN;
    const ny = /^\d+$/.test(y) ? parseInt(y, 10) : NaN;
    if (!isNaN(nx) && !isNaN(ny)) {
      if (nx !== ny) return nx > ny ? 1 : -1;
      continue;
    }
    if (x !== y) return x > y ? 1 : -1;
  }
  return 0;
}

// 直连 api.github.com 读 tag（与 readReleaseViaProxy 的解析口径一致，只是不带反代前缀）
async function readReleaseViaDirectApi(ms) {
  const ctrl = new AbortController();
  const timer = setTimeout(function () { try { ctrl.abort(); } catch (e) {} }, ms || 4500);
  try {
    const res = await fetch(SF_GH_RELEASE_API, {
      cache: 'no-store', signal: ctrl.signal, headers: { Accept: 'application/vnd.github+json' }
    });
    if (!res.ok) return '';
    const j = await res.json();
    if (j && j.tag_name) return String(j.tag_name).replace(/^v/i, '');
  } catch (e) {
    // 直连失败交给下一级通道
  } finally {
    clearTimeout(timer);
  }
  return '';
}

// 直连 releases/latest 并解析最终 URL 里的 tag；method 用 HEAD 省流量，失败再退 GET
async function sfFetchTagViaPage(url, ms, method) {
  const ctrl = new AbortController();
  const timer = setTimeout(function () { try { ctrl.abort(); } catch (e) {} }, ms);
  try {
    const res = await fetch(url, {
      method: method || 'HEAD', redirect: 'follow', cache: 'no-store', signal: ctrl.signal
    });
    const m = /\/releases\/tag\/([^\/?#]+)/.exec(res.url || '');
    if (m) return decodeURIComponent(m[1]).replace(/^v/i, '');
  } catch (e) {
    // 超时 / 被重置：调用方换下一级通道
  } finally {
    clearTimeout(timer);
  }
  return '';
}

// 返回 { tag, source } 或 null
// 三级通道，前一级成功就停（全程只读版本号，不下载安装包）：
//   1) 直连 GitHub 网页 releases/latest（读 301 后的 tag）+ 直连 api.github.com
//   2) 公共反代 gh-proxy.com 反代 api.github.com（大陆网络下的常用通道）
//   3) Gitee 镜像：Gitee OpenAPI → Gitee 页面重定向（与 GitHub 完全独立的线路）
//
// ⚠️ 四级串行最坏能拖到 20s+（每级都要等满自己的超时），所以这里有三道闸：
//   · 总预算 SF_CHECK_BUDGET_MS：每级开跑前看剩余时间，不够就直接跳下一级；
//   · 每级超时取 min(本级默认, 剩余预算 - 后面几级的预留)，不会越界，
//     也不会出现「前三级慢超时把 Gitee 的额度吃光」——那等于最该保底的一级被跳过；
//   · onStage 回调把「正在试哪一级」报到界面上，用户看得见在动，不会以为卡死。
const SF_CHECK_BUDGET_MS = 12000;

async function sfFetchLatestRelease(onStage) {
  const t0 = Date.now();
  const left = function () { return SF_CHECK_BUDGET_MS - (Date.now() - t0); };
  const stage = function (label) { try { if (onStage) onStage(label); } catch (e) {} };
  // reserve = 给后面各级预留的毫秒数；永远至少跑 600ms，避免"预算不够就干脆不发请求"
  const take = function (dflt, reserve) {
    return Math.max(600, Math.min(dflt, left() - (reserve || 0)));
  };

  // ---- 1) 直连 GitHub ----
  stage('GitHub 直连');
  const page = SF_GH_DIRECT_BASE + SF_GH_REPO_PATH + SF_GH_UPDATE_PATH;
  let tag = await sfFetchTagViaPage(page, take(3500, 9000), 'HEAD');
  if (!tag && left() > 800) tag = await sfFetchTagViaPage(page, take(4500, 7000), 'GET');
  if (tag) return { tag: tag, source: 'github.com' };

  if (left() > 800) {
    const apiTag = await readReleaseViaDirectApi(take(3500, 5500));
    if (apiTag) return { tag: apiTag, source: 'api.github.com' };
  }

  // ---- 2) 公共代理 ----
  if (left() > 800) {
    stage('公共代理');
    const rel = await readReleaseViaProxy(take(4000, 5000));
    if (rel) return { tag: rel.tag, source: rel.source };
  }

  // ---- 3) Gitee 镜像（最后一级，吃满剩余预算）----
  if (left() > 800) {
    stage('Gitee 镜像');
    const gi = await readReleaseViaGitee(take(5000));
    if (gi) return { tag: gi.tag, source: gi.source };
  }
  return null;
}

(function initCheckUpdate() {
  function setTip(text, cls) {
    const el = $('checkUpdateTip');
    if (!el) return;
    el.hidden = !text;
    el.textContent = text || '';
    el.className = 'about-note update-tip' + (cls ? ' ' + cls : '');
  }

  async function run(btn) {
    const cur = sfOwnVersion();
    const label = btn.textContent;
    btn.disabled = true;
    btn.textContent = '检查中…';
    setTip('正在查询最新版本…', 'is-wait');
    let rel = null;
    try {
      rel = await sfFetchLatestRelease(function (label) {
        setTip('正在查询最新版本…（' + label + '）', 'is-wait');
      });
    } catch (e) {
      rel = null;
    }
    btn.disabled = false;
    btn.textContent = label;

    if (!rel) {
      setTip('查询失败：GitHub、公共代理与 Gitee 镜像均不可达，请稍后重试，或点「前往 Gitee 查看更新」手动查看。', 'is-fail');
      return;
    }
    const cmp = sfCmpVersion(rel.tag, cur);
    if (cmp > 0) {
      setTip('检测到新版本：v' + sfNormTag(rel.tag), 'is-new');
    } else {
      // cmp === 0：逐字节相同；cmp < 0：线上版本反而更低（多为本地测试版）——都算「无可用更新」
      setTip('无可用更新', 'is-ok');
    }
    console.log('[检查更新] 本地 v' + cur + '，线上 v' + sfNormTag(rel.tag) + '（来源：' + rel.source + '），比较结果 ' + cmp);
  }

  function bind() {
    const btn = $('checkUpdateBtn');
    if (!btn) return;
    btn.addEventListener('click', function () {
      if (btn.disabled) return;   // 连点只跑一次
      run(btn);
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', bind);
  else bind();
})();

/* ============================================================================
 * 云端名单同步（关于页「从云端更新名单」按钮）
 * ----------------------------------------------------------------------------
 * 数据流：按钮 → worker GET /list?type=white|black（两份并行）→ 清洗去重 →
 *         覆盖写入 storage.local 对应键 → background 收到 storage.onChanged 立即重注入；
 *         内容脚本在下次页面加载（getSettings）时注入。
 *
 * 语义是「镜像覆盖」不是「合并追加」：
 *   每次拉取成功后，用云端这一份**整体替换**上一份快照，本地 sfCloudWhite / sfCloudBlack
 *   始终等于云端最新内容。这样云端删掉的条目（误报反馈后的移除）才能真正生效——
 *   并集语义下删掉的条目会永久留在本地，状态行的条数也只会单调递增。
 *   云端的空响应已在 fetchCloudList() 里被拦下（抛错，不进入写入路径），
 *   因此不存在「云端异常导致本地被清空」的风险。
 *
 * 注意：云端名单与**内置名单**(rules/iocs.js)、**用户手写名单**(settings.allowlist /
 *   customBadDomains) 始终是三份独立数据；判定时由 analyzer 做双集合查找
 *   （isOfficialDomain / isKnownBad 内部分别查 内置 ∪ 云端），互不覆盖。
 *
 * 为什么存 storage.local 而不是 storage.sync：
 *   sync 单键上限 8192 bytes ≈ 550 个域名，上千条会「静默写失败」
 *   （回调里只带 runtime.lastError，界面看起来却是成功的）。
 *   本扩展已申请 unlimitedStorage，storage.local 实际无上限。
 * ============================================================================ */

// worker 的名单接口（manifest 的 connect-src 为 'self' https:，允许该 HTTPS 请求）
const SF_CLOUD_API = 'https://api.silverfoxblocker.dpdns.org/list';
// ⚠️ 必须填成 Cloudflare Worker 里 env.LIST_API_KEY 的同一个值，否则接口返回 401。
//    留空时两个按钮不会发请求，只提示「未配置 API Key」。
const SF_CLOUD_API_KEY = 'R6fNcSm^$Z5d6s';
// 与 analyzer / content / background 三处约定的存储键，改名要同步改那三处
const SF_CLOUD_KEY_WHITE = 'sfCloudWhite';
const SF_CLOUD_KEY_BLACK = 'sfCloudBlack';
const SF_CLOUD_META_KEY = 'sfCloudListMeta';

// ---------------------------------------------------------------------------
// 云名单的第二、第三通道（直连 Worker 失败时使用）
//   主通道 = 自建 Worker（实时读私有仓库，带 API Key 鉴权）；
//   备用   = 公开仓库里的**加密快照**：GitHub raw 直连 + 若干公共反代。
//   为什么需要：Worker 挂在自定义域名（api.silverfoxblocker.dpdns.org）上，一旦该域名
//   被 DNS 污染或线路不通，状态行只会干等超时，用户无从自救。而私有仓库的内容
//   任何公共反代都读不到（没有凭据 → 一律 404），所以只能事先把一份**加密**副本
//   放公开仓库：反代透明转发密文，扩展在本机解密后再走同一套清洗/落盘流程。
//   ⚠️ 需要把 Cloud/blacklist.json.enc 与 Cloud/whitelist.json.enc 上传到公开仓库
//      （SF_CLOUD_MIRROR_REPO 的 Cloud/ 目录，由 tools/encrypt_cloud.js 生成）。
//      没上传时这两个通道会很快 404，代码会自动跳过后续反代、只报「镜像未发布」，
//      不影响原有直连逻辑。
//
// 加密快照的定位（说清楚边界，别当成真的保密）：
//   · 挡住「随手点开链接看名单」和「改一个域名试试」——密文不可读，改一个字节
//     AES-GCM 就校验失败，扩展拒绝写入本地名单；
//   · 挡不住解包扩展读口令的人（口令必须内置，否则扩展自己解不开）；
//   · 真正的保密仍然只有 Worker 那条路（GITHUB_TOKEN 只在服务端）。
// ---------------------------------------------------------------------------
const SF_CLOUD_MIRROR_REPO = 'bbjj12345/SilverFoxBlocker';
const SF_CLOUD_MIRROR_BRANCH = 'main';
const SF_CLOUD_MIRROR_DIR = 'Cloud';
// 公开快照是否使用加密文件（.json.enc）。改成 false 则回退到旧的明文 .json 方案，
//   但明文意味着任何人打开 raw 链接就能看到整份名单，仅在临时排查时使用。
const SF_CLOUD_MIRROR_ENCRYPTED = true;
// Gitee 镜像（发布在 gitee.com 的同一份**加密**快照）：GitHub 直连与所有公共反代都失败时
//   的最后一跳。顺序上排在 GitHub 之后，符合「优先 GitHub、失败才用 Gitee」。
//   Gitee 的 raw 路径对公开库可直接匿名读取，且同样只有密文，安全性不降级。
//   注意：Gitee 仓库**不会自动同步**，改完名单要手动推一次，否则这里拿到的是旧快照。
const SF_GITEE_MIRROR_ENABLED = true;
// 用 SF_CLOUD_MIRROR_REPO（两个平台同名）而不是 SF_GITEE_REPO_PATH：
//   这段代码会被测试整段 eval 出去，只带得动切片内的常量，少一个外部依赖少一处踩空。
const SF_GITEE_MIRROR_RAW = 'https://gitee.com/' + SF_CLOUD_MIRROR_REPO + '/raw/' +
  SF_CLOUD_MIRROR_BRANCH + '/' + SF_CLOUD_MIRROR_DIR + '/';
// ⚠️ 必须与 tools/encrypt_cloud.js 的 DEFAULT_PASS 一致；改口令要两处同步 + 重新生成快照
const SF_CLOUD_ENC_PASS = 'aYGJ_rskoMvjXBjKCqQDqTjKMjMRNyH-';
const SF_CLOUD_ENC_TAG = 'sfenc1';
// 公共 GitHub 反代：统一前缀写法 <proxy>/<原始 raw 地址>，只用于文件（JSON/zip），不用于网页
const SF_GH_PROXIES = [
  { name: 'gh-proxy.com', prefix: 'https://gh-proxy.com/' },
  { name: 'ghfast.top', prefix: 'https://ghfast.top/' },
  { name: 'ghproxy.net', prefix: 'https://ghproxy.net/' },
  { name: 'ghfile.geekertao.top', prefix: 'https://ghfile.geekertao.top/' },
  { name: 'gh.geekertao.top', prefix: 'https://gh.geekertao.top/' },
  { name: 'ghproxy.cc', prefix: 'https://ghproxy.cc/' }
];
// 单通道超时：直连卡住时不能无限等（原来没有超时，断网时会一直「正在拉取…」）
const SF_CLOUD_FETCH_TIMEOUT = 6000;
// 云端接口（Worker）自己最多花 9s（GitHub 4.5s + Gitee 兜底），所以给它 10s；
// 镜像/反代还是 6s。若两者一样大，Worker 还在跑、这边已经判超时，用户看到的是「失败」
// 而服务端其实成功了，还会白跑一遍镜像通道。
const SF_CLOUD_API_TIMEOUT = 10000;

// 兼容多种云端 JSON 形态：纯数组 / {domains:[]} / {list:[]} / {data:[]} / 换行分隔字符串
function extractCloudArray(json) {
  if (Array.isArray(json)) return json;
  if (json && typeof json === 'object') {
    const keys = ['domains', 'list', 'data', 'items', 'all', 'white', 'black'];
    for (let i = 0; i < keys.length; i++) {
      if (Array.isArray(json[keys[i]])) return json[keys[i]];
    }
    if (json.data && Array.isArray(json.data.domains)) return json.data.domains;
    return null;
  }
  if (typeof json === 'string') return json.split(/[\r\n,]+/);
  return null;
}

// 被丢弃条目的原因码 → 人话（状态行 / 报错里直接用）
const CLOUD_DROP_REASON = {
  'not-string': '不是字符串',
  'empty': '空条目',
  'too-long': '超长',
  'invalid-char': '含空格/斜杠/@ 或连续点',
  'no-dot': '不是域名（没有点）',
  'idn-in-wildcard': '通配标签里有中文，请改写为 punycode',
  'suffix-malformed': '`*.` 后缀写法不合法',
  'need-two-labels': '至少要有两级域名',
  'tld-wildcard': '不允许通配顶级域',
  'bad-length': '长度不合法',
  'empty-label': '存在空标签',
  'bad-syntax': '无法编译为正则',
  // 2026-11-11：白名单也允许通配，本原因码仅在显式开启「严格模式」(allowWild:false) 时才会出现
  'wild-not-allowed': '该名单当前不允许通配符',
  'wild-over-limit': '超出 200 条通配上限',
  'path-over-limit': '超出 500 条路径条目上限'
};
function dropReasonText(code) { return CLOUD_DROP_REASON[code] || code || '无效'; }
function dropReasonBrief(dropped) {
  const seen = [];
  (dropped || []).forEach((x) => {
    const t = dropReasonText(x.reason);
    if (seen.indexOf(t) === -1) seen.push(t);
  });
  return seen.join('、');
}

// 云端名单清洗的**唯一入口**：先抽出数组，再交给 analyzer 的同一套规则清洗。
// ★ 为什么必须复用 analyzer：此前设置页自己洗一遍、analyzer 里再洗一遍，两套规则不一致，
//   结果就是「页面报 205 条、实际只有 200 条生效」以及「白名单写了通配符照样计入条数」这类
//   静默失效。现在落盘的条目 = 真正会生效的条目，状态行的数字才有意义。
// 返回 { list, wild, dropped }；analyzer 缺失时退化为「只做基础清洗」（dropped 为空）。
function normalizeCloudListEx(json, opts) {
  const arr = extractCloudArray(json) || [];
  const A = (typeof window !== 'undefined' && window.SF_ANALYZER) || null;
  if (A && typeof A.sanitizeCloudDomains === 'function') return A.sanitizeCloudDomains(arr, opts);
  // 兜底路径同样要「报得出丢弃」：否则 analyzer 缺失时又变成静默丢弃。
  const seen = new Set();
  const list = [];
  const wild = [];
  const dropped = [];
  arr.forEach((d) => {
    const raw = String(d == null ? '' : d);
    let v = raw.trim().toLowerCase();
    // 2026-11-09：与 analyzer._splitHostPath 同语义——主机名/路径分开校验。
    // 兜底路径也必须认路径条目，否则 analyzer 缺失时同一份名单在两处得到不同结论。
    v = v.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
    const cut = v.search(/[?#]/);
    if (cut !== -1) v = v.slice(0, cut);
    let path = '';
    const sl = v.indexOf('/');
    if (sl !== -1) {
      path = v.slice(sl).replace(/\/+$/, '');
      v = v.slice(0, sl);
      if (path === '/') path = '';
      else if (/[\s\x00-\x1f]/.test(path) || path.indexOf('..') !== -1) {
        dropped.push({ entry: raw, reason: 'invalid-char' });
        return;
      }
    }
    v = v.replace(/^www\./, '').replace(/^\.+/, '').replace(/\.+$/, '');
    let reason = '';
    if (!v) reason = 'empty';
    else if (v.length > 253) reason = 'too-long';
    else if (v.indexOf('.') === -1) reason = 'no-dot';
    else if (/[\s@]/.test(v) || v.indexOf('..') !== -1) reason = 'invalid-char';
    else if (opts && opts.allowWild === false && /[*?]/.test(v)) reason = 'wild-not-allowed';
    if (reason) { dropped.push({ entry: v || raw, reason: reason }); return; }
    const stored = v + path;
    if (!seen.has(stored)) {
      seen.add(stored);
      list.push(stored);
      if (/[*?]/.test(v)) wild.push(stored);
    }
  });
  return { list: list, wild: wild, dropped: dropped, paths: countPathEntries(list) };
}
// 旧签名（只取条目），保留给其它调用点
function normalizeCloudList(json, opts) { return normalizeCloudListEx(json, opts).list; }

function setCloudStatus(text) {
  const el = $('cloudListStatus');
  if (el) el.textContent = text;
}

// 统一的同步状态文案：只报云端名册规模（黑 / 白），不报「新增/合并」这类中间量，
// 因为合并后本地条数会把内置与云端混在一起，用户真正关心的是云端有多少条。
// ★ 2026-11-09：条数改为「实际生效条数」，并单独报出被丢弃的条目数。
//   此前把被丢弃的也算进去（通配超 200 条、白名单写通配、中文域名），
//   用户看到「已更新 205 条」却只有 200 条生效，属于最坏的静默失败。
function cloudCountsText(w, b, bw, ignoredW, ignoredB, unchanged, pathB, pathW, source) {
  // 通配条目单独点出来：否则用户写完 `*web.cdn-deepseek.com` 只看到"黑名单 1 条"，
  // 无法判断那条到底是被当成普通域名（永不命中）还是被当成规则收录了。
  // 2026-11-09：路径条目（主机名/路径）同理——只对特定链接生效，必须让用户看得见。
  const tags = function (wild, path) {
    const arr = [];
    if (wild) arr.push(wild + ' 条通配');
    if (path) arr.push(path + ' 条路径');
    return arr.length ? '（含 ' + arr.join('、') + '）' : '';
  };
  let s = '已更新' + (unchanged ? '（无变化）' : '') +
    '，云端黑名单' + b + '条' + tags(bw, pathB) +
    '，云端白名单' + w + '条' + tags(0, pathW);
  if (ignoredB) s += '；已忽略黑名单 ' + ignoredB + ' 条（格式不合法或超出通配上限）';
  if (ignoredW) s += '；已忽略白名单 ' + ignoredW + ' 条（格式不合法或超出通配上限）';
  // 只有走了备用通道才标注来源：默认直连时不必让用户看到技术细节
  if (source && source !== '云端接口') s += '（数据源：' + source + '）';
  return s;
}
// 名单里含路径的条目数（`主机名/路径` 形式；通配条目单独统计）
function countPathEntries(arr) {
  return (Array.isArray(arr) ? arr : []).filter(function (d) {
    const v = String(d == null ? '' : d);
    return v.indexOf('/') !== -1;
  }).length;
}
// 名单里含通配符（* / ?）的条目数
function countWildEntries(arr) {
  return (Array.isArray(arr) ? arr : []).filter(function (d) {
    const v = String(d == null ? '' : d);
    return v.indexOf('*') !== -1 || v.indexOf('?') !== -1;
  }).length;
}

// 「未生效条目」明细：把 dropped 的原文与原因摊开给用户看。
// 只列前若干条，其余折成「等 N 条」——这里的目的不是搬运日志，而是让用户能立刻发现
// 「我写的那条为什么没生效」（通配超上限、通配写法非法、中文通配标签是最常见的三种）。
function renderCloudDropDetail(mw, mb, strayWhiteEntries) {
  const row = $('cloudDropRow');
  const el = $('cloudDropDetail');
  if (!row || !el) return;
  const parts = [];
  const pushAll = function (drops, tag) {
    (drops || []).forEach(function (d) {
      const entry = String((d && d.entry) || '');
      parts.push(tag + (entry ? entry : '(空)') + '：' + dropReasonText(d && d.reason));
    });
  };
  pushAll(mw.drops, '白名单 ');
  pushAll(mb.drops, '黑名单 ');
  const stray = (strayWhiteEntries || []).length;
  // 老快照（升级前写入）没有 drops 明细，只有计数：至少说清「有东西没生效、请重新同步」
  const known = ((mw && mw.dropped) || 0) + ((mb && mb.dropped) || 0);
  if (!parts.length && !known && !stray) { row.style.display = 'none'; el.textContent = ''; return; }
  let text = parts.join('；');
  if (stray) {
    const note = '白名单旧快照含 ' + stray + ' 条通配条目（不会生效，重新同步即可清除）' +
      '：' + strayWhiteEntries.slice(0, 10).join('、');
    text = text ? text + '；' + note : note;
  }
  const shown = parts.length + stray;
  const total = Math.max(known, shown);
  if (!text && total) text = '有 ' + total + ' 条未生效，请重新同步以查看原因';
  else if (total > shown) text += '（共 ' + total + ' 条未生效，仅列出前 ' + shown + ' 条）';
  el.textContent = text;
  row.style.display = '';
}

function refreshCloudListStatus() {
  const el = $('cloudListStatus');
  if (!el) return;
  const dropRow = $('cloudDropRow');
  const hideDrops = function () { if (dropRow) dropRow.style.display = 'none'; };
  if (!hasStorageLocal()) { el.textContent = '未同步（当前环境无扩展存储）'; hideDrops(); return; }
  chrome.storage.local.get({ [SF_CLOUD_KEY_WHITE]: [], [SF_CLOUD_KEY_BLACK]: [], [SF_CLOUD_META_KEY]: {} }, (o) => {
    const w = (o[SF_CLOUD_KEY_WHITE] || []).length;
    const b = (o[SF_CLOUD_KEY_BLACK] || []).length;
    const m = o[SF_CLOUD_META_KEY] || {};
    const t = Math.max((m.white && m.white.updated) || 0, (m.black && m.black.updated) || 0);
    // 两份名单都为空但存在同步元数据 → 云端确实同步过、只是内容为空，
    //   报「未同步」会让用户以为没生效（尤其此时还可能有被忽略的条目要展示）。
    if (!w && !b && !t) { el.textContent = '未同步'; hideDrops(); return; }
    const mb = m.black || {};
    const mw = m.white || {};
    // 通配数 / 忽略数优先取同步时记下的元数据；老快照没有这两个字段时回退到现场统计。
    // 2026-11-11：白名单已支持通配，「旧快照里的白名单通配条目不会生效」这条告警不再成立
    //   （它们现在照常生效），因此不再把白名单里的通配条目算作「已忽略」。
    // 旧：const strayWhiteWild = countWildEntries(o[SF_CLOUD_KEY_WHITE]);
    el.textContent = cloudCountsText(
      w, b,
      (mb.wild != null ? mb.wild : countWildEntries(o[SF_CLOUD_KEY_BLACK])),
      // 旧：Math.max(mw.dropped || 0, strayWhiteWild),   ← 白名单通配不再算忽略
      mw.dropped || 0,
      mb.dropped || 0,
      false,
      (mb.paths != null ? mb.paths : countPathEntries(o[SF_CLOUD_KEY_BLACK])),
      (mw.paths != null ? mw.paths : countPathEntries(o[SF_CLOUD_KEY_WHITE])),
      // 刷新后也要看得出上次是走备用通道拿到的（否则用户以为一直直连成功）
      (mw.source && mw.source !== '云端接口') ? mw.source
        : ((mb.source && mb.source !== '云端接口') ? mb.source : '')
    );
    // 未生效条目的明细（原文 + 原因）直接列在下面：此前只在 console 里，用户看不到
    // 旧：白名单里含 * / ? 的条目一律列为「不会生效」的杂项；2026-11-11 起白名单也支持通配，
    //   这类条目照常生效，不再列举（保留变量名是为了不动 renderCloudDropDetail 的签名）。
    // const strayWhiteEntries = (o[SF_CLOUD_KEY_WHITE] || []).filter(function (d) {
    //   const v = String(d == null ? '' : d);
    //   return v.indexOf('*') !== -1 || v.indexOf('?') !== -1;
    // });
    const strayWhiteEntries = [];
    renderCloudDropDetail(mw, mb, strayWhiteEntries);
    // 同步时间放在 title 里：正文只保留用户要的那句，鼠标悬停仍能看到上次同步时刻
    if (t) {
      const srcs = [];
      if (mw && mw.source && mw.source !== '云端接口') srcs.push('白名单 ' + mw.source);
      if (mb && mb.source && mb.source !== '云端接口') srcs.push('黑名单 ' + mb.source);
      el.title = '上次同步 ' + formatAbsTime(t) + (srcs.length ? '（备用通道：' + srcs.join('；') + '）' : '');
    }
  });
}

// 单次请求带超时：AbortController 到点即中止，避免「网络半死」时按钮永远转圈
async function fetchWithTimeout(url, opts, ms) {
  const ctrl = new AbortController();
  const timer = setTimeout(function () { try { ctrl.abort(); } catch (e) {} }, ms || SF_CLOUD_FETCH_TIMEOUT);
  try {
    return await fetch(url, Object.assign({ cache: 'no-store', signal: ctrl.signal }, opts || {}));
  } finally {
    clearTimeout(timer);
  }
}

// 按「直连 Worker → GitHub raw → 各公共反代 → Gitee raw」生成候选通道。
// 只有直连通道带 API Key：把密钥发给第三方反代等于公开密钥。
// 顺序即优先级：GitHub 系全部在前，Gitee 只作最后一跳（用户要求：优先 GitHub，失败才用 Gitee）。
function cloudUrlCandidates(type) {
  const q = type === 'white' ? 'white' : 'black';
  const file = (q === 'white' ? 'whitelist.json' : 'blacklist.json') +
    (SF_CLOUD_MIRROR_ENCRYPTED ? '.enc' : '');
  const raw = 'https://raw.githubusercontent.com/' + SF_CLOUD_MIRROR_REPO + '/' +
    SF_CLOUD_MIRROR_BRANCH + '/' + SF_CLOUD_MIRROR_DIR + '/' + file;
  const out = [{
    name: '云端接口',
    url: SF_CLOUD_API + '?type=' + q + '&_=' + Date.now(),
    headers: { 'X-API-Key': SF_CLOUD_API_KEY },
    mirror: false,
    enc: false
  }];
  // 镜像通道拿到的都是密文：enc:true 让 fetchCloudList 多走一步本地解密
  out.push({ name: 'GitHub 镜像', url: raw + '?_=' + Date.now(), headers: {}, mirror: true, enc: SF_CLOUD_MIRROR_ENCRYPTED });
  SF_GH_PROXIES.forEach(function (p) {
    out.push({ name: p.name + ' 代理', url: p.prefix + raw, headers: {}, mirror: true, enc: SF_CLOUD_MIRROR_ENCRYPTED });
  });
  // Gitee 兜底：走的是自己的域名与 CDN，不受 github.com / raw.githubusercontent.com /
  // 各反代的可用性影响；gitee:true 让上面的「镜像未发布」短路判断分开计数
  // （GitHub 404 不代表 Gitee 也没有）。
  if (SF_GITEE_MIRROR_ENABLED) {
    out.push({
      name: 'Gitee 镜像',
      url: SF_GITEE_MIRROR_RAW + file + '?_=' + Date.now(),
      headers: {},
      mirror: true,
      enc: SF_CLOUD_MIRROR_ENCRYPTED,
      gitee: true
    });
  }
  return out;
}

// base64 → Uint8Array（不用 atob 的字符串遍历写法在超大输入上会慢，这里按块处理）
function sfB64ToBytes(b64) {
  const s = atob(String(b64 || '').replace(/-/g, '+').replace(/_/g, '/'));
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

// 解开 tools/encrypt_cloud.js 生成的密文信封（PBKDF2-SHA256 + AES-256-GCM）。
// 口令错了 → OperationError；内容被改过 → GCM 校验失败（同样是 OperationError），
//   两种情况都直接抛错，绝不把「解不开」当成「名单为空」写进本地。
async function decryptCloudSnapshot(env) {
  if (!env || env._enc !== SF_CLOUD_ENC_TAG) {
    throw new Error('不是加密快照（缺少 ' + SF_CLOUD_ENC_TAG + ' 标记）');
  }
  if (!(window.crypto && window.crypto.subtle)) {
    throw new Error('当前环境不支持 WebCrypto，无法解密快照');
  }
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    'raw', enc.encode(SF_CLOUD_ENC_PASS), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: sfB64ToBytes(env.salt), iterations: env.iter || 120000, hash: 'SHA-256' },
    baseKey, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  let plain;
  try {
    // WebCrypto 的 AES-GCM 约定：密文末尾 16 字节就是认证 tag（与 Node 端拼接方式一致）
    plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: sfB64ToBytes(env.iv) }, key, sfB64ToBytes(env.data));
  } catch (e) {
    throw new Error('快照解密失败（口令不匹配或文件被改动），已拒绝写入本地名单');
  }
  return JSON.parse(new TextDecoder().decode(plain));
}

async function fetchCloudList(type) {
  const cands = cloudUrlCandidates(type);
  const errs = [];
  // 两套短路标记必须分开：GitHub 侧 404（快照没发布）不代表 Gitee 也没有；
  //   合成一个会让 Gitee 兜底被误跳过，等于白加。
  let ghMirrorMissing = false;   // GitHub raw + 各反代整批不可用（404/403）
  let giteeMissing = false;      // Gitee raw 不可用（仓库不存在 / 分支或目录不同 / 未同步）
  const isWhite = type === 'white';
  const name = isWhite ? '白名单' : '黑名单';

  for (let i = 0; i < cands.length; i++) {
    const c = cands[i];
    if (c.mirror && (c.gitee ? giteeMissing : ghMirrorMissing)) continue;
    try {
      const res = await fetchWithTimeout(c.url, { headers: c.headers },
        c.name === '云端接口' ? SF_CLOUD_API_TIMEOUT : SF_CLOUD_FETCH_TIMEOUT);
      const text = await res.text();
      if (!res.ok) {
        if (res.status === 401) throw new Error('鉴权失败：API Key 与 worker 的 LIST_API_KEY 不一致');
        if (c.mirror && (res.status === 404 || res.status === 403 || res.status === 400)) {
          // 镜像还没发布 / 反代拒绝：同一侧的后续通道拿的也是同一个 404，直接跳过
          if (c.gitee) giteeMissing = true; else ghMirrorMissing = true;
          errs.push(c.name + '：镜像未发布（HTTP ' + res.status + '）');
          continue;
        }
        throw new Error('HTTP ' + res.status);
      }
      let json;
      try { json = JSON.parse(text); } catch (e) { throw new Error('返回的不是合法 JSON'); }
      // 加密快照：JSON 外壳解开后才是真正的名单对象，后面所有步骤完全复用。
      // 解密失败（口令不匹配 / 文件被篡改）对每个反代都是同一个结果，不必挨个重试。
      if (c.enc) {
        try {
          json = await decryptCloudSnapshot(json);
        } catch (de) {
          const err = new Error(de && de.message ? de.message : '快照解密失败');
          err.noRetry = true;
          throw err;
        }
      }
      const raws = extractCloudArray(json);
      // 结构都认不出来（例如 Worker 返回了 {error:...}）→ 换通道，别写空名单
      if (!raws) throw new Error('返回的结构无法识别（找不到域名数组）');
      // 2026-11-11：黑白名单都允许通配（白名单原先 allowWild:false，含 * / ? 的条目被丢弃）
      // 旧：const r = normalizeCloudListEx(json, { allowWild: !isWhite });
      const r = normalizeCloudListEx(json, { allowWild: true });
      // 有条目但全被丢弃 → 中止（否则等于把这份名单清空，用户却以为同步成功）
      // 这是**数据问题**，换通道也救不了，标记 noRetry 直接抛出
      if (raws.length && !r.list.length) {
        const err = new Error('云端' + name + ' ' + r.dropped.length + ' 条全部无效，已中止同步（' +
          dropReasonBrief(r.dropped) + '）');
        err.noRetry = true;
        throw err;
      }
      // 原本就是空数组 → 允许（例如白名单暂时清空），状态行会显示 0 条，不会被误解
      r.source = c.name;
      // Worker 会在响应头里注明这份名单最终取自 GitHub 还是 Gitee 镜像，
      // 转发到状态行（「数据源：云端接口·Gitee」），否则源站切换了用户完全看不出来。
      if (c.name === '云端接口') {
        try {
          const ds = res.headers.get('X-Data-Source');
          if (ds) r.dataSource = String(ds).slice(0, 20);
        } catch (e) { /* 读不到头不影响同步结果 */ }
      }
      if (c.name !== '云端接口') console.log('[云端名单] ' + name + ' 经备用通道「' + c.name + '」获取成功');
      return r;
    } catch (e) {
      if (e && e.noRetry) throw e;
      const msg = (e && e.message) ? e.message : '网络错误';
      errs.push(c.name + '：' + (/abort/i.test(msg) || msg === 'The user aborted a request.' ? '超时' : msg));
    }
  }
  throw new Error('所有通道均失败（' + (function () {
    // 头部几条有代表性，但 Gitee（最后一跳）的失败原因同样关键，
    //   只截前 4 条会把「Gitee 为什么也不行」整段吞掉。
    const head = errs.slice(0, 3);
    const last = errs.length > head.length ? errs[errs.length - 1] : null;
    const shown = head.concat(last && head.indexOf(last) === -1 ? [last] : []);
    return shown.join('；') + (errs.length > shown.length ? ' 等' : '');
  })() + '）');
}

// 一次拉取黑 + 白两份云端名单并整体覆盖本地快照。
// 合并成一个按钮的原因：两份名单本来就是同一次部署的产物，分开点会出现
// 「黑名单已更新、白名单还是旧的」这种过期组合，状态行也没法一次报全。
async function updateCloudLists(btn) {
  if (!SF_CLOUD_API_KEY) {
    setCloudStatus('未配置 API Key：请先在 ui/options.js 填入 SF_CLOUD_API_KEY');
    return;
  }
  if (!hasStorageLocal()) { setCloudStatus('当前环境不支持扩展存储'); return; }
  const orig = btn ? btn.textContent : '';
  if (btn) { btn.disabled = true; btn.textContent = '同步中…'; }
  setCloudStatus('正在从云端拉取黑白名单…');
  try {
    // 两份并行拉取；任一失败都会抛错，此时本地不做任何写入（不会出现半新半旧）
    // 两份并行拉取；任一失败都会抛错，此时本地不做任何写入（不会出现半新半旧）
    // fetchCloudList 返回的是 { list, wild, dropped }：list 已经是「会真正生效」的条目
    const lists = await Promise.all([fetchCloudList('white'), fetchCloudList('black')]);
    const white = lists[0];
    const black = lists[1];
    const cur = await new Promise((resolve) => {
      chrome.storage.local.get({
        [SF_CLOUD_KEY_WHITE]: [], [SF_CLOUD_KEY_BLACK]: [], [SF_CLOUD_META_KEY]: {}
      }, resolve);
    });
    // 镜像覆盖：云端这份直接替换旧快照（不是并集），云端删掉的条目才会真正失效
    const diff = function (prev, next) {
      const p = new Set(prev || []);
      const n = new Set(next);
      return {
        added: next.filter(function (d) { return !p.has(d); }).length,
        removed: (prev || []).filter(function (d) { return !n.has(d); }).length
      };
    };
    // 顺序也纳入比较：云端重排但内容相同时，没必要重写 → 不触发后台/各标签页重新注入
    const sameList = function (a, b) {
      const x = a || [];
      if (x.length !== b.length) return false;
      for (let i = 0; i < x.length; i++) { if (x[i] !== b[i]) return false; }
      return true;
    };
    const sameW = sameList(cur[SF_CLOUD_KEY_WHITE], white.list);
    const sameB = sameList(cur[SF_CLOUD_KEY_BLACK], black.list);
    const dw = diff(cur[SF_CLOUD_KEY_WHITE], white.list);
    const db = diff(cur[SF_CLOUD_KEY_BLACK], black.list);
    const now = Date.now();
    const meta = Object.assign({}, cur[SF_CLOUD_META_KEY] || {});
    // wild / dropped 一并落盘：刷新页面后状态行仍能报出「含 N 条通配、忽略 M 条」，
    //   不用等到下次点同步才知道上次丢过东西。
    // drops 是**明细**（原文 + 原因码），上限 40 条：只在设置页展示，不必全存，
    //   但要保证「为什么这条没生效」能直接看到，而不是只在控制台里躺一份。
    meta.white = {
      updated: now, count: white.list.length, pulled: white.list.length + white.dropped.length,
      added: dw.added, removed: dw.removed, wild: white.wild.length, dropped: white.dropped.length,
      paths: white.paths || 0, drops: white.dropped.slice(0, 40),
      source: white.source || '云端接口'
    };
    meta.black = {
      updated: now, count: black.list.length, pulled: black.list.length + black.dropped.length,
      added: db.added, removed: db.removed, wild: black.wild.length, dropped: black.dropped.length,
      paths: black.paths || 0, drops: black.dropped.slice(0, 40),
      source: black.source || '云端接口'
    };
    // 内容没变就只写 meta：此前无条件 set 会触发 onChanged → 后台重注入 + 四个缓存清空，
    //   一份干净的名单也跟着抖一下。
    const payload = { [SF_CLOUD_META_KEY]: meta };
    if (!sameW) payload[SF_CLOUD_KEY_WHITE] = white.list;
    if (!sameB) payload[SF_CLOUD_KEY_BLACK] = black.list;
    await new Promise((resolve) => {
      chrome.storage.local.set(payload, resolve);
    });
    if (chrome.runtime.lastError) throw new Error(chrome.runtime.lastError.message || '写入失败');
    refreshCloudListStatus();
    const srcNote = (white.source && white.source !== '云端接口') || (black.source && black.source !== '云端接口')
      ? (white.source || black.source)
      // 走的是 Worker 直连，但 Worker 自己换了源站（GitHub→Gitee）时也要标出来
      : ((white.dataSource || black.dataSource)
        ? '云端接口·' + (white.dataSource === black.dataSource
          ? white.dataSource : (white.dataSource || '') + '/' + (black.dataSource || ''))
        : '');
    setCloudStatus(cloudCountsText(
      white.list.length, black.list.length, black.wild.length,
      white.dropped.length, black.dropped.length, sameW && sameB,
      black.paths || 0, white.paths || 0,    // 形参顺序：pathB, pathW
      srcNote
    ));
    console.log('[云端名单] 黑', black.list.length, '条（通配', black.wild.length,
      '/ 忽略', black.dropped.length, '；新增', db.added, '/ 移除', db.removed,
      '）；白', white.list.length, '条（忽略', white.dropped.length,
      '；新增', dw.added, '/ 移除', dw.removed, '）');
    // 被忽略的条目一定要可见：控制台里给出原文与原因，用户/作者才有办法修名单
    if (black.dropped.length || white.dropped.length) {
      console.warn('[云端名单] 以下条目未生效：', white.dropped.concat(black.dropped));
    }
    showToast();
  } catch (e) {
    setCloudStatus('名单同步失败：' + (e && e.message ? e.message : '未知错误'));
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = orig; }
  }
}

(function initCloudListSync() {
  function bind() {
    const b = $('cloudPullList');
    if (b) b.addEventListener('click', function () { updateCloudLists(b); });
    refreshCloudListStatus();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', bind);
  else bind();
})();

// ===== 名单上报：把「自定义信任域名白名单 / 自定义恶意域名黑名单」直接发到作者邮箱 =====
// 与「反馈与建议 → 发送反馈到作者邮箱」共用同一个 Worker 接口（POST { message, contact }），
// 区别只有三点：
//   1) 正文由程序拼装，用户不必写任何描述，只需维护自己的域名清单；
//   2) 不传 contact → Worker 侧 `data.contact || "未提供"`，邮件里呈现「联系方式：未提供」；
//   3) 不做「不少于 5 个字符」的反馈校验，改为「至少 1 条域名 + 正文 2000 字符上限」。
(function initListMail() {
  var MAX = 2000; // 与 Worker 端 feedbackText.length > 2000 的校验保持一致
  var JOBS = [
    { btn: 'mailWhiteBtn', ta: 'allowlist', spin: 'mailWhiteSpin', msg: 'mailWhiteMsg', kind: '自定义白名单' },
    { btn: 'mailBlackBtn', ta: 'customBadDomains', spin: 'mailBlackSpin', msg: 'mailBlackMsg', kind: '自定义黑名单' }
  ];

  function setMsg(el, text, kind) {
    if (!el) return;
    el.hidden = !text;
    el.textContent = text || '';
    el.style.color = kind === 'ok' ? '#4be38b' : (kind === 'warn' ? '#ffae42' : '');
  }

  // 逐行解析：去空行、去重、剥离协议与首尾点、统一小写。
  // 这里**不**过滤非法域名——作者收到的是用户原始意图，写错了由人工复核，
  // 悄悄丢掉反而会让用户以为已经上报成功。
  function parseDomains(raw) {
    var seen = {}, out = [];
    String(raw || '').split(/[\r\n]+/).forEach(function (line) {
      var v = line.trim();
      if (!v || v.charAt(0) === '#') return; // 允许 # 开头的备注行
      if (v.indexOf('://') !== -1) { try { v = new URL(v).hostname; } catch (e) { return; } }
      v = v.replace(/^\.+/, '').replace(/\.+$/, '').toLowerCase();
      if (!v || seen[v]) return;
      seen[v] = 1;
      out.push(v);
    });
    return out;
  }

  function send(job) {
    var btn = $(job.btn), ta = $(job.ta), spin = $(job.spin), msgEl = $(job.msg);
    if (!btn || !ta || btn.disabled) return;
    var list = parseDomains(ta.value);
    if (!list.length) {
      setMsg(msgEl, '输入框里还没有域名，请先填写再发送。', 'warn');
      ta.focus();
      return;
    }
    var body = '问题类型：' + job.kind + '\n' + list.join('\n');
    if (body.length > MAX) {
      setMsg(msgEl, '域名过多（' + list.length + ' 个，正文 ' + body.length + ' 字符），超出 ' + MAX + ' 字符上限，请分批发送。', 'warn');
      return;
    }
    var cfg = window.SFB_FEEDBACK;
    var endpoint = (cfg && cfg.decode) ? cfg.decode(cfg.endpointCodes) : '';
    if (!cfg || !cfg.enabled || !endpoint) {
      setMsg(msgEl, '邮件上报尚未配置，暂时无法发送。', 'warn');
      return;
    }
    btn.disabled = true;
    if (spin) spin.hidden = false;
    setMsg(msgEl, '', '');
    fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: body, contact: '' })
    })
      .then(function (res) {
        if (!res.ok) throw new Error('HTTP ' + res.status);
        setMsg(msgEl, '已发送 ' + list.length + ' 个域名，感谢你的贡献！', 'ok');
      })
      .catch(function () {
        setMsg(msgEl, '发送失败，请稍后重试。', 'warn');
      })
      .then(function () {
        btn.disabled = false;
        if (spin) spin.hidden = true;
      });
  }

  function bind() {
    JOBS.forEach(function (job) {
      var b = $(job.btn);
      if (b) b.addEventListener('click', function () { send(job); });
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', bind);
  else bind();
})();
