/* options.js — SilverFoxBlocker 设置控制面板逻辑（侧边栏分类版） */
'use strict';

// 360 系统急救箱官方下载直链（绿色版，无需安装）。现为「备用直链」：点击按钮时会自动抓取
// 官网/软件宝库的最新 64 位独立版直链；仅当自动抓取失败时才回退到此处。
const RESCUE_DOWNLOAD_URL = 'https://dl.360safe.com/360c0mpkill_5.1.64.1289-0701.zip';

// 火绒专杀工具（无签名版）官方下载直链（备用种子）。点击按钮时会自动探测火绒 CDN 的最新无签名版；
// 该工具可解除银狐木马对常规杀毒软件的打开限制；因无签名，Windows Defender 与安全下载检测会拦截——属正常现象，用户放行即可。
// 有签名版同样会被银狐类病毒拦截，故只提供无签名版。自动抓取失败时才回退到此种子直链。
const HRKILL_DOWNLOAD_URL = 'https://down7.huorong.cn/hrkill/hrkill_unsign-1.0.0.200.exe';

// （银狐系统解锁工具已停止维护并下架，此处不再提供下载入口。）

const DEFAULTS = {
  enabledGlobal: true,
  showWarning: true,
  autoBlockDownloads: true,
  notify: true,
  icpApiVerify: true,   // ICP 备案权威核验（只发域名给公开备案接口，且仅在核验有价值时发起）
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

function $(id) { return document.getElementById(id); }
// 扩展环境才有 chrome.storage；浏览器直接预览时优雅退回默认值，不影响真实行为
function hasStorage() { return (typeof chrome !== 'undefined') && chrome.storage && chrome.storage.sync; }
function hasStorageLocal() { return (typeof chrome !== 'undefined') && chrome.storage && chrome.storage.local; }
function getSettings() {
  if (!hasStorage()) return Promise.resolve(Object.assign({}, DEFAULTS));
  return new Promise((resolve) => chrome.storage.sync.get(DEFAULTS, (s) => resolve(Object.assign({}, DEFAULTS, s || {}))));
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
  { targets: ['rules'],   label: '规则与白名单',title: '规则与白名单', desc: '信任域名、自定义关键词与黑名单', icon: 'doc' },
  { targets: ['stats'],   label: '防护统计', title: '防护统计', desc: '已拦截风险与下载次数',       icon: 'chart' },
  { targets: ['rescue'],  label: '银狐急救', title: '银狐急救', desc: '中招后的下载与查杀引导',     icon: 'cross' },
  { targets: ['about'],   label: '关于',     title: '关于',     desc: '版本信息与说明',             icon: 'info' }
];
// 新版（8 项分组导航，默认）：同类合并、语义归类
const NAV_NEW_GROUPS = [
  {
    label: '防护', items: [
      { targets: ['detect', 'behavior'], label: '检测拦截', title: '检测与拦截', desc: '检测维度与命中后的处置方式', icon: 'shield' },
      { targets: ['rules'],              label: '规则与白名单', title: '规则与白名单', desc: '信任域名、关键词与黑名单', icon: 'doc' },
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

  // 灵敏度分段（带滑动药丸动画）—— 防护总览页已移除，仅当控件存在时绑定
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
/* 下钻导航：枢纽页卡片 → 独立子页面，返回时回到来源枢纽页（规则白名单 + 工具中心 + 个性化主题共用）。
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

function sfRescueDirect(btn, urlEl, url, originalText, safety) {
  if (safety) clearTimeout(safety);
  if (btn) { btn.disabled = false; btn.textContent = originalText; }
  if (urlEl) urlEl.textContent = url;
  if (typeof chrome !== 'undefined' && chrome.downloads && chrome.downloads.download) {
    chrome.downloads.download({ url: url, filename: url.split('/').pop() || 'rescue.bin', conflictAction: 'uniquify' });
  } else {
    window.open(url, '_blank', 'noopener');
  }
}

function sfRescueDownload(tool) {
  const btn = tool === '360' ? $('rescueBtn') : $('hrkillBtn');
  const urlEl = tool === '360' ? $('rescueUrl') : $('hrkillUrl');
  const fallbackUrl = tool === '360' ? RESCUE_DOWNLOAD_URL : HRKILL_DOWNLOAD_URL;
  if (!btn) return;
  const originalText = btn.textContent;
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
        kv[tool === '360' ? 'rescue360Url' : 'hrkillUrl'] = res.url;
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

function bindRescue() {
  const urlEl = $('rescueUrl');
  if (urlEl) {
    urlEl.textContent = RESCUE_DOWNLOAD_URL;
    urlEl.title = '点击复制';
    urlEl.addEventListener('click', function () {
      const txt = urlEl.textContent || RESCUE_DOWNLOAD_URL;
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(txt).then(function () { showToast(); }, function () { showToast(); });
        } else { showToast(); }
      } catch (e) { showToast(); }
    });
  }

  const btn = $('rescueBtn');
  if (!btn) return;
  btn.addEventListener('click', function () { sfRescueDownload('360'); });

  // 火绒专杀工具（无签名版）：可解除银狐对杀毒软件的打开限制
  const hkUrl = $('hrkillUrl');
  if (hkUrl) {
    hkUrl.textContent = HRKILL_DOWNLOAD_URL;
    hkUrl.title = '点击复制';
    hkUrl.addEventListener('click', function () {
      const txt = hkUrl.textContent || HRKILL_DOWNLOAD_URL;
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(txt).then(function () { showToast(); }, function () { showToast(); });
        } else { showToast(); }
      } catch (e) { showToast(); }
    });
  }

  const hkBtn = $('hrkillBtn');
  if (hkBtn) hkBtn.addEventListener('click', function () { sfRescueDownload('hrkill'); });

  // 优先显示上次抓取到的直链（秒显），没有再用内置备用直链
  try {
    if (chrome.storage && chrome.storage.local) {
      chrome.storage.local.get(['rescue360Url', 'hrkillUrl'], function (kv) {
        kv = kv || {};
        if (urlEl && kv.rescue360Url) { urlEl.textContent = kv.rescue360Url; urlEl.title = '点击复制'; }
        if (hkUrl && kv.hrkillUrl) { hkUrl.textContent = kv.hrkillUrl; hkUrl.title = '点击复制'; }
      });
    }
  } catch (e) {}
}

function collectSettings() {
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
  const sensSeg = $('sensitivity');
  const sensBtn = sensSeg ? sensSeg.querySelector('button.active') : null;
  const activeFont = (document.querySelector('.font-opt.active') || { dataset: {} }).dataset;
  return {
    enabledGlobal: (window.__sfSettings ? !!window.__sfSettings.enabledGlobal : true),
    showWarning: $('showWarning').checked,
    autoBlockDownloads: $('autoBlockDownloads').checked,
    notify: $('notify').checked,
    icpApiVerify: ($('icpApiVerify') ? $('icpApiVerify').checked : true),
    sensitivity: sensBtn ? sensBtn.dataset.v : 'medium',
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
        recent.slice(0, 12).forEach((x) => {
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
          if (!confirm('导入将覆盖当前「信任域名白名单 / 自定义风险关键词 / 自定义恶意域名黑名单」三项内容，确定继续？')) return;
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
  bindDlBlacklist();
  bindRulesIO();
  loadDlBlacklist();

  setupPixelEgg();
  setupUpdateToast();

  // 关于页：反馈与建议 —— 点击「发送反馈」打开项目 GitHub Issues 新建页并预填内容。
  // 零第三方表单、无邮箱暴露；失败绝不假装成功，短文本有最小长度校验。
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

  $('saveBtn').addEventListener('click', () => {
    const patch = collectSettings();
    // 保存成功后同步回写缓存，保证 window.__sfSettings 与已落盘的 sync 一致，
    // 避免后续 applyAppearance / collectSettings 回退分支读到陈旧值。
    if (window.__sfSettings) Object.assign(window.__sfSettings, patch);
    // 自定义主题可能含大体积背景图，单独存 chrome.storage.local，避免 sync 8KB 配额静默失败
    if (hasStorageLocal()) chrome.storage.local.set({ sfCustomThemes: (window.__sfSettings && Array.isArray(window.__sfSettings.customThemes)) ? window.__sfSettings.customThemes : [] });
    if (hasStorage()) {
      chrome.storage.sync.set(patch, () => { showToast(); loadStats(); });
    } else {
      showToast();
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

