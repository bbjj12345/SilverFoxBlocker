/* popup.js — SilverFoxBlocker 弹出面板逻辑 */
'use strict';

const DEFAULTS = {
  enabledGlobal: true,
  fontMode: 'system',   // 'system' | 'smiley'
  theme: 'dark',        // 'dark' | 'light'
  themePalette: 'classic', // 'classic' | 'gold' | 'neon' | 'mist' | 'space' | 'pixel'
  material: 'frosted',  // 'frosted' | 'liquid'
  bgImage: '',          // 自定义背景 dataURL
  fontScale: 1,         // 0.85 ~ 1.40，设置界面字号缩放系数
  // 威胁情报 API（可选）：默认关闭；启用后扩展实时查询当前域名在第三方情报库的判定。
  // VirusTotal 需用户自有 Key；URLhaus / NetAPI 无需 Key（免费公开接口）。
  threatIntel: {
    enabled: false,
    providers: { virustotal: { enabled: false, apiKey: '' }, urlhaus: { enabled: false }, netapi: { enabled: false }, googlesafebrowsing: { enabled: false, apiKey: '' } }
  },
  // 社区维护的本地黑名单总开关（默认关闭）：关闭时三个名单均不参与比对
  communityLists: { enabled: false },
  openphish: { enabled: false, lastUpdated: 0 },
  phishdestroy: { enabled: false, lastUpdated: 0 },
  hagezi: { enabled: false, lastUpdated: 0, variant: 'full' }
};

function $(id) { return document.getElementById(id); }

function getSettings() {
  return new Promise((resolve) => {
    chrome.storage.sync.get(DEFAULTS, (s) => resolve(Object.assign({}, DEFAULTS, s || {})));
  });
}

const LEVEL_COLOR = { danger: '#ff6b6b', warn: '#ffb454', safe: '#6ee7b7' };
function formatAbsTime(ts) {
  if (!ts) return '';
  const d = new Date(ts);
  const p = (n) => String(n).padStart(2, '0');
  return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' +
         p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
}
function loadPopupStats() {
  chrome.storage.local.get({ stats: { warnings: 0, blocks: 0, recent: [] } }, (r) => {
    const st = r.stats || { warnings: 0, blocks: 0, recent: [] };
    const w = $('ppWarn'), b = $('ppBlock');
    if (w) w.textContent = st.warnings || 0;
    if (b) b.textContent = st.blocks || 0;
    const recent = Array.isArray(st.recent) ? st.recent : [];
    const list = $('ppRecent'), empty = $('ppRecentEmpty');
    if (!list) return;
    if (!recent.length) { list.innerHTML = ''; if (empty) empty.hidden = false; return; }
    if (empty) empty.hidden = true;
    list.innerHTML = '';
    recent.forEach((x) => {
      const lv = x.level || 'safe';
      const li = document.createElement('li');
      const dot = document.createElement('span'); dot.className = 'rdot'; dot.style.background = LEVEL_COLOR[lv] || '#888';
      const h = document.createElement('span'); h.className = 'h'; h.textContent = x.hostname || '未记录域名';
      const t = document.createElement('span'); t.className = 's'; t.textContent = formatAbsTime(x.time);
      li.append(dot, h, t);
      list.appendChild(li);
    });
    fitPopupWidth();
    fitRecentWidth();
    requestAnimationFrame(() => { fitPopupWidth(); fitRecentWidth(); });
  });
}

// 长域名兜底：若某条记录在弹窗最大宽度(800px)内仍放不下，则对其换行（优先撑宽单行完整显示）
function fitRecentWidth() {
  const list = $('ppRecent');
  if (!list) return;
  list.querySelectorAll('li').forEach((li) => {
    if (li.scrollWidth > li.clientWidth + 1) li.classList.add('wrap');
    else li.classList.remove('wrap');
  });
}

// 宽度最小步长：按最宽一行（域名+时间）把弹窗撑到刚好放得下，下限 400px、上限 800px，
// 保证内容不被挤压；超过上限才由 fitRecentWidth 换行。
function fitPopupWidth() {
  const list = $('ppRecent');
  if (!list) return;
  let widest = 0;
  list.querySelectorAll('li').forEach((li) => { if (li.scrollWidth > widest) widest = li.scrollWidth; });
  let need = widest + 64; // 卡片内边距(16*2) + app 内边距(16*2)
  if (need < 400) need = 400;
  if (need > 800) need = 800;
  document.body.style.minWidth = need + 'px';
}

const LEVEL_MAP = { danger: '危险', warn: '可疑', safe: '保持警惕', official: '官方', unknown: '未知' };

// 当前网站评分：无论是否为风险域名，都向活动标签页的内容脚本索取实时评分并展示
function loadCurrentSite() {
  const hostEl = $('siteHost'), scoreEl = $('siteScore'), levelEl = $('siteLevel'), reasonsEl = $('siteReasons');
  if (!hostEl) return;
  const unknown = (txt) => {
    hostEl.textContent = '—'; scoreEl.textContent = '—';
    scoreEl.classList.remove('skip');
    levelEl.textContent = txt; levelEl.className = 'site-level lvl-unknown';
    if (reasonsEl) reasonsEl.innerHTML = '';
  };
  // 「跳过检测」的几种情形：这类页面根本没有进入评分引擎，分数是不存在的。
  // 既不能显示成「未知」（读起来像引擎出错），也不能显示成「0 分」（读起来像「完全干净」）。
  // 2026-11-06：等级统一显示「已跳过评分」，说明行统一为「该域名在<哪张名单>中，<结果>。」，
  // 只替换名单名称，不再出现「已跳过检测 / 官方域名」这类不同说法。
  const SKIP_INFO = {
    allowlist: {
      text: '已跳过评分', lvl: 'official',
      reason: (r) => r.skipBy === 'user'
        ? '该域名在你的信任域名白名单中，未进入评分引擎。'
        // 内置的可信分发名单（GitHub / 网盘 / 下载站等）与官方域名表同属「扩展内置的可信号名单」，
        // 用户要求两者说法完全一致，故共用同一句。
        : '该域名在扩展内置的官方可信域名表中，未进入评分引擎。'
    },
    official: { text: '已跳过评分', lvl: 'official', reason: '该域名在扩展内置的官方可信域名表中，未进入评分引擎。' },
    disabled: { text: '防护已关闭', lvl: 'unknown', reason: '防护已全局关闭，未参与评分。' },
    protocol: { text: '不适用', lvl: 'unknown', reason: '非 http(s) 页面，不参与评分。' },
    localhost: { text: '本地地址', lvl: 'official', reason: '本地开发地址（localhost / 127.0.0.1），未进入评分引擎。' }
  };
  const render = (r, fallbackHost) => {
    const host = r.hostname || fallbackHost || '—';
    hostEl.textContent = host;
    // 尚未分析完（刚打开标签页 / 异步补强中）：显示「分析中」而不是「未知」，避免被误读成判定失败
    if (r.analyzed === false) {
      scoreEl.textContent = '—';
      scoreEl.classList.remove('skip');
      levelEl.textContent = '分析中';
      levelEl.className = 'site-level lvl-unknown';
      if (reasonsEl) { reasonsEl.innerHTML = ''; reasonsEl.textContent = '正在分析当前页面…'; }
      return;
    }
    // 兼容旧载荷（skip 字段上线前的缓存结果）：没有 skip 时按原有标志位推断
    let skip = r.skip || '';
    if (!skip && r.analyzed && typeof r.score !== 'number') {
      if (r.allowlisted) skip = 'allowlist';
      else if (r.official) skip = 'official';
      else if (r.disabled) skip = 'disabled';
    }
    // ★ 2026-11-08 兜底：official/allowlisted 是「根本没跑评分引擎」的事实标记，比 skip 更可靠。
    //   此前 content.js 有一条分支只带 official/score 不带 skip，弹窗就退化成「0 分 / 保持警惕」，
    //   把「白名单生效」误读成「干净但需警惕」。凡是带 official 标记且未声明 skip 的载荷，
    //   一律按官方名单跳过渲染（引擎侧所有 official 结果也都同时带 skip，不会与真实评分冲突）。
    if (!skip && r.official) skip = 'official';
    if (skip && SKIP_INFO[skip]) {
      const info = SKIP_INFO[skip];
      scoreEl.textContent = '跳过';
      scoreEl.classList.add('skip');
      levelEl.textContent = info.text;
      levelEl.className = 'site-level lvl-' + info.lvl;
      const why = (typeof info.reason === 'function') ? info.reason(r) : info.reason;
      if (reasonsEl) { reasonsEl.innerHTML = ''; reasonsEl.textContent = why; }
      return;
    }
    scoreEl.classList.remove('skip');
    const score = (typeof r.score === 'number') ? r.score : null;
    scoreEl.textContent = (score == null) ? '—' : String(score);
    const level = r.level || (score == null ? 'unknown' : 'safe');
    levelEl.textContent = LEVEL_MAP[level] || '未知';
    levelEl.className = 'site-level lvl-' + level;
      if (reasonsEl) {
      reasonsEl.innerHTML = '';
      if (r.analyzed === false) reasonsEl.textContent = '正在分析当前页面…';
      else {
        const rs = Array.isArray(r.reasons) ? r.reasons : [];
        if (!rs.length) reasonsEl.textContent = score > 0 ? '已命中风险特征。' : '未命中任何风险特征。';
        else {
          // 显示完整评分依据：逐条列出所有命中特征，不再截断为「等 N 项特征」。
          rs.forEach((x) => {
            const d = document.createElement('div'); d.className = 'reason';
            d.textContent = '· ' + (x.label || '') + (x.detail ? '：' + x.detail : '');
            reasonsEl.appendChild(d);
          });
        }
      }
    }
  };
  const queryStatus = () => {
    try {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const tab = tabs && tabs[0];
        if (!tab || tab.id == null || !tab.url || !/^https?:\/\//i.test(tab.url)) { unknown('当前页面不支持评分'); return; }
        let fallbackHost = ''; try { fallbackHost = new URL(tab.url).hostname; } catch (e) {}
        chrome.tabs.sendMessage(tab.id, { type: 'sf-getStatus' }, (resp) => {
          if (chrome.runtime.lastError || !resp) { unknown('无法获取评分（请刷新页面后重试）'); return; }
          render(resp, fallbackHost);
        });
      });
    } catch (e) { unknown('无法获取评分（请刷新页面后重试）'); }
  };
  queryStatus();
  // 评分依赖异步补强（域名年龄 / ICP 核验 / 深链下挖），延后补查一次，确保弹窗结论与页面浮层一致
  setTimeout(queryStatus, 1500);
  setTimeout(queryStatus, 5000);
}

async function init() {
  const settings = await getSettings();

  // 应用字体、深浅色、外观主题、材质、自定义背景（与设置页保持一致）
  const root = document.documentElement;
  root.classList.toggle('font-smiley', settings.fontMode === 'smiley');
  root.classList.toggle('theme-light', settings.theme === 'light');
  const pal = settings.themePalette || 'classic';
  root.classList.toggle('theme-gold', pal === 'gold');
  root.classList.toggle('theme-neon', pal === 'neon');
  root.classList.toggle('theme-mist', pal === 'mist');
  root.classList.toggle('theme-space', pal === 'space');
  root.classList.toggle('theme-pixel', pal === 'pixel');
  const material = settings.material || 'frosted';
  root.classList.toggle('material-liquid', material === 'liquid' && pal !== 'pixel');
  if (typeof settings.fontScale === 'number') {
    let s = settings.fontScale;
    if (settings.fontMode === 'smiley') s *= 1.10;
    root.style.setProperty('--sf-scale', s.toFixed(3));
  }
  if (settings.bgImage && pal !== 'pixel') {
    root.style.setProperty('--sf-bg-image', 'url(' + settings.bgImage + ')');
  } else {
    root.style.removeProperty('--sf-bg-image');
  }

  // 防护状态药丸
  const pill = $('globalPill');
  if (pill) {
    pill.textContent = settings.enabledGlobal ? '防护中' : '已关闭';
    pill.className = 'pill' + (settings.enabledGlobal ? '' : ' off');
  }
  const appEl = document.querySelector('.app');
  if (appEl) appEl.classList.toggle('guarding', !!settings.enabledGlobal);
  loadPopupStats();
  loadCurrentSite();

  // 两个入口：直接打开设置页对应子页面（#sec=<id> 由 options.js 接管跳转）
  const base = chrome.runtime.getURL('ui/options.html');
  const openSettings = $('openSettings');
  if (openSettings) openSettings.addEventListener('click', () => chrome.tabs.create({ url: base + '#sec=detect' }));
  const openReport = $('openReport');
  if (openReport) openReport.addEventListener('click', () => chrome.tabs.create({ url: base + '#sec=about' }));

  const ppMore = $('ppMore');
  if (ppMore) ppMore.addEventListener('click', () => chrome.tabs.create({ url: base + '#sec=stats' }));
  // 左下角：跳转「规则与名单」页（信任域名 / 自定义关键词 / 黑名单 / 威胁情报 API）
  const ppRules = $('ppRules');
  if (ppRules) ppRules.addEventListener('click', () => chrome.tabs.create({ url: base + '#sec=rules' }));
}

init();
