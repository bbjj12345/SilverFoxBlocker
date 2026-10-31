/* popup.js — SilverFoxBlocker 弹出面板逻辑 */
'use strict';

const DEFAULTS = {
  enabledGlobal: true,
  fontMode: 'system',   // 'system' | 'smiley'
  theme: 'dark',        // 'dark' | 'light'
  themePalette: 'classic', // 'classic' | 'gold' | 'neon' | 'mist' | 'space' | 'pixel'
  material: 'frosted',  // 'frosted' | 'liquid'
  bgImage: '',          // 自定义背景 dataURL
  fontScale: 1          // 0.85 ~ 1.40，界面字号缩放系数
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
    recent.slice(0, 5).forEach((x) => {
      const lv = x.level || 'safe';
      const li = document.createElement('li');
      const dot = document.createElement('span'); dot.className = 'rdot'; dot.style.background = LEVEL_COLOR[lv] || '#888';
      const h = document.createElement('span'); h.className = 'h'; h.textContent = x.hostname || '未记录域名';
      const t = document.createElement('span'); t.className = 's'; t.textContent = formatAbsTime(x.time);
      li.append(dot, h, t);
      list.appendChild(li);
    });
  });
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

  // 两个入口：直接打开设置页对应子页面（#sec=<id> 由 options.js 接管跳转）
  const base = chrome.runtime.getURL('ui/options.html');
  const openSettings = $('openSettings');
  if (openSettings) openSettings.addEventListener('click', () => chrome.tabs.create({ url: base + '#sec=detect' }));
  const openReport = $('openReport');
  if (openReport) openReport.addEventListener('click', () => chrome.tabs.create({ url: base + '#sec=about' }));

  const ppMore = $('ppMore');
  if (ppMore) ppMore.addEventListener('click', () => chrome.tabs.create({ url: base + '#sec=stats' }));
}

init();
