/* popup.js — 银狐防护弹出面板逻辑 */
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

  // 两个入口：直接打开设置页对应子页面（#sec=<id> 由 options.js 接管跳转）
  const base = chrome.runtime.getURL('ui/options.html');
  const openSettings = $('openSettings');
  if (openSettings) openSettings.addEventListener('click', () => chrome.tabs.create({ url: base + '#sec=detect' }));
  const openReport = $('openReport');
  if (openReport) openReport.addEventListener('click', () => chrome.tabs.create({ url: base + '#sec=about' }));
}

init();
