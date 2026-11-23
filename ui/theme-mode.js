/* theme-mode.js — SilverFoxBlocker 明暗模式控制器（2026-11-23）
 *
 * 四种模式（设置页侧边栏底部「防护中」上方 / 弹窗底部四个文字按钮）：
 *   dark           黑暗 —— 现有默认外观（不改动任何既有样式）
 *   light          明亮 —— 把设置页与弹窗的底色 / 文字做反色（复用 CSS 里已有的 html.theme-light 配色）
 *   system         跟随系统 —— 系统深色→深色，系统浅色→浅色
 *   system-invert  反转系统 —— 系统深色→浅色，系统浅色→深色
 *
 * 为什么不用 filter: invert()
 *   反色滤镜会连「防护中」（绿）、「高危」（红）、「可疑」（黄）、威胁情报横幅与 toast 一起反掉，
 *   而这些是语义色、反了会误读。这里只切换 html 上的 theme-light 类，状态色一条规则都不覆盖，
 *   因此它们在任何模式下都保持原色。
 *
 * 对外接口：window.SFThemeMode = { MODES, LABELS, init, set, get, isLight, resolve }
 *   isLight() 同步读取 html[data-color-resolved]，供 options.js 的 applyAppearance() 复用，
 *   避免两套逻辑互相覆盖 theme-light 类。
 */
(function () {
  'use strict';

  var KEY = 'colorMode';
  var MODES = ['dark', 'light', 'system', 'system-invert'];
  var LABELS = { dark: '黑暗', light: '明亮', system: '跟随系统', 'system-invert': '反转系统' };
  var root = document.documentElement;
  var mql = (window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null);
  var current = 'dark';

  function norm(mode) { return MODES.indexOf(mode) >= 0 ? mode : 'dark'; }

  /* 规则 → 实际渲染的明暗。system / system-invert 只在设置变化或系统切换时求值一次。 */
  function resolve(mode) {
    mode = norm(mode);
    if (mode === 'light') return 'light';
    if (mode === 'system') return (mql && mql.matches) ? 'dark' : 'light';
    if (mode === 'system-invert') return (mql && mql.matches) ? 'light' : 'dark';
    return 'dark';
  }

  function paint(mode) {
    current = norm(mode);
    var real = resolve(current);
    root.setAttribute('data-color-mode', current);
    root.setAttribute('data-color-resolved', real);
    root.classList.toggle('theme-light', real === 'light');
    var btns = document.querySelectorAll('.mode-btn');
    for (var i = 0; i < btns.length; i++) {
      var on = btns[i].getAttribute('data-mode') === current;
      btns[i].classList.toggle('active', on);
      btns[i].setAttribute('aria-pressed', on ? 'true' : 'false');
    }
    /* 本地镜像：下次打开设置页 / 弹窗时先同步落一次，避免首帧闪一下深色 */
    try { localStorage.setItem('sfColorMode', current); } catch (e) {}
  }

  function save(mode) {
    paint(mode);
    try { chrome.storage.sync.set({ colorMode: current }); } catch (e) {}
  }

  function onClick(ev) {
    var t = ev.target;
    var btn = (t && t.closest) ? t.closest('.mode-btn') : null;
    if (!btn) return;
    ev.preventDefault();
    save(btn.getAttribute('data-mode'));
  }

  function watchSystem() {
    if (!mql) return;
    var fn = function () {
      if (current === 'system' || current === 'system-invert') paint(current);
    };
    if (mql.addEventListener) mql.addEventListener('change', fn);
    else if (mql.addListener) mql.addListener(fn);
  }

  function init() {
    try {
      var cached = localStorage.getItem('sfColorMode');
      if (cached) paint(cached);
    } catch (e) {}
    try {
      chrome.storage.sync.get({ colorMode: 'dark' }, function (s) {
        paint((s && s.colorMode) || 'dark');
      });
    } catch (e) { /* 非扩展环境（本地直接打开 HTML）：沿用本地镜像 / 默认深色 */ }
    watchSystem();
    document.addEventListener('click', onClick, false);
    try {
      chrome.storage.onChanged.addListener(function (ch, area) {
        if (area === 'sync' && ch && ch[KEY]) paint(ch[KEY].newValue);
      });
    } catch (e) {}
  }

  window.SFThemeMode = {
    MODES: MODES,
    LABELS: LABELS,
    init: init,
    set: save,
    get: function () { return current; },
    resolve: resolve,
    isLight: function () { return root.getAttribute('data-color-resolved') === 'light'; }
  };

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
