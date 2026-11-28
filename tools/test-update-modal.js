#!/usr/bin/env node
/**
 * tools/test-update-modal.js —— 版本更新弹窗的测试（2026-11-29，v2）
 *
 * 跑法：node tools/test-update-modal.js
 *
 * 背景：手动「检查更新」与后台「自动检查更新」此前各写一行小字，文案不同、也没有下载入口。
 *   现在两条路都走 options.js 的 sfAnnounceNewVersion()，查到新版本就弹同一个窗。
 *
 * v2（2026-11-29 晚）改了三件事，这个文件同时钉住它们：
 *   1) 「稍后」只在本次页面加载内生效（内存），刷新 / 重开 / 再开一个标签会再提醒一次；
 *      同一页内的子页切换不会重复弹。
 *   2) 每次页面加载先走一段「正在检查更新……」伪横幅（顶部胶囊 + 透明挡板），
 *      短暂挡住鼠标操作，结论回来再决定弹不弹。
 *   3) 焦点兜底：用户正在输入框里打字就挂起，blur 后或最多 6 秒再弹（6 秒那次不抢焦点）。
 */
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const OPT_JS = path.join(ROOT, 'ui', 'options.js');
const OPT_HTML = path.join(ROOT, 'ui', 'options.html');
const OPT_CSS = path.join(ROOT, 'ui', 'options.css');
const BG_JS = path.join(ROOT, 'background.js');

const js = fs.readFileSync(OPT_JS, 'utf8');
const html = fs.readFileSync(OPT_HTML, 'utf8');
const css = fs.readFileSync(OPT_CSS, 'utf8');
const bg = fs.readFileSync(BG_JS, 'utf8');

let pass = 0, fail = 0;
function t(name, cond) {
  if (cond) { pass++; console.log('  ✓ ' + name); }
  else { fail++; console.log('  ✗ ' + name); }
}
function group(name) { console.log('\n' + name); }

/* ---------------- 1. 结构 ---------------- */
group('弹窗结构（ui/options.html）');
t('弹窗容器 #updateModal 存在且只有一个', (html.match(/id="updateModal"/g) || []).length === 1);
t('弹窗是 .modal-overlay + .modal（继承四套外观主题）',
  /class="modal-overlay" id="updateModal"[\s\S]{0,400}class="modal upd-modal"/.test(html));
t('标题是「发现新版本」', /id="updTitle"[^>]*>发现新版本</.test(html));
t('有「最新版本」与「当前版本」两栏', /最新版本/.test(html) && /当前版本/.test(html));
t('最新版本号容器 #updLatest', /id="updLatest"/.test(html));
t('当前版本号容器 #updCurrent', /id="updCurrent"/.test(html));
t('「稍后」按钮 #updLater', /id="updLater"[^>]*>稍后</.test(html));
t('「立即更新」按钮 #updNow', /id="updNow"[^>]*>立即更新</.test(html));
t('两个按钮都是 type="button"（避免在表单里回车提交）',
  /id="updLater" type="button"/.test(html) && /id="updNow" type="button"/.test(html));
t('「立即更新」在主按钮位（btn-primary），「稍后」为中性次要样式（不是红色 btn-ghost）',
  /class="btn upd-secondary" id="updLater"/.test(html) && /class="btn btn-primary" id="updNow"/.test(html));
t('弹窗带 aria-modal / aria-labelledby（可被读屏识别）',
  /role="dialog" aria-modal="true" aria-labelledby="updTitle"/.test(html));
t('options.js 缓存戳已更新到 20261129c', /options\.js\?v=20261129c/.test(html));

group('伪横幅结构（ui/options.html）');
t('横幅 #updateBusy 默认 hidden（不占位、不闪）', /id="updateBusy" hidden/.test(html));
t('横幅文案节点 #updateBusyTxt', /id="updateBusyTxt"/.test(html));
t('横幅带 role="status" / aria-live（读屏会念一句，不打断）',
  /id="updateBusy" hidden role="status" aria-live="polite"/.test(html));
t('挡板 #updateShield 默认 hidden', /id="updateShield" hidden/.test(html));
t('横幅在弹窗之前（层级由 CSS 控制，DOM 顺序不影响）',
  html.indexOf('id="updateBusy"') < html.indexOf('id="updateModal"'));

group('样式（ui/options.css）');
t('.upd-modal 有独立宽度', /\.upd-modal\s*\{[^}]*width:\s*min\(/.test(css));
t('版本号两栏用 flex 等分', /\.modal \.upd-vers\s*\{[^}]*display:\s*flex/.test(css));
t('最新版本那栏有绿色强调', /\.modal \.upd-v\.is-new b\s*\{[^}]*color:\s*#3ddc84/.test(css));
t('明亮模式有对应配色', /html\.theme-light \.modal \.upd-v\.is-new b/.test(css));
t('「版本更新」行高亮动画存在', /@keyframes sfRowFlash\s*\{/.test(css) && /\.about-row\.is-flash\s*\{[^}]*animation:\s*sfRowFlash/.test(css));
t('明亮模式有独立的高亮动画', /@keyframes sfRowFlashLight\s*\{/.test(css));
t('「稍后」按钮有中性样式（深浅两套）',
  /\.upd-modal \.btn\.upd-secondary\s*\{/.test(css) && /html\.theme-light \.upd-modal \.btn\.upd-secondary\s*\{/.test(css));
t('伪横幅有胶囊样式与转圈', /\.upd-busy\s*\{[^}]*position:\s*fixed/.test(css) && /@keyframes updBusySpin/.test(css));
t('挡板透明、只吃指针事件（非模态，不暗化页面）',
  /\.upd-shield\s*\{[^}]*background:\s*transparent[^}]*cursor:\s*progress/.test(css));
t('挡板层级低于 .modal-overlay（真弹窗时不会被挡）',
  /\.upd-shield\s*\{[^}]*z-index:\s*90/.test(css) && /\.modal-overlay\s*\{[^}]*z-index:\s*100/.test(css));
t('挡板期间光标提示 progress', /html\.upd-busy-on \.sidebar \.nav-item\s*\{[^}]*cursor:\s*progress/.test(css));
t('「减弱动画」下横幅不转圈、不播动画',
  /html\.reduce-motion \.upd-busy-spin\s*\{[^}]*animation:\s*none !important/.test(css) &&
  /html\.reduce-motion \.upd-busy\s*\{[^}]*animation:\s*none !important/.test(css));

/* ---------------- 2. 接线 ---------------- */
group('两条路径统一到 sfAnnounceNewVersion（ui/options.js）');
t('手动检查命中新版本时调用统一入口', /sfAnnounceNewVersion\(rel\.tag, cur, \{ source: 'manual', force: true \}\)/.test(js));
t('自动检查（storage 回读 / onChanged）也调用统一入口', /sfAnnounceNewVersion\(info\.latest, cur, \{ source: 'auto' \}\)/.test(js));
t('自动检查用「当前真实版本」重算，而不是信 info.newer', /sfCmpVersion\(info\.latest, cur\) <= 0\)\s*return;/.test(js));
t('自动检查监听 storage.onChanged（停在设置页也能弹）', /chrome\.storage\.onChanged\.addListener/.test(js));
t('bindControls 里挂上弹窗绑定与自动监听', /sfBindUpdateModal\(\);\s*\n\s*sfWatchAutoUpdate\(\);/.test(js));
t('旧的 autoUpdateTip 单独回显已注释保留', /---- 旧（2026-11-29 前）：自动检查的结果单独写一行 autoUpdateTip ----/.test(js));
t('旧的「只写一行小字」实现已注释保留', /旧（2026-11-29 前）：只写一行小字，没有弹窗/.test(js));
t('旧的「写 storage.local 永久稍后」已注释保留', /旧（2026-11-29 晚之前）：写进 storage\.local，永久生效/.test(js));

group('「立即更新」不打开新标签页');
const modalSrc = js.slice(js.indexOf('const SF_UPD_DISMISS_KEY'), js.indexOf('function sfBindUpdateModal'));
t('弹窗模块里没有 window.open', !/window\.open/.test(modalSrc));
t('弹窗模块里没有 chrome.tabs.create', !/chrome\.tabs\.create/.test(modalSrc));
t('sfGoAboutUpdateRow 走本页导航（findNavForTarget + click）',
  /const nav = findNavForTarget\('about'\);[\s\S]{0,120}nav\.click\(\)/.test(js));
t('「版本更新」行只有 data-page-node-id、没有 id（getElementById 会拿到 null）',
  /data-page-node-id="SF_UC_ROW_VER"/.test(html) && !/class="about-row" id="SF_UC_ROW_VER"/.test(html));
t('定位该行用 querySelector + data-page-node-id（id 只作兜底）',
  /querySelector\('\[data-page-node-id="SF_UC_ROW_VER"\]'\)/.test(js) && /classList\.add\('is-flash'\)/.test(js));
t('闪烁两次（animation-iteration-count: 2）',
  /animation:\s*sfRowFlash\s+[\d.]+s\s+ease-in-out\s+2/.test(css));
t('「减弱动画」下有恒亮兜底（不会因为全局 0.001ms 而看不见）',
  /html\.reduce-motion \.about-row\.is-flash\s*\{[^}]*animation:\s*none !important/.test(css));
t('高亮会在 3.4s 后撤掉（比 2.7s 的两次闪烁更晚，不切尾）', /row\.classList\.remove\('is-flash'\); \}, 3400\)/.test(js));
// 旧实现以注释形式留在源码里，所以先剥掉注释再判断「当前是否真的没有绑定」
const jsLive = js.replace(/\/\*[\s\S]*?\*\//g, '');
t('点遮罩空白处不再绑定关闭（误关成本太高）', !/ov\.addEventListener\('click'/.test(jsLive));
t('Esc 仍可关闭（键盘用户有出路）', /e\.key === 'Escape' \|\| e\.key === 'Esc'/.test(js));

group('后台配合（background.js）');
t('设置页打开时问「到点了没」不会 force 跳过闸门',
  /SF_AUTO_CHECK_IF_DUE[\s\S]{0,200}sfAutoCheckUpdate\(false\)/.test(bg));
t('开关刚打开仍然 force（明确意图）', /SF_AUTO_CHECK_NOW[\s\S]{0,200}sfAutoCheckUpdate\(true\)/.test(bg));
t('有闸门（距上次成功 ≥ 周期 90% 才算到点）', /SF_AUTO_DUE_RATIO\s*=\s*0?\.\d+/.test(bg));
t('单轮锁避免「启动补偿」与「首声闹钟」同时发两轮', /sfAutoVerInFlight/.test(bg) && /sfAutoCloudInFlight/.test(bg));
t('失败不写时间戳（断网开机不会被记成「已跑过」）',
  /sfAutoMarkRun\(SF_AUTO_LAST_VER_KEY\)/.test(bg) &&
  /sfAutoMarkRun\(SF_AUTO_LAST_CLOUD_KEY\)/.test(bg));
t('浏览器启动与扩展安装/更新都会补一次',
  /chrome\.runtime\.onStartup\.addListener\(function \(\) \{ sfAutoCatchUp/.test(bg) &&
  /onInstalled[\s\S]{0,200}sfAutoCatchUp/.test(bg));

/* ---------------- 3. 行为（假 DOM 跑真实代码） ---------------- */
group('行为：把真实代码抽出来跑');

const block = js.slice(js.indexOf('const SF_UPD_DISMISS_KEY'), js.indexOf('function sfWatchAutoUpdate'));
const _watchAt = js.indexOf('function sfWatchAutoUpdate');
const _watchEnd = js.lastIndexOf('/*', js.indexOf('* 云端名单同步（关于页', _watchAt));
const watchBlock = js.slice(_watchAt, _watchEnd);
const cmpSrc = js.slice(js.indexOf('function sfNormTag'), js.indexOf('// 直连 api.github.com 读 tag'));
const normSrc = js.slice(js.indexOf('function sfNormTag'), js.indexOf('function sfCmpVersion'));

function mkEl(id, tag) {
  const cls = new Set();
  return {
    id: id, tagName: tag || 'DIV', textContent: '', hidden: false, offsetWidth: 0,
    classList: {
      add: (c) => cls.add(c), remove: (c) => cls.delete(c),
      contains: (c) => cls.has(c), toggle: (c, on) => { on ? cls.add(c) : cls.delete(c); },
      _set: cls
    },
    _handlers: {},
    addEventListener: function (ev, fn) { (this._handlers[ev] = this._handlers[ev] || []).push(fn); },
    fire: function (ev, arg) { (this._handlers[ev] || []).forEach((f) => f(arg || { target: this })); return this; },
    focus: function () { this._focused = true; },
    scrollIntoView: function () { this._scrolled = true; },
    click: function () { this._clicked = true; }
  };
}

function makeEnv(opts) {
  opts = opts || {};
  const els = {};
  ['updateModal', 'updLatest', 'updCurrent', 'updSrc', 'updLater', 'updNow',
    'checkUpdateTip', 'autoUpdateTip', 'checkUpdateBtn',
    'updateBusy', 'updateShield', 'updateBusyTxt'].forEach((id) => { els[id] = mkEl(id); });
  els.updateBusy.hidden = true;
  els.updateShield.hidden = true;
  const row = mkEl('SF_UC_ROW_VER');
  const nav = mkEl('nav-about', 'BUTTON');

  const store = opts.store || {};
  const timers = [];
  const saved = {};
  const docHandlers = {};
  const rootCls = new Set();
  const sent = [];

  const chrome = {
    storage: {
      local: {
        get: function (defs, cb) { cb(Object.assign({}, defs, store)); },
        set: function (obj, cb) { Object.keys(obj).forEach((k) => { saved[k] = obj[k]; store[k] = obj[k]; }); if (cb) cb(); }
      },
      sync: {
        get: function (defs, cb) { cb(Object.assign({}, defs, opts.sync || {})); }
      },
      onChanged: { addListener: function (fn) { chrome.__onChanged = fn; } }
    },
    runtime: {
      lastError: null,
      sendMessage: function (msg, cb) {
        sent.push(msg);
        if (opts.holdMessage) return;            // 模拟「后台迟迟不回」
        if (cb) cb(opts.messageReply || { ok: true });
      }
    }
  };
  // 只对已知 id 返回元素；其他 id 返回 null（真实页面里也大多不存在）
  // 关键：getElementById 只认真实存在的 id —— 页面里「版本更新」行没有 id，
  // 上一版这里顺手把 row 也返回给 getElementById，于是掩盖了真实 bug（永远不会高亮）。
  const $ = function (id) { return els[id] || null; };
  const document = {
    activeElement: opts.activeElement || null,
    documentElement: {
      classList: {
        add: (c) => rootCls.add(c), remove: (c) => rootCls.delete(c), contains: (c) => rootCls.has(c)
      }
    },
    getElementById: function (id) { return els[id] || null; },
    querySelector: function (sel) {
      return sel === '[data-page-node-id="SF_UC_ROW_VER"]' ? row : null;
    },
    addEventListener: function (ev, fn) { (docHandlers[ev] = docHandlers[ev] || []).push(fn); },
    removeEventListener: function (ev, fn) {
      const a = docHandlers[ev] || []; const i = a.indexOf(fn); if (i >= 0) a.splice(i, 1);
    },
    fire: function (ev, arg) { (docHandlers[ev] || []).slice().forEach((f) => f(arg || {})); },
    _has: function (ev, fn) { return (docHandlers[ev] || []).indexOf(fn) >= 0; }
  };
  const findNavForTarget = function (id) { return id === 'about' ? nav : null; };

  // 短延时（<500ms）立刻执行：模拟「同一帧内完成」；长延时先挂起，由 flush() 推进，
  // 否则 3.4s 撤高亮、6s 焦点兜底、2.2s 横幅兜底会在断言之前就自己跑掉。
  function fakeTimeout(fn, delay) {
    if (!delay || delay <= 500) { fn(); return 0; }
    timers.push(fn);
    return timers.length;
  }
  function flush() {
    let guard = 40;
    while (guard-- > 0) {
      const batch = timers.splice(0);
      if (!batch.length) return;
      batch.forEach((f) => { try { f(); } catch (e) {} });
    }
  }

  const factory = new Function(
    'document', 'chrome', 'hasStorageLocal', 'sfOwnVersion', 'findNavForTarget', '$', 'setTimeout',
    normSrc + '\n' + cmpSrc + '\n' + block + '\n' + watchBlock +
    '\nreturn { announce: sfAnnounceNewVersion, bind: sfBindUpdateModal, watch: sfWatchAutoUpdate, ' +
    'consider: sfUpdConsider, hide: sfUpdHide, busy: function () { return { bar: $("updateBusy"), shield: $("updateShield"), root: document.documentElement.classList.contains("upd-busy-on") }; }, ' +
    'state: function () { return _sfUpdDismissed; } };'
  );
  const api = factory(
    document, chrome, function () { return true; },
    function () { return opts.localVer || '1.14.10'; },
    findNavForTarget, $, fakeTimeout
  );
  return {
    api: api, els: els, row: row, nav: nav, chrome: chrome, saved: saved, store: store,
    timers: timers, flush: flush, sent: sent, document: document, rootCls: rootCls
  };
}

// —— 3.1 自动检查查到新版本 → 弹窗，版本号正确 ——
{
  const e = makeEnv();
  e.api.bind();
  e.api.announce('1.15.0', '1.14.10', { source: 'auto' });
  t('自动检查：没被稍后过 → 弹窗', e.els.updateModal.classList.contains('show'));
  t('最新版本显示 v1.15.0', e.els.updLatest.textContent === 'v1.15.0');
  t('当前版本显示 v1.14.10', e.els.updCurrent.textContent === 'v1.14.10');
  t('版本行小字与弹窗同一句', e.els.checkUpdateTip.textContent === '检测到新版本：v1.15.0');
  t('不再单独写 autoUpdateTip（合并成一行）', e.els.autoUpdateTip.hidden === true);

  // 点「稍后」：关窗 + 只在本次会话里记住
  e.els.updLater.fire('click');
  t('「稍后」关掉弹窗', !e.els.updateModal.classList.contains('show'));
  t('「稍后」不再写 storage.local（v2 改为会话内记忆）', !e.saved.sfUpdatePopupDismissed);
  t('「稍后」后焦点回到「检查更新」（键盘用户不迷路）', e.els.checkUpdateBtn._focused === true);

  // 同一页内、同一版本再来一次自动检查 → 不打扰
  e.api.announce('1.15.0', '1.14.10', { source: 'auto' });
  t('同一页同一版本再次自动检查 → 不再弹', !e.els.updateModal.classList.contains('show'));

  // 手动检查同一版本 → 仍然弹（用户主动点的）
  e.api.announce('1.15.0', '1.14.10', { source: 'manual', force: true });
  t('同一版本手动检查 → 仍然弹', e.els.updateModal.classList.contains('show'));
}

// —— 3.1b 同一页内：没按稍后也不重复弹（子页来回切不该反复打扰） ——
{
  const e = makeEnv();
  e.api.bind();
  e.api.announce('1.15.0', '1.14.10', { source: 'auto' });
  e.api.hide();                                   // 用户点了「立即更新」或后面被别的东西关掉
  e.api.announce('1.15.0', '1.14.10', { source: 'auto' });
  t('同一页内已播报过的版本 → 关掉后不再自己弹回来', !e.els.updateModal.classList.contains('show'));

  e.api.announce('1.15.1', '1.14.10', { source: 'auto' });
  t('出现更高的版本 → 照常弹', e.els.updateModal.classList.contains('show'));
  t('更高版本号已回填', e.els.updLatest.textContent === 'v1.15.1');
}

// —— 3.2 「立即更新」：只切页 + 高亮，不新开标签 ——
{
  const e = makeEnv();
  e.api.bind();
  e.api.announce('1.15.0', '1.14.10', { source: 'manual' });
  e.els.updNow.fire('click');
  t('「立即更新」关掉弹窗', !e.els.updateModal.classList.contains('show'));
  t('「立即更新」切到「关于」（本页导航被点击）', e.nav._clicked === true);
  t('「立即更新」高亮「版本更新」行', e.row.classList.contains('is-flash'));
  t('「立即更新」没有留下「已稍后」记录', !e.saved.sfUpdatePopupDismissed);
}

// —— 3.2b 点遮罩空白处不再关闭 ——
{
  const e = makeEnv();
  e.api.bind();
  e.api.announce('1.15.0', '1.14.10', { source: 'manual' });
  e.els.updateModal.fire('click', { target: e.els.updateModal });   // 点在遮罩本身（空白处）
  t('点遮罩空白处 → 弹窗仍然打开', e.els.updateModal.classList.contains('show'));
  t('点空白处不会被记成「稍后」', !e.saved.sfUpdatePopupDismissed);
  e.els.updLater.fire('click');
  t('点「稍后」才真正关闭', !e.els.updateModal.classList.contains('show'));
}

// —— 3.3 已经是最新版本 / 线上更低 → 不弹 ——
{
  const e = makeEnv({ store: { sfAutoUpdate: { latest: '1.14.10', local: '1.14.10', newer: true } } });
  e.api.bind();
  e.api.consider(e.store.sfAutoUpdate);
  t('后台记录与当前版本相同 → 不弹（不信过期的 newer 标记）', !e.els.updateModal.classList.contains('show'));

  e.api.consider({ latest: '1.13.0', local: '1.14.10', newer: true });
  t('线上版本反而更低（本地测试版）→ 不弹', !e.els.updateModal.classList.contains('show'));

  e.api.consider({ latest: '1.16.2', local: '1.14.10', newer: true });
  t('更高的版本 → 立刻弹', e.els.updateModal.classList.contains('show'));
  t('弹窗里的版本号正确', e.els.updLatest.textContent === 'v1.16.2');
}

// —— 3.4 重开设置页：上次按过「稍后」的版本仍然提醒（v2 的核心变化） ——
{
  const e = makeEnv({ store: { sfUpdatePopupDismissed: '1.15.0', sfAutoUpdate: { latest: '1.15.0' } } });
  e.api.bind();
  e.api.watch();
  e.flush();
  t('残留的旧 sfUpdatePopupDismissed 被忽略 → 重开会话照常弹',
    e.els.updateModal.classList.contains('show'));
  t('新打开的页面里「已稍后」状态是空的', e.api.state() === null);
}

// —— 3.5 每次页面加载都会问后台「到点了没」并走伪横幅 ——
{
  const e = makeEnv({ store: { sfAutoUpdate: { latest: '1.15.0' } } });
  e.api.bind();
  e.api.watch();
  t('页面加载后横幅显示', e.els.updateBusy.hidden === false);
  t('挡板盖住页面', e.els.updateShield.hidden === false);
  t('html 上有 upd-busy-on（光标提示 progress）', e.rootCls.has('upd-busy-on'));
  t('横幅文案被写成「正在检查更新……」', /^正在检查更新/.test(e.els.updateBusyTxt.textContent));
  t('向后后台发了 SF_AUTO_CHECK_IF_DUE（不 force）',
    e.sent.some((m) => m && m.type === 'SF_AUTO_CHECK_IF_DUE'));
  t('横幅期间还没有弹窗（先挡住操作，再决定）', !e.els.updateModal.classList.contains('show'));

  e.flush();
  t('横幅收起', e.els.updateBusy.hidden === true && e.els.updateShield.hidden === true);
  t('撤掉 upd-busy-on（光标恢复）', !e.rootCls.has('upd-busy-on'));
  t('结论回来后才弹窗', e.els.updateModal.classList.contains('show'));
  t('弹窗版本号来自后台记录', e.els.updLatest.textContent === 'v1.15.0');
}

// —— 3.6 横幅到点自动收（后台迟迟不回也要能收） ——
{
  const e = makeEnv({ store: {}, holdMessage: true });
  e.api.bind();
  e.api.watch();
  t('后台没回应时横幅先显示', e.els.updateBusy.hidden === false);
  e.flush();      // 2.2s 兜底定时器
  t('到点自动收起（不会一直挡着用户）', e.els.updateBusy.hidden === true);
  t('没有新版本 → 不弹窗', !e.els.updateModal.classList.contains('show'));
}

// —— 3.7 Esc 可立刻撤掉横幅（不等到点） ——
{
  const e = makeEnv({ holdMessage: true });
  e.api.bind();
  e.api.watch();
  t('横幅已显示', e.els.updateBusy.hidden === false);
  e.document.fire('keydown', { key: 'Escape' });
  e.flush();
  t('按 Esc → 横幅立刻收起', e.els.updateBusy.hidden === true);
}

// —— 3.8 焦点兜底：用户正在输入框里打字 → 挂起，blur 后弹 ——
{
  const input = mkEl('someInput', 'INPUT');
  const e = makeEnv({ activeElement: input, store: { sfAutoUpdate: { latest: '1.15.0' } } });
  e.api.bind();
  e.api.consider(e.store.sfAutoUpdate);
  t('焦点在输入框 → 先不弹（不抢焦点）', !e.els.updateModal.classList.contains('show'));

  e.document.activeElement = null;
  e.document.fire('focusout', {});
  t('离开输入框后弹窗出现', e.els.updateModal.classList.contains('show'));
  t('这一档正常聚焦「稍后」', e.els.updLater._focused === true);
}

// —— 3.9 焦点兜底：用户一直不走 → 最多 6 秒后弹出，但不抢焦点 ——
{
  const input = mkEl('someInput', 'TEXTAREA');
  const e = makeEnv({ activeElement: input, store: { sfAutoUpdate: { latest: '1.15.0' } } });
  e.api.bind();
  e.api.consider(e.store.sfAutoUpdate);
  t('一直在打字 → 仍然不弹', !e.els.updateModal.classList.contains('show'));
  e.flush();      // 6s 兜底
  t('6 秒后窗摆出来（用户抬头就能看见）', e.els.updateModal.classList.contains('show'));
  t('这一档不抢焦点（「稍后」未被 focus）', e.els.updLater._focused !== true);
}

// —— 3.10 可编辑区同样算「在打字」 ——
{
  const box = mkEl('rich', 'DIV');
  box.isContentEditable = true;
  const e = makeEnv({ activeElement: box, store: { sfAutoUpdate: { latest: '1.15.0' } } });
  e.api.bind();
  e.api.consider(e.store.sfAutoUpdate);
  t('contenteditable 里打字 → 同样挂起', !e.els.updateModal.classList.contains('show'));
}

// —— 3.11 自动检查关着 → 不显示横幅、不发内部消息（不白挡用户 0.5 秒） ——
{
  const e = makeEnv({ sync: { autoCheckUpdate: false }, holdMessage: true });
  e.api.bind();
  e.api.watch();
  t('自动检查关着 → 横幅不出现', e.els.updateBusy.hidden === true);
  t('自动检查关着 → 不向后台问「到点了没」', e.sent.length === 0);
}

// —— 3.12 自动检查关着，但已存着更高版本 → 仍然弹（只是不走横幅） ——
{
  const e = makeEnv({ sync: { autoCheckUpdate: false }, store: { sfAutoUpdate: { latest: '1.16.0' } } });
  e.api.bind();
  e.api.watch();
  t('开关关着也能用已存的结果提醒', e.els.updateModal.classList.contains('show'));
  t('这一档不显示横幅', e.els.updateBusy.hidden === true);
}

console.log('\n' + (fail ? '✗ ' : '✓ ') + 'update-modal: ' + pass + ' passed, ' + fail + ' failed');
process.exit(fail ? 1 : 0);
