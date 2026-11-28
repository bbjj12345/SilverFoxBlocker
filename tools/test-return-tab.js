#!/usr/bin/env node
/**
 * tools/test-return-tab.js —— 说明页「返回上一页」焦点回归的测试（2026-11-28）
 *
 * 跑法：node tools/test-return-tab.js
 *
 * 背景：说明页由后台 chrome.tabs.create 打开、排在最右侧，页面自己 window.close()
 *   之后 Chrome 会把焦点交给左邻（打开前的最后一个标签页），用户看到的就成了
 *   「关掉说明页 + 焦点跳到最右边那个标签」，并没有回到触发拦截的页面。
 *   修法是后台记一张「新标签页 id → 来源标签页 id」，返回时先激活来源页再关自己。
 *
 * 覆盖什么：
 *   1) 记录与消费：sfRememberReturnTab 只收数字、拒绝自指，超过 20 条丢最旧；
 *   2) 正常路径：先 tabs.update(active) → windows.update(focused) → 再 tabs.remove，
 *      顺序错就会「先关后激活」，焦点仍可能落回左邻；
 *   3) 没记录（手动粘贴打开）/ 来源页已关：只关自己，返回 returned=false 让页面走旧兜底；
 *   4) 消费后清账：同一条记录不会被第二次使用。
 *
 * 为什么要单独留这份测试：这段逻辑的正确性全靠「调用顺序」和「谁先谁后关」，
 *   错一处就是「点了返回，页面还在 / 焦点去了别的标签」，而且只在真浏览器里才看得出来。
 */
'use strict';

const fs = require('fs');
const path = require('path');

const BG = path.join(__dirname, '..', 'background.js');

function extractHelpers() {
  const code = fs.readFileSync(BG, 'utf8');
  const start = code.indexOf("const SF_RETURN_KEY = 'sfReturnTabs';");
  // 注意：文件里还留着一条被注释掉的旧 onMessage 监听器，必须从 start 之后找
  const end = code.indexOf('chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {', start);
  if (start < 0 || end < 0 || end <= start) throw new Error('未能在 background.js 里定位到返回标签页的实现段');
  const src = code.slice(start, end);
  // 用 Function 包一层：只在测试沙箱里跑这一小段，不执行 background.js 的其余初始化
  return new Function('chrome', src + '\nreturn { remember: sfRememberReturnTab, forget: sfForgetReturnTab,'
    + ' close: sfCloseTabAndReturn, read: sfReadReturnTabs, table: function () { return sfReturnTabs; } };');
}

function makeEnv(opts) {
  opts = opts || {};
  const log = [];
  const session = { sfReturnTabs: Object.assign({}, opts.table || {}) };
  const liveTabs = new Set(opts.liveTabs || []);
  const chrome = {
    runtime: { lastError: null },
    storage: {
      session: {
        get: function (defaults, cb) {
          const out = {};
          Object.keys(defaults || {}).forEach(function (k) {
            out[k] = (k in session) ? session[k] : defaults[k];
          });
          cb(out);
        },
        set: function (obj, cb) { Object.assign(session, obj); if (cb) cb(); }
      }
    },
    tabs: {
      get: function (id, cb) {
        log.push(['get', id]);
        if (!liveTabs.has(id)) {
          chrome.runtime.lastError = { message: 'No tab with id: ' + id };
          cb(undefined);
          chrome.runtime.lastError = null;
          return;
        }
        cb({ id: id, windowId: opts.windowId || 1 });
      },
      update: function (id, props, cb) { log.push(['update', id, props && props.active]); if (cb) cb({ id: id }); },
      remove: function (id, cb) { log.push(['remove', id]); if (cb) cb(); }
    },
    windows: {
      update: function (id, props, cb) { log.push(['window', id, props && props.focused]); if (cb) cb({ id: id }); }
    }
  };
  return { chrome: chrome, log: log, session: session };
}

let pass = 0;
let fail = 0;
function ok(name, cond, extra) {
  if (cond) { pass++; console.log('  ✓ ' + name); }
  else { fail++; console.log('  ✗ ' + name + (extra ? '  →  ' + extra : '')); }
}
function eq(name, actual, expected) {
  ok(name, JSON.stringify(actual) === JSON.stringify(expected), '实际 ' + JSON.stringify(actual));
}

const build = extractHelpers();

// ---------------------------------------------------------------------------
console.log('\n[1] 记录的收与放');
{
  const env = makeEnv({});
  const api = build(env.chrome);

  api.remember(101, 7);
  eq('记下 101 → 7', env.session.sfReturnTabs['101'], 7);

  api.remember(101, 101);
  eq('拒绝自指（新页 = 来源页）', env.session.sfReturnTabs['101'], 7);

  api.remember('102', 7);
  eq('拒绝非数字 id', env.session.sfReturnTabs['102'], undefined);

  for (let i = 200; i < 230; i++) api.remember(i, 7);
  ok('超过 20 条后丢最旧', Object.keys(env.session.sfReturnTabs).length === 20,
    '实际 ' + Object.keys(env.session.sfReturnTabs).length + ' 条');

  api.forget(229);
  eq('consume 后能清账', env.session.sfReturnTabs['229'], undefined);
}
{
  const env = makeEnv({});
  const api = build(env.chrome);
  api.read(function (map) { eq('read 取回存储里的表', Object.keys(map).length, 0); });
}

// ---------------------------------------------------------------------------
console.log('\n[2] 正常路径：先激活来源页，再关自己');
{
  const env = makeEnv({ table: { 55: 33 }, liveTabs: [33, 55] });
  const api = build(env.chrome);
  let res = null;
  api.close(55, function (r) { res = r; });

  eq('返回 returned=true', res, { ok: true, returned: true });
  eq('调用顺序 = 查来源页 → 激活 → 提窗口 → 关自己',
    env.log,
    [['get', 33], ['update', 33, true], ['window', 1, true], ['remove', 55]]);
  eq('关掉的是说明页本身', env.log[env.log.length - 1], ['remove', 55]);
  eq('消费后清账', env.session.sfReturnTabs['55'], undefined);
}

// ---------------------------------------------------------------------------
console.log('\n[3] 异常路径：只关自己，交回浏览器默认行为');
{
  const env = makeEnv({ table: {}, liveTabs: [55] });
  const api = build(env.chrome);
  let res = null;
  api.close(55, function (r) { res = r; });
  eq('没记录 → returned=false(NO-ORIGIN)', res, { ok: true, returned: false, reason: 'no-origin' });
  eq('没记录时不乱激活别的标签', env.log, [['remove', 55]]);
}
{
  const env = makeEnv({ table: { 55: 33 }, liveTabs: [55] });   // 33 已被用户关掉
  const api = build(env.chrome);
  let res = null;
  api.close(55, function (r) { res = r; });
  eq('来源页已关 → returned=false(ORIGIN-GONE)', res, { ok: true, returned: false, reason: 'origin-gone' });
  eq('来源页已关时仍然关掉自己', env.log, [['get', 33], ['remove', 55]]);
  eq('失效记录被清掉', env.session.sfReturnTabs['55'], undefined);
}

// ---------------------------------------------------------------------------
console.log('\n[4] 二次点击不会重复消费');
{
  const env = makeEnv({ table: { 55: 33 }, liveTabs: [33, 55] });
  const api = build(env.chrome);
  let first = null;
  let second = null;
  api.close(55, function (r) { first = r; });
  api.close(55, function (r) { second = r; });
  ok('第一次 returned=true', first && first.returned === true);
  ok('第二次变成 no-origin（记录已消费）', second && second.returned === false && second.reason === 'no-origin');
}

// ---------------------------------------------------------------------------
console.log('\n[5] 代码层面的护栏');
{
  const bg = fs.readFileSync(BG, 'utf8');
  ok('SF_OPEN_TAB 会记下来源标签页', bg.indexOf('sfRememberReturnTab(tab.id, srcTabId)') >= 0);
  ok('tabs.create 带 openerTabId', bg.indexOf('createOpts.openerTabId = srcTabId') >= 0);
  ok('openerTabId 失败时能重开（不至于打不开说明页）', bg.indexOf('chrome.tabs.create({ url: u, active: msg.active !== false }, onCreated)') >= 0);
  ok('存在 SF_CLOSE_RETURN 分支', bg.indexOf("msg.type === 'SF_CLOSE_RETURN'") >= 0);
  ok('旧实现以注释形式保留', /旧实现（保留备查）[\s\S]{0,400}SF_OPEN_TAB/.test(bg));

  const page = fs.readFileSync(path.join(__dirname, '..', 'ui', 'no-correct-site.js'), 'utf8');
  ok('说明页改为走后台', page.indexOf("type: 'SF_CLOSE_RETURN'") >= 0);
  ok('说明页保留本地兜底 legacyClose', page.indexOf('function legacyClose()') >= 0);
  ok('说明页旧实现以注释形式保留', page.indexOf('旧实现（保留备查）') >= 0);
}

console.log('\n通过 ' + pass + ' / ' + (pass + fail));
process.exit(fail ? 1 : 0);
