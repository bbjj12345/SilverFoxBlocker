#!/usr/bin/env node
/**
 * tools/test-update-badge.js —— 「工具栏红点（新徽标）」+「查到更新发系统通知」的测试
 *                           （2026-11-29）
 *
 * 跑法：node tools/test-update-badge.js
 *
 * 为什么单独测这两个：
 *   1) 徽标这一路在上一版被「只在查成功的那一刻写一次」绑死了。闸门 + 单轮锁上线后，
 *      扩展在 chrome://extensions 里点一次「重新加载」就会把徽标清空，而要等下一轮真正
 *      查成功（最长 6 小时）才会重新亮 —— 用户看到的就是「明明查到 1.14.10 了却没有红点」。
 *      这类问题**不报错、不崩溃**，只能靠断言把它钉住。
 *   2) 系统通知是独立开关（默认关）+ 同版本只提醒一次，判错的表现是「一直不弹」或
 *      「每次闹钟都弹」，同样安静。
 *
 * 做法：从 background.js 里抽出真实的几个函数（不复制逻辑），配一个假 chrome 跑。
 */
'use strict';

const fs = require('fs');
const path = require('path');

const BG = path.join(__dirname, '..', 'background.js');

let pass = 0, fail = 0;
function t(name, ok) {
  if (ok) { pass++; console.log('  ✓ ' + name); }
  else { fail++; console.log('  ✗ ' + name); }
}

function slice(src, startMark, endMark) {
  const i = src.indexOf(startMark);
  const j = src.indexOf(endMark, i + 1);
  if (i < 0 || j < 0 || j <= i) throw new Error('定位失败：' + startMark);
  return src.slice(i, j);
}

const source = fs.readFileSync(BG, 'utf8');

// 1) 版本比较 + 归一化（sfUpdateBadgeApply / sfUpdateNotify 都依赖）
const verSrc = slice(source, 'function sfAutoNormTag(t)', 'async function sfAutoFetchJson');
// 2) 徽标 / 通知这一整块
const badgeSrc = slice(source, '// 唯一徽标出口。返回是否「有新版本」', '// —— 自动检查更新 ——');
// 常量（真实定义在文件里，抽取时单独补上）
const constSrc = [
  "const SF_AUTO_UPDATE_KEY = 'sfAutoUpdate';",
  "const SF_NOTIFY_UPDATE_KEY = 'notifyOnUpdate';",
  "const SF_NOTIFIED_VER_KEY = 'sfNotifiedVersion';"
].join('\n');

function makeChrome(opts) {
  opts = opts || {};
  const sync = Object.assign({}, opts.sync || {});
  const local = Object.assign({}, opts.store || {});
  const calls = { badges: [], colors: [], titles: [], created: [], cleared: [], opened: [] };
  const handlers = {};
  const chrome = {
    runtime: {
      getManifest: function () { return { version: opts.version || '1.14.9' }; },
      getURL: function (p) { return 'chrome-extension://fake/' + p; },
      openOptionsPage: function () { calls.opened.push('openOptionsPage'); }
    },
    action: {
      setBadgeText: function (o) { calls.badges.push(o.text); },
      setBadgeBackgroundColor: function (o) { calls.colors.push(o.color); },
      setTitle: function (o) { calls.titles.push(o.title); }
    },
    storage: {
      sync: {
        get: function (d, cb) {
          const o = {};
          Object.keys(d).forEach(function (k) { o[k] = Object.prototype.hasOwnProperty.call(sync, k) ? sync[k] : d[k]; });
          cb(o);
        }
      },
      local: {
        get: function (d, cb) {
          const o = {};
          Object.keys(d).forEach(function (k) { o[k] = Object.prototype.hasOwnProperty.call(local, k) ? local[k] : d[k]; });
          cb(o);
        },
        set: function (o) { Object.assign(local, o); }
      }
    },
    notifications: {
      create: function (id, opt, cb) { calls.created.push({ id: id, opt: opt }); if (cb) cb(); },
      clear: function (id, cb) { calls.cleared.push(id); if (cb) cb(); },
      onClicked: { addListener: function (f) { handlers.clicked = f; } },
      onButtonClicked: { addListener: function (f) { handlers.btn = f; } }
    },
    tabs: { create: function (o) { calls.opened.push(o.url); } }
  };
  const api = new Function('chrome', constSrc + '\n' + verSrc + '\n' + badgeSrc + '\n' +
    'return { apply: sfUpdateBadgeApply, restore: sfUpdateBadgeRestore, notify: sfUpdateNotify, open: sfUpdateNotifyOpen };')(chrome);
  return { api: api, chrome: chrome, calls: calls, handlers: handlers, sync: sync, local: local };
}

console.log('\n【工具栏「新」徽标】');
(function () {
  // 有新版本：徽标写「新」、底色是红、标题带版本号
  const e = makeChrome({ version: '1.14.9' });
  const newer = e.api.apply('v1.14.10', '1.14.9');
  t('1.14.10 > 1.14.9 → 返回 true', newer === true);
  t('徽标写「新」', e.calls.badges[e.calls.badges.length - 1] === '新');
  t('徽标底色是红色 #e5484d', e.calls.colors[e.calls.colors.length - 1] === '#e5484d');
  t('标题里写明最新 / 当前版本',
    /v1\.14\.10/.test(e.calls.titles[e.calls.titles.length - 1]) &&
    /v1\.14\.9/.test(e.calls.titles[e.calls.titles.length - 1]));

  // 同版本 / 线上更低：清空徽标、标题恢复默认
  const e2 = makeChrome({ version: '1.14.10' });
  t('同版本 → 返回 false', e2.api.apply('1.14.10', '1.14.10') === false);
  t('同版本 → 徽标清空', e2.calls.badges[e2.calls.badges.length - 1] === '');
  t('同版本 → 标题恢复默认', e2.calls.titles[e2.calls.titles.length - 1] === 'SilverFoxBlocker');

  const e3 = makeChrome({ version: '1.15.0' });
  t('线上版本更低（本地测试版）→ 不长红点', e3.api.apply('1.14.10', '1.15.0') === false);

  // 不传 local 时用 manifest 里的版本
  const e4 = makeChrome({ version: '1.14.9' });
  t('local 省略时读 manifest 版本', e4.api.apply('1.14.10') === true);
})();

console.log('\n【重载 / 唤醒后的还原（本次修复的核心）】');
(function () {
  // 缓存里有更高的版本 → 不联网也要把红点还原回来
  const e = makeChrome({
    version: '1.14.9',
    store: { sfAutoUpdate: { at: 1, latest: '1.14.10', local: '1.14.9', newer: true } }
  });
  e.api.restore();
  t('按缓存还原：徽标重新出现', e.calls.badges[e.calls.badges.length - 1] === '新');
  t('按缓存还原：标题带新版本号', /v1\.14\.10/.test(e.calls.titles[e.calls.titles.length - 1]));

  // 缓存里的版本已经装上（用户更新过了）→ 清空徽标
  const e2 = makeChrome({
    version: '1.14.10',
    store: { sfAutoUpdate: { at: 1, latest: '1.14.10', local: '1.14.9', newer: true } }
  });
  e2.api.restore();
  t('已装上缓存里的版本 → 徽标清空（不留假红点）', e2.calls.badges[e2.calls.badges.length - 1] === '');

  // 没有缓存 → 清空，不能因为「查不到」而留着上一次的红点
  const e3 = makeChrome({ version: '1.14.9' });
  e3.api.restore();
  t('没有缓存 → 清空徽标', e3.calls.badges[e3.calls.badges.length - 1] === '');
})();

console.log('\n【系统通知：独立开关 + 同版本只提醒一次】');
(function () {
  // 默认关：什么都不弹
  const off = makeChrome({ version: '1.14.9', sync: {} });
  off.api.notify('1.14.10', '1.14.9');
  t('开关没开（默认）→ 不弹通知', off.calls.created.length === 0);

  // 明确关掉：同样不弹
  const off2 = makeChrome({ version: '1.14.9', sync: { notifyOnUpdate: false } });
  off2.api.notify('1.14.10', '1.14.9');
  t('开关 false → 不弹通知', off2.calls.created.length === 0);

  // 打开：弹一条，标题/正文带两个版本号
  const on = makeChrome({ version: '1.14.9', sync: { notifyOnUpdate: true } });
  on.api.notify('1.14.10', '1.14.9');
  t('开关 true → 弹一条通知', on.calls.created.length === 1);
  t('通知 id 带上版本号（同版本可去重）', on.calls.created[0].id === 'sf-upd-1.14.10');
  t('通知标题带最新版本、正文带当前版本',
    /1\.14\.10/.test(on.calls.created[0].opt.title) && /1\.14\.9/.test(on.calls.created[0].opt.message));
  t('通知带「查看更新」按钮', on.calls.created[0].opt.buttons[0].title === '查看更新');
  t('未读通知的图标是本地扩展图标', /icons\/icon128\.png$/.test(on.calls.created[0].opt.iconUrl));
  t('弹过之后记下版本号', on.local.sfNotifiedVersion === '1.14.10');

  // 再查一次同一版本：不重复弹（闹钟 6 小时一轮 + 每次开设置页都会查到）
  on.api.notify('1.14.10', '1.14.9');
  t('同一版本第二次 → 不重复弹', on.calls.created.length === 1);

  // 下一个版本：再弹一次
  on.api.notify('1.14.11', '1.14.9');
  t('更高的新版本 → 再弹一次', on.calls.created.length === 2);

  // 没有更新的时候：一条都不弹
  const cur = makeChrome({ version: '1.14.10', sync: { notifyOnUpdate: true } });
  cur.api.notify('1.14.10', '1.14.10');
  t('已是最新 → 不弹通知', cur.calls.created.length === 0);

  // 用户已经更新过（上次通知过的版本就是这个版本）→ 更不该弹
  const up = makeChrome({
    version: '1.14.10',
    sync: { notifyOnUpdate: true },
    store: { sfNotifiedVersion: '1.14.10' }
  });
  up.api.notify('1.14.10', '1.14.10');
  t('通知过的版本已经装上 → 不弹', up.calls.created.length === 0);
})();

console.log('\n【点通知的落点】');
(function () {
  const e = makeChrome({ version: '1.14.9', sync: { notifyOnUpdate: true } });
  e.api.notify('1.14.10', '1.14.9');
  // 点主体
  e.handlers.clicked('sf-upd-1.14.10');
  t('点通知打开「关于」页并带高亮参数',
    e.calls.opened[0] === 'chrome-extension://fake/ui/options.html#sec=about&hl=ver');
  t('打开后把通知从通知中心清掉', e.calls.cleared[0] === 'sf-upd-1.14.10');

  // 点「查看更新」按钮
  const e2 = makeChrome({ version: '1.14.9', sync: { notifyOnUpdate: true } });
  e2.handlers.btn('sf-upd-1.14.10', 0);
  t('点「查看更新」按钮同样是打开关于页',
    e2.calls.opened[0] === 'chrome-extension://fake/ui/options.html#sec=about&hl=ver');

  // 别的通知（比如「已暂停下载」）：不许抢着处理
  const e3 = makeChrome({ version: '1.14.9' });
  e3.handlers.clicked('sf-exe-123');
  t('不是更新通知 → 不打开设置页', e3.calls.opened.length === 0);
})();

console.log('\n通过 ' + pass + ' / ' + (pass + fail) + (fail ? '，失败 ' + fail : ''));
process.exit(fail ? 1 : 0);
