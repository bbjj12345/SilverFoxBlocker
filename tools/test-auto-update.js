#!/usr/bin/env node
/**
 * tools/test-auto-update.js —— 关于页两枚自动开关的测试（2026-11-28）
 *
 * 跑法：node tools/test-auto-update.js
 *
 * 背景：关于页「版本」「云端名单更新」两行各新增一枚开关（自动检查更新 / 自动更新），
 *   默认都开。真正干活的是后台闹钟，所以这里校验三件事：
 *   1) 版本比较：1.6.10 必须比 1.6.9 新（纯字典序会判反），前导 v / 空白要能吃掉；
 *   2) 云端名单的结构识别与「内容相同」判断（内容没变就只写 meta，不触发重注入）；
 *   3) 接线是否齐全：默认值、开关 id、后台闹钟名与消息名、样式里的加宽规则。
 *
 * 为什么单独测版本比较：这段只影响「工具栏图标标不标新」和关于页那一行提示，
 *   出错不会报错、也不会崩，只会安静地一直提示「已是最新」或永远标「新」。
 */
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const BG = path.join(ROOT, 'background.js');
const OPT_JS = path.join(ROOT, 'ui', 'options.js');
const OPT_HTML = path.join(ROOT, 'ui', 'options.html');
const OPT_CSS = path.join(ROOT, 'ui', 'options.css');

function slice(file, startMark, endMark) {
  const code = fs.readFileSync(file, 'utf8');
  const start = code.indexOf(startMark);
  const end = code.indexOf(endMark, start + 1);
  if (start < 0 || end < 0 || end <= start) throw new Error('定位失败：' + startMark);
  return code.slice(start, end);
}

function loadVerHelpers() {
  const src = slice(BG, "const SF_AUTO_VER_ALARM = 'sfAutoCheckUpdateAlarm';", 'async function sfAutoFetchJson');
  return new Function(src + '\nreturn { cmp: sfAutoCmpVersion, norm: sfAutoNormTag };')();
}

function loadCloudHelpers() {
  // 两个函数之间隔着 sfAutoSanitize / sfAutoNormCorrect / sfAutoPull，直接取到 sfAutoSameList 为止
  const src = slice(BG, 'function sfAutoExtractDomains(json)', 'async function sfAutoCloudSyncOnce');
  return new Function(src + '\nreturn { extract: sfAutoExtractDomains, same: sfAutoSameList };')();
}

let pass = 0, fail = 0;
function t(name, cond, extra) {
  if (cond) { pass++; console.log('  ✓ ' + name); }
  else { fail++; console.log('  ✗ ' + name + (extra ? '  ← ' + extra : '')); }
}

console.log('== 1) 版本比较 ==');
const V = loadVerHelpers();
t('1.6.10 > 1.6.9（不能按字典序）', V.cmp('1.6.10', '1.6.9') === 1);
t('1.14.10 > 1.14.9', V.cmp('1.14.10', '1.14.9') === 1);
t('1.14.9 < 1.14.10', V.cmp('1.14.9', '1.14.10') === -1);
t('完全相同 → 0', V.cmp('1.14.10', '1.14.10') === 0);
t('前导 v 与空白被吃掉', V.cmp('  v1.14.10 ', '1.14.10') === 0);
t('本地更旧时线上更高（2.0.0 > 1.14.10）', V.cmp('2.0.0', '1.14.10') === 1);
t('线上更低时不算新版本', V.cmp('1.9.9', '1.14.10') === -1);
t('多段号缺位按 0 处理（1.14 == 1.14.0）', V.cmp('1.14', '1.14.0') === 0);
t('空值不会抛错', V.cmp('', '1.0.0') === 0 && V.cmp(null, undefined) === 0);
t('非数字段退化为字符串比较但不炸', V.cmp('1.14.10-beta', '1.14.10') !== 0);

console.log('== 2) 云端名单结构识别 ==');
const C = loadCloudHelpers();
const arr = ['a.com'];
t('裸数组', C.extract(arr) === arr);
t('{domains:[]}', C.extract({ domains: arr }) === arr);
t('{list:[]}', C.extract({ list: arr }) === arr);
t('{data:{domains:[]}}', C.extract({ data: { domains: arr } }) === arr);
t('字符串按行/逗号拆', C.extract('a.com\nb.com,c.com').length === 3);
t('{error:…} → null（不能写空名单）', C.extract({ error: 'x' }) === null);
t('相同顺序 → same', C.same(['a', 'b'], ['a', 'b']) === true);
t('仅顺序不同 → 视为变化（与设置页口径一致）', C.same(['b', 'a'], ['a', 'b']) === false);
t('长度不同 → 变化', C.same(['a'], ['a', 'b']) === false);
t('两边都空 → same', C.same([], []) === true);
t('空/undefined 不炸', C.same(undefined, null) === true);

console.log('== 3) 设置项与接线 ==');
const js = fs.readFileSync(OPT_JS, 'utf8');
const html = fs.readFileSync(OPT_HTML, 'utf8');
const bg = fs.readFileSync(BG, 'utf8');
const css = fs.readFileSync(OPT_CSS, 'utf8');
t('DEFAULTS 里 autoCheckUpdate 默认 true', /autoCheckUpdate:\s*true/.test(js));
t('DEFAULTS 里 autoCloudUpdate 默认 true', /autoCloudUpdate:\s*true/.test(js));
t('两个开关 id 都在 HTML 里', /id="autoCheckUpdate"/.test(html) && /id="autoCloudUpdate"/.test(html));
t('开关文案：「自动检查更新」「自动更新」', /自动检查更新/.test(html) && />自动更新</.test(html));
t('三枚开关都放在 about-row 行内（.about-toggle）', (html.match(/class="about-toggle"/g) || []).length === 3);
t('「自动检查更新」紧跟版本行（checkUpdateTip 之后）',
  html.indexOf('id="checkUpdateTip"') < html.indexOf('id="autoCheckUpdate"'));
t('「自动更新」紧跟云端名单更新行（SF_CLOUD_TIP 之后）',
  html.indexOf('id="SF_CLOUD_TIP"') < html.indexOf('id="autoCloudUpdate"'));
t('collectSettings 带上两个开关', /autoCheckUpdate:\s*\(\$\('autoCheckUpdate'\)/.test(js));
t('改动即时写 sync（不必点保存）', /chrome\.storage\.sync\.set\(\{ \[key\]: on \}\)/.test(js));
t('打开开关会立刻通知后台', /SF_AUTO_CHECK_NOW/.test(js) && /SF_AUTO_CLOUD_NOW/.test(js));
t('后台有两条闹钟名', /SF_AUTO_VER_ALARM = 'sfAutoCheckUpdateAlarm'/.test(bg) && /SF_AUTO_CLOUD_ALARM = 'sfAutoCloudSyncAlarm'/.test(bg));
t('后台有闹钟监听', /alarm\.name === SF_AUTO_VER_ALARM/.test(bg) && /alarm\.name === SF_AUTO_CLOUD_ALARM/.test(bg));
t('后台有立即执行的消息分支', /msg\.type === 'SF_AUTO_CHECK_NOW'/.test(bg) && /msg\.type === 'SF_AUTO_CLOUD_NOW'/.test(bg));
t('自动同步只在内容变化时写名单（否则只写 meta）', /if \(!sameW\) payload\[SF_AUTO_CLOUD_KEYS\.white\]/.test(bg));
t('自动同步两份并行、任一失败不写盘', /Promise\.all\(\[sfAutoPull\('white'\), sfAutoPull\('black'\)\]\)/.test(bg));
t('清洗复用 analyzer（不自己洗一套）', /A\.sanitizeCloudDomains\(arr, \{ allowWild: true, listKind: listKind \}\)/.test(bg));
t('官网映射复用 iocs', /I\.normalizeCorrectSites\(sitesRaw/.test(bg));
t('关于页版心加宽只在 about 生效', /\.content:has\(#about\.active\) \{\s*max-width: 1120px;/.test(css) && !/^\.content \{ max-width: 1120px/m.test(css));
t('加宽同时收窄内边距（否则 1080 窗口看不出变化）', /\.content:has\(#about\.active\) \{[\s\S]*?padding-left: clamp\(16px, 3\.2vw, 44px\)/.test(css));
t('窄窗口收起开关文字', /\.about-row \.about-toggle-txt \{ display: none; \}/.test(css));

/* ---- 2026-11-29：系统通知开关（默认关）+ 工具栏徽标的还原 ----
   这两件事都是「不报错、只是安静地不生效」的类型：
   开关没接上线 = 用户勾了也不弹；徽标只在成功那一刻写一次 = 重载后红点消失。
   所以这里逐条钉住接线。 */
t('系统通知开关 id 在 HTML 里', /id="notifyOnUpdate"/.test(html));
t('系统通知开关紧跟「自动检查更新」（同一列竖排）',
  /id="autoCheckUpdate"[\s\S]{0,1600}id="notifyOnUpdate"/.test(html));
t('系统通知默认关（DEFAULTS 里 notifyOnUpdate: false）', /notifyOnUpdate:\s*false/.test(js));
t('系统通知开关不触发检查（runtimeMsg 传 null）',
  /bindOne\('notifyOnUpdate', 'notifyOnUpdate', null, false\)/.test(js));
t('collectSettings 带上系统通知开关', /notifyOnUpdate:\s*\(\$\('notifyOnUpdate'\)/.test(js));
t('后台读系统通知开关、默认 false', /\[SF_NOTIFY_UPDATE_KEY\]: false/.test(bg));
t('同一版本只提醒一次（sfNotifiedVersion）',
  /SF_NOTIFIED_VER_KEY/.test(bg) && /sfAutoNormTag\(o\[SF_NOTIFIED_VER_KEY\]\) === tag/.test(bg));
t('徽标只有一个出口 sfUpdateBadgeApply', /function sfUpdateBadgeApply/.test(bg));
t('闸门跳过时也还原徽标（不再干等 6 小时）',
  /async function sfAutoCheckUpdate\(force\)[\s\S]{0,600}sfUpdateBadgeRestore\(\);/.test(bg));
t('worker 唤醒即按缓存还原徽标',
  /sfAutoEnsureAlarm\(SF_AUTO_CLOUD_ALARM, SF_AUTO_CLOUD_PERIOD, 5\);\s*[\s\S]{0,400}sfUpdateBadgeRestore\(\)/.test(bg));
t('手动查到的更新也交给后台（SF_UPDATE_NOTIFY）',
  /msg\.type === 'SF_UPDATE_NOTIFY'/.test(bg) && /type: 'SF_UPDATE_NOTIFY'/.test(js));
t('点通知打开关于页并高亮版本行', /options\.html#sec=about&hl=ver/.test(bg) && /hl=ver/.test(js));
t('通知开关竖排容器样式', /\.about-row \.about-toggle-stack \{/.test(css));

console.log('\n通过 ' + pass + ' / ' + (pass + fail) + (fail ? '，失败 ' + fail : ''));
process.exit(fail ? 1 : 0);
