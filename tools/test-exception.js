#!/usr/bin/env node
/**
 * tools/test-exception.js —— 「三层例外」优先矩阵的回归测试（2026-11-23）
 *
 * 跑法：node tools/test-exception.js
 *
 * 覆盖什么：
 *   1) 优先级矩阵本身：云端例外 > 云端黑名单 > 内置例外 > 内置黑名单 > 用户例外 > 用户黑名单 > 白名单；
 *   2) 「例外只管自己那一层」：用户例外推翻不了内置/云端黑名单，内置例外推翻不了云端黑名单；
 *   3) 例外同样是「主机名 / 通配 / 主机名+路径」三种写法，且护栏与白名单一致
 *      （TLD 通配在例外里不生效——放行侧比拦截侧危险，不能给 `*.*` 开口子）；
 *   4) 例外不影响白名单档位：没有任何黑名单命中时，例外条目不会被误当成「已跳过评分」。
 *
 * 为什么要单独留这份测试：这套矩阵把「谁能推翻谁」写死成了顺序，
 *   顺序错一格就是安全漏洞（用户例外若能推翻云端黑名单，钓鱼站骗一次点击就绕过整条防线）。
 */
'use strict';

const path = require('path');

// 内置例外是随扩展发的静态数据（iocs.js 的 EXCEPTION_DOMAINS），测试要在 analyzer 编译它之前注入。
// 这里用「先加载 iocs、改数组、再加载 analyzer」的顺序：analyzer 内部 require('./iocs') 命中同一个
// 模块实例，于是它编译到的就是改过的那份 —— 不必为测试在生产代码里开 setter。
const iocsPath = require.resolve(path.join(__dirname, '..', 'rules', 'iocs.js'));
const analyzerPath = require.resolve(path.join(__dirname, '..', 'rules', 'analyzer.js'));
delete require.cache[iocsPath];
delete require.cache[analyzerPath];
const I = require(iocsPath);
I.EXCEPTION_DOMAINS.push(
  'chrome-china.net',        // 真实存在于内置黑名单：用来验证「内置例外 > 内置黑名单」
  'bb.bad-zone.example',     // 用来验证「云端黑名单 > 内置例外」
  'safe.bad-zone.example'    // 与云端例外重复，验证云端例外仍然排最前
);
const A = require(analyzerPath);

let fail = 0;
let total = 0;

function check(name, got, want) {
  total++;
  const ok = String(got) === String(want);
  if (!ok) {
    fail++;
    console.log('  FAIL  ' + name + '  →  ' + got + '   期望 ' + want);
  }
}

// 把 resolveListTier 压成一行短字符串，便于逐条断言
function tier(host, url, settings) {
  const r = A.resolveListTier(host, url, settings || {}, false);
  return (r.kind || '-') + '/' + (r.key || '-');
}

// ---------- 场景准备：云端黑名单 + 云端例外 ----------
A.registerCloudBad(['*.bad-zone.example'], { replace: true });
A.registerCloudException([
  'safe.bad-zone.example',
  'path.bad-zone.example/ok',
  '*-deepseek-*.*',          // 放行侧：TLD 通配必须被丢弃
  '*.*.foo.*'               // TLD 位带通配：必须被丢弃
], { replace: true });

console.log('== 1) 优先级矩阵：高优先级例外推翻低优先级黑名单 ==');
check('云端例外推翻云端黑名单（整站）',
  tier('safe.bad-zone.example', 'https://safe.bad-zone.example/'), 'exc/cloudException');
check('云端例外推翻云端黑名单（路径级）',
  tier('path.bad-zone.example', 'https://path.bad-zone.example/ok/x'), 'exc/cloudException');
check('同主机其它路径仍然按云端黑名单拦截',
  tier('path.bad-zone.example', 'https://path.bad-zone.example/other'), 'bad/cloudBlack');
check('普通子域仍被云端黑名单拦截',
  tier('x.bad-zone.example', 'https://x.bad-zone.example/'), 'bad/cloudBlack');
check('内置例外推翻内置黑名单',
  tier('chrome-china.net', 'https://chrome-china.net/'), 'exc/builtinException');
check('未写进例外的内置黑名单照拦',
  tier('deepvseek.com.cn', 'https://deepvseek.com.cn/'), 'bad/builtinBlack');

console.log('== 2) 例外只管自己那一层（跨层不生效） ==');
check('云端黑名单 > 内置例外',
  tier('bb.bad-zone.example', 'https://bb.bad-zone.example/'), 'bad/cloudBlack');
const s1 = { customBadDomains: ['user-bad.example'], exceptionDomains: ['ok.user-bad.example', 'deepvseek.com.cn', 'x.bad-zone.example'] };
check('用户例外推翻用户黑名单', tier('ok.user-bad.example', '', s1), 'exc/customException');
check('用户黑名单子域仍被拦', tier('sub.user-bad.example', '', s1), 'bad/customBlack');
check('用户例外推翻不了内置黑名单', tier('deepvseek.com.cn', '', s1), 'bad/builtinBlack');
check('用户例外推翻不了云端黑名单', tier('x.bad-zone.example', '', s1), 'bad/cloudBlack');

console.log('== 3) 白名单仍排在所有黑名单之后 ==');
const s2 = { allowlist: ['x.bad-zone.example', 'white-only.example'] };
check('白名单推翻不了云端黑名单', tier('x.bad-zone.example', '', s2), 'bad/cloudBlack');
check('没有任何黑名单命中时才是白名单', tier('white-only.example', '', s2), 'white/customWhite');
check('例外条目不会把无关站点变成白名单',
  tier('unrelated.example', '', { exceptionDomains: ['ok.user-bad.example'] }), '-/-');

console.log('== 4) 例外的通配护栏（放行侧不放宽 TLD） ==');
check('TLD 通配被丢弃：*-deepseek-*.* 不生效', A.isCloudException('my-deepseek-vip.xyz'), 'false');
check('TLD 位带通配的写法同样被丢弃', A.isCloudException('a.b.foo.example'), 'false');
A.registerCloudException(['*.sub.example', 'ab?.wild.example'], { replace: true });
check('普通通配仍生效（后缀）', A.isCloudException('x.sub.example'), 'true');
check('普通通配仍生效（标签内 ?）', A.isCloudException('ab1.wild.example'), 'true');
check('标签内 ? 不跨点', A.isCloudException('ab.c.wild.example'), 'false');

console.log('== 5) 覆盖语义：云端删掉例外后必须失效 ==');
A.registerCloudException([], { replace: true });
check('清空后不再命中', A.isCloudException('x.sub.example'), 'false');

console.log('');
if (fail) {
  console.log('✗ ' + fail + ' / ' + total + ' 条断言失败');
  process.exit(1);
}
console.log('✓ 三层例外：' + total + ' / ' + total + ' 条断言通过');
