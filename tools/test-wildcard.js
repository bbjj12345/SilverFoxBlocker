#!/usr/bin/env node
/**
 * tools/test-wildcard.js —— 通配符「放行策略」的回归测试
 *
 * 跑法：node tools/test-wildcard.js
 *
 * 覆盖四件事：
 *   1) 策略 #1（前导 `*.` 与其它通配混用）语义正确：`*.ab?.foo.com` = 「ab? 的任意子域」；
 *   2) 历史写法的判定**一条都没变**（`*.foo.com` 仍是后缀条目，`?b?04.…` 仍照旧）；
 *   3) 危险写法仍被拦：`*.*`、`*a*.*`、`*.com`、`foo.*`（即使 #3 已放开，也靠 minAnchorLen 挡住）；
 *   4) 六份名单（云端黑/白、内置黑/白、自定义黑/白）**共用同一套规则但各持一份策略**：
 *      `cloudBlack` 已放行 #3（TLD 位通配），其余五份仍拒绝；把开关改回去会立刻恢复旧行为、
 *      且不牵连其它名单（回滚是一行的事）。
 *
 * 为什么要单独留这份测试：通配护栏的每一条都是「少拦一个就等于漏一批」或
 * 「多放一个就等于全拦」的分界线，改动后必须能一眼看出哪条变了。
 */
'use strict';

const path = require('path');
const A = require(path.join(__dirname, '..', 'rules', 'analyzer.js'));

const KINDS = ['builtinBlack', 'builtinWhite', 'cloudBlack', 'cloudWhite', 'customBlack', 'customWhite'];

let fail = 0;
let total = 0;

function check(name, got, want) {
  total++;
  const ok = String(got) === String(want);
  if (!ok) {
    fail++;
    console.log('  FAIL  ' + name + '  →  ' + got + '   期望 ' + want);
  }
  return ok;
}

function kindOf(entry, listKind) {
  const r = A.compileWildEntry(entry, listKind);
  return r.kind || ('!' + r.reason);
}

// 用「注册一条 → 查几个主机名」验证真实命中面，而不是只看编译结果
function hitsOf(entry, listKind, hosts) {
  if (listKind === 'cloudBlack') A.registerCloudBad([entry], { replace: true });
  else A.registerCloudBad([], { replace: true });
  return hosts.map(function (h) { return A.isKnownBad(h) ? '1' : '0'; }).join('');
}

console.log('== 1) 策略 #1：前导 *. 与其它通配混用 ==');
['*.ab?.foo.com', '*.deepseek-*.com', '*.*.foo.com', '*.a*.b?.foo.com'].forEach(function (p) {
  KINDS.forEach(function (k) { check(p + ' @' + k, kindOf(p, k), 'suffix-wild'); });
});
check('*.foo.com 仍是后缀条目', kindOf('*.foo.com', 'cloudBlack'), 'suffix');
check('*.deepseek-vip.com 仍是后缀条目', kindOf('*.deepseek-vip.com', 'cloudBlack'), 'suffix');

// 语义：*.ab?.foo.com 覆盖 ab1.foo.com 及其子域，但不含 foo.com 本身
check('*.ab?.foo.com 命中面',
  hitsOf('*.ab?.foo.com', 'cloudBlack',
    ['ab1.foo.com', 'x.ab1.foo.com', 'a.b.ab1.foo.com', 'foo.com', 'ab.foo.com', 'ab12.foo.com']),
  '111000');

console.log('== 2) 历史写法判定不变 ==');
[['?b?04.8msg8.com', 'wild'], ['*deepseek*.com', 'wild'], ['*bot.*.qpefh.com', 'wild']].forEach(function (c) {
  KINDS.forEach(function (k) { check(c[0] + ' @' + k, kindOf(c[0], k), c[1]); });
});

console.log('== 3) 危险写法仍被拦 ==');
check('*.*', kindOf('*.*', 'cloudBlack'), '!suffix-malformed');
check('*.com', kindOf('*.com', 'cloudBlack'), '!suffix-malformed');
check('*.cn', kindOf('*.cn', 'cloudBlack'), '!suffix-malformed');
check('foo.*（无锚点）', kindOf('foo.*', 'cloudBlack'), '!weak-anchor');
check('*a*.*（锚点只有 1 字）', kindOf('*a*.*', 'cloudBlack'), '!weak-anchor');
check('x.c?m（锚点 <4）', kindOf('x.c?m', 'cloudBlack'), '!weak-anchor');
// 2026-11-12：云端黑名单已放开 #3，`*-deepseek-*.*` 现在是**合法**条目；其它五份仍拒绝（见第 4 节）。
check('*-deepseek-*.* @cloudBlack 已放行', kindOf('*-deepseek-*.*', 'cloudBlack'), 'wild');
// 归一化阶段（_normCloudDomainEx）先把「连续点 / 无点」挡掉，所以这两条不会走到编译器
check('a..foo.com', kindOf('a..foo.com', 'cloudBlack'), '!invalid-char');
check('裸 *', kindOf('*', 'cloudBlack'), '!no-dot');
check('*.a..foo.com', kindOf('*.a..foo.com', 'cloudBlack'), '!invalid-char');

console.log('== 4) 六份名单：同一编译器、各自一份策略 ==');
const six = KINDS.map(function (k) { return A.wildPolicyOf(k); });
check('六份策略对象互不相同', six.every(function (p, i) { return six.indexOf(p) === i; }), 'true');
check('五份仍与默认策略逐位相同',
  KINDS.filter(function (k) { return k !== 'cloudBlack'; })
    .every(function (k) { return JSON.stringify(A.wildPolicyOf(k)) === JSON.stringify(A.WILD_POLICY); }), 'true');
const cb = A.wildPolicyOf('cloudBlack');
const diffKeys = Object.keys(A.WILD_POLICY).filter(function (k) { return A.WILD_POLICY[k] !== cb[k]; }).sort();
check('cloudBlack 只差 tldWildcard / tldMultilevel 两项', diffKeys.join(','), 'tldMultilevel,tldWildcard');
check('cloudBlack.tldWildcard = true', cb.tldWildcard, 'true');
check('cloudBlack.tldMultilevel = true', cb.tldMultilevel, 'true');
check('WILD_POLICY 默认仍为 false（新名单不会误继承）',
  String(A.WILD_POLICY.tldWildcard) + '/' + String(A.WILD_POLICY.tldMultilevel), 'false/false');

// 其余五份名单：同一写法结论完全一致（说明策略是各持一份，不是全局开关）
KINDS.filter(function (k) { return k !== 'cloudBlack'; }).forEach(function (k) {
  check(k + ' 拒绝 TLD 通配', kindOf('*-deepseek-*.*', k), '!tld-wildcard');
});

// 临时在云端黑名单上**关掉** #3，验证「一行可回滚、且不牵连其它名单」
cb.tldWildcard = false;
try {
  check('关掉后 cloudBlack 立刻拒绝', kindOf('*-deepseek-*.*', 'cloudBlack'), '!tld-wildcard');
} finally {
  cb.tldWildcard = true;
}
check('恢复后 cloudBlack 再次接受', kindOf('*-deepseek-*.*', 'cloudBlack'), 'wild');

// 真实命中面（注册进运行期名单，用 isKnownBad 验证，而不是只看编译结果）
//   `*-deepseek-*` 与 `*deepseek-*` 是两条规则：品牌词前/后各一个伪品牌段，正是钓鱼站最常见的两种排布。
check('*-deepseek-*.* 命中面',
  hitsOf('*-deepseek-*.*', 'cloudBlack',
    ['my-deepseek-vip.xyz', 'a1-deepseek-b2.top', 'deepseek-ai.xyz', 'deepseek.com', 'deepseekai.xyz', 'a.my-deepseek-vip.xyz']),
  '110000');
check('*deepseek-*.* 命中面',
  hitsOf('*deepseek-*.*', 'cloudBlack',
    ['deepseek-ai.xyz', 'mydeepseek-vip.top', 'www.deepseek-official.cloud', 'deepseekai.xyz', 'deepseek.com']),
  '11100');
// 任意层级：`*.` 前缀（策略 #1）把「rest 的任意子域」交给后缀正则，再叠加 #3 的 TLD 通配
check('*.deepseek-*.* 覆盖任意层级',
  hitsOf('*.deepseek-*.*', 'cloudBlack',
    ['deepseek-x.cloud', 'a.b.deepseek-x.cloud', 'deepseek.com', 'xdeepseek-a.top']),
  '1100');

// 多级后缀（策略 #3b）：`com.cn` / `co.uk` 这类后缀下，只有 TLD 位的 `*` 能吃多级才覆盖得到
console.log('== 4b) 多级后缀（#3b）：app.vip-deepseek-offical.com.cn ==');
check('#3b 关闭时覆盖不到（对照：临时关掉）', (function () {
  const saved = cb.tldMultilevel;
  cb.tldMultilevel = false;
  try { return hitsOf('*.*deepseek-*.*', 'cloudBlack', ['app.vip-deepseek-offical.com.cn']); }
  finally { cb.tldMultilevel = saved; }
})(), '0');
check('*.*deepseek-*.* 覆盖 4 级 + com.cn',
  hitsOf('*.*deepseek-*.*', 'cloudBlack',
    ['app.vip-deepseek-offical.com.cn', 'a.b.vip-deepseek-x.co.uk', 'deepseek-ai.xyz', 'cdn.deepseek-vip.cn',
      'deepseek.com', 'deepseek.ai', 'deepseekai.xyz', 'notdeepseek.club']),
  '11110000');
check('*.*-deepseek*.* 覆盖「连字符在前」的形态',
  hitsOf('*.*-deepseek*.*', 'cloudBlack',
    ['app.vip-deepseek-offical.com.cn', 'my-deepseek.cc', 'deepseek-ai.xyz', 'deepseek.com']),
  '1100');
// 放宽的只有 TLD 位；其它位置的 `*` 仍不跨点（`app.vip-...` 不会被 `*-deepseek-*.*` 直接吃掉）
check('其它位置 `*` 仍不跨标签',
  hitsOf('*-deepseek-*.*', 'cloudBlack', ['app.vip-deepseek-offical.com.cn', 'my-deepseek-vip.xyz']),
  '01');
hitsOf('', 'cloudBlack', []);   // 清空运行期名单

console.log('== 5) 说明文案随策略生成 ==');
check('cloudBlack 文案说明已放开 TLD',
  A.wildHelpLines('cloudBlack').join(' ').indexOf('顶级域可通配') !== -1, 'true');
check('customWhite 文案仍是「顶级域不可通配」',
  A.wildHelpLines('customWhite').join(' ').indexOf('顶级域不可通配') !== -1, 'true');
check('说明行数', A.wildHelpLines('customWhite').length, 4);

console.log('\n合计 ' + total + ' 项，失败 ' + fail + ' 项');
process.exit(fail ? 1 : 0);
