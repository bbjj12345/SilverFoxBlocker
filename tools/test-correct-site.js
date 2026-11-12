#!/usr/bin/env node
/**
 * tools/test-correct-site.js —— 「访问正确的页面」官网映射的回归测试
 *
 * 跑法：node tools/test-correct-site.js
 *
 * 覆盖三件事：
 *   1) 内置表（rules/iocs.js 的 CORRECT_SITE_CATALOG）的品牌词命中与边界护栏；
 *   2) 云端补录（whitelist.json 的 correct_sites）注入后与内置表合并后的优先级；
 *   3) 「都不命中 → 空字符串」（调用方据此打开说明页），不能误返回某个无关官网。
 *
 * 为什么值得单独留一份测试：品牌词是子串匹配，改动一个字母就可能把
 * myhuorong.com 认成火绒、把 qqq.com 认成 QQ；这类错误不会报错，只会把用户
 * 送到错误的官网。表一改就该跑一遍。
 */
'use strict';

const fs = require('fs');
const path = require('path');
const A = require(path.join(__dirname, '..', 'rules', 'analyzer.js'));

// [主机名, 期望官网（'' = 应打开说明页）]
const BUILTIN_CASES = [
  // ---- 火绒：仿冒站最常见的「品牌词 + 后缀」写法 ----
  // ---- 第四轮：教育/金融/企业机构/平台生态/个人站（已全部内置化）----
  ['xueersi-vip.com', 'xueersi.com'],
  ['chaoxing-cn.com', 'chaoxing.com'],
  ['koolearn-vip.com', 'koolearn.com'],
  ['chsi-verify.com', 'chsi.com.cn'],
  ['moe-gov.cn', 'moe.gov.cn'],
  ['edu-cn.com', 'edu.cn'],
  ['icbc-vip.com', 'icbc.com.cn'],
  ['icbcvip.com', 'icbc.com.cn'],
  ['ccb-safe.com', 'ccb.com'],
  ['cmbchina-vip.com', 'cmbchina.com'],
  ['95588-vip.com', '95588.com'],
  ['citicbank-cn.com', 'citicbank.com'],
  ['cib-vip.com', 'cib.com.cn'],
  ['guosen-vip.com', 'guosen.com.cn'],
  ['chinaamc-cn.com', 'chinaamc.com'],
  ['pandasecurity-cn.com', 'pandasecurity.com'],
  ['10086-vip.com', '10086.cn'],
  ['sinopec-vip.com', 'sinopec.com'],
  ['cnpc-cn.com', 'cnpc.com'],
  ['byd-vip.com', 'byd.com'],
  ['haier-cn.com', 'haier.com'],
  ['sf-express-vip.com', 'sf-express.com'],
  ['ctrip-vip.com', 'ctrip.com'],
  ['moutai-vip.com', 'moutai.com.cn'],
  ['sasac-gov.cn', 'sasac.gov.cn'],
  ['12306-vip.com', '12306.cn'],
  ['vercel-app.com', 'vercel.com'],
  ['kafan-cn.com', 'bbs.kafan.cn'],
  ['geogebra-cn.com', 'geogebra.org'],
  ['gsk-vip.com', 'gsk.com'],
  ['sogou-pinyin.cn', 'shurufa.sogou.com'],
  ['ie.sogou.com', 'ie.sogou.com'],                 // 裸词 sogou 不得把浏览器入口吃掉
  ['panda.tv', ''],                                 // 裸词 panda 已移除，不再指向杀毒站
  ['lzk.hl.cn', 'lzk.hl.cn'],
  ['huorongsafe.com.cn', 'huorong.cn'],
  ['www.huorong.cn.evil.top', 'huorong.cn'],
  ['huorong-safe.cn', 'huorong.cn'],
  ['huorong1.top', 'huorong.cn'],
  ['myhuorong.com', ''],
  // ---- 短品牌词：右侧跟字母时不能命中 ----
  ['qqq.com', ''],
  ['qq2013.com', 'im.qq.com'],
  ['ima.qq.com', 'im.qq.com'],
  ['xb2999qq2013.com', ''],
  // ---- 含数字的品牌词（360）：后缀跟字母是常态，必须命中 ----
  ['360anquan.com', '360.cn'],
  ['360safe.com', '360.cn'],
  // ---- 长词优先 ----
  ['sogoubrowser.com', 'ie.sogou.com'],
  ['sogou-pinyin.com', 'shurufa.sogou.com'],
  ['sogoubrowser-qq.com', 'ie.sogou.com'],
  ['baidushurufa.com', 'shurufa.baidu.com'],
  ['guanjia-qq.com', 'guanjia.qq.com'],
  ['gujianjia-qq.com', 'im.qq.com'],          // 只命中 qq，指到 QQ 官网（同公司，可接受）
  // ---- 办公与 IM ----
  ['wps-cn.top', 'wps.cn'],
  ['kdocs-download.com', 'kdocs.cn'],
  ['docs.qq.com.evil.cn', 'docs.qq.com'],
  ['work.weixin.com.cn', 'work.weixin.qq.com'],
  ['weixin-qq.com', 'weixin.qq.com'],
  ['microsoft365-free.com', 'microsoft365.com'],
  ['microsoftonline-login.cn', 'microsoftonline.com'],
  ['outlook-verify.com', 'outlook.com'],
  // ---- 安全软件 ----
  ['zonealarm-free.com', 'zonealarm.com'],
  ['fsecure-cn.com', 'f-secure.com'],
  ['f-secure-cn.com', 'f-secure.com'],
  ['threatbook.com.cn', 'threatbook.cn'],
  ['pandasecurity.cn', 'pandasecurity.com'],
  // ---- 词根误伤：左侧粘连字母必须拒绝 ----
  ['pineapple.com', ''],
  ['operating-system.com', 'opera.com'],       // 左侧是标签开头，命中（可接受，指向官网）
  ['apple-id.com', 'apple.com'],
  // ---- 影音娱乐 ----
  ['vqq-video.com', 'v.qq.com'],
  ['iqiyi-vip.com', 'iqiyi.com'],
  ['aiqiyi-cn.com', 'iqiyi.com'],
  ['youku-hd.com', 'youku.com'],
  ['bilibili-download.cn', 'bilibili.com'],
  ['douyin-cn.com', 'douyin.com'],
  ['kugou-music.cn', 'kugou.com'],
  ['ximalaya-download.com', 'ximalaya.com'],
  ['qishui-music.com', 'qishui.com'],
  // ---- 云盘与存储 ----
  ['baiduwangpan-1.com', 'pan.baidu.com'],
  ['alipan-download.com', 'alipan.com'],
  ['lanzou-cloud.com', 'lanzou.com'],
  ['quarkpan.com', 'quark.cn'],
  ['weiyun-pan.com', 'weiyun.com'],
  // ---- AI 大模型 ----
  ['deepseek-cn.top', 'deepseek.com'],
  ['doubao-ai.com', 'doubao.com'],
  ['kimi-chat.cn', 'kimi.com'],
  ['moonshot-cn.com', 'kimi.com'],
  ['wenxin-yiyan.com', 'wenxin.baidu.com'],
  ['qianwen-ai.com', 'qianwen.com'],
  ['chatgpt-mirror.com', 'openai.com'],
  // ---- 下载与压缩 ----
  ['xunlei-vip.com', 'xunlei.com'],
  ['idm-crack.com', 'internetdownloadmanager.com'],
  ['free-winrar.cn', 'rarlab.com'],
  ['7zip-cn.com', '7-zip.org'],
  ['bandizip-download.com', 'bandisoft.com'],
  ['motrix-download.com', 'motrix.app'],
  // ---- 系统工具 ----
  ['todesk-cn.com', 'todesk.com'],
  ['sunlogin-download.com', 'sunlogin.oray.com'],
  ['cpuz-download.com', 'cpuid.com'],
  ['ludashi-cn.com', 'ludashi.com'],
  ['diskgenius-cn.com', 'diskgenius.cn'],
  ['rufus-usb.com', 'rufus.ie'],
  ['msi-gaming.cn', 'msi.com'],
  ['hp-driver.com', 'hp.com'],
  ['dell-driver.cn', 'dell.com'],
  ['voidtools-everything.com', 'voidtools.com'],
  // ---- 新增词根的误伤护栏 ----
  ['shop.com', ''],
  ['myphp.com', ''],                          // php 已是云端品牌词，但左侧粘连时不命中
  ['dynamic-dns.top', ''],
  // ---- 什么都不是 ----
  ['random-domain.xyz', ''],
  ['example.com', ''],
  ['localhost', ''],
  ['', '']
];

const CLOUD_CASES = [
  ['meeting.tencent.com.co', 'meeting.tencent.com'],
  ['qqmail-verify.com', 'mail.qq.com'],
  ['exmail-qq.com', 'exmail.qq.com'],
  ['wechatpay-secure.com', 'pay.weixin.qq.com'],
  ['163mail-login.com', '163.com'],
  ['chromium-download.com', 'chromium.org'],
  ['duckduckgo-browser.cn', 'duckduckgo.com'],
  ['windows-license.cn', 'microsoft.com'],
  ['xfyun-cn.com', 'xfyun.cn'],
  ['iciba-download.com', 'iciba.com'],
  ['huorongbbs.com', 'bbs.huorong.cn'],
  // ---- 第三轮：电商/支付/地图/开发者/游戏/新闻（云端补录）----
  ['taobao-vip.com', 'taobao.com'],
  ['jd-vip.com', 'jd.com'],
  ['pinduoduo-coupon.com', 'pinduoduo.com'],
  ['meituan-vip.com', 'meituan.com'],          // 云端 meituan 比内置 meitu 长，正确压过
  ['alipay-verify.com', 'alipay.com'],
  ['zhifubao-safe.com', 'alipay.com'],
  ['wechatpay-secure.cn', 'pay.weixin.qq.com'],
  ['amap-download.com', 'amap.com'],
  ['didichuxing-cn.com', 'didiglobal.com'],
  ['aliyun-console.com', 'aliyun.com'],
  ['github-download.cn', 'github.com'],
  ['vscode-cn.com', 'code.visualstudio.com'],
  ['epicgames-cn.com', 'epicgames.com'],
  ['thepaper-cn.com', 'thepaper.cn'],
  ['huorongsafe.com.cn', 'huorong.cn']          // 云端与内置同词 → 内置优先
];

// ---- typo 回退（2026-11-12）----
// 这些域名都没有「品牌词子串」，字面查表一定落空；能不能给出官网，全靠
// analyzer 的 _typoBrandFallback 复用检测链路的编辑距离结论。
// 最后一组是反向护栏：与品牌只差一两个字符的**别的公司**，必须仍然走说明页。
const TYPO_CASES = [
  ['huorlong.cn', 'huorong.cn'],
  ['hurong.cn', 'huorong.cn'],
  ['huoron.cn', 'huorong.cn'],   // 漏一个字母 g：字面查不到，只能走 typo 回退
  ['huolong.cn', ''],            // 火龙：与 huorong 只共享 'huo' 三字符，护栏必须挡住
  ['xb2999qq2013.com', ''],      // 含 qq 但左侧粘连、且与任何品牌都不成 typo
];

// ---- branddomain 回退（2026-11-12）----
// 前半组：品牌词在正确官网表里（含产品名）→ 直接给出官网；
// 后半组：品牌词只出现在官方域名表里 → 由「主干 == 品牌词」反查；
// 最后是把反查表挡回去的情形（没有同名主站，宁可走说明页也不乱送）。
const BRANDDOMAIN_CASES = [
  ['todesk.com.cn', 'todesk.com'],
  ['todesk.cn', 'todesk.com'],
  ['www.todesk.com.cn', 'todesk.com'],
  ['todesk.net.cn', 'todesk.com'],
  ['anydesk.com.cn', 'anydesk.com'],
  ['threatbook.com.cn', 'threatbook.cn'],
  ['huorong.com.cn', 'huorong.cn'],
  ['huawei.com.cn', 'huawei.com'],          // 官网表未收录 huawei → 官方域名表反查
  ['huawei.cn', 'huawei.com'],
  ['photoshop.com.cn', 'photoshop.com'],
  ['ppsspp.cn', 'ppsspp.org'],
  ['panda.com.cn', ''],                     // 只反查到 panda.tv（已停运的直播站）→ 宁可说明页
  ['2345.com.cn', ''],                      // 只反查到 haozip.2345.cc（好压子站）→ 宁可说明页
  ['teams.com.cn', ''],                     // 官方域是 teams.microsoft.com，主干不同名 → 不猜
  ['chrome.com.cn', '']                     // 官方域是 google.com，主干不同名 → 不猜
];

function runTypo(cases) {
  let bad = 0;
  console.log('\n== typo 回退 ==');
  cases.forEach(function (c) {
    const host = c[0];
    const want = c[1];
    let got = '';
    let conf = '';
    try {
      const r = A.resolveCorrectSite(host);
      got = r ? r.domain : '';
      conf = r ? (r.confidence || '') : '';
    } catch (e) { got = 'ERR:' + e.message; }
    const wantConf = want ? 'typo' : '';
    if (got !== want || conf !== wantConf) {
      bad++;
      console.log('FAIL  ' + host.padEnd(24) + ' → ' + (got || '(说明页)') + ' conf=' + (conf || '-') + '   期望 ' + (want || '(说明页)') + ' conf=' + (wantConf || '-'));
    }
  });
  console.log((bad ? '✗ ' : '✓ ') + (cases.length - bad) + '/' + cases.length + ' 通过');
  return bad;
}

// ---- branddomain 回退（2026-11-12 同日扩展）----
// 这些主机名的注册域主干恰好等于品牌词，但后缀换了注册局（todesk.com.cn / huawei.cn），
// 检测链路判为 branddomain 仿冒。来源有两种：正确官网表（带产品名）与官方域名表反查。
function runBrandDomain(cases) {
  let bad = 0;
  console.log('\n== branddomain 回退 ==');
  cases.forEach(function (c) {
    const host = c[0];
    const want = c[1];
    let got = '';
    let conf = '';
    try {
      const r = A.resolveCorrectSite(host);
      got = r ? r.domain : '';
      conf = r ? (r.confidence || '') : '';
    } catch (e) { got = 'ERR:' + e.message; }
    const wantConf = want ? 'branddomain' : '';
    if (got !== want || conf !== wantConf) {
      bad++;
      console.log('FAIL  ' + host.padEnd(24) + ' → ' + (got || '(说明页)') + ' conf=' + (conf || '-') + '   期望 ' + (want || '(说明页)') + ' conf=' + (wantConf || '-'));
    }
  });
  console.log((bad ? '✗ ' : '✓ ') + (cases.length - bad) + '/' + cases.length + ' 通过');
  return bad;
}

function run(title, cases) {
  let bad = 0;
  console.log('\n== ' + title + ' ==');
  cases.forEach(function (c) {
    const host = c[0];
    const want = c[1];
    let got = '';
    try { got = A.resolveCorrectDomain(host); } catch (e) { got = 'ERR:' + e.message; }
    if (got !== want) {
      bad++;
      console.log('FAIL  ' + host.padEnd(30) + ' → ' + (got || '(说明页)') + '   期望 ' + (want || '(说明页)'));
    }
  });
  console.log((bad ? '✗ ' : '✓ ') + (cases.length - bad) + '/' + cases.length + ' 通过');
  return bad;
}

let fail = run('内置表', BUILTIN_CASES);
fail += runTypo(TYPO_CASES);
fail += runBrandDomain(BRANDDOMAIN_CASES);

// 云端补录：读私有仓库里的 whitelist.json（不在本仓库内时跳过这一组）
const WL = path.join(__dirname, '..', '..', 'SilverFoxBlocker-Cloud', 'List', 'whitelist.json');
if (fs.existsSync(WL)) {
  try {
    const j = JSON.parse(fs.readFileSync(WL, 'utf8'));
    const n = A.registerCloudCorrect(j.correct_sites || []);
    console.log('\n云端补录品牌词：' + n + ' 个');
    fail += run('内置 + 云端', BUILTIN_CASES.concat(CLOUD_CASES));
  } catch (e) {
    console.log('\n（读取 whitelist.json 失败，跳过云端用例：' + e.message + '）');
  }
} else {
  console.log('\n（未找到 ' + WL + '，跳过云端用例）');
}

console.log('\n合计失败：' + fail);
process.exit(fail ? 1 : 0);
