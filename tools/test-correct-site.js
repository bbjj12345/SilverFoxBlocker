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
  // ---- 第五轮（2026-11-21）：新闻/教育/金融的主域迁移与新品牌词 ----
  ['gtht-vip.com', 'gtht.com'],            // 国泰海通合并后 gtja.com 301 到 gtht.com
  ['chinalife-vip.com', 'chinalife.com.cn'], // 中国人寿主域无连字符
  ['cinda-vip.com', 'cinda.com.cn'],        // 中国信达主域（amc.cinda.com 已停）
  ['pingan-vip.com', 'pingan.com'],         // 中国平安主站（pa18.com 旧入口）
  ['neea-vip.com', 'neea.edu.cn'],          // 中国教育考试网
  ['gaotu-vip.com', 'gaotu.cn'],            // 高途主域（baijia.com 只做 301）
  // ---- 第六轮（2026-11-21）：企业机构 / 平台生态的主域迁移与新品牌词 ----
  ['dfmc-vip.com', 'dfmc.com.cn'],           // 东风汽车集团（dongfeng.com 无 A 记录）
  ['hworld-vip.com', 'hworld.com'],          // 华住集团新主域（huazhu.com 301）
  ['crec-vip.com', 'www.crec.cn'],           // 中国中铁（crec.com 已属美国 Colliers）
  ['mcdonalds-vip.com', 'mcdonalds.com.cn'],  // 麦当劳中国（mcd.com.cn 是 NXDOMAIN）
  ['airchina-vip.com', 'airchina.com.cn'],   // 国航（airchina.com 无响应）
  ['gacgroup-vip.com', 'gacgroup.com'],      // 广汽集团（gac.com.cn 301）
  ['pandasecurity-cn.com', 'pandasecurity.com'],
  ['10086-vip.com', '10086.cn'],
  ['sinopec-vip.com', 'sinopec.com'],
  ['cnpc-cn.com', 'cnpc.com.cn'],   // 2026-11-21 起主域改为集团站 cnpc.com.cn（股份站 petrochina.com.cn 为第二站点）
  ['byd-vip.com', 'byd.com'],
  ['haier-cn.com', 'haier.com'],
  ['sf-express-vip.com', 'sf-express.com'],
  ['ctrip-vip.com', 'ctrip.com'],
  ['moutai-vip.com', 'moutai.com.cn'],
  ['sasac-gov.cn', 'sasac.gov.cn'],
  ['12306-vip.com', 'www.12306.cn'],   // 2026-11-21 起官网改指 www（裸域会降级到 HTTP）
  ['vercel-app.com', 'vercel.com'],
  ['kafan-cn.com', 'bbs.kafan.cn'],
  ['geogebra-cn.com', 'geogebra.org'],
  ['gsk-vip.com', 'gsk.com'],
  ['sogou-pinyin.cn', 'shurufa.sogou.com'],
  ['ie.sogou.com', 'sogou.browser.qq.com'],         // 裸词 sogou 不得把浏览器入口吃掉；2026-11-21 ie.sogou.com 已 301 到 sogou.browser.qq.com
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
  ['sogoubrowser.com', 'sogou.browser.qq.com'],     // 同上：目录里的正确域名已随 301 更新
  ['sogou-pinyin.com', 'shurufa.sogou.com'],
  ['sogoubrowser-qq.com', 'sogou.browser.qq.com'],
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
  // 2026-11-18：WinRAR 改为三站点，.domain 取「第一个主机名级站点」= www.win-rar.com
  // ['free-winrar.cn', 'rarlab.com'],
  ['free-winrar.cn', 'www.win-rar.com'],
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
  // 旧（2026-11-22 前）：photoshop / teams / chrome 都不是官网表品牌词，
  //   photoshop.com.cn 只能反查同名主站，teams / chrome 主干不同名 → 宁可落说明页
  // ['photoshop.com.cn', 'photoshop.com'],
  // ['teams.com.cn', ''],
  // ['chrome.com.cn', ''],
  // 新（2026-11-22 第十二轮）：三者已补进官网表品牌词，branddomain 直接给出所属产品官网
  ['photoshop.com.cn', 'adobe.com'],
  ['teams.com.cn', 'microsoft.com'],
  ['chrome.com.cn', 'google.com'],
  ['ppsspp.cn', 'ppsspp.org'],
  ['panda.com.cn', ''],                     // 只反查到 panda.tv（已停运的直播站）→ 宁可说明页
  ['2345.com.cn', ''],                      // 只反查到 haozip.2345.cc（好压子站）→ 宁可说明页
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
fail += runSites();

// ---- 多官网 / 链接级官网（2026-11-18）----
// 从「只看 .domain」升级为「看整份 sites 列表」：顺序、条数、自定义文案、kind 判定都要验。
// 这一节的价值在于：站点列表直接决定说明页给用户看哪些地址，写错一个字符就是把用户
// 送去钓鱼站 —— 而这类错误不会抛异常，只会安静地显示一个错误链接。
function runSites() {
  let bad = 0;
  // 旧（2026-11-18）：条数写死，每加一条断言都要改一处 total
  // const total = 19;
  // 新（2026-11-22）：断言条数动态统计，增删断言不必再改计数
  let ran = 0;
  const t = function (name, cond, extra) {
    ran++;
    if (!cond) { bad++; console.log('FAIL  ' + name + (extra !== undefined ? '   ' + extra : '')); }
  };
  const I = require(path.join(__dirname, '..', 'rules', 'iocs.js'));
  console.log('\n== 多官网 / 链接级官网 ==');

  // 1) WinRAR：三站点、顺序即数据顺序、第三条带自定义文案
  const w = A.resolveCorrectSite('free-winrar.cn');
  const ws = (w && w.sites) || [];
  t('WinRAR 列出 3 个站点', ws.length === 3, ws.length);
  t('WinRAR 顺序与表内一致',
    !!ws[0] && ws[0].url === 'https://www.win-rar.com' &&
    !!ws[1] && ws[1].url === 'https://www.rarlab.com' &&
    !!ws[2] && ws[2].url === 'https://www.winrar.com.cn',
    JSON.stringify(ws.map(function (s) { return s.url; })));
  t('WinRAR 第三条文案是「中国官网」', !!ws[2] && ws[2].label === '中国官网', ws[2] && ws[2].label);
  t('WinRAR 三条都是主机名级', ws.every(function (s) { return s.kind === 'host'; }));
  t('WinRAR .domain 取第一个主机名级站点', !!w && w.domain === ws[0].host, w && w.domain);

  // 旧（2026-11-18）：qBEE 只有自己的 2 个站点
  //   2026-11-22 起与 qBittorrent 互相关联，站点数变成 3（多出原版官网），断言随之更新。
  /*
  const q = A.resolveCorrectSite('qbittorrent-enhanced.cc');
  const qs = (q && q.sites) || [];
  t('qBittorrent EE 列出 2 个站点（发布页 + 镜像）', qs.length === 2, qs.length);
  */
  // 2) qBittorrent EE：没有主机名官网，唯一入口是 GitHub Releases（链接级）；
  //    2026-11-22 起与 qBittorrent 互相「关联品牌词」，所以还会带出原版官网。
  const q = A.resolveCorrectSite('qbittorrent-enhanced.cc');
  const qs = (q && q.sites) || [];
  t('qBittorrent EE 列出 3 个站点（发布页 + 镜像 + 关联的原版官网）', qs.length === 3, qs.length);
  t('qBittorrent EE 指向 Releases 链接',
    !!qs[0] && qs[0].url === 'https://github.com/c0re100/qBittorrent-Enhanced-Edition/releases',
    qs[0] && qs[0].url);
  t('qBittorrent EE 判定为链接级', !!qs[0] && qs[0].kind === 'link', qs[0] && qs[0].kind);
  t('qBittorrent EE 带「GitHub 发布页」文案', !!qs[0] && qs[0].label === 'GitHub 发布页', qs[0] && qs[0].label);
  t('qBittorrent EE 自己那两条没有分组名', !qs[0].group && !qs[1].group, (qs[0] && qs[0].group) || '');
  t('qBittorrent EE 关联出原版官网（group=qBittorrent）',
    !!qs[2] && qs[2].url === 'https://qbittorrent.org' && qs[2].group === 'qBittorrent',
    qs[2] && (qs[2].url + ' | ' + qs[2].group));

  // 2b) 反方向：原版条目的仿冒站也要能看到增强版入口（这正是用户报的问题）
  const qo = A.resolveCorrectSite('qbittorrent.org.cn');
  const qos = (qo && qo.sites) || [];
  t('qBittorrent 列出 3 个站点（原版官网 + 增强版两条）', qos.length === 3, qos.length);
  t('qBittorrent 首条是原版官网且无分组', !!qos[0] && qos[0].url === 'https://qbittorrent.org' && !qos[0].group,
    qos[0] && qos[0].url);
  t('qBittorrent 带出增强版 GitHub 发布页',
    !!qos[1] && qos[1].url === 'https://github.com/c0re100/qBittorrent-Enhanced-Edition/releases',
    qos[1] && qos[1].url);
  t('关联站点都打了 group=qBittorrent Enhanced Edition',
    !!qos[1] && qos[1].group === 'qBittorrent Enhanced Edition' &&
    !!qos[2] && qos[2].group === 'qBittorrent Enhanced Edition',
    qos[1] && qos[1].group);
  t('关联合并后无重复 url', new Set(qos.map(function (x) { return x.url; })).size === qos.length);

  // 3) WorkBuddy：两个官网，第二个是挂在 codebuddy.cn 的链接级页面
  const b = A.resolveCorrectSite('workbuddy-cn.com');
  const bs = (b && b.sites) || [];
  t('WorkBuddy 列出 4 个站点', bs.length === 4, bs.length);
  t('WorkBuddy 第一条是主站', !!bs[0] && bs[0].url === 'https://www.workbuddy.cn', bs[0] && bs[0].url);
  t('WorkBuddy 第二条是 workbuddy.ai', !!bs[1] && bs[1].url === 'https://www.workbuddy.ai' && bs[1].kind === 'host', bs[1] && (bs[1].url + ' ' + bs[1].kind));
  t('WorkBuddy 第四条是 CodeBuddy 链接级页 /work/',
    !!bs[3] && bs[3].url === 'https://www.codebuddy.cn/work/' && bs[3].kind === 'link',
    bs[3] && (bs[3].url + ' ' + bs[3].kind));

  // 4) 单站点条目自动补出 sites（旧数据不改也能被说明页消费）
  const h = A.resolveCorrectSite('huorongsafe.com.cn');
  const hs = (h && h.sites) || [];
  // 旧（2026-11-18）：火绒只有 1 个站点
  //   2026-11-22 起与「火绒安全论坛」互相关联，站点数变成 2（见本节第 7 组断言）。
  // t('火绒虽为旧写法也有 sites', hs.length === 1 && hs[0].url === 'https://huorong.cn', JSON.stringify(hs));
  t('火绒旧写法条目也有 sites 且首条是主站', hs.length >= 1 && !!hs[0] && hs[0].url === 'https://huorong.cn', JSON.stringify(hs));

  // 5) 查不到 → null（说明页据此显示「暂未收录」）
  t('无关域名返回 null', A.resolveCorrectSite('totally-unrelated-xyz.com') === null);

  // 7) 「关联品牌词」：火绒主站 ↔ 火绒安全论坛（2026-11-22）
  const hr = A.resolveCorrectSite('huorong.cn');
  const hrs = (hr && hr.sites) || [];
  t('火绒列出 2 个站点（主站 + 官方论坛）', hrs.length === 2, hrs.length);
  t('火绒第一条是主站且无分组名', !!hrs[0] && hrs[0].url === 'https://huorong.cn' && !hrs[0].group,
    hrs[0] && (hrs[0].url + ' | ' + hrs[0].group));
  t('火绒第二条是论坛，group=火绒安全论坛',
    !!hrs[1] && hrs[1].url === 'https://bbs.huorong.cn' && hrs[1].group === '火绒安全论坛',
    hrs[1] && (hrs[1].url + ' | ' + hrs[1].group));
  const hb = A.resolveCorrectSite('huorongbbs.com');
  const hbs = (hb && hb.sites) || [];
  t('仿冒论坛命中「火绒安全论坛」条目', !!hb && hb.brand === 'huorongbbs', hb && hb.brand);
  t('火绒论坛反向带出主站（group=火绒安全软件）',
    hbs.length === 2 && !!hbs[1] && hbs[1].url === 'https://huorong.cn' && hbs[1].group === '火绒安全软件',
    JSON.stringify(hbs.map(function (x) { return x.url + '|' + x.group; })));

  // 8) 云端 correct_sites 迁入内置表（2026-11-22）：4 个品牌现在必须由内置表命中
  const migrated = [
    ['tencentmeeting-x.com', '腾讯会议', 2],
    ['chromium-fake.com', 'Chromium', 1],
    ['xfyun-fake.com', '讯飞开放平台', 2],
    ['iciba-fake.com', '金山词霸', 2]
  ];
  for (let mi = 0; mi < migrated.length; mi++) {
    const m = migrated[mi];
    const r = A.resolveCorrectSite(m[0]);
    t(m[1] + ' 已由内置表命中（source=builtin）', !!r && r.source === 'builtin', r && r.source);
    t(m[1] + ' 列出 ' + m[2] + ' 个站点', !!r && r.sites.length === m[2], r && r.sites.length);
  }

  // 9) 跨数据源关联（方案二）：内置条目 rel 指向「只存在于云端」的品牌，也必须生效
  const relSaved = I.CORRECT_SITE_RELATIONS['huorong'];
  I.CORRECT_SITE_RELATIONS['huorong'] = ['zzcloudbbs'];
  A.registerCloudCorrect([{ product: '云端论坛', brands: ['zzcloudbbs'], domain: 'bbs.example-cdn-test.com' }]);
  const cs = (A.resolveCorrectSite('huorong.cn') || {}).sites || [];
  t('内置条目能带出云端补录的关联条目',
    cs.length === 3 && !!cs[2] && cs[2].url === 'https://bbs.example-cdn-test.com',
    JSON.stringify(cs.map(function (x) { return x.url; })));
  t('跨数据源追加的站点带 group=云端产品名', !!cs[2] && cs[2].group === '云端论坛', cs[2] && cs[2].group);
  A.registerCloudCorrect([]);                      // 还原云端表，避免污染后续用例
  I.CORRECT_SITE_RELATIONS['huorong'] = relSaved;   // 还原内置关联表

  // 10) 「同一产品的区域版 / 国际版」关联（2026-11-22 第十一轮）
  //     判据：同一产品的两套站点、共用账号或同一品牌授权；被拦在任一方的仿冒站上，看到对方官网是有用的。
  const pairs = [
    { a: 'feishu.cn',           b: 'larksuite.com',    pa: '飞书',       pb: 'Lark（飞书国际版）' },
    { a: 'douyin.com',          b: 'tiktok.com',       pa: '抖音',       pb: 'TikTok' },
    { a: 'steampowered.com',    b: 'steamchina.com',   pa: 'Steam',      pb: '蒸汽平台' },
    { a: 'alipay.com',          b: 'alipayplus.com',   pa: '支付宝',     pb: '支付宝国际' },
    { a: 'unionpay.com',        b: 'unionpayintl.com', pa: '中国银联',   pb: '银联国际' }
  ];
  for (let pi = 0; pi < pairs.length; pi++) {
    const pr = pairs[pi];
    const ra = A.resolveCorrectSite(pr.a);
    const rb = A.resolveCorrectSite(pr.b);
    t(pr.pa + ' 能带出 ' + pr.pb,
      !!ra && ra.sites.some(function (x) { return x.url === "https://" + pr.b && x.group === pr.pb; }),
      ra && JSON.stringify(ra.sites.map(function (x) { return x.url + "|" + x.group; })));
    t(pr.pb + ' 反向带出 ' + pr.pa,
      !!rb && rb.sites.some(function (x) { return x.url === "https://" + pr.a && x.group === pr.pa; }),
      rb && JSON.stringify(rb.sites.map(function (x) { return x.url + "|" + x.group; })));
  }

  // 11) Aria2 曾拆成两条（aria2 / aria2.github，同产品同站点），2026-11-22 合并为一条
  const ar = A.resolveCorrectSite('aria2.github.io');
  t('Aria2 只剩一条条目（站点数 1）', !!ar && ar.sites.length === 1, ar && ar.sites.length);
  t('Aria2 品牌词已含 aria2.github', !!ar && /aria2\.github/.test(ar.brand), ar && ar.brand);

  // 12) 冗余条目注释后仍能解析（2026-11-22 第十二轮）：品牌词已并入保留的那一行
  const mergedRows = [
    ['mi.com',                 '小米',           'https://xiaomi.com'],
    ['mi.com.cn',              '小米',           'https://xiaomi.com'],
    ['wechatpay-vip.top',      '微信支付',       'https://pay.weixin.qq.com'],
    ['wxpay.top',              '微信支付',       'https://pay.weixin.qq.com'],
    ['163vip.top',             '网易',           'https://163.com'],
    ['sogou.browser.qq.com',   '搜狗高速浏览器', 'https://sogou.browser.qq.com'],
    ['chat.baidu.com',         '百度文心',       'https://wenxin.baidu.com'],
    ['ime.baidu.com',          '百度输入法',     'https://shurufa.baidu.com'],
    ['zhifubao.top',           '支付宝',         'https://alipay.com']
  ];
  for (let mi2 = 0; mi2 < mergedRows.length; mi2++) {
    const mr = mergedRows[mi2];
    const rr = A.resolveCorrectSite(mr[0]);
    t('合并后 ' + mr[0] + ' 仍落到「' + mr[1] + '」',
      !!rr && rr.product === mr[1] && !!rr.sites[0] && rr.sites[0].url === mr[2],
      rr && (rr.product + " | " + (rr.sites[0] || {}).url));
  }
  const sgb = A.resolveCorrectSite('sogou-browser.top');
  t('带连字符的 sogou-browser.top 落到搜狗浏览器（不再误落搜狗搜索）',
    !!sgb && sgb.product === '搜狗高速浏览器', sgb && sgb.product);

  // 13) 补品牌词后新命中（2026-11-22 第十二轮）：此前一律落说明页
  const addedWords = [
    ['skywork-shop.top',    '天工 Skywork'],
    ['react-official.top',  'React'],
    ['chrome-setup.top',    'Google / Chrome'],
    ['kwai-vip.top',        '快手'],
    ['wetv-vip.top',        '腾讯视频'],
    ['temu-shop.top',       '拼多多'],
    ['bigmodel-fake.top',   '智谱清言'],
    ['photoshop-crack.top', 'Adobe'],
    ['excel-crack.top',     'Microsoft Office / 365'],
    ['teams-crack.top',     'Microsoft 微软']
  ];
  for (let ai2 = 0; ai2 < addedWords.length; ai2++) {
    const aw = addedWords[ai2];
    const ar2 = A.resolveCorrectSite(aw[0]);
    t('补词后 ' + aw[0] + ' 落到「' + aw[1] + '」',
      !!ar2 && ar2.product === aw[1],
      ar2 && (ar2.product + " | " + ar2.brand));
  }

  // 6) 归一化护栏：脏数据一律丢弃，绝不能变成可点链接
  const bad1 = I.normalizeCorrectSites(['javascript:alert(1)']);
  t('拒绝 javascript: 协议', bad1.length === 0, JSON.stringify(bad1));
  const bad2 = I.normalizeCorrectSites(['*.example.com', 'exa mple.com', '<img src=x>']);
  t('拒绝通配 / 空白 / 标签', bad2.length === 0, JSON.stringify(bad2));
  const bad3 = I.normalizeCorrectSites([['a.example.com', '某个文案']]);
  t('拒绝 [地址, 文案] 数组形态', bad3.length === 0, JSON.stringify(bad3));
  const dedup = I.normalizeCorrectSites(['a.example.com', 'https://a.example.com']);
  t('同一地址去重', dedup.length === 1, dedup.length);
  const cap = I.normalizeCorrectSites(['a1.com', 'a2.com', 'a3.com', 'a4.com', 'a5.com', 'a6.com', 'a7.com', 'a8.com', 'a9.com', 'a10.com']);
  t('单条最多 8 个站点', cap.length === 8, cap.length);

  // 旧：条数写死（2026-11-22 改为 ran 动态统计）
  // const total = 19;
  // console.log((bad ? '✗ ' : '✓ ') + '站点列表 ' + (total - bad) + '/' + total + ' 通过');
  console.log((bad ? '✗ ' : '✓ ') + '站点列表 ' + (ran - bad) + '/' + ran + ' 通过');
  return bad;
}

// 云端补录：读私有仓库里的 whitelist.json（不在本仓库内时跳过这一组）
const WL = path.join(__dirname, '..', '..', 'SilverFoxBlocker-Cloud', 'List', 'whitelist.json');
if (fs.existsSync(WL)) {
  try {
    const j = JSON.parse(fs.readFileSync(WL, 'utf8'));
    const n = A.registerCloudCorrect(j.correct_sites || []);
    console.log('\n云端补录品牌词：' + n + ' 个');
    fail += run('内置 + 云端', BUILTIN_CASES.concat(CLOUD_CASES));

    // 2026-11-18：云端补录同样支持 sites（多官网 / 链接级），与内置条目同构
    {
      console.log('\n== 云端补录的 sites 字段 ==');
      let bad = 0;
      const t = function (name, cond, extra) {
        if (!cond) { bad++; console.log('FAIL  ' + name + (extra !== undefined ? '   ' + extra : '')); }
      };
      const r = A.resolveCorrectSite('tencentmeeting-x.com');
      const s = (r && r.sites) || [];
      t('腾讯会议列出 2 个站点', s.length === 2, s.length);
      t('第一条是 meeting.tencent.com', !!s[0] && s[0].host === 'meeting.tencent.com', s[0] && s[0].host);
      t('第二条带自定义文案「国际版 VooV」', !!s[1] && s[1].label === '国际版 VooV', s[1] && s[1].label);
      // 旧（2026-11-18）：腾讯会议只存在于云端补录
      // t('云端条目标记为 source=cloud', !!r && r.source === 'cloud', r && r.source);
      // 新（2026-11-22）：该条已迁入内置表；云端 correct_sites 里留的是回滚副本，内置优先 → builtin
      t('腾讯会议条目已由内置表提供（source=builtin）', !!r && r.source === 'builtin', r && r.source);
      console.log((bad ? '✗ ' : '✓ ') + (4 - bad) + '/4 通过');
      fail += bad;
    }
  } catch (e) {
    console.log('\n（读取 whitelist.json 失败，跳过云端用例：' + e.message + '）');
  }
} else {
  console.log('\n（未找到 ' + WL + '，跳过云端用例）');
}

// 2026-11-21：浏览器 / IM / 输入法三类的「多官网」条目（本轮按实测结果补齐）
{
  console.log('\n== 三类多官网条目（浏览器 / IM / 输入法）==');
  const _failBefore3 = fail;
  const t = function (name, cond, extra) {
    if (!cond) { fail++; console.log('FAIL  ' + name + (extra !== undefined ? '   ' + extra : '')); }
  };
  const sites = function (h) { const r = A.resolveCorrectSite(h); return (r && r.sites) || []; };

  // 浏览器：UC 中国站 + 国际站
  const uc = sites('ucweb-browser-fake.com');
  t('UC 浏览器 2 个站点', uc.length === 2, uc.length);
  t('UC 第一条 uc.cn「中国官网」', !!uc[0] && uc[0].host === 'uc.cn' && uc[0].label === '中国官网', uc[0] && (uc[0].host + ' ' + uc[0].label));
  t('UC 第二条 ucweb.com 且为主机名级', !!uc[1] && uc[1].host === 'ucweb.com' && uc[1].kind === 'host', uc[1] && (uc[1].host + ' ' + uc[1].kind));

  // 浏览器：Apple 国际站 + 中国站
  const ap = sites('apple-id-support.com');
  t('Apple 2 个站点', ap.length === 2, ap.length);
  t('Apple 第二条 apple.com.cn「中国官网」', !!ap[1] && ap[1].host === 'apple.com.cn' && ap[1].label === '中国官网', ap[1] && (ap[1].host + ' ' + ap[1].label));

  // 浏览器：Safari 没有独立域名 → 唯一站点是链接级
  const sf = sites('safari-download-free.com');
  t('Safari 只有 1 个站点且为链接级', sf.length === 1 && sf[0].kind === 'link', JSON.stringify(sf.map(s => s.kind)));
  t('Safari 指向 apple.com/safari/', !!sf[0] && sf[0].url === 'https://apple.com/safari/', sf[0] && sf[0].url);

  // 浏览器：360 极速 = 极速X + 旧版 /ee/
  const se = sites('360chrome-fake.com');
  t('360 极速 2 个站点', se.length === 2, se.length);
  t('360 极速第二条是 /ee/ 链接级', !!se[1] && se[1].url === 'https://browser.360.cn/ee/' && se[1].kind === 'link', se[1] && se[1].url);

  // 浏览器：QQ 浏览器两个独立入口
  const qq = sites('qqbrowser-download.com');
  t('QQ 浏览器 2 个站点', qq.length === 2, qq.length);
  t('QQ 浏览器第二条 liulanqi.qq.com', !!qq[1] && qq[1].host === 'liulanqi.qq.com', qq[1] && qq[1].host);

  // IM：微信中国版 + 国际版（品牌词 weixin / wechat 同一张表）
  const wx = sites('weixin-safe.com');
  t('微信 2 个站点', wx.length === 2, wx.length);
  t('微信第二条 wechat.com「国际版官网」', !!wx[1] && wx[1].host === 'wechat.com' && wx[1].label === '国际版官网', wx[1] && (wx[1].host + ' ' + wx[1].label));

  // IM：微博主站 + 手机版
  const wb = sites('weibo-vip.com');
  t('微博 2 个站点，第二条 weibo.cn', wb.length === 2 && wb[1].host === 'weibo.cn', JSON.stringify(wb.map(s => s.host)));

  // IM：即刻新域在前、旧域在后
  const jk = sites('ruguoapp-app.com');
  t('即刻 2 个站点，okjike.com 在前', jk.length === 2 && jk[0].host === 'okjike.com' && jk[1].host === 'ruguoapp.com', JSON.stringify(jk.map(s => s.host)));

  // IM：小红书仍只有 1 个（xhs.com 已不可访问）
  const xhs = sites('xiaohongshu-shop.com');
  t('小红书只有 1 个站点', xhs.length === 1 && xhs[0].host === 'xiaohongshu.com', JSON.stringify(xhs.map(s => s.host)));

  // 输入法：讯飞 = 产品站 + 科大讯飞官网
  const xf = sites('xunfei-download.com');
  t('讯飞输入法 2 个站点', xf.length === 2, xf.length);
  t('讯飞第二条 iflytek.com「科大讯飞官网」', !!xf[1] && xf[1].host === 'iflytek.com' && xf[1].label === '科大讯飞官网', xf[1] && (xf[1].host + ' ' + xf[1].label));

  // 输入法：百度输入法两个入口
  const bd = sites('baidushurufa-pc.com');
  t('百度输入法 2 个站点，第二条 ime.baidu.com', bd.length === 2 && bd[1].host === 'ime.baidu.com', JSON.stringify(bd.map(s => s.host)));

  const bad3 = fail - _failBefore3;
  console.log((bad3 ? '✗ ' + (24 - bad3) + '/24' : '✓ 24/24') + ' 通过');
}

console.log('\n合计失败：' + fail);
process.exit(fail ? 1 : 0);
