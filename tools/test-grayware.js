// 临时测试：2026-11-24 新增的 8 个「诱导下载/灰产」维度
// 用法：node tools/test-grayware.js
const A = require('../rules/analyzer.js');

let pass = 0, fail = 0;
function t(name, cond, extra) {
  if (cond) { pass++; console.log('PASS ' + name); }
  else { fail++; console.log('FAIL ' + name + (extra ? '  → ' + extra : '')); }
}
function feat(res, id) { return !!(res && res.features && res.features[id]); }
function run(data) {
  return A.analyze(Object.assign({ hostname: 'demo-site.test', protocol: 'https:', title: '', html: '', links: [], scripts: [] }, data), {});
}

// ---------- 1. 脚本集中下载地址 ----------
let r = run({
  html: '<a href="javascript:void(0)">立即下载</a>',
  scripts: ["var GLOBAL_DOWNLOAD_URL = 'https://demo-site.test/download.php?id=12';function go(){location.href=GLOBAL_DOWNLOAD_URL;}"]
});
t('scriptedDownload 命中 GLOBAL_DOWNLOAD_URL + download.php', feat(r, 'scriptedDownload'), JSON.stringify(r.reasons.map(x => x.label)));

r = run({
  html: '<img src="/a.png">',
  scripts: ["var downloadUrl = 'https://cdn.demo-site.test/logo/icon-32.png';"]
});
t('scriptedDownload 不误判普通资源变量', !feat(r, 'scriptedDownload'));

// ---------- 2. 占位下载按钮 ----------
r = run({
  html: '<a href="javascript:void(0)">立即下载</a><a href="#">下载客户端</a>',
  links: [
    { href: 'javascript:void(0)', text: '立即下载' },
    { href: '#', text: '下载客户端' }
  ],
  scripts: ["var GLOBAL_DOWNLOAD_URL = 'https://demo-site.test/download.php?id=7';"]
});
t('jsVoidDownload 命中（占位按钮 + 脚本集中地址）', feat(r, 'jsVoidDownload'));

r = run({
  html: '<a href="javascript:void(0)">立即下载</a><a href="#">下载客户端</a><a href="/about">关于</a>',
  links: [
    { href: 'javascript:void(0)', text: '立即下载' },
    { href: '#', text: '下载客户端' }
  ],
  scripts: ["var x = 1;"]
});
t('jsVoidDownload 无其它证据时不判（正规站弹层按钮）', !feat(r, 'jsVoidDownload'));

// ---------- 3. 多平台共用同一安装包 ----------
r = run({
  links: [
    { href: 'https://demo-site.test/setup.zip', text: 'Windows版下载' },
    { href: 'https://demo-site.test/setup.zip', text: 'Mac版下载' },
    { href: 'https://demo-site.test/setup.zip', text: 'Android版下载' }
  ]
});
t('sharedPackage 命中（三平台同一 zip）', feat(r, 'sharedPackage'), JSON.stringify(r.reasons.filter(x => /平台/.test(x.label))));

r = run({
  links: [
    { href: 'https://demo-site.test/win.zip', text: 'Windows版下载' },
    { href: 'https://demo-site.test/mac.zip', text: 'Mac版下载' },
    { href: 'https://demo-site.test/apk.zip', text: 'Android版下载' }
  ]
});
t('sharedPackage 不误判（各平台各自安装包）', !feat(r, 'sharedPackage'));

// ---------- 4. 下载链接运行时改写 ----------
t('hrefRewrite 命中（3 个链接被改写）', feat(run({ hrefRewrites: 3 }), 'hrefRewrite'));
t('hrefRewrite 不误判（仅 1 个）', !feat(run({ hrefRewrites: 1 }), 'hrefRewrite'));

// ---------- 5. 品牌冒充 + 官方身份 ----------
r = run({
  hostname: 'deepseek-pc-download.test',
  title: 'DeepSeek 官方网站 - 官方下载',
  html: '<a href="/x.zip">下载</a>',
  links: [{ href: '/x.zip', text: '下载' }]
});
t('brandOfficialClaim 命中（仿冒 deepseek + 官网话术）', feat(r, 'brandOfficialClaim'), JSON.stringify(r.reasons.map(x => x.label)));

r = run({
  hostname: 'www.deepseek.com',
  title: 'DeepSeek 官方网站',
  html: '<a href="/x.zip">下载</a>',
  links: [{ href: '/x.zip', text: '下载' }]
});
t('brandOfficialClaim 不误判官方站', !feat(r, 'brandOfficialClaim'));

// ---------- 6. 备案号格式 ----------
t('icpFormat 命中（流水号 3 位）', feat(run({ icp: { icpNumber: '京ICP备123号' }, html: '<p>京ICP备123号</p>' }), 'icpFormat'));
t('icpFormat 命中（全 0）', feat(run({ icp: { icpNumber: '沪ICP备00000000号' }, html: '<p>沪ICP备00000000号</p>' }), 'icpFormat'));
t('icpFormat 不误判（正常 10 位）', !feat(run({ icp: { icpNumber: '粤ICP备2023012345号' }, html: '<p>粤ICP备2023012345号</p>' }), 'icpFormat'));
t('icpFormat 权威确认有备案时不判', !feat(run({ icp: { icpNumber: '京ICP备123号' }, icpAuth: { queried: true, hasIcp: true } }), 'icpFormat'));

// ---------- 7. 黑产基础设施指纹 ----------
t('blackhatFingerprint 命中 adseo', feat(run({ html: '<script src="https://www.adseo.com.cn/s.js"></script>' }), 'blackhatFingerprint'));
t('blackhatFingerprint 命中 noah/api.php', feat(run({ html: '<script>fetch("https://noah-api.test/v1/api.php")</script>', scripts: ['fetch("https://noah-api.test/v1/api.php")'] }), 'blackhatFingerprint'));
t('blackhatFingerprint 不误判普通 api.php', !feat(run({ html: '<script>fetch("https://demo-site.test/api.php")</script>', scripts: ['fetch("https://demo-site.test/api.php")'] }), 'blackhatFingerprint'));

// ---------- 8. 反开发者 ----------
r = run({
  html: '<a href="/setup.zip">下载客户端</a>',
  scripts: ['setInterval(function(){ debugger; }, 500);']
});
t('antiDeveloper 命中（debugger 死循环 + 有下载入口）', feat(r, 'antiDeveloper'), JSON.stringify(r.reasons.map(x => x.label)));

r = run({
  html: '<p>纯内容页</p>',
  scripts: ['setInterval(function(){ debugger; }, 500);']
});
t('antiDeveloper 无下载入口时不判', !feat(r, 'antiDeveloper'));

// ---------- 回归：最小输入不崩、官方域仍是官方 ----------
r = run({ hostname: 'www.deepseek.com', html: '<html><body>hi</body></html>' });
t('回归：最小输入可正常判定', typeof r.score === 'number' && !!r.level);

// ---------- 9. 阈值标定（danger=72）：过/欠评分回归 ----------
// 典型诱导页：下载地址不写在 href 里（占位按钮）+ 脚本集中地址 + 反调试，但没有 noah/adseo 硬指纹。
// 旧权重 40 + 门控漏判 antiDeveloper = 62（停在 warn，没有拦截）；标定后应 ≥72 判危。
r = run({
  hostname: 'down-soft-free.test', title: '官方下载',
  html: '<a href="javascript:void(0)">立即下载</a><a href="#">下载安装包</a>',
  links: [{ href: 'javascript:void(0)', text: '立即下载' }, { href: '#', text: '下载安装包' }],
  scripts: ["var DOWNLOAD_URL='https://cdn.x.test/dl.php?id=1';setInterval(function(){debugger},500);"]
});
t('标定：典型诱导页达 danger（≥72）', r.level === 'danger' && r.score >= 72, r.level + '/' + r.score);

// 良性对照：国产 CMS 官方下载页（集中下载地址 + 合规备案号 + 防复制 + 直链 exe）。
// 刻意不写「官方」字样、不触发组合升级，用来单独验证权重：40+18+12 = 70（旧），34+20+12 = 66（现）。
r = run({
  hostname: 'www.my-soft-site.test', title: '软件下载中心',
  html: '<footer>粤ICP备12345678号-1</footer><a href="/download/setup.exe">下载</a>',
  links: [{ href: '/download/setup.exe', text: '立即下载' }],
  scripts: ["var GLOBAL_DOWNLOAD_URL='/download/file.php?id=3';document.addEventListener('contextmenu',function(e){e.preventDefault();});"],
  icp: { icpNumber: '粤ICP备12345678号-1' }
});
t('标定：良性 CMS 下载页不判 danger（<72）', r.level !== 'danger' && r.score < 72, r.level + '/' + r.score);

// ---------- 10. 黑产指纹 / 反开发者 的权重实测（2026-11-24 第二轮）----------
// 黑产指纹原 35：单条只有 35 分连 warn 线（42）都不到；与集中下载地址叠加 69 分仍不拦。
t('标定：仅 adseo 引用至少有预警（≥warn 线 42）', (function () {
  const x = run({ hostname: 'cheap-soft.test', html: '<script src="https://www.adseo.com.cn/j.js"></script><h1>软件下载</h1>' });
  return x.score >= 42 && x.level !== 'safe';
})(), (function () { const x = run({ hostname: 'cheap-soft.test', html: '<script src="https://www.adseo.com.cn/j.js"></script><h1>软件下载</h1>' }); return x.level + '/' + x.score; })());
t('标定：黑产指纹 + 集中下载地址 判 danger', (function () {
  const x = run({
    hostname: 'cheap-soft.test', html: '<script src="https://www.adseo.com.cn/j.js"></script><a href="/dl/x.zip">下载</a>',
    links: [{ href: '/dl/x.zip', text: '下载' }], scripts: ["var DOWNLOAD_URL='https://cdn.x.test/dl.php?id=1';"]
  });
  return x.level === 'danger';
})(), (function () {
  const x = run({
    hostname: 'cheap-soft.test', html: '<script src="https://www.adseo.com.cn/j.js"></script><a href="/dl/x.zip">下载</a>',
    links: [{ href: '/dl/x.zip', text: '下载' }], scripts: ["var DOWNLOAD_URL='https://cdn.x.test/dl.php?id=1';"]
  });
  return x.level + '/' + x.score;
})());
// 反开发者原 18：占位按钮+集中地址+debugger、但不写「官方」话术时只有 70 分，差 2 分不拦。
r = run({
  hostname: 'down-soft-free.test', title: '软件下载',
  html: '<a href="javascript:void(0)">立即下载</a><a href="#">下载安装包</a>',
  links: [{ href: 'javascript:void(0)', text: '立即下载' }, { href: '#', text: '下载安装包' }],
  scripts: ["var DOWNLOAD_URL='https://cdn.x.test/dl.php?id=1';setInterval(function(){debugger},500);"]
});
t('标定：无「官方」话术的典型诱导页也达 danger（≥72）', r.level === 'danger' && r.score >= 72, r.level + '/' + r.score);

// noah 品牌域自带的 /api.php（同站）不算黑产基础设施
t('blackhatFingerprint 不误判 noah 品牌域自身 api.php',
  !feat(run({ hostname: 'www.noah.com.cn', html: '<script>fetch("/api.php?id=1")</script>', scripts: ['fetch("https://www.noah.com.cn/api.php?id=1")'] }), 'blackhatFingerprint'));
t('blackhatFingerprint 不误判纯字母品牌词（noahsoft）',
  !feat(run({ html: '<script>fetch("https://cdn.noahsoft.io/api.php")</script>', scripts: ['fetch("https://cdn.noahsoft.io/api.php")'] }), 'blackhatFingerprint'));

// 权重不漂移
const w = {};
(A.CATEGORIES || []).forEach(function (c) { w[c.id] = c.weight; });
t('权重：scriptedDownload=34', w.scriptedDownload === 34, '实际 ' + w.scriptedDownload);
t('权重：icpFormat=12', w.icpFormat === 12, '实际 ' + w.icpFormat);
t('权重：blackhatFingerprint=45', w.blackhatFingerprint === 45, '实际 ' + w.blackhatFingerprint);
t('权重：antiDeveloper=20', w.antiDeveloper === 20, '实际 ' + w.antiDeveloper);

t('回归：CATEGORIES 数量 = 37', A.CATEGORIES.length === 37, '实际 ' + A.CATEGORIES.length);

console.log('\n' + pass + ' passed, ' + fail + ' failed');
process.exit(fail ? 1 : 0);
