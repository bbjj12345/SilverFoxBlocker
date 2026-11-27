// 品牌词「重排 / 插字」变体（隐藏分支 A+B）回归
// 用法：node tools/test-brand-variant.js
// 背景：basic（段/子串/编辑距离 + LCP·LCS≥4）漏掉的两类样本，由隐藏分支补齐；
//       本文件同时锁定「basic 结果不变」与「变体不进 STRONG 组合」两条边界。
const A = require('../rules/analyzer.js');

let pass = 0, fail = 0;
function t(name, cond, extra) {
  if (cond) { pass++; console.log('PASS ' + name); }
  else { fail++; console.log('FAIL ' + name + (extra ? '  → ' + extra : '')); }
}
function run(d, o) {
  return A.analyze(Object.assign({ hostname: 'demo.test', protocol: 'https:', title: '', html: '', links: [], scripts: [] }, d), o || {});
}
function variant(r) { return r.reasons.find(x => /拼写变体/.test(x.label)); }
function spoof60(r) { return r.reasons.find(x => x.label === '域名仿冒官方品牌'); }

// ---------- 1. 目标样本：重排 / 插字 ----------
let r = run({ hostname: 'ai.deekseep-e.com.cn' });
t('重排变体命中（deekseep-e：与 deepseek 字母集相同）', !!variant(r) && variant(r).weight === 45, r.score + '/' + r.level);
t('重排变体文案标明「重排」', /重排/.test((variant(r) || {}).detail || ''), (variant(r) || {}).detail);

r = run({ hostname: 'cn.deeposieek.com.cn' });
t('插字变体命中（deeposieek：插 o/i）', !!variant(r) && variant(r).weight === 45, r.score + '/' + r.level);
t('插字变体文案标明「插入」', /插入/.test((variant(r) || {}).detail || ''), (variant(r) || {}).detail);

t('变体只给分不给 STRONG（features.domainImpersonation=false）', run({ hostname: 'deekseep.test' }).features.domainImpersonation === false);

// ---------- 2. basic 结果必须原样保留 ----------
r = run({ hostname: 'deepseak.test' });
t('basic 仍按 typo 命中并给 60 分', !!spoof60(r) && spoof60(r).weight === 60, r.score + '/' + r.level);
t('basic 命中时不叠加变体分支（只出现一条理由）', run({ hostname: 'deepseak.test' }).reasons.filter(x => /域名仿冒/.test(x.label)).length === 1);
t('官方域名仍判安全（www.deepseek.com）', run({ hostname: 'www.deepseek.com' }).score === 0);
t('官方子域仍判安全（chat.deepseek.com）', run({ hostname: 'chat.deepseek.com' }).score === 0);

// ---------- 3. 误报护栏 ----------
for (const h of ['www.desktop.com', 'www.teams.com', 'www.deepseeker.com', 'blog.deepseeking.com',
  'www.finance.com', 'www.telemark.com', 'www.netscape.com']) {
  t('不误判：' + h, !variant(run({ hostname: h })), JSON.stringify((variant(run({ hostname: h })) || {}).detail));
}
t('UGC 托管平台不判（deepseek.github.io）', !variant(run({ hostname: 'deepseek.github.io' })));

// ---------- 4. 与 basic 共用豁免 ----------
t('权威备案确认有备案时跳过变体分支', !variant(run({ hostname: 'ai.deekseep-e.com.cn', icpAuth: { queried: true, hasIcp: true } })));

// ---------- 5. 不可独立关闭：随「域名仿冒」维度开关 ----------
t('关闭域名仿冒维度后变体同时失效', !variant(run({ hostname: 'deekseep.test' }, { enabled: { domainImpersonation: false } })));
t('变体不是独立维度（CATEGORIES 中无对应项）', !A.CATEGORIES.some(c => /variant|变体/i.test(c.id)));

// ---------- 6. 组合行为：变体靠分数叠加，不靠「强特征即判危」 ----------
r = run({ hostname: 'deekseep-e.cn', title: 'DeepSeek 官方下载', html: '<a href="/x.exe">下载</a>', links: [{ href: '/x.exe', text: '下载' }] });
t('变体 + 下载 + 官方话术 达 danger', r.level === 'danger', r.score + '/' + r.level);
t('同页仍不把变体计为组合升级因子', r.features.domainImpersonation === false);

// ---------- 7. token 切分 / 窗口拼接 / 子串包含（2026-11-24 第二轮升级）----------
// 目标样本：382web.cnds-deepseek-harness.com.cn。basic 的段匹配已能命中（hyphen 段 = 品牌词）。
r = run({ hostname: '382web.cnds-deepseek-harness.com.cn', title: 'DeepSeek 官方下载', html: '<a href="/x.exe">下载</a>' });
t('目标域名 basic 段匹配命中（60 分）', !!spoof60(r) && spoof60(r).weight === 60, r.score + '/' + r.level);
t('目标域名整页判危', r.level === 'danger', r.score + '/' + r.level);

// 同一族的分片写法：品牌词被连字符拆成 deep + seek，全局拼接后长度差 >3 会被旧实现丢弃
r = run({ hostname: '382web.cnds-deep-seek-harness.com.cn' });
t('连字符拆分品牌词由窗口拼接命中（deep-seek）', !!variant(r) && variant(r).weight === 45, r.score + '/' + r.level);
t('窗口拼接文案标明「分片拼接」', /分片拼接/.test((variant(r) || {}).detail || ''), (variant(r) || {}).detail);
t('分片拼接仍不进 STRONG 组合', r.features.domainImpersonation === false);
t('连字符拆分在非品牌域上也命中（my-deep-seek-app.com）', !!variant(run({ hostname: 'my-deep-seek-app.com' })));

// 连字符被整段删掉的拼接式：A/B 都够不到，由子串包含兜底（30 分）
r = run({ hostname: '382web.cndsdeepseekharness.com.cn' });
t('拼接式（cndsdeepseekharness）命中且只给 30 分', !!variant(r) && variant(r).weight === 30, r.score + '/' + r.level);
t('拼接式文案标明「嵌有品牌词」', /嵌有品牌词/.test((variant(r) || {}).detail || ''), (variant(r) || {}).detail);
t('拼接式 30 分单独够不到可疑线', run({ hostname: 'cndsdeepseekharness.com' }).score < 42);
t('拼接式不进 STRONG 组合', run({ hostname: 'cndsdeepseekharness.com' }).features.domainImpersonation === false);
t('拼接式 + 页面证据可判危',
  run({ hostname: '382web.cndsdeepseekharness.com.cn', title: '官方下载', html: '<a href="javascript:void(0)">立即下载</a>', scripts: ["var DOWNLOAD_URL='/api.php?id=1';"] }).level === 'danger');

// 护栏：品牌词前后只挂「站点性质词」时不按拼接式判
for (const h of ['mydeepseek.com', 'mydeepseekfan.com', 'thedeepseek.com', 'getdeepseek.com',
  'deepseektools.com', 'bestdeepseektools.com', 'deepseekcloud.com', 'deepseekers.com', 'www.deepseeker.com']) {
  t('拼接式不误判：' + h, !variant(run({ hostname: h })), JSON.stringify((variant(run({ hostname: h })) || {}).detail));
}
// 品牌自有域名（SLD 恰为品牌词）与 basic 同样豁免
for (const h of ['chrome.com', 'android.com', 'safari.com', 'firefox.com']) {
  const rr = run({ hostname: h });
  t('品牌自有域名不误判：' + h, rr.score === 0 && !variant(rr), rr.score + '/' + rr.level);
}

// ---------- 8. 架构：单一豁免闸门 / 信号分级 / 不双计 ----------
// 两条线共用一道豁免闸门（_spoofExempt），任一分支漏写都会在这组用例暴露
for (const h of ['www.moonshot.cn', 'kimi.moonshot.cn', 'wechat-tips.github.io', 'wps-guide.vercel.app']) {
  t('统一闸门：官方/UGC 不判仿冒 ' + h, run({ hostname: h }).score === 0, run({ hostname: h }).score + '/' + run({ hostname: h }).level);
}
// 信号分级：basic 60 > variant 45 > embed 30，且任一域名只产出一条「域名仿冒」理由
const tierCases = [['deepseak.test', 60], ['deekseep.test', 45], ['cndsdeepseekharness.com', 30]];
for (const [h, w] of tierCases) {
  const rr = run({ hostname: h });
  const hits = rr.reasons.filter(x => /域名仿冒/.test(x.label));
  t('分级：' + h + ' 命中 ' + w + ' 分且仅一条理由', hits.length === 1 && hits[0].weight === w, hits.map(x => x.weight).join(','));
}
// soft 只标在非 basic 上（basic 才允许参与 STRONG 组合升级）
const basicHit = run({ hostname: 'deepseak.test' }).reasons.find(x => /域名仿冒/.test(x.label));
t('basic 命中不带 soft 标记', basicHit && basicHit.soft === undefined);
// 窗口拼接与子串包含不会对同一域名重复加分
r = run({ hostname: '382web.cnds-deep-seek-harness.com.cn' });
t('同一域名不会同时计「分片拼接」与「子串包含」',
  r.reasons.filter(x => /拼写变体/.test(x.label)).length === 1, r.reasons.map(x => x.label).join('|'));

// ---------- 9. 数字未被形近归一化吃掉 / 品牌词+完整词缀 ----------
// ① 形近归一化会把 0→o、1→l，导致「品牌词 + 数字」被折叠成假剩余（deepseek10 → deepseeklo）。
//    修复方式：原始标签与折叠标签各扫一遍，数字保留时仍走 B 类子串（60 分）。
for (const h of ['deepseek10.com', 'deepseek2026.com', 'deepseek365.com']) {
  const rr = run({ hostname: h });
  t('数字后缀仍按「品牌词+数字」命中 60：' + h, !!spoof60(rr) && spoof60(rr).weight === 60, rr.score + '/' + rr.level);
}
// 形近替换本身不能因此失效（这两例靠折叠标签命中）
for (const [h, b] of [['g00gle.com', 'google'], ['taoba0.com', 'taobao'], ['g00g1e.com', 'google']]) {
  const rr = run({ hostname: h });
  t('形近替换仍命中：' + h, !!spoof60(rr) && rr.spoof && rr.spoof.brand === b, rr.score + '/' + rr.level);
}
// ② 品牌词 + **等长**词缀（旧实现 `rem.length > a.length` 永远剥不掉，只剩 45 分变体分）
for (const h of ['deepseekcn.com', 'deepseekapp.com', 'deepseekvip.com', 'deepseekcom.com', 'taobaocn.com', 'wechatapp.com']) {
  const rr = run({ hostname: h });
  t('品牌词+完整词缀命中 60：' + h, !!spoof60(rr) && spoof60(rr).weight === 60, rr.score + '/' + rr.level);
}
// ③ 官方域 / 白名单不受这两项改动影响
for (const h of ['office365.com', 'wechatpay.com', 'www.deepseek.com', 'chat.deepseek.com', 'qq.com']) {
  const rr = run({ hostname: h });
  t('官方/白名单仍不判仿冒：' + h, rr.score === 0, rr.score + '/' + rr.level);
}

// ---------- 10. basic typo 误报治理（真英文词 vs 品牌词） ----------
// 这些词与某品牌词编辑距离 1~2、尾部咬合很深，但本身是常用英文单词；结构上无法与真 typo 区分。
for (const h of ['webchat.com', 'discard.com', 'black.com', 'small.com', 'skill.com', 'merge.com',
  'matrix.com', 'index.com', 'release.com', 'decent.com', 'decode.com', 'bitter.com',
  'double.com', 'exceed.com', 'kingdom.com', 'north.com', 'tongue.com', 'ferry.com']) {
  const rr = run({ hostname: h });
  t('英文词不判仿冒：' + h, rr.score === 0 && !rr.spoof, rr.score + '/' + rr.level);
}
// 真 typo 必须保留（含首字母后插入、双写、尾部插入）
for (const [h, b] of [['deepseak.com', 'deepseek'], ['deepsek.com', 'deepseek'], ['telegrm.com', 'telegram'],
  ['whatsap.com', 'whatsapp'], ['wwechat.com', 'wechat'], ['wechatt.com', 'wechat'], ['xdeepseek.com', 'deepseek']]) {
  const rr = run({ hostname: h });
  t('真 typo 仍命中 60：' + h, !!spoof60(rr) && spoof60(rr).weight === 60 && rr.spoof.brand === b, rr.score + '/' + rr.level);
}

// ---------- 11. 分片拼接：品牌词之外只剩站点性质词 → 30 分弱信号 ----------
for (const h of ['my-deep-seek-app.com', 'my-deep-seek.com', 'the-deep-seek-app.com',
  'deep-seek-tool.com', 'open-deep-seek-tools.com', 'my-we-chat.com', 'deep-seek-team.com']) {
  const rr = run({ hostname: h });
  const v = variant(rr);
  t('填充词包裹的拼接只算弱信号（30 且 <42）：' + h, !!v && v.weight === 30 && rr.score < 42, rr.score + '/' + rr.level + '/' + (v && v.weight));
}
// 品牌词之外还有实义词 → 仍按 45 分（分片式仿冒特征明显）
for (const h of ['cnds-deep-seek-harness.com', '382web.cnds-deep-seek-harness.com.cn', 'my-deep-seek-team-cn-x.com']) {
  const rr = run({ hostname: h });
  const v = variant(rr);
  t('有实义词的拼接仍按 45：' + h, !!v && v.weight >= 45, rr.score + '/' + rr.level + '/' + (v && v.weight));
}
// 插入式也同口径：品牌词 + 站点性质词 = 弱信号
for (const h of ['deepseekfan.com', 'deepseekhub.com']) {
  const v = variant(run({ hostname: h }));
  t('插入式填充词同样降为 30：' + h, !!v && v.weight === 30, v && v.weight);
}

// ---------- 12. 英文词表全量扫描：白名单是否仍然完备 ----------
// 用 tools/data/en-common-10000.txt（google-10000-english）逐个当域名扫一遍。
// 只要出现一个「常用英文词被判成仿冒」，就说明 _TYPO_EN_STOPWORDS 需要补词（或品牌词表新增了碰撞）。
// 曾经唯一的例外是 matchType==='seg'：标签本身就等于某个品牌词（erp.com → 品牌词 erp）。
// v1.13.6 起「通用缩写 + 裸域」已在 A 段被豁免（详见下面第 14 节），所以这里应当是**零例外**。
const fs = require('fs');
const path = require('path');
const dictPath = path.join(__dirname, 'data', 'en-common-10000.txt');
let segOnly = [], newCollide = [];
if (fs.existsSync(dictPath)) {
  const words = [...new Set(fs.readFileSync(dictPath, 'utf8').split(/\s+/)
    .map(w => w.trim().toLowerCase()).filter(w => /^[a-z]{3,12}$/.test(w)))];
  for (const w of words) {
    const rr = run({ hostname: w + '.com' });
    // ⚠️ 旧写法看 rr.spoof —— 但 rr.spoof 只承载 **basic** 结论，变体命中的词会被整批漏掉
    //   （实测漏了 discovered / operating / operation / officers / tenant / accent 6 个）。
    //   现在改成看 reasons，basic 与变体一视同仁。
    const sp = rr.reasons.filter((x) => /仿冒/.test(x.label));
    if (!sp.length) continue;
    if (rr.spoof && rr.spoof.matchType === 'seg') segOnly.push(w);
    else newCollide.push(w + '↔' + ((rr.spoof && rr.spoof.brand) || '?') + '(' + ((rr.spoof && rr.spoof.matchType) || 'variant') + ')');
  }
  t('英文词表扫描：无新增 typo/变体碰撞（' + words.length + ' 词）',
    newCollide.length === 0, newCollide.slice(0, 8).join(' '));
  t('英文词表扫描：裸域段匹配零例外（erp.com 已豁免）', segOnly.length === 0, segOnly.join(','));
} else {
  console.log('SKIP 英文词表缺失：' + dictPath);
}

// ---------- 13. 数字形近：数字被当成「一个字符的多种读法」（2026-11-24）----------
// ba1du 是这一轮的基准样本：1 被 normalizeHomoglyph 读成 l（baldu），与 baidu 首尾都咬不住，
// typo 护栏（max(lcp,lcs)≥4）与隐藏分支（lcp≥3）双双失效 → 此前 0 分。
for (const [h, b] of [['ba1du.com', 'baidu'], ['b41du.com', 'baidu'], ['ba1du.com.cn', 'baidu'],
  ['al1pay.com', 'alipay'], ['x1aomi.com', 'xiaomi']]) {
  const rr = run({ hostname: h });
  t('数字形近命中 60：' + h, !!spoof60(rr) && spoof60(rr).weight === 60 && rr.spoof.brand === b, rr.score + '/' + rr.level);
  t('数字形近文案说明「写成数字」：' + h, /写成数字/.test((spoof60(rr) || {}).detail || ''), (spoof60(rr) || {}).detail);
}
// 反向不认：品牌词自己的数字位、以及含数字的普通域名都不该被这条规则带走
for (const h of ['hao123.com', 'hao123.cn', '51job.com', '12306.cn', 'abc123.com', '365days.cn']) {
  const rr = run({ hostname: h });
  t('含数字的普通域名不判仿冒：' + h, !rr.reasons.some(x => /仿冒/.test(x.label)), rr.score + '/' + rr.level);
}
// 长度不等时不走这条规则（等长是判据的一半）
t('长度不等不由数字规则命中（ba1duu.com）', !/写成数字/.test(JSON.stringify(run({ hostname: 'ba1duu.com' })).toString()));
// 数字形近与 typo 同属「拼写对不上」，「访问正确的页面」照旧能反查官网
t('数字形近可反查官网（ba1du.com → baidu.com）',
  (A.resolveCorrectSite('ba1du.com') || {}).domain === 'baidu.com' &&
  (A.resolveCorrectSite('ba1du.com') || {}).confidence === 'typo');

// ---------- 14. 有界缓存改成 LRU（只淘汰最旧一条，不再整表清空）----------
// 现象：旧实现在容量到顶时 cache.clear()，同一批页面会在清空后集体落到冷路径（抖一下）；
// 这里只锁「淘汰压力下结论不变 / null 也被缓存」，容量与耗时属于实现细节，不锁死。
const snap = JSON.stringify(run({ hostname: 'ba1du.com' }));
const csBefore = JSON.stringify(A.resolveCorrectSite('huorlong.cn'));
const nullBefore = JSON.stringify(A.resolveCorrectSite('definitely-not-a-brand-xyz.com'));
for (let i = 0; i < 900; i++) run({ hostname: 'p' + i + '-probe' + (i % 11) + '.example' + (i % 17) + '.com' });
t('缓存淘汰后同一域名结论不变', JSON.stringify(run({ hostname: 'ba1du.com' })) === snap);
t('官网表缓存淘汰后结论一致（huorlong.cn）', JSON.stringify(A.resolveCorrectSite('huorlong.cn')) === csBefore);
t('null 结果同样被缓存且淘汰后一致', JSON.stringify(A.resolveCorrectSite('definitely-not-a-brand-xyz.com')) === nullBefore);
const t0 = Date.now();
for (let i = 0; i < 300; i++) run({ hostname: 'ba1du.com' });
t('重复查询走缓存（300 次 analyze < 600ms）', Date.now() - t0 < 600, (Date.now() - t0) + 'ms');

// ---------- 14. 通用行业缩写 + 裸域：段匹配豁免（2026-11-24）----------
// 背景：erp.com 曾是「段匹配 60 + 缺备案 18 = 78 判危」，但 erp 是通用缩写（企业资源计划），
//   做 ERP 的公司注册 erp.com 完全合法。规则只在「域名主干**整体**等于该缩写」时豁免，
//   「缩写 + 词缀 / 子域」的仿冒形态必须原样保留 60 分。
for (const h of ['erp.com', 'www.erp.com', 'erp.com.cn']) {
  const rr = run({ hostname: h });
  t('通用缩写裸域不判仿冒：' + h, !spoof60(rr) && !variant(rr) && rr.score < 42, rr.score + '/' + rr.level);
}
t('erp.cn 只剩缺备案 18（不再叠加仿冒 60）', run({ hostname: 'erp.cn' }).score === 18, run({ hostname: 'erp.cn' }).score);
for (const h of ['erp-login.xxx.top', 'erp.evil.com', 'erp-login.com']) {
  const rr = run({ hostname: h });
  t('缩写 + 词缀/子域仍判仿冒 60：' + h, !!spoof60(rr) && spoof60(rr).weight === 60, rr.score + '/' + rr.level);
}
// 反向：真实品牌名即使同样短，不受影响（msi 是品牌，未进通用缩写表）
t('短品牌词不受波及（msi.net 仍 60）', !!spoof60(run({ hostname: 'msi.net' })) && spoof60(run({ hostname: 'msi.net' })).weight === 60);
// 反向：通用词早就整体出表，不受本次改动影响
t('通用词 pdf.com 仍为 0 分', run({ hostname: 'pdf.com' }).score === 0);

// ---------- 15. ICP 权威结论（含「迟到补强」）落到判定上的契约 ----------
// 内容脚本现在允许「先判定、后补强」：uapis 对无备案域名要 8~10s 才回 404，
// 判定等不到就先用页面数据出结论，等权威结论到了再重判一次（只允许**变严**）。
// 这里锁死「补强数据一到，结论必须变成 100 分判危」这一契约，避免以后改引擎时静默失配。
const _icpPage = {
  hostname: 'ai.deekseep-e.com.cn',
  icp: { hasIcpNumber: true, icpNumber: '京ICP备20240001号-1', hasGovIcp: false, hasBeianLink: false },
};
{
  const before = run(Object.assign({}, _icpPage));
  t('补强前：只有变体 45 分（warn，不拦）', before.score === 45 && !before.reasons.some(x => /盗用/.test(x.label)), before.score + '/' + before.level);
  const queriedFalse = run(Object.assign({ icpAuth: { queried: false, hasIcp: false } }, _icpPage));
  t('查询失败（queried:false）不臆断：仍是 45', queriedFalse.score === 45 && !queriedFalse.reasons.some(x => /盗用/.test(x.label)), queriedFalse.score);
  const noRecord = run(Object.assign({ icpAuth: { queried: true, hasIcp: false } }, _icpPage));
  const stolen = noRecord.reasons.find(x => x.label === '盗用他人备案号');
  t('权威确认无记录 → 盗用 55 + 变体 45 = 100 判危', noRecord.score === 100 && noRecord.level === 'danger' && !!stolen && stolen.weight === 55, noRecord.score + '/' + noRecord.level);
  t('盗用文案给出页面展示的备案号', /京ICP备20240001号-1/.test((stolen || {}).detail || ''), (stolen || {}).detail);
  const hasRecord = run(Object.assign({ icpAuth: { queried: true, hasIcp: true } }, _icpPage));
  t('权威确认确有备案 → 仿冒与缺备案一起弃权（0 分）', hasRecord.score === 0, hasRecord.score + '/' + hasRecord.level);
}

// ---------- 16. 「访问正确的页面」要认得出变体，并带出 Harness 产品页 ----------
// 缺陷（v1.13.6 内修复）：检测链路判了 45 分「拼写变体」，官网按钮却因为只问 basic 线
//   （detectSpoof）而落到「没有已收录的正确域名」—— 两条线自相矛盾。
// 反向护栏同样重要：variant-typo（huolong.cn 火龙 vs huorong 火绒）是**另一家公司**，
//   宁可留在说明页，也不能把用户送到火绒官网。
{
  const cs = (h) => A.resolveCorrectSite(h) || {};
  for (const h of ['ai.deekseep-e.com.cn', 'cn.deeposieek.com.cn', 'deepaiseek.com.cn', 'deekseep-e.com']) {
    const r = cs(h);
    t('变体命中后能给出 DeepSeek 官网：' + h, r.domain === 'deepseek.com' && r.product === 'DeepSeek', r.domain + '/' + r.confidence);
  }
  t('变体回退的置信度是 variant（说明页用专有措辞）', cs('ai.deekseep-e.com.cn').confidence === 'variant', cs('ai.deekseep-e.com.cn').confidence);
  t('variant-typo 不接（huolong.cn 火龙 ≠ 火绒）', cs('huolong.cn').domain === undefined, JSON.stringify(cs('huolong.cn')));
  t('basic 的 typo 回退不受影响（huorlong.cn）', cs('huorlong.cn').domain === 'huorong.cn' && cs('huorlong.cn').confidence === 'typo');
  t('数字形近仍按 typo 回退（ba1du.com）', cs('ba1du.com').domain === 'baidu.com' && cs('ba1du.com').confidence === 'typo');

  // DeepSeek Harness：链接级产品页 + 与 deepseek 双向关联
  const ds = cs('deepseek.com');
  const dsUrls = (ds.sites || []).map((s) => s.url);
  t('DeepSeek 条目带出 Harness 产品页', dsUrls.indexOf('https://www.deepseek.com/harness/') !== -1, dsUrls.join(' '));
  const harnessSite = (ds.sites || []).filter((s) => s.url === 'https://www.deepseek.com/harness/')[0] || {};
  t('Harness 站点是链接级、带分组名', harnessSite.kind === 'link' && harnessSite.group === 'DeepSeek Harness', JSON.stringify(harnessSite));
  const hs = cs('382web.cnds-deepseek-harness.com.cn');
  t('deepseek-harness 主机名能反查 Harness 条目', hs.product === 'DeepSeek Harness', hs.product);
  const hsUrls = (hs.sites || []).map((s) => s.url);
  t('Harness 条目反向带出 DeepSeek 主站（双向关联）',
    hsUrls.indexOf('https://www.deepseek.com/harness/') === 0 && hsUrls.indexOf('https://deepseek.com') !== -1, hsUrls.join(' '));
  t('Harness 品牌词不单收 harness（harness.io 不受影响）', cs('harness.io').domain === undefined, JSON.stringify(cs('harness.io')));
}

// ---------- 17. 下载页误报治理：扩展名 / 平台名 / 通用名词品牌词 ----------
// 现场：www.libreoffice.org 与 www.onlyoffice.com 被判 116 分拦截，属扩展自身误报，三条根因：
//   ① `libreoffice` / `onlyoffice` = 修饰词 + 通用名词品牌词 office，被当「拼接式仿冒」30 分；
//   ② 文件名 `..._x86-64.msi` 的 **.msi 扩展名**被当品牌词「msi」（微星），配合可执行判定 → 40 分；
//   ③ `.../mobile/android/onlyoffice-documents.apk` 的路径段 android 被当品牌词 → 40 分。
{
  const dl = (d) => run(Object.assign({ hostname: 'dl.test' }, d));
  // ① 通用名词品牌词不参与拼接/插入
  for (const h of ['libreoffice.org', 'www.libreoffice.org', 'onlyoffice.com', 'www.onlyoffice.com', 'openoffice.org']) {
    const r2 = run({ hostname: h });
    t('官方软件域名不判仿冒：' + h, !variant(r2) && !spoof60(r2), r2.score + ' ' + r2.reasons.map(x => x.label).join(','));
  }
  // 只挡弱分支：真仿冒仍走段匹配 / 编辑距离
  t('office 段匹配仍生效（office-login.xxx.top）', (spoof60(run({ hostname: 'office-login.xxx.top' })) || {}).weight === 60);
  t('office 编辑距离仍生效（offlce.com）', (variant(run({ hostname: 'offlce.com' })) || {}).weight === 45);
  // ② .msi 扩展名不是微星
  const pkg = (href, text) => [{ href: href, text: text }];
  let r3 = dl({ hostname: 'www.libreoffice.org', links: pkg('https://download.documentfoundation.org/libreoffice/stable/26.8.3/win/x86_64/LibreOffice_26.8.3_Win_x86-64.msi', 'LibreOffice 26.8.3 Windows (x86-64)') });
  t('.msi 扩展名不再命中品牌词 msi', !r3.reasons.some(x => x.label === '品牌仿冒安装包'), r3.reasons.map(x => x.label + ':' + x.weight).join(','));
  t('LibreOffice 下载页降到可疑线以下', r3.score < 42, r3.score + '');
  // ③ android 平台名不是品牌
  r3 = dl({ hostname: 'www.onlyoffice.com', links: pkg('https://download.onlyoffice.com/install/mobile/android/onlyoffice-documents.apk', '获取 APK') });
  t('路径段 android 不再命中品牌词', !r3.reasons.some(x => x.label === '品牌仿冒安装包'), r3.reasons.map(x => x.label + ':' + x.weight).join(','));
  // 反向：真木马化投递必须照旧抓
  r3 = dl({ hostname: 'wechat-download.evil.top', links: pkg('https://evil-cdn.top/WeChat_Setup.exe', '微信官方版') });
  t('真仿冒仍命中品牌仿冒安装包（WeChat_Setup.exe）', r3.reasons.some(x => x.label === '品牌仿冒安装包' && x.weight === 40), r3.score + '');
  r3 = dl({ hostname: 'msi-tool.evil.top', links: pkg('https://evil.top/MSI_Afterburner_Setup.exe', '微星超频工具') });
  t('路径中的真品牌词不被误剥离（MSI_Afterburner）', r3.reasons.some(x => x.label === '品牌仿冒安装包' && x.weight === 40), r3.score + '');
}

console.log('\n' + pass + ' passed, ' + fail + ' failed');
process.exit(fail ? 1 : 0);
