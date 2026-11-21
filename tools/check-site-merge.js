/*
 * 两表同步体检：WHITELIST_CATALOG（白名单，谁不用检测） vs CORRECT_SITE_CATALOG（官网表，被拦后去哪儿）
 *   跑法：node tools/check-site-merge.js            ← 只报告
 *         node tools/check-site-merge.js --verbose  ← 连链接级站点一起列出
 *
 * 为什么需要它：两张表用途不同、故意分开维护，但「官网表认定是官网、白名单却当陌生站检测」
 *   属于数据自相矛盾（用户点了「访问正确的页面」跳到某个域名，回来访问同一域名却仍被评分）。
 *   2026-11-21 做过一轮单向合并（官网表 → 白名单，补 138 个主机名），本脚本用来防止两表再次走散。
 *
 * 判定口径（与 2026-11-21 合并时一致）：
 *   · 白名单按「精确 + 标签对齐后缀」匹配，查询侧先去掉 www.，所以比较前两边都去 www.、转小写；
 *   · 白名单里若有父域，子域视为已覆盖（example.com 覆盖 a.example.com），不算缺失；
 *   · 链接级站点（带路径 / 查询串）**不参与**主机名白名单，单列出来供人工确认，不计入「缺失」。
 * 退出码：0 = 无缺失；1 = 存在「官网表有、白名单没有」的主机名级站点。
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const FILE = path.join(__dirname, '..', 'rules', 'iocs.js');
const VERBOSE = process.argv.includes('--verbose');

function loadCatalogs() {
  const src = fs.readFileSync(FILE, 'utf8');
  const quiet = { warn() {}, log() {}, error() {} };
  const sandbox = { console: quiet };
  sandbox.window = sandbox;
  sandbox.self = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(src, sandbox);
  const exp = sandbox.SF_IOCS || sandbox;
  if (!exp.WHITELIST_CATALOG || !exp.CORRECT_SITE_CATALOG) {
    throw new Error('iocs.js 未导出 WHITELIST_CATALOG / CORRECT_SITE_CATALOG');
  }
  return { WC: exp.WHITELIST_CATALOG, CC: exp.CORRECT_SITE_CATALOG };
}

// 站点字段 → [{ url, host, kind }]，口径与 rules/iocs.js 的 normalizeCorrectSites 一致
function sitesOf(field) {
  const list = typeof field === 'string' ? [field]
    : Array.isArray(field) ? field
      : (field && typeof field === 'object' ? [field] : []);
  return list.map(s => {
    let url = typeof s === 'string' ? s : s.url;
    let kind = typeof s === 'string' ? null : s.kind;
    url = String(url || '').trim().replace(/^https?:\/\//i, '');
    const host = url.split(/[/?#]/)[0].toLowerCase().replace(/:\d+$/, '').replace(/^www\./, '');
    if (!kind) kind = /[/?#]/.test(url) ? 'link' : 'host';
    return { url, host, kind };
  }).filter(s => s.host && s.host.indexOf('.') !== -1);
}

const { WC, CC } = loadCatalogs();

// ---- 白名单：精确条目（通配条目跳过，它们没有唯一归属）----
const wlExact = new Set();
for (const [, items] of WC) {
  for (const it of items) {
    for (const d of String(it[1] || '').split(/\s+/)) {
      const dom = d.trim().toLowerCase().replace(/^www\./, '');
      if (dom && !/[*?]/.test(dom)) wlExact.add(dom);
    }
  }
}
function wlCovers(host) {
  const h = String(host || '').toLowerCase();
  if (!h) return false;
  if (wlExact.has(h)) return true;
  let i = h.indexOf('.');
  while (i !== -1) {
    if (wlExact.has(h.slice(i + 1))) return true;
    i = h.indexOf('.', i + 1);
  }
  return false;
}

// ---- 官网表：按大类收集缺失主机名 ----
const missingByCat = new Map();
const linkSkipped = [];
const seen = new Set();
let hostCount = 0;
for (const [cat, items] of CC) {
  for (const it of items) {
    for (const s of sitesOf(it[2])) {
      if (s.kind === 'link') { linkSkipped.push({ cat, product: it[0], url: s.url, host: s.host }); continue; }
      hostCount++;
      if (seen.has(s.host)) continue;
      seen.add(s.host);
      if (wlCovers(s.host)) continue;
      if (!missingByCat.has(cat)) missingByCat.set(cat, []);
      missingByCat.get(cat).push({ host: s.host, product: it[0] });
    }
  }
}

const missingTotal = [...missingByCat.values()].reduce((n, a) => n + a.length, 0);
console.log('白名单主机名（精确）:', wlExact.size);
console.log('官网表主机名级站点:', hostCount, '/ 链接级站点:', linkSkipped.length);
console.log('官网表有、白名单没有的主机名:', missingTotal);

if (missingTotal) {
  for (const [cat, arr] of missingByCat) {
    console.log(`\n## ${cat}  (${arr.length})`);
    for (const m of arr) console.log(`  ${m.host}   <- ${m.product}`);
  }
  console.log('\n处理办法：把上面这些主机名按同名大类补进 WHITELIST_CATALOG（去 www.、跳过已覆盖项），' +
    '只补主机名级，链接级不要补 —— 详见 iocs.js 里「与官网表合并」的注释。');
} else {
  console.log('\n✓ 主机名级站点已全部覆盖，两表一致');
}

if (VERBOSE) {
  console.log('\n--- 链接级站点（按设计不进主机名白名单）---');
  for (const l of linkSkipped) {
    console.log(`  ${wlCovers(l.host) ? '[已覆盖]' : '[未覆盖]'} ${l.url}   <- ${l.product}`);
  }
}
process.exit(missingTotal ? 1 : 0);
