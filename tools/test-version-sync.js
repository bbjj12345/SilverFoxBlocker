// 版本号一致性回归（2026-11-28，v1.14.9 起）
// 用法：node tools/test-version-sync.js
//
// 唯一事实来源是 manifest.json 的 version。本用例只做一件事：拿它去核对
// README / PRIVACY 里所有「对外宣称当前是哪个版本」的地方，防止再次出现
// 「包是 1.14.9、文档写 1.13.15」这种对不上号的情况。
// 注意：文档里形如（v1.13.6）的标注是「某个改动发生在哪版」，属于历史记录，
// 允许存在；这里只校验不能出现比 manifest 更新的版本号（那一定是拍脑袋写的）。
const fs = require('fs');
const path = require('path');

let pass = 0, fail = 0;
function t(name, cond, extra) {
  if (cond) { pass++; console.log('PASS ' + name); }
  else { fail++; console.log('FAIL ' + name + (extra ? '  → ' + extra : '')); }
}

const root = path.join(__dirname, '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');

// ---------- 1. manifest 是唯一来源 ----------
let manifest = null;
try { manifest = JSON.parse(read('manifest.json')); } catch (e) { /* 下面会判 */ }
t('manifest.json 可解析为 JSON', !!manifest);
const ver = manifest && manifest.version;
t('manifest.version 存在', typeof ver === 'string' && ver.length > 0);
t('manifest.version 符合 x.y.z', /^\d+\.\d+\.\d+$/.test(String(ver)), String(ver));

if (!ver) { console.log('\n结果：' + pass + ' 通过 / ' + fail + ' 失败'); process.exit(1); }

const cur = String(ver);
const readme = read('README.md');
const privacy = read('PRIVACY.md');

// ---------- 2. README 的「当前版本」 ----------
t('README 的「当前版本」= manifest', readme.includes('当前版本 **v' + cur + '**'),
  '未找到 “当前版本 **v' + cur + '**”');

// ---------- 3. 打包命令里的 zip 名 ----------
const zipName = 'SilverFoxBlocker-' + cur + '.zip';
const zipHits = readme.split(zipName).length - 1;
t('README 打包命令的 zip 名 = manifest（两处）', zipHits === 2, '实际命中 ' + zipHits + ' 处');

// ---------- 4. PRIVACY 的「适用版本」与英文摘要 ----------
t('PRIVACY 的「适用版本」= manifest', privacy.includes('适用版本：v' + cur),
  '未找到 “适用版本：v' + cur + '”');
t('PRIVACY 英文摘要版本 = manifest', privacy.includes('**SilverFoxBlocker v' + cur + '**'),
  '未找到 “**SilverFoxBlocker v' + cur + '**”');

// ---------- 5. changelog 里有这一版的条目 ----------
t('README 存在本版 changelog 条目（v' + cur + '）', readme.includes('（v' + cur + '）'),
  '未找到 “（v' + cur + '）”');

// ---------- 6. 所有「宣称当前版本」的位置必须字面等于 manifest ----------
// 只认「当前版本 / 适用版本 / 英文摘要标题」这三类明确声明，
// 不去扫全篇的 x.y.z —— 文中的 IDM 6.43.18 之类是别人家的版本号，扫了必然误报。
function declaredVersions(text) {
  const pats = [
    /当前版本\s*\*\*v?(\d+\.\d+\.\d+)\*\*/g,
    /适用版本：v?(\d+\.\d+\.\d+)/g,
    /\*\*SilverFoxBlocker v(\d+\.\d+\.\d+)\*\*/g,
  ];
  const out = [];
  for (const re of pats) {
    let m;
    while ((m = re.exec(text))) out.push(m[1]);
  }
  return out;
}
const rv = declaredVersions(readme);
const pv = declaredVersions(privacy);
t('README 至少有一处「当前版本」声明', rv.length > 0);
t('README 的版本声明全部 = manifest', rv.every((v) => v === cur), '实际：' + rv.join(', '));
t('PRIVACY 至少有一处版本声明', pv.length > 0);
t('PRIVACY 的版本声明全部 = manifest', pv.every((v) => v === cur), '实际：' + pv.join(', '));

// ---------- 7. 代码不写死版本号（一律运行时读 manifest） ----------
// 只查「getManifest 取不到时的兜底字面量」：兜底值若写成一个像真版本的旧号，
// 界面就会显示一个错的版本，且谁也发现不了。其余业务字段（如上报用的
// clientVersion、规则导出格式号）不是扩展版本，不在此列。
const codeFiles = ['background.js', 'ui/options.js'];
let fallbackLits = [];
for (const f of codeFiles) {
  const src = read(f);
  const re = /getManifest\(\)[\s\S]{0,80}?\|\|\s*['"]([1-9]\d*\.\d+\.\d+)['"]/g;
  let m;
  while ((m = re.exec(src))) fallbackLits.push(f + ':' + m[1]);
}
t('版本兜底值不是硬编码的真版本号', fallbackLits.length === 0, fallbackLits.join(', '));

// 版本号在扩展里的来源必须是 getManifest()
const bg = read('background.js');
t('background.js 通过 getManifest() 取版本', /getManifest\(\)\.version/.test(bg));
const opt = read('ui/options.js');
t('ui/options.js 通过 getManifest() 取版本', /getManifest\(\)/.test(opt));

console.log('\n当前 manifest 版本：v' + cur);
console.log('结果：' + pass + ' 通过 / ' + fail + ' 失败');
process.exit(fail ? 1 : 0);
