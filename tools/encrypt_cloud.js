#!/usr/bin/env node
/**
 * tools/encrypt_cloud.js —— 把私有仓库里的明文名单打包成「公开可发布」的加密快照
 *
 * 背景（方案 C）：
 *   私有仓库 (SilverFoxBlocker-Cloud) 无法被公共反代访问 —— 反代没有凭据，一律 404；
 *   把 GitHub PAT 交给反代又等于公开密钥。而 Worker 只保住了「直连」这一条腿，
 *   一旦 api.silverfoxblocker.dpdns.org 被污染，云端名单就彻底同步不了。
 *   折中做法：把名单**加密**后放进公开仓库，raw / 各公共反代都能原样透传密文，
 *   扩展在本机用内置口令解密。反代与路过的人只看到一段 base64。
 *
 * 安全边界（务必理解）：
 *   口令硬编码在 ui/options.js 里，扩展源码是公开的 → 有心人解包就知道口令。
 *   因此这不是「密码学意义上的保密」，只是：
 *     · 不能随手在浏览器里把 cloud 文件点开看（内容是不可读的密文）
 *     · 不能修改（改一个字节 AES-GCM 校验就失败，扩展会拒绝写入本地名单）
 *   要真正保密，只能继续走 Worker（带 GITHUB_TOKEN，密钥只在服务端）。
 *
 * 用法：
 *   node tools/encrypt_cloud.js                       # 默认：../SilverFoxBlocker-Cloud → ./Cloud
 *   node tools/encrypt_cloud.js --src DIR --out DIR
 *   node tools/encrypt_cloud.js --verify              # 加密后立刻解回来比对（推荐每次发布前跑）
 *   node tools/encrypt_cloud.js --gen-key             # 生成新口令（需同步改 ui/options.js）
 *
 * 产物：
 *   Cloud/blacklist.json.enc
 *   Cloud/whitelist.json.enc
 *   → 提交到公开仓库 bbjj12345/SilverFoxBlocker 的 Cloud/ 目录（即 raw 路径 .../main/Cloud/...）
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ⚠️ 必须与 ui/options.js 里的 SF_CLOUD_ENC_PASS 完全一致，否则扩展解密会失败
const DEFAULT_PASS = 'aYGJ_rskoMvjXBjKCqQDqTjKMjMRNyH-';
const ITER = 120000;          // PBKDF2-SHA256 迭代次数（浏览器端 deriveKey 会照抄信封里的值）
const TAG = 'sfenc1';         // 信封标记：扩展靠它确认「这是密文，不是明文名单」
const SALT_BYTES = 16;
const IV_BYTES = 12;          // AES-GCM 标准 nonce 长度

function b64(buf) { return Buffer.from(buf).toString('base64'); }
function unb64(s) { return Buffer.from(String(s || ''), 'base64'); }

// 加密：返回可直接 JSON.stringify 的信封对象
function encryptJson(obj, pass, meta) {
  const plain = Buffer.from(JSON.stringify(obj), 'utf8');
  const salt = crypto.randomBytes(SALT_BYTES);
  const iv = crypto.randomBytes(IV_BYTES);
  const key = crypto.pbkdf2Sync(pass, salt, ITER, 32, 'sha256');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const body = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    _enc: TAG,
    alg: 'AES-256-GCM',
    kdf: 'PBKDF2-SHA256',
    iter: ITER,
    // WebCrypto 的 AES-GCM 默认把 16 字节 tag 追加在密文尾部，Node 端显式拼接以保持一致
    salt: b64(salt),
    iv: b64(iv),
    data: b64(Buffer.concat([body, tag])),
    file: (meta && meta.file) || '',
    bytes: plain.length,
    at: new Date().toISOString()
  };
}

function decryptEnvelope(env, pass) {
  if (!env || env._enc !== TAG) throw new Error('不是加密快照（缺少 _enc 标记）');
  const salt = unb64(env.salt);
  const iv = unb64(env.iv);
  const data = unb64(env.data);
  if (data.length <= 16) throw new Error('密文长度异常');
  const body = data.subarray(0, data.length - 16);
  const tag = data.subarray(data.length - 16);
  const key = crypto.pbkdf2Sync(pass, salt, env.iter || ITER, 32, 'sha256');
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
  d.setAuthTag(tag);
  const plain = Buffer.concat([d.update(body), d.final()]);   // 篡改会在这里抛错
  return JSON.parse(plain.toString('utf8'));
}

function genKey() {
  const k = crypto.randomBytes(24).toString('base64url');
  console.log('新口令：' + k);
  console.log('请把 ui/options.js 的 SF_CLOUD_ENC_PASS 与本文件 DEFAULT_PASS 同时改成它，然后重新生成快照。');
}

function main(argv) {
  if (argv.indexOf('--gen-key') !== -1) return genKey();

  const getArg = function (name, def) {
    const i = argv.indexOf(name);
    return i !== -1 && argv[i + 1] ? argv[i + 1] : def;
  };
  const EXT_DIR = path.resolve(__dirname, '..');
  const src = path.resolve(getArg('--src', path.join(EXT_DIR, '..', 'SilverFoxBlocker-Cloud')));
  const out = path.resolve(getArg('--out', path.join(EXT_DIR, 'Cloud')));
  const pass = getArg('--pass', DEFAULT_PASS);
  const verify = argv.indexOf('--verify') !== -1;

  const files = ['blacklist.json', 'whitelist.json'];
  if (!fs.existsSync(src)) {
    console.error('找不到源目录：' + src);
    process.exit(1);
  }
  fs.mkdirSync(out, { recursive: true });

  let okCount = 0;
  files.forEach(function (f) {
    const p = path.join(src, f);
    if (!fs.existsSync(p)) { console.warn('跳过（不存在）：' + f); return; }
    let obj;
    try { obj = JSON.parse(fs.readFileSync(p, 'utf8')); }
    catch (e) { console.error('✗ ' + f + '：不是合法 JSON（' + e.message + '）'); return; }
    const n = Array.isArray(obj) ? obj.length : (Array.isArray(obj.domains) ? obj.domains.length : 0);
    if (!n) { console.warn('⚠ ' + f + '：域名数组为空，仍然生成（扩展会按 0 条处理）'); }

    const env = encryptJson(obj, pass, { file: f });
    const dest = path.join(out, f + '.enc');
    fs.writeFileSync(dest, JSON.stringify(env, null, 2), 'utf8');

    let note = '';
    if (verify) {
      try {
        const back = decryptEnvelope(env, pass);
        const same = JSON.stringify(back) === JSON.stringify(JSON.parse(JSON.stringify(obj)));
        note = same ? '，回读校验通过' : '，⚠ 回读内容不一致';
        if (!same) process.exitCode = 2;
      } catch (e) {
        note = '，⚠ 回读失败：' + e.message;
        process.exitCode = 2;
      }
    }
    console.log('✓ ' + f + ' → Cloud/' + f + '.enc（' + n + ' 条，密文 ' +
      fs.statSync(dest).size + ' 字节' + note + '）');
    okCount++;
  });

  if (!okCount) { console.error('没有任何文件被处理。'); process.exit(1); }
  console.log('\n下一步：把 ' + out + ' 下的 *.json.enc 提交到公开仓库的 Cloud/ 目录，');
  console.log('        确保扩展里 SF_CLOUD_MIRROR_REPO / DIR 指向它（当前：bbjj12345/SilverFoxBlocker · Cloud）。');
}

if (require.main === module) main(process.argv.slice(2));

module.exports = { encryptJson, decryptEnvelope, TAG, ITER, DEFAULT_PASS };
