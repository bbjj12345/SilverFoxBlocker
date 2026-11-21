/*
 * crypto-helper.js — 银狐拦截器（SilverFoxBlocker）情报源 API Key 加密辅助
 * ----------------------------------------------------------------------------
 * 目的：API Key 不以明文形式落盘（满足「不以可直接读取的形式保存在扩展内或本地硬盘上」）。
 *       chrome.storage.sync / storage.local 里只会写入密文 + 随机 salt + 随机 IV，
 *       直接阅读存储内容无法还原出原始 Key。
 *
 * 做法：AES-GCM(256) 加密；密钥由「代码内固化的口令（已混淆）」经 PBKDF2(SHA-256, 10万轮)
 *       派生，并配合每条记录随机生成的 16 字节 salt 与 12 字节 IV。
 *
 * 重要说明（务必如实告知用户）：
 *   · 浏览器扩展运行环境无法调用系统密钥环 / OS Keychain，也没有用户口令可用，
 *     因此「口令」只能固化在扩展包内（已做字符串拆分混淆）——这本质是「防明文泄露 / 防随手读取」，
 *     并非对抗拥有扩展包与存储内容的攻击者的绝对保密。
 *   · 若需更强保护，正确做法是改用后端代理（Worker / 云函数）持有 Key，由代理转发查询；
 *     本扩展当前为「小白友好」设计，保留本地存储策略，仅把明文 Key 改为密文存储。
 *   · 解密只在后台 service worker 内发生（content 脚本永远拿不到明文 Key）。
 *
 * 密文格式： "v1." + base64(salt16) + "." + base64(iv12) + "." + base64(ciphertext)
 */
'use strict';

// 口令混淆：拆成多段拼接，避免明文 grep 直接命中；切勿误以为这是高强度保密。
var _SF_CRYPTO_PASS = (function () {
  var a = 'SfB';          // SilverFoxBlocker
  var b = 'lk-2026';      // 混淆段
  var c = 'gK#9';         // 混淆段
  var d = 'wb-x';         // 混淆段
  return a + b + '-' + c + '-' + d + '7m';
})();

// 把 ArrayBuffer / TypedArray 转 base64（兼容扩展 content/background 环境，无 btoa 限制）
function _sfB64From(buf) {
  try {
    var bytes = new Uint8Array(buf);
    var bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  } catch (e) { return ''; }
}

// 把 base64 转 Uint8Array
function _sfB64To(s) {
  try {
    var bin = atob(s);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch (e) { return new Uint8Array(0); }
}

// 由 salt 派生 AES-GCM 密钥
async function _sfDeriveKey(saltBuf) {
  var enc = new TextEncoder();
  var baseKey = await crypto.subtle.importKey(
    'raw', enc.encode(_SF_CRYPTO_PASS), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltBuf, iterations: 100000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * 加密明文 Key → 返回带版本/盐/IV 的密文字符串；失败返回 null（调用方应拒绝回退明文）。
 * @param {string} plain 明文 API Key
 * @returns {Promise<string|null>}
 */
async function sfEncryptKey(plain) {
  try {
    if (typeof plain !== 'string' || !plain) return null;
    if (!crypto || !crypto.subtle || !crypto.getRandomValues) return null;
    var enc = new TextEncoder();
    var salt = crypto.getRandomValues(new Uint8Array(16));
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var key = await _sfDeriveKey(salt);
    var ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, enc.encode(plain));
    return 'v1.' + _sfB64From(salt) + '.' + _sfB64From(iv) + '.' + _sfB64From(ct);
  } catch (e) {
    return null;
  }
}

/**
 * 解密密文 → 返回明文 Key；失败（格式错误/被篡改/口令不符）返回空字符串（调用方视作未配置）。
 * @param {string} packed 密文字符串
 * @returns {Promise<string>}
 */
async function sfDecryptKey(packed) {
  try {
    if (typeof packed !== 'string' || packed.indexOf('v1.') !== 0) return '';
    if (!crypto || !crypto.subtle) return '';
    var parts = packed.split('.');
    if (parts.length !== 4) return '';
    var salt = _sfB64To(parts[1]);
    var iv = _sfB64To(parts[2]);
    var ct = _sfB64To(parts[3]);
    if (!salt.length || !iv.length || !ct.length) return '';
    var key = await _sfDeriveKey(salt);
    var pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ct);
    return new TextDecoder().decode(pt);
  } catch (e) {
    return '';
  }
}

// 粗略判断一个字符串是否像我们生成的密文（供 UI 区分「已配置密文」与「明文输入」）
function sfLooksEncrypted(s) {
  return typeof s === 'string' && s.indexOf('v1.') === 0 && s.split('.').length === 4;
}
