/* liststore.js — 自定义域名名单的存储层（2026-11-12）
 *
 * 为什么需要这一层：
 *   自定义白名单 / 黑名单（settings.allowlist / settings.customBadDomains）原先存在
 *   chrome.storage.sync，而 sync 有 QUOTA_BYTES_PER_ITEM = 8192 的**单键**上限
 *   （键名 + JSON 一起算，约 550 个域名）。超出后 sync.set 直接失败，用户看到的是
 *   「点了保存、提示成功、名单却少了后半截」—— 和“通配超上限被丢弃”同一类静默失效。
 *   manifest 已申请 unlimitedStorage，storage.local 实际无上限，因此名单改以 local 为准。
 *
 * 策略：
 *   · 名单（allowlist / customBadDomains）**以 storage.local 为准**；
 *   · 读取：local 有该键就用 local，没有才回落到 sync（兼容老用户 / 新设备 / 回滚版本），
 *     回落成功后顺手写回 local 完成迁移（不删 sync 副本）；
 *   · 写入：先写 local（真正生效的那份），再尽力把小体积名单镜像到 sync 以保留跨设备同步；
 *     单键超过镜像阈值（7000 字节，留出 8192 的包装余量）时**删除** sync 里的旧键，
 *     否则旧的小名单会盖住新的大名单（读取虽以 local 优先，但新设备上就只有旧的那份）。
 *
 * 只处理“名单类”键，其它设置完全不动，故不影响既有 sync 设置的读写路径。
 */
(function (root) {
  'use strict';
  if (!root) return;

  var LIST_KEYS = ['allowlist', 'customBadDomains'];
  var MIRROR_MAX = 7000;          // sync 单键上限 8192，留 ~1KB 给键名与 JSON 包装
  var hasChrome = (typeof chrome !== 'undefined') && chrome && chrome.storage;

  function hasSync() { return hasChrome && chrome.storage.sync; }
  function hasLocal() { return hasChrome && chrome.storage.local; }
  function runtimeErr() {
    try { return chrome.runtime && chrome.runtime.lastError; } catch (e) { return null; }
  }
  function sizeOf(v) {
    try { return JSON.stringify(v).length; } catch (e) { return MIRROR_MAX + 1; }
  }

  // 把体积允许的键镜像到 sync；超限的键从 sync 删除（避免旧值遮蔽新值）
  function mirror(patch) {
    if (!hasSync()) return;
    var setObj = {}, del = [];
    LIST_KEYS.forEach(function (k) {
      if (!Object.prototype.hasOwnProperty.call(patch, k)) return;
      if (sizeOf(patch[k]) <= MIRROR_MAX) setObj[k] = patch[k];
      else del.push(k);
    });
    var clear = function (keys) {
      if (!keys.length) return;
      try { chrome.storage.sync.remove(keys); } catch (e) {}
    };
    if (Object.keys(setObj).length) {
      try {
        chrome.storage.sync.set(setObj, function () {
          // 镜像失败（多半是总配额满了）：删掉对应键，宁可不同步，也不要留下旧名单
          if (runtimeErr()) clear(Object.keys(setObj));
        });
      } catch (e) { clear(Object.keys(setObj)); }
    }
    clear(del);
  }

  // 读取名单：回传对象里只含 LIST_KEYS 中“确实存在”的键，缺的交给调用方用 DEFAULTS 兜底
  function read(cb) {
    cb = (typeof cb === 'function') ? cb : function () {};
    if (!hasChrome) return cb({});
    if (!hasLocal()) {
      if (!hasSync()) return cb({});
      try { return chrome.storage.sync.get(LIST_KEYS, function (s) { cb(s || {}); }); } catch (e) { return cb({}); }
    }
    var forward = function (localVals, syncVals) {
      var out = {};
      LIST_KEYS.forEach(function (k) {
        if (localVals && Array.isArray(localVals[k])) out[k] = localVals[k];
        else if (syncVals && Array.isArray(syncVals[k])) out[k] = syncVals[k];
      });
      cb(out);
    };
    try {
      chrome.storage.local.get(LIST_KEYS, function (l) {
        l = l || {};
        var missing = LIST_KEYS.filter(function (k) { return !Array.isArray(l[k]); });
        if (!missing.length || !hasSync()) return forward(l, null);
        try {
          chrome.storage.sync.get(missing, function (s) {
            s = s || {};
            var migrate = {};
            missing.forEach(function (k) { if (Array.isArray(s[k])) migrate[k] = s[k]; });
            // 一次性迁移：把 sync 里的旧名单搬到 local（保留 sync 副本，老设备仍能读）
            if (Object.keys(migrate).length) { try { chrome.storage.local.set(migrate); } catch (e) {} }
            forward(l, s);
          });
        } catch (e) { forward(l, null); }
      });
    } catch (e) { cb({}); }
  }

  // 写入名单：只接受 LIST_KEYS 里的数组，其它键忽略（避免误把整份设置搬进 local）
  function write(obj, cb) {
    cb = (typeof cb === 'function') ? cb : function () {};
    var patch = {};
    LIST_KEYS.forEach(function (k) {
      if (obj && Array.isArray(obj[k])) patch[k] = obj[k];
    });
    if (!Object.keys(patch).length) return cb(null);
    if (!hasLocal()) {              // 无 local（例如纯网页预览）→ 退回 sync
      if (!hasSync()) return cb(null);
      try {
        chrome.storage.sync.set(patch, function () { cb(runtimeErr()); });
      } catch (e) { cb(e); }
      return;
    }
    try {
      chrome.storage.local.set(patch, function () {
        var err = runtimeErr();
        mirror(patch);
        cb(err || null);
      });
    } catch (e) { cb(e); }
  }

  root.SFListStore = {
    KEYS: LIST_KEYS,
    isListKey: function (k) { return LIST_KEYS.indexOf(k) !== -1; },
    read: read,
    write: write
  };
})(typeof self !== 'undefined' ? self : this);
