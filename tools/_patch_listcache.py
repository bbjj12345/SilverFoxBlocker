# -*- coding: utf-8 -*-
"""把 /list 改成「5 分钟缓存 + 失败回退旧副本」，并把双源拉取抽成可复用函数。"""
import io

P = 'worker/index.js'
s = io.open(P, encoding='utf-8').read()

# ---------------------------------------------------------------- 1) 插入助手
anchor = '// ============================================================================\n// 名单存活巡检（HTTP 探测为主；DNS / RDAP 只做佐证）—— 2026-11-17 第二版'
assert s.count(anchor) == 1

helpers = r'''// ============================================================================
// /list 的「5 分钟缓存」（v1.13.15）
//
// 为什么必须加：/list 原先没有任何缓存，**每个请求都真的去打一次 GitHub → Gitee**。
//   配合「任意扩展来源放行」之后，任何人写个脚本循环 curl 就能：
//     ① 烧掉 Worker 的每日请求额度；② 吃光 GitHub token 的 5000 次/小时配额；
//     ③ 把 Gitee 镜像打到限流（429），于是**真用户也拉不到名单**。
//   名单一天最多变几次，却按「每个请求一次上游」的代价去取，纯属浪费。
//
// 做法（不是「限流」，但把上游压力压到理论下限）：
//   · 命中 5 分钟内的副本 → 直接返回，**一个上游子请求都不发**；
//   · 过期才去拉，拉到就写回 KV；同一 isolate 内并发请求共享同一个 Promise（防击穿）；
//   · 上游双源都失败时，**有旧副本就发旧的**（标 X-Data-Stale: 1），总比让用户看到 502 强；
//   · diag / force / nocache 三个参数一律穿透缓存 —— 诊断必须看到「此刻」的真实上游行为。
//
// 为什么是 5 分钟：名单更新频率以「天」计，5 分钟已经足够新鲜；再长会让作者改完名单后
//   自己都要等，反而添乱。要改只动 LIST_CACHE_TTL_MS。
//
// 存储复用已有 KV，不要求新建命名空间：
//   LIST_CACHE（可选，想独立管理时再建）→ 没绑就退到 HEALTH；
//   都没有（本地 wrangler dev 没配 KV）→ 自动降级成「不缓存」，行为与旧版一致。
//   留存 24 小时是为了「上游挂了还能发旧的」，新鲜度只看记录里的 ts，不看 TTL。
//
// 边界（如实写清）：这是**共享缓存**，不是鉴权。拿到 X-API-Key 的人依然能读名单
//   （它本来就随扩展包分发、仓库公开），缓存只保证「读的人再多，上游只被打一次/5 分钟」。
// ============================================================================
var LIST_CACHE_TTL_MS = 5 * 60 * 1000;          // 新鲜期：5 分钟
var LIST_CACHE_KEEP_S = 24 * 60 * 60;           // KV 留存：24 小时（用于上游故障时兜底）
var LIST_CACHE_MAX_BYTES = 20 * 1024 * 1024;    // 单份名单上限（KV 单值上限 25MB，留余量）

function listCacheKv(env) {
  return (env && (env.LIST_CACHE || env.HEALTH)) || null;
}

function listCacheKey(file) {
  return 'list_cache_v1:' + String(file).replace(/[^A-Za-z0-9]/g, '_');
}

// 返回记录对象或 null；任何异常都当「没缓存」，绝不让缓存层把主流程弄挂
async function readListCache(env, file) {
  var kv = listCacheKv(env);
  if (!kv) return null;
  try {
    var raw = await kv.get(listCacheKey(file));
    if (!raw) return null;
    var rec = JSON.parse(raw);
    if (!rec || typeof rec.text !== 'string' || !rec.text || typeof rec.ts !== 'number') return null;
    return rec;
  } catch (e) {
    console.warn('[list] 读缓存失败，按未命中处理：' + ((e && e.message) || e));
    return null;
  }
}

function listCacheFresh(rec) {
  return !!rec && typeof rec.ts === 'number' && (Date.now() - rec.ts) < LIST_CACHE_TTL_MS;
}

async function writeListCache(env, file, rec) {
  var kv = listCacheKv(env);
  if (!kv || !rec || typeof rec.text !== 'string' || !rec.text) return false;
  if (rec.text.length > LIST_CACHE_MAX_BYTES) {
    console.warn('[list] 名单过大（' + rec.text.length + ' 字节），跳过写缓存');
    return false;
  }
  try {
    await kv.put(listCacheKey(file), JSON.stringify(rec), { expirationTtl: LIST_CACHE_KEEP_S });
    return true;
  } catch (e) {
    console.warn('[list] 写缓存失败（不影响本次返回）：' + ((e && e.message) || e));
    return false;
  }
}

// 双源拉取：主源 GitHub → 备源 Gitee。只负责「去拿」，不碰缓存、不拼响应。
async function fetchListUpstream(env, file, force) {
  var t0 = Date.now();
  var deadline = t0 + TOTAL_BUDGET_MS;
  // 主源最多占 GH_BUDGET_MS，剩下的时间强制留给 Gitee：
  // 否则「GitHub 卡死」这种最需要备源的场景，预算反而被主源吃光，备源一次都跑不到。
  var ghDeadline = Math.min(deadline, t0 + GH_BUDGET_MS);
  var useGithub = force !== 'gitee';
  var useGitee = force !== 'github';

  var gh = useGithub
    ? await readFromGithub(env, file, ghDeadline)
    : { ok: false, skipped: true, tries: [{ src: 'GitHub', error: '已跳过（force=gitee）' }] };

  if (gh.ok) {
    return {
      ok: true, text: gh.text, source: gh.source, path: gh.path, count: gh.count,
      ghTries: gh.tries, gtTries: [], giteeAttempted: false, elapsedMs: Date.now() - t0
    };
  }

  if (useGithub) console.warn('[list] GitHub 拉取失败，切换到 Gitee 镜像：' + JSON.stringify(gh.tries));

  var gt = useGitee
    ? await readFromGitee(env, file, deadline)
    : { ok: false, skipped: true, tries: [{ src: 'Gitee', error: '已跳过（force=github）' }] };

  return {
    ok: !!gt.ok, text: gt.ok ? gt.text : '', source: gt.ok ? gt.source : null,
    path: gt.ok ? gt.path : null, ref: gt.ok ? gt.ref : null, count: gt.ok ? gt.count : null,
    ghTries: gh.tries, gtTries: gt.tries, giteeAttempted: true, elapsedMs: Date.now() - t0
  };
}

// 同一 isolate 内的并发合并：10 个请求同时未命中，只让 1 个真去打上游。
//   只在 isolate 内存里有效（Cloudflare 会起多个 isolate），所以它是「锦上添花」，
//   真正的止血靠上面的 KV 缓存。
var LIST_INFLIGHT = Object.create(null);

function fetchListShared(env, file, force) {
  if (force) return fetchListUpstream(env, file, force);   // 强制源不参与合并，诊断语义更干净
  var k = String(file);
  if (LIST_INFLIGHT[k]) return LIST_INFLIGHT[k];
  var p = fetchListUpstream(env, file, force);
  LIST_INFLIGHT[k] = p;
  var done = function () { if (LIST_INFLIGHT[k] === p) delete LIST_INFLIGHT[k]; };
  p.then(done, done);
  return p;
}

// 统一的名单响应：把「数据来自哪、是不是缓存、缓存多旧」都放进响应头，便于排障
function listDataResponse(rec, cacheState, corsHeaders, stale) {
  var headers = {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store',   // 缓存由服务端统一管，别让浏览器/CDN 再存一份（否则改动后要等两层过期）
    'X-Cache': cacheState,
    ...corsHeaders
  };
  if (rec.source) headers['X-Data-Source'] = rec.source;
  if (rec.path) headers['X-Data-Path'] = rec.path;
  if (rec.ts) headers['X-Cache-Age'] = String(Math.max(0, Math.round((Date.now() - rec.ts) / 1000)));
  if (stale) headers['X-Data-Stale'] = '1';
  return new Response(rec.text, { headers: headers });
}

'''
s = s.replace(anchor, helpers + anchor, 1)

# ---------------------------------------------------------------- 2) 重写路由
start = s.index('    // ==========================================\n    // 功能 A: 实时拉取并返回名单 (GET /list)')
end = s.index('    // ==========================================\n    // 功能 C: 名单存活巡检')
old = s[start:end]
assert 'if (request.method === "GET" && url.pathname === "/list")' in old
assert len(old) < 6000

new = r'''    // ==========================================
    // 功能 A: 实时拉取并返回名单 (GET /list)
    //   主源 GitHub 私有仓库 → 备源 Gitee 私有镜像仓库
    //   加 ?diag=1 只回诊断信息（逐通道的尝试记录），不返回名单正文
    //   加 ?nocache=1 跳过缓存强制回源（改完名单想立刻看到效果时用）
    //   带 ?force=gitee|github 时同样穿透缓存 —— 它本来就是「强行验证某个源」的诊断开关
    //   v1.13.15：正常请求走 5 分钟缓存，命中时**一个上游子请求都不发**
    // ==========================================
    if (request.method === "GET" && url.pathname === "/list") {
      const apiKey = request.headers.get("X-API-Key");
      if (apiKey !== env.LIST_API_KEY) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
          status: 401,
          headers: { "Content-Type": "application/json", ...cors.headers }
        });
      }

      const type = url.searchParams.get("type") || "black";
      const fileName = type === "white" ? "whitelist.json" : "blacklist.json";
      const diag = url.searchParams.get("diag");
      // ?force=gitee / ?force=github：只走指定的那一个源，用来「强行验证备源」。
      // 正常同步（扩展）永远不带这个参数，所以线上行为仍然是 GitHub 优先、Gitee 兜底。
      const force = String(url.searchParams.get("force") || "").toLowerCase();
      const nocache = url.searchParams.get("nocache") === "1";
      const t0 = Date.now();
      // 诊断 / 强制源 / 手动跳过：一律穿透缓存。诊断要是看到缓存，等于什么都没诊断出来。
      const useCache = !diag && !force && !nocache;

      let cached = null;
      if (useCache) {
        cached = await readListCache(env, fileName);
        if (listCacheFresh(cached)) {
          return listDataResponse(cached, "HIT", cors.headers, false);
        }
      }

      const up = await fetchListShared(env, fileName, force);

      // 诊断模式：永远回「此刻真实的上游尝试记录」，不写缓存、不读缓存
      if (diag) {
        return new Response(JSON.stringify(up.ok ? {
          ok: true, type: type, source: up.source, path: up.path, count: up.count,
          force: force || null, cache: "bypass",
          elapsedMs: Date.now() - t0,
          tries: up.giteeAttempted ? up.gtTries : up.ghTries,
          github: up.ghTries, gitee: up.gtTries,
          giteeAttempted: up.giteeAttempted
        } : {
          ok: false, type: type, source: null, path: null, count: null,
          force: force || null, cache: "bypass",
          elapsedMs: Date.now() - t0,
          github: up.ghTries, gitee: up.gtTries
        }, null, 2), {
          status: 200,
          headers: { "Content-Type": "application/json", "X-Cache": "BYPASS", ...cors.headers }
        });
      }

      if (up.ok) {
        const rec = {
          ts: Date.now(), text: up.text, source: up.source,
          path: up.path, count: up.count
        };
        if (useCache) await writeListCache(env, fileName, rec);
        // 写缓存耗时算在这次响应里（未命中本来就慢），但响应头要如实说明它是「刚拉的新鲜数据」
        return listDataResponse(rec, useCache ? "MISS" : "BYPASS", cors.headers, false);
      }

      // 双源都失败：有旧副本就发旧的（比 502 有用得多；作者也能从 X-Data-Stale 看出是兜底数据）
      if (cached) {
        console.warn("[list] 双源均失败，回退到缓存副本（" +
          Math.round((Date.now() - cached.ts) / 1000) + " 秒前）");
        return listDataResponse(cached, "STALE", cors.headers, true);
      }

      console.error("[list] 双源均失败且无缓存可用：" + JSON.stringify({ github: up.ghTries, gitee: up.gtTries }));
      return new Response(JSON.stringify({
        error: "云端名单服务器暂时不可用，请稍后再试。",
        detail: {
          github: up.ghTries.map(function (t) { return (t.path || "") + " → " + (t.error || t.status); }),
          gitee: up.gtTries.map(function (t) { return (t.path || "") + "[" + (t.ref || "") + "] → " + (t.error || t.status); })
        }
      }), {
        status: 502,
        headers: { "Content-Type": "application/json", "X-Cache": "MISS", ...cors.headers }
      });
    }

'''
s = s[:start] + new + s[end:]
io.open(P, 'w', encoding='utf-8', newline='').write(s)
print('ok: route replaced, old=%d new=%d' % (len(old), len(new)))
