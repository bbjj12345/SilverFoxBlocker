function __t(){
 if(false){}
  } else if (msg.type === 'sf-intel-query') {
    // 威胁情报查询：按设置中启用的 provider 并行查询当前域名，仅返回"判定为恶意"的结果
    // （满足"只显示判断为恶意的 API"），供内容脚本在网页顶部横幅展示。
    (function () {
      try {
        const host = (msg.hostname || '').toLowerCase();
        const cacheKey = 'sf_intel_' + host;
        const cached = _intelCache[cacheKey];
        if (cached && (Date.now() - cached.t) < _INTEL_CACHE_TTL) {
          try { sendResponse({ enabled: true, results: cached.r }); } catch (e) {}
          return;
        }
        getSettings().then(function (settings) {
          const ti = settings.threatIntel || { enabled: false, providers: {} };
          if (!ti.enabled || !host) {
            try { sendResponse({ enabled: !!ti.enabled, results: [] }); } catch (e) {}
            return;
          }
          const providers = ti.providers || {};
          const jobs = THREAT_INTEL_PROVIDERS
            .filter(function (p) { return providers[p.id] && providers[p.id].enabled; })
            .map(function (p) {
              return Promise.resolve()
                .then(function () { return p.query(host, (providers[p.id].apiKey || '')); })
                .then(function (r) {
                  if (r && r.malicious) return { id: p.id, name: p.name, hasScore: !!p.hasScore, score: r.score, scoreMax: r.scoreMax, detail: r.detail };
                  return null;
                })
                .catch(function () { return null; });
            });
          Promise.all(jobs).then(function (list) {
            const results = list.filter(Boolean);
            _intelCache[cacheKey] = { t: Date.now(), r: results };
            try { sendResponse({ enabled: true, results: results }); } catch (e) {}
          }).catch(function () {
            try { sendResponse({ enabled: true, results: [] }); } catch (e) {}
          });
        }).catch(function () {
          try { sendResponse({ enabled: false, results: [] }); } catch (e) {}
        });
      } catch (e) {
        try { sendResponse({ enabled: false, results: [] }); } catch (e2) {}
      }
    })();
    return true; // 异步 sendResponse
  }
}
