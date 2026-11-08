# SilverFoxBlocker

Chrome / Edge 浏览器扩展（Manifest V3，当前版本 **v1.0.5**），用于检测并拦截「银狐木马（Silver Fox / 游蛇）」相关的钓鱼站、仿冒官网与恶意下载入口。

核心防护**完全在本地运行**，不依赖任何在线服务；威胁情报 API 与社区黑名单是**默认关闭的可选增强**。

> 💡 **算法致敬**：检测引擎基于 [@Lolitide](https://github.com/Lolitide) 的开源作品
> [VirusDetector](https://github.com/Lolitide/VirusDetector)（MIT License）的规则算法，
> 在其基础上做了大幅改良与扩展（加权评分、组合信号升级、自动下载竞速兜底、跳转链污染追踪等）。
>
> 🔁 **二次修改**：本仓库是 [@yinbo345](https://github.com/yinbo345) 的 SilverFox Guard v1.6.3 预览版
> （https://github.com/yinbo345/silverfox-guard ，MIT License）的二次修改版本，由 @bbjj12345 在作者同意下独立发布。
>
> 特此致谢二位，本改良版同样以 MIT License 发布。

---

## ✨ 功能

### 一、本地检测与拦截（默认全部开启，无需联网）

- **实时网页分析**：解析 DOM 结构、下载入口、话术特征，而不是只比对域名黑名单。
- **多维加权评分**：官方域名早期退出、ICP 备案核验、域名仿冒检测（编辑距离 / 去连字符比对）、代码工程化与 AI 生成痕迹评估等 11 个可独立开关的检测维度。
- **拦截任意下载入口**：`<a>` / `<button>` / `<div>` 等任意元素；同时覆盖 JS 程序化下载（`window.open` / `a.click` / `blob` / `location` 跳转）。
- **自动下载竞速兜底**：`<meta refresh>`、服务端强制下载（`Content-Disposition: attachment`）等「点进即下」场景也能拦截。
- **跳转链污染追踪**：危险站跳转到新域名后，仍能识别并拦截下游下载。
- **下载发现层**：递归解析内联脚本里的直链、`.txt` 里藏的真实地址、meta refresh 目标、iframe 嵌套资源，弥补「只有指定 URL 才拦得住」的短板。
- **智能免误拦**：官方 / 搜索引擎 / 可信分发（GitHub、网盘等）白名单；`file://`、浏览器内部页、localhost 自动跳过。

### 二、威胁情报 API（可选，默认关闭）

需要先打开「威胁情报 API」总开关，再单独开启各情报源。命中后会在网页顶部横幅提示，VT 横幅还可展开逐引擎检出明细。

| 情报源 | 是否需要 Key | 发送的数据 | 判定口径 |
|---|---|---|---|
| VirusTotal (API v3) | 需要（自有 Key，密文存储） | 域名的 base64url / URL 的 base64url（查询 ID，不上传页面内容） | 按引擎可信度分三档：可能是误报 / 请保持谨慎 / 请提高警惕 |
| URLhaus (abuse.ch) | 不需要 | 域名、当前页面 URL | 仅「活跃」证据才判危；只剩历史记录时降级为「曾被标记」 |
| NetAPI | 不需要 | 域名 | 仅「当前在列（24h 内）」判危，历史记录只提示 |
| Google Safe Browsing (v4 Lookup) | 需要（自有 Key，密文存储） | **完整页面 URL** | 命中即「疑似」，措辞带限定并附 Google 免责说明 |

### 三、社区维护的本地黑名单（可选，默认关闭）

同样是「总开关 + 单名单开关」两级结构，名单下载后存在本地，只用于本机比对，不会上传你的访问记录。

| 名单 | 规模 | 本地存储形式 | 更新 |
|---|---|---|---|
| OpenPhish | 数百条钓鱼域名 | `storage.local` 域名数组 | 每日自动 / 手动 |
| PhishDestroy | 约 14 万条 | `storage.local` 域名文本 | 每日自动 / 手动 |
| HaGeZi's TIF | 约 181 万条 | IndexedDB 布隆过滤器位图（约 4.8 MB，误判率 2.5e-5，无漏判） | 每日自动 / 手动（可选完整版 / 中等版） |

### 四、其他

- **防护统计**：拦截次数、告警次数、近期记录，仅存本地。
- **银狐急救**：一键从 360 / 火绒官方域名下载查杀工具（用户主动点击才发请求）。
- **反馈与建议**：经自建 Cloudflare Worker 转发邮件，不暴露收件地址。
- **界面**：深浅主题、多套配色、字号缩放、自定义背景；「银狐急救」页含查杀引导。

---

## 🛡️ 工作原理

1. **采集**：页面域名、HTML、下载链接、代码特征。
2. **评分**：加权评分引擎得出 0–200+ 风险分，命中组合信号直接升级为危险。
3. **预警**：跨过阈值触发 `warn`（顶部提示）或 `danger`（拦截浮层 + 禁用下载入口）。
4. **兜底**：后台 `chrome.downloads` 监听，覆盖内容脚本判定前的自动下载。
5. **可选增强**：威胁情报 API 与社区黑名单，命中后追加情报横幅。

---

## 📦 安装

- **开发者模式**：打开 `chrome://extensions`（或 `edge://extensions`）→ 开启「开发者模式」→「加载已解压的扩展程序」→ 选择本目录。
- 改动代码后点一次「重新加载」，并**刷新已打开的页面**（内容脚本不会注入到重载前就已存在的标签页）。

---

## 📁 目录结构

```
SilverFoxBlocker/
├── manifest.json              # MV3 清单：权限、CSP、内容脚本注入
├── background.js              # Service Worker：下载兜底、跳转链、情报源查询、
│                              #   社区名单下载/落盘/布隆过滤器、统计、急救下载、定时任务
├── content/
│   ├── content.js             # 内容脚本：页面采集、评分调用、拦截浮层、情报横幅
│   └── content.css            # 页面内注入样式（浮层、横幅、按钮）
├── rules/
│   ├── iocs.js                # 特征库：官方域名表、恶意域名、可疑 TLD、话术词表、分类器
│   ├── analyzer.js            # 评分引擎：11 个检测维度 + 阈值 + 结论稳定性护栏
│   └── resource-resolver.js   # 下载发现层：BFS 解析脚本/文本/跳转/iframe 中的直链
├── ui/
│   ├── popup.html/.js/.css    # 工具栏弹窗：当前站点评分、近期拦截
│   ├── options.html/.js/.css  # 设置页：检测维度、拦截行为、规则与名单、统计、急救、关于
│   └── feedback-config.js     # 反馈后端端点（字符码存储，避免明文域名）
├── crypto-helper.js           # 情报源 API Key 的 AES-GCM 加密 / 解密（仅在 SW 内解密）
├── icons/                     # 扩展图标 16 / 48 / 128
├── fonts/                     # 界面字体（SmileySans，笑脸模式）
├── _locales/zh_CN/            # 扩展名称与描述
├── worker/index.js            # Cloudflare Worker：反馈邮件转发（不随扩展运行）
├── tools/rescue-scripts/      # 急救工具直链的本地更新脚本（开发用，不参与打包运行）
└── sponsors.json              # 赞助者名单
```

> `worker/` 与 `tools/` 只在开发/部署时使用，扩展运行时不会加载它们。

---

## 🔑 权限说明

本扩展遵循最小权限原则，`manifest.json` 中的每一项权限都有实际用途：

| 权限 | 用途 |
|---|---|
| `storage` | 保存设置（开关、权重、白名单、黑名单、情报源配置）、防护统计、社区名单与元数据、下载黑名单、连坐集合 |
| `unlimitedStorage` | 社区名单体积较大：HaGeZi 位图约 4.8 MB，另有两份域名名单存于 `storage.local`，开启完整版后接近浏览器默认配额上限 |
| `downloads` | 监听并取消高危下载；「银狐急救」按用户点击下载查杀工具 |
| `webNavigation` | 监听顶级框架导航：页面开始加载即进入「检测中」闸门，并追踪「危险页 → 新域名」的跳转链 |
| `notifications` | 检测到高风险网站/下载时弹系统原生告警（不依赖声音，无需用户手势解锁） |
| `alarms` | 社区名单的每日自动更新，以及「立即更新」的一次性任务（MV3 中 SW 会被回收，定时任务必须走 alarms） |
| `host_permissions: <all_urls>` | ① 内容脚本需要在所有 http(s) 页面注入以做实时检测；② 允许后台向 RDAP / ICP / 情报源 / 名单 CDN / 360·火绒官方域名发起请求 |
| `web_accessible_resources` | 页面内浮层需要加载自带字体；`sponsors.json` 供「关于」页读取 |
| `content_security_policy.connect-src` | 显式白名单化可连接的域名（各注册局 RDAP、情报源、jsDelivr 镜像、360/火绒等），未列出的域名一律禁止连接 |

**不申请的权限**：`tabs`（仅用 `tabs.query` 读当前标签，配合 host 权限即可）、`cookies`、`history`、`bookmarks`、`webRequest`（改用 `webNavigation` + 内容脚本，避免全量拦截网络请求）、`nativeMessaging`、`scripting`。

---

## 🌐 网络请求清单

除下列请求外，扩展不会发起任何外部连接。**默认关闭的项在未开启前一次都不会请求。**

| # | 目标 | 触发条件 | 发送内容 | 默认 |
|---|---|---|---|---|
| 1 | `rdap.org` 及各注册局 RDAP | 页面分析需要判断域名年龄时 | 注册域名（如 `example.com`，不含路径/参数） | 开 |
| 2 | `uapis.cn` / `cn.apihz.cn`（ICP 备案查询） | 需要核验备案且页面有可疑信号时 | 域名 | 开（可在设置页关闭） |
| 3 | `www.virustotal.com` | 开启 VT 情报源 | 域名 / URL 的 base64url 查询 ID | 关 |
| 4 | `urlhaus-api.abuse.ch` | 开启 URLhaus | 域名、当前页面 URL | 关 |
| 5 | `netapi.com` | 开启 NetAPI | 域名 | 关 |
| 6 | `safebrowsing.googleapis.com` | 开启 GSB | 完整页面 URL | 关 |
| 7 | `cdn.jsdelivr.net` / `fastly` / `gcore` / `testingcf` / `raw.githubusercontent.com` / `gh-proxy.com` | 开启社区名单并更新时（多镜像回退） | 无（GET 名单文件） | 关 |
| 8 | `dl.360safe.com` / `baoku.360.cn` / `weishi.360.cn` / `down7.huorong.cn` | 用户在「银狐急救」点击下载 | 无 | —（需点击） |
| 9 | `api.silverfoxblocker.dpdns.org`（Cloudflare Worker） | 用户填写并发送反馈 | 反馈正文 + 选填联系方式 | —（需点击） |
| 10 | 当前页面已引用的资源 | 下载发现层解析时 | 无（按需读取页面已引用的资源或跳转目标，用于判断真实指向） | 开 |

> 早期版本会从 `site-directory-cache.pages.dev` 拉取第三方「官方域名库」，已因「来源不可控、无签名校验、体积过大」于 2026-11-01 完整移除。**当前版本不含任何云端官网库。**

---

## 🤖 关于 AI 功能

早期上游版本内置过「云端 AI 辅助研判」开关，**当前版本已不再包含任何 AI 分析逻辑**：扩展不会把你的页面文本、URL 或文件特征发送给任何大模型服务商。（`ui/options.js` 里残留的 `aiMaxMode` 等字段仅为兼容旧配置，无对应实现与 UI。）

---

## 🔒 隐私

- 核心防护、评分、名单比对全部在本地完成。
- 所有设置与统计数据只写本机 `storage` / IndexedDB，**不做云同步、不上传**。
- 情报源 API Key 以 AES-GCM 密文形式落盘，明文只在后台 SW 内短暂存在，内容脚本拿不到。
- 完整的数据流、存储项与法律声明见 [PRIVACY.md](./PRIVACY.md)。

---

## ⚠️ 可能误拦与免责

本扩展采用**启发式特征评分**。虽已内置官方 / 可信分发白名单、`file://` 与浏览器内部页自动跳过等免误拦措施，但**仍可能把个别正常网站误判为风险**。

遇到误拦：

1. 在设置 →「规则与名单」→ 信任域名白名单里加上该域名，立即放行；
2. 在「关于」页选择「误报」提交反馈；
3. 临时访问可在拦截浮层里选「仍要访问」（需二次确认）。

> 它只负责「在你被诱导下载前尝试阻止」，不能替代专业的安全软件；发现漏报同样欢迎反馈。

## ⚠️ 已知限制：第三方下载器（IDM / 迅雷 / EagleGet 等）

浏览器扩展**只能在 Chrome / Edge 的下载与网络栈内拦截**。IDM 等下载器会装一个原生 companion 进程 + 浏览器插件，在「点击 / 右键 / mousedown」阶段就把 URL 抢走、由它自己的进程下载——此时 `chrome.downloads.onCreated` **根本不会触发**，后台兜底层失效。这是浏览器扩展的固有限制，不是本扩展的 bug。

本扩展用「在 URL 抵达下载器之前拦截」的分层思路弥补：

- **页面级硬钩子**（`document_start` 即安装）：覆盖 `window.open`、`<a>.click` 原型、`location` 跳转，并在 `mousedown` / `pointerdown` 捕获阶段拦截下载入口；
- **元素禁用**：命中下载入口的按钮置灰、移除 `href`、`pointer-events:none`，并拦截 `contextmenu`；
- **警示提醒**：风险页浮层提示「临时关闭下载器的浏览器接管」。

> 仍无法覆盖：手动复制 URL 粘进下载器、或把下载器设为系统默认下载器——这类下载完全不经过浏览器，任何扩展都拦不住。

## 💖 支持作者（爱发电）

如果这个扩展帮到了你，欢迎到 [爱发电](https://ifadian.net/a/SilverFoxBlocker) 支持作者。赞助者将列入公开感谢名单。

## 📜 许可证

原算法与部分规则来自 [Lolitide/VirusDetector](https://github.com/Lolitide/VirusDetector)，其上游 SilverFox Guard 由 [@yinbo345](https://github.com/yinbo345) 维护，均以 MIT License 发布。
本仓库同样以 MIT License 发布，详见 [LICENSE](./LICENSE)。
版权声明：Copyright (c) Lolitide, yinbo345, bbjj12345。
