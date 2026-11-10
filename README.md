# SilverFoxBlocker

Chrome / Edge 浏览器扩展（Manifest V3，当前版本 **v1.6.1**），用于检测并拦截「银狐木马（Silver Fox / 游蛇）」相关的钓鱼站、仿冒官网与恶意下载入口。

**检测、评分、名单比对与拦截全部在本地完成**，不依赖在线服务即可工作。默认开启的 RDAP / ICP 辅助核验会发送**域名**；云端黑 / 白名单、威胁情报 API、社区黑名单都是**需要你主动开启或点击**的增强项。v1.6.1 包含作者维护的云端黑 / 白名单、名单上报（把你的自定义名单发给作者）、KVRT / SoftcnKiller / AdwCleaner 三款清除工具，以及蓝奏云版本更新源。

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

### 一、本地检测与拦截（默认全部开启）

- **实时网页分析**：解析 DOM 结构、下载入口、话术特征，而不是只比对域名黑名单。
- **判定顺序（先名单、后联网）**：先查六类名单（云端 / 扩展内置 / 自定义，各有黑、白两份），命中即按名单处理，均为本地查表、毫秒级，不发起任何外部请求；未命中才**并行**查询 ICP 备案与域名年龄，并保证**页面加载完成后 5 秒内**给出结论（超时即以现有信息判定，ICP / 年龄仅作加分项）。
- **名单优先级（宁可杀错，不可放过）**：**任意黑名单 > 任意白名单**；同色内部按 **云端 > 扩展内置 > 自定义** 归因。即同一域名只要出现在任一黑名单里就判危并拦截，即使同时出现在白名单里也不豁免——避免远端可变的云端白名单被误加或投毒后开出一条绕过样本 IOC 的通道。该顺序在页面判定、评分引擎、下载拦截三条链路上完全一致。
- **名单粒度（域名 / 链接两级）**：云端黑、白名单都支持纯主机名（`example.com`，覆盖该域名及其全部子域）与「主机名/路径」（`wwavz.lanzout.com/b01gigjayb`）两种写法，后者只对匹配的链接及其子路径生效（前缀须落在 `/` 边界，`/b01gigjayb2` 不命中；只比对 pathname，忽略查询串与锚点）。路径条目在**页面判定与下载拦截**两条链路上同时生效，适合「只信任某个网盘分享链接、同站其它页面照常检测」的场景。
- **多维加权评分**：官方域名早期退出、ICP 备案核验、域名仿冒检测（编辑距离 / 去连字符比对）、代码工程化与 AI 生成痕迹评估等 11 个可独立开关的检测维度。
- **拦截任意下载入口**：`<a>` / `<button>` / `<div>` 等任意元素；同时覆盖 JS 程序化下载（`window.open` / `a.click` / `blob` / `location` 跳转）。
- **自动下载竞速兜底**：`<meta refresh>`、服务端强制下载（`Content-Disposition: attachment`）等「自动下载」场景也能拦截。
- **跳转链污染追踪**：危险站跳转到新域名后，仍能识别并拦截下游下载。
- **下载发现层**：递归解析内联脚本里的直链、`.txt` 里藏的真实地址、meta refresh 目标、iframe 嵌套资源，弥补「只有指定 URL 才拦得住」的短板。
- **智能免误拦**：官方 / 搜索引擎 / 可信分发（GitHub、网盘等）白名单；`file://`、浏览器内部页、localhost 自动跳过。

### 二、作者维护的云端黑 / 白名单（手动同步，默认无数据）

在「关于 → 云端名单更新」点击一次 **从云端更新名单**，才会发生一次联网拉取；**扩展不会自动定时同步**，建议每天手动更新一次。

- **数据来源**：作者维护的 `whitelist.json` / `blacklist.json`（托管在作者的私有 GitHub 仓库），经自建 Cloudflare Worker 的 `GET /list?type=white|black` 实时读取并转发。请求只带一个随扩展分发的只读 `X-API-Key`（用于 Worker 对扩展鉴权，不是你的身份标识），**不上传任何本地数据**。
- **备用通道**：Worker 域名被污染或线路不通时，改用公开仓库里的**加密快照**（`Cloud/*.json.enc`）——经 GitHub raw 或公共反代取回密文，在扩展本机解密后再走同一套清洗/落盘流程。密文用 AES-256-GCM 保护，口令内置在扩展里，因此它挡住的是「随手点开链接看名单」和「改一个域名试试」，挡不住解包阅读源码的人；真正的保密仍然靠 Worker（GitHub 令牌只在服务端）。解密失败（口令不符 / 文件被改）会直接报错中止，绝不会把名单当空写入。
- **落盘方式**：两份名单并行拉取、清洗校验后**整体覆盖**写入 `chrome.storage.local`（`sfCloudWhite` / `sfCloudBlack` / `sfCloudListMeta`）；后台收到 `storage.onChanged` 立即重新注入，内容脚本在下一次页面加载时读取。是「镜像覆盖」不是「合并追加」，所以云端删掉的误报条目会真正失效；任一份拉取失败则**两份都不写入**，不会出现半新半旧。空响应或全部条目非法时同样中止，不会把本地名单清空。
- **生效规则**：黑名单支持 `*` / `?` 同级别通配（上限 200 条），白名单不支持通配（避免开出过宽的放行通道）；两份名单都支持路径条目（单次上限 500 条）。被丢弃的条目及原因会在「关于 → 未生效条目」里列出，不会静默失效。
- **与内置名单的关系**：云端名单、`rules/iocs.js` 内置名单、你手写的名单始终是三份独立数据，互不覆盖；判定时由评分引擎做集合查找（内置 ∪ 云端）。

### 三、名单上报（把你的自定义名单发给作者）

在「规则与名单 → 自定义信任域名白名单 / 自定义恶意域名黑名单」里，各有一个「发送白/黑名单到作者邮箱」按钮。**只有点击时才发送**，内容仅限该文本框里的域名（去重、去协议、小写，加一行类型标记），不含浏览记录、页面 URL、其它设置或联系方式；正文上限 2000 字符，超出会提示分批。经与「反馈与建议」相同的 Worker 以邮件送达作者，作者人工复核后择优并入云端名单。如果不想分享自己维护的域名，不点即可。

### 四、威胁情报 API（可选，默认关闭）

需要先打开「威胁情报 API」总开关，再单独开启各情报源。命中后会在网页顶部横幅提示，VT 横幅还可展开逐引擎检出明细。

| 情报源 | 是否需要 Key | 发送的数据 | 判定口径 |
|---|---|---|---|
| VirusTotal (API v3) | 需要（自有 Key，**AES-GCM 密文**存储） | 域名的 base64url / URL 的 base64url（查询 ID，不上传页面内容） | 按引擎可信度分三档：可能是误报 / 请保持谨慎 / 请提高警惕 |
| URLhaus (abuse.ch) | 不需要 | 域名、当前页面 URL | 仅「活跃」证据才判危；只剩历史记录时降级为「曾被标记」 |
| NetAPI | 不需要 | 域名 | 仅「当前在列（24h 内）」判危，历史记录只提示 |
| Google Safe Browsing (v4 Lookup) | 需要（自有 Key，**AES-GCM 密文**存储） | **完整页面 URL** | 命中即「疑似」，措辞带限定并附 Google 免责说明 |

> 两个 Key 都只以 AES-GCM 密文保存在浏览器自身的存储中，不会发给作者；`storage.sync` 是否跨设备同步由你的浏览器账号决定，与作者无关。明文只在后台 Service Worker 内短暂解密，内容脚本拿不到；设置页只显示圆点掩码，绝不回显明文或密文。旧版本明文保存的 VT Key 会在你打开一次设置页时自动加密迁移，无需重新粘贴，迁移前后台也照常兼容明文查询。

### 五、社区维护的本地黑名单（可选，默认关闭）

同样是「总开关 + 单名单开关」两级结构，名单下载后存在本地，只用于本机比对，不会上传你的访问记录。

| 名单 | 规模 | 本地存储形式 | 更新 |
|---|---|---|---|
| OpenPhish | 数百条钓鱼域名 | `storage.local` 域名数组 | 每日自动 / 手动 |
| PhishDestroy | 约 14 万条 | `storage.local` 域名文本 | 每日自动 / 手动 |
| HaGeZi's TIF | 约 181 万条 | IndexedDB 布隆过滤器位图（约 4.8 MB，误判率 2.5e-5，无漏判） | 每日自动 / 手动（可选完整版 / 中等版） |

### 六、工具中心与版本更新源

全部由**用户主动点击**触发，扩展不会自动下载任何可执行文件。

| 工具 | 来源 | 触发方式 |
|---|---|---|
| 360 系统急救箱（独立版） | 先探测 `weishi.360.cn` / `baoku.360.cn` 页面拿最新直链，再从 `dl.360safe.com` 下载；失败回退内置备用直链 | `chrome.downloads.download` |
| 火绒恶性木马专杀（无签名版） | 在 `down3/down7/update/down2/down-tencent.huorong.cn` 之间探测最新版本号再下载 | `chrome.downloads.download` |
| Kaspersky Virus Removal Tool（KVRT） | 官方固定直链 `devbuilds.s.kaspersky-labs.com/kvrt/latest/full/kvrt.exe`，始终指向最新版，无需探测 | `chrome.downloads.download` |
| AdwCleaner（Malwarebytes） | 官方 release 直链 `adwcleaner.malwarebytes.com/adwcleaner?channel=release`，保存为 `adwcleaner.exe` | `chrome.downloads.download` |
| SoftcnKiller（流氓软件清除） | 蓝奏云分享页 `free.lanzoux.com/b0cpu1guf`（无需提取码） | 打开新标签页，按页面提示自行下载 |
| 更多工具镜像 | 123 云盘、迅雷光鸭云盘分享目录（设置页「银狐急救」内链接） | 打开新标签页 |

「关于 → 版本更新」提供两个入口：**GitHub 仓库**与**蓝奏云镜像**（`wwavz.lanzout.com/b01gigjayb`，提取码 `2hxh`）。点击蓝奏云按钮时会把提取码复制到剪贴板，方便在分享页粘贴；跳转本身是普通的 `<a target="_blank" rel="noreferrer">`，扩展不拦截、不改写导航，也不读取分享页内容。

银狐急救页还包含 hosts 修复、关闭内存完整性、查杀顺序等分步引导，以及 SoftcnKiller → AdwCleaner 的清理顺序建议。

### 七、其他

- **防护统计**：拦截次数、告警次数、近期记录，仅存本地。
- **反馈与建议**：两种通道——「发送反馈到 GitHub Issue」打开预填的 Issues 新建页（内容会出现在地址栏并在 GitHub 公开），「发送反馈到作者邮箱」把正文与选填联系方式 POST 到自建 Worker 转发邮件。弹窗里的「一键上报网站」只是快捷打开「关于」页。
- **界面**：深浅主题、多套配色、字号缩放、自定义背景、配置导入导出。
- **远程代码**：不加载任何远程脚本；云端名单、社区名单都只是数据（域名字符串），经清洗校验后才生效，不会 `eval`。

---

## 🛡️ 工作原理

1. **采集**：页面域名、HTML、下载链接、代码特征。
2. **名单短路**：六类名单本地查表，命中黑名单直接判危、命中白名单跳过评分；未命中才进入评分。
3. **评分**：加权评分引擎得出 0–200+ 风险分，并行查询 RDAP / ICP 作为加分项，命中组合信号直接升级为危险。
4. **预警**：跨过阈值触发 `warn`（顶部提示）或 `danger`（拦截浮层 + 禁用下载入口）。
5. **兜底**：后台 `chrome.downloads` 监听，覆盖内容脚本判定前的自动下载。
6. **可选增强**：威胁情报 API 与社区黑名单命中后追加情报横幅；云端名单快照由你手动同步。

---

## 📦 安装

- **开发者模式**：打开 `chrome://extensions`（或 `edge://extensions`）→ 开启「开发者模式」→「加载已解压的扩展程序」→ 选择本目录。
- 改动代码后点一次「重新加载」，并**刷新已打开的页面**（内容脚本不会注入到重载前就已存在的标签页）。
- 首次使用若想启用云端名单：进入「关于」→ 点「从云端更新名单」；状态行会显示黑 / 白各多少条与上次同步时间。

---

## 📁 目录结构

```
SilverFoxBlocker/
├── manifest.json              # MV3 清单：版本、权限、CSP、内容脚本注入
├── background.js              # Service Worker：下载兜底、跳转链、情报源查询、
│                              #   社区名单下载/落盘/布隆过滤器、云端名单热重注入、
│                              #   急救工具直链探测、统计、定时任务
├── content/
│   ├── content.js             # 内容脚本：页面采集、评分调用、拦截浮层、情报横幅、云端名单注入
│   └── content.css            # 页面内注入样式（浮层、横幅、按钮）
├── rules/
│   ├── iocs.js                # 特征库：官方域名表、恶意域名、可疑 TLD、话术词表、分类器
│   ├── analyzer.js            # 评分引擎：11 个检测维度 + 名单清洗/通配/路径匹配 + 结论护栏
│   └── resource-resolver.js   # 下载发现层：BFS 解析脚本/文本/跳转/iframe 中的直链
├── ui/
│   ├── popup.html/.js/.css    # 工具栏弹窗：当前站点评分、近期拦截、一键上报入口
│   ├── options.html/.js/.css  # 设置页：检测维度、拦截行为、规则与名单（含名单上报）、
│   │                          #   工具中心/急救、统计、关于（云端名单、蓝奏云更新、反馈）
│   └── feedback-config.js     # 反馈 Worker 端点（字符码存储，避免明文域名）
├── crypto-helper.js           # VT / GSB API Key 的 AES-GCM 加密 / 解密
├── worker/index.js            # Cloudflare Worker：GET /list 转发云端名单 + POST 反馈/名单上报
├── wrangler.toml              # Worker 部署配置（KV 绑定、日志开关），不随扩展运行
├── tools/rescue-scripts/      # 急救工具直链的本地更新脚本（开发用，不参与打包运行）
├── tools/encrypt_cloud.js     # 把私有仓库的明文名单打包成公开仓库用的加密快照（方案 C）
├── Cloud/*.json.enc           # 云端名单的加密快照（备用通道取它；内容不可直接阅读）
├── icons/                     # 扩展图标 16 / 48 / 128
├── fonts/                     # 界面字体（SmileySans，笑脸模式）
├── _locales/zh_CN/            # 扩展名称与描述
└── sponsors.json              # 赞助者名单
```

> `worker/` 与 `wrangler.toml` 用于部署作者侧的 Cloudflare Worker，`tools/` 只在维护直链时使用；扩展运行时都不会加载它们。云端名单的**内容**存放在独立的私有仓库中，不在本目录内。

---

## 🔑 权限说明

`manifest.json` 中每一项权限都有实际用途：

| 权限 | 用途 |
|---|---|
| `storage` | 保存设置（开关、权重、白名单、黑名单、情报源配置）、防护统计、云端名单快照、社区名单与元数据、下载黑名单、连坐集合 |
| `unlimitedStorage` | 云端名单镜像、HaGeZi 位图约 4.8 MB、两份域名名单与自定义主题都落在 `storage.local`，合计会超过浏览器默认配额 |
| `downloads` | 监听并取消高危下载；按用户点击下载 360 / 火绒 / KVRT / AdwCleaner 工具 |
| `webNavigation` | 监听顶级框架导航：页面开始加载即进入「检测中」闸门，并追踪「危险页 → 新域名」的跳转链 |
| `notifications` | 检测到高风险网站/下载时弹系统原生告警（不依赖声音，无需用户手势解锁） |
| `alarms` | 三份社区名单的每日自动更新，以及「立即更新」的一次性任务（MV3 中 SW 会被回收，定时任务必须走 alarms） |
| `host_permissions: <all_urls>` | ① 内容脚本需要在所有 http(s) 页面注入以做实时检测；② 允许后台向 RDAP / ICP / 情报源 / 名单 CDN / 工具官方域名发起请求 |
| `web_accessible_resources` | 页面内浮层需要加载自带字体；`sponsors.json` 供「关于」页读取 |
| `content_security_policy` | `script-src 'self'`、`object-src 'self'`：禁止远程脚本与插件；`connect-src 'self' https:`：**允许连接任意 HTTPS 主机，并未做域名级白名单**——实际请求目标由代码里的固定清单决定，默认关闭的项在未开启前一次都不会请求 |

**不申请的权限**：`tabs`（`tabs.create` / `tabs.sendMessage` 无需该权限，读取标签页 URL 由 host 权限覆盖）、`cookies`、`history`、`bookmarks`、`webRequest`（改用 `webNavigation` + 内容脚本，避免全量拦截网络请求）、`nativeMessaging`、`scripting`。

---

## 🌐 网络请求清单

除下列请求外，扩展不会发起任何外部连接。**默认关闭的项在未开启前一次都不会请求；标注「需点击」的项只在用户操作时发生一次。**

### 自动发出（默认开启，可关闭）

| # | 目标 | 触发条件 | 发送内容 |
|---|---|---|---|
| 1 | `rdap.org` 及各注册局 RDAP | 页面未命中名单、进入评分流程时（用于域名年龄加分） | 注册域名（如 `example.com`，不含路径/参数） |
| 2 | `uapis.cn` / `cn.apihz.cn`（ICP 备案查询） | 未命中名单，且：页面出现备案号需验真伪 / `.cn` 域名未找到备案号 / 已检出域名仿冒 | 域名；可在设置 → 检测维度关闭 |
| 3 | 当前页面已引用的资源 | 下载发现层解析脚本跳转、`.txt` 藏链、meta refresh、iframe 时 | 无（只在页面上下文内按需读取，不发往作者服务器、不带跨域凭据） |

### 可选增强（默认关闭）

| # | 目标 | 触发条件 | 发送内容 |
|---|---|---|---|
| 4 | `www.virustotal.com` | 开启 VT 情报源 | 域名 / URL 的 base64url 查询 ID |
| 5 | `urlhaus-api.abuse.ch` | 开启 URLhaus | 域名、当前页面 URL |
| 6 | `netapi.com` | 开启 NetAPI | 域名 |
| 7 | `safebrowsing.googleapis.com` | 开启 GSB | 完整页面 URL |
| 8 | `cdn.jsdelivr.net` / `fastly` / `gcore` / `testingcf` / `raw.githubusercontent.com` / `gh-proxy.com` | 开启社区名单并每日自动 / 手动更新时（多镜像回退） | 无（GET 名单文件） |

### 用户主动触发

| # | 目标 | 触发条件 | 发送内容 |
|---|---|---|---|
| 9 | `api.silverfoxblocker.dpdns.org/list` | 点「从云端更新名单」（无自动定时） | GET，仅 `type=white\|black`、时间戳与只读 `X-API-Key`；**不上传本地数据** |
| 9b | `raw.githubusercontent.com` 及公共反代 `gh-proxy.com` / `ghfast.top` / `ghproxy.net` / `ghfile.geekertao.top` / `gh.geekertao.top` / `ghproxy.cc` | **仅当第 9 项直连失败（超时 / DNS 不通）时**自动重试，成功一次即停 | 只 GET 公开仓库 `Cloud/whitelist.json.enc` / `blacklist.json.enc`（**密文**）；这些是第三方代理，因此**不带 `X-API-Key`、不带任何本地数据**。反代只能转发、无法解密 |
| 10 | `api.silverfoxblocker.dpdns.org` | 点「发送反馈到作者邮箱」或「发送白/黑名单到作者邮箱」 | POST：反馈正文（≤2000 字）+ 选填联系方式，或仅域名清单；见 [PRIVACY.md](./PRIVACY.md) |
| 11 | `weishi.360.cn` / `baoku.360.cn` / `dl.360safe.com` / `*.huorong.cn` | 点击下载 360 急救箱 / 火绒专杀（先探测版本再下载） | 无 |
| 12 | `devbuilds.s.kaspersky-labs.com` / `adwcleaner.malwarebytes.com` | 点击下载 KVRT / AdwCleaner | 无 |
| 13 | 外链跳转：`wwavz.lanzout.com`（版本更新，提取码 2hxh）、`free.lanzoux.com`（SoftcnKiller）、123 云盘、光牙盘、GitHub / GitHub Issues、爱发电 | 用户点击链接，普通新标签页打开 | 扩展不注入参数、不读取页面内容；后续行为受目标站点自身政策约束 |
| 13b | GitHub 全站镜像 `kkgithub.com` / `bgithub.xyz` | 点「前往 GitHub 查看更新」（落点 `…/releases/latest`）且直连 `github.com` 超时（先探测直连，1.5s 不通才改道） | 无。镜像只用来打开同一个更新页（内容与官网一致），不传键值、不传页面数据 |
| 13c | `gh-proxy.com` 反代 `api.github.com` | 直连与镜像**都**不通时，退一步只查「有没有新版」 | 无。GET `releases/latest` 公开信息（版本号 / 日期），4s 超时；不下载安装包、不携带任何本地数据 |

### 后端链路（由 Worker 发起，不是扩展）

`GET /list` 由 Worker 向 `api.github.com` 读取私有仓库里的 `whitelist.json` / `blacklist.json`；`POST` 由 Worker 经 `api.brevo.com` 发信到 `feedback@silverfoxblocker.dpdns.org`，再经邮件路由转给作者。**只有 POST**（反馈与名单上报）会走 KV 限流：按「IP + 日期」计数，60 次/天/IP、24 小时过期；Worker 同时开启了调用日志，因此两类请求在服务端都可能留下来源 IP 记录。

> 早期上游版本会从 `site-directory-cache.pages.dev` 拉取第三方「官方域名库」，已于 2026-11-01 移除。**当前版本的云端名单是作者自行维护的黑 / 白名单，不是第三方官方站点清单，也不含任何可执行内容。**

---

## 🤖 关于 AI 功能

早期上游版本内置过「云端 AI 辅助研判」开关，**当前版本不再包含任何 AI 分析逻辑**：扩展不会把页面文本、URL 或文件特征发送给任何大模型服务商。`aiMaxMode` 等字段仅作为旧配置兼容保留，没有对应实现、UI 或网络请求。

---

## 🔒 隐私

- 检测、评分、名单比对与拦截全部在本地完成；不建立账号、不收集浏览历史、不接入统计或崩溃上报。
- 设置与统计只写本机 `storage` / IndexedDB；`storage.sync` 的跨设备同步由浏览器账号决定，**不经过作者服务器**。
- **两个例外需要你主动点击**：反馈邮件与名单上报会把你填写的内容发给作者，Worker 还会在邮件中附上来源 IP 用于限流与溯源；不想分享就不要点。
- 完整数据流、存储项（含两个 API Key 的密文存储与旧明文迁移）与法律声明见 [PRIVACY.md](./PRIVACY.md)。

---

## ⚠️ 可能误拦与免责

本扩展采用**启发式特征评分**。虽已内置官方 / 可信分发白名单、`file://` 与浏览器内部页自动跳过等免误拦措施，但**仍可能把个别正常网站误判为风险**。

遇到误拦：

1. 在设置 →「规则与名单」→ 自定义信任域名白名单里加上该域名，立即放行；
2. 在「关于」页选择「误报」提交反馈（GitHub Issue 或邮件）；
3. 临时访问可在拦截浮层里选「仍要访问」（需二次确认）。

> 它只负责「在你被诱导下载前尝试阻止」，不能替代专业的安全软件；急救工具也请自行核对来源与扫描结果后再处理。发现漏报同样欢迎反馈。

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
