# SilverFoxBlocker

Chrome / Edge 浏览器扩展（Manifest V3，当前版本 **v1.8.3**），用于检测并拦截「银狐木马（Silver Fox / 游蛇）」相关的钓鱼站、仿冒官网与恶意下载入口。

**检测、评分、名单比对与拦截全部在本地完成**，不依赖在线服务即可工作。默认开启的 RDAP / ICP 辅助核验会发送**域名**；云端黑 / 白名单、威胁情报 API、社区黑名单都是**需要你主动开启或点击**的增强项。v1.7.3 包含 29 维加权检测引擎、六类名单（云端 / 内置 / 自定义 × 黑白）、下载与自动下载拦截、云端名单手动同步（Worker 侧 GitHub 优先、Gitee 回落）、可选四家威胁情报与三份社区黑名单、五款急救工具下载引导，以及 GitHub / Gitee / 蓝奏云三个更新入口。

**无需账号、无遥测、无广告**：不收集浏览历史，不注入参数，不加载任何远程代码。

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

### 总览：这个扩展做了什么

| 模块 | 你能看到的功能 | 默认状态 | 是否联网 |
|---|---|---|---|
| **本地检测引擎** | 29 个可独立开关的加权检测维度：域名仿冒（333 条品牌关键词做编辑距离比对）、缺/盗用 ICP 备案、域名年龄、代码工程化程度、AI 生成痕迹、链接跨域、双扩展名、密码压缩包、NOAH 投递组件、运行时取链、伪造更新、钓鱼话术等；给出风险分与逐项理由 | 开启 | 否（纯本地） |
| **拦截与处置** | 按风险分分三级（安全 / 可疑 / 危险）：页面顶部横幅、警告浮层、**禁用页面全部下载与跳转链接**、系统通知；任意元素（`a`/`button`/`div`）上的下载入口拦截，含 `window.open`、`a.click`、`blob:`、`location` 跳转、`meta refresh`、`Content-Disposition: attachment` 自动下载；拦截浮层给三个出口：离开此网站 / 继续访问（仍拦截下载）/ **访问正确的页面** | 开启 | 否 |
| **分析闸门（判定前默认拒绝）** | 页面加载完成但判定尚未出来时，本页下载与下载跳转**先被阻止**（页面顶部常驻一条提示横幅），已进入浏览器的下载先挂起；判定安全则自动解除并静默重下，判定危险则保持拦截。**不依赖「自动拦截下载」开关**。SPA（`pushState` 换路由）也会重新起闸并重判，旧路由的迟到结论按代数丢弃 | 开启 | 否 |
| **六类名单比对** | 云端 / 内置 / 自定义，各有黑、白两份；**任意黑名单 > 任意白名单**；支持域名级、`*` `?` 同级别通配、以及「域名/路径」条目 | 内置名单开启 | 否（查表在本地） |
| **云端黑 / 白名单** | 「关于 → 从云端更新名单」手动同步作者维护的名单；Worker 优先读 GitHub、失败回落 Gitee，扩展侧再按 GitHub raw → 6 个公共反代 → Gitee raw 逐级兜底 | 无数据，需手动点击 | 是（仅点击时） |
| **威胁情报（可选）** | VirusTotal、URLhaus、NetAPI、Google Safe Browsing 四项，命中后横幅显示依据；VT 可展开逐引擎检出 | 关闭 | 是（开启后） |
| **社区黑名单（可选）** | OpenPhish、PhishDestroy、HaGeZi TIF、uBlock Origin - Badware risks、Dandelion Sprout 五份，每日自动更新，本地比对；后三份用布隆过滤器位图 | 关闭 | 是（开启后） |
| **银狐急救** | 360 急救箱 / 火绒专杀 / KVRT / AdwCleaner / SoftcnKiller 的官方下载与查杀顺序引导；hosts 修复、关闭内存完整性等分步说明 | 可用 | 是（点击时） |
| **统计与界面** | 拦截/告警计数、近期记录、逐站评分；深 / 浅主题 + 5 套配色（classic / gold / neon / mist / space，另有隐藏彩蛋）+ 自定义主题导入、自定义背景、字号缩放；规则与名单可导出为 JSON 或导入他人分享的配置 | 开启 | 否 |
| **反馈与上报** | GitHub Issue 预填、邮件反馈（经自建 Worker）、把自定义名单发给作者 | 需手动点击 | 是（点击时） |
| **版本更新** | 「检查更新」四级接力（直连 GitHub → api.github.com → 公共反代 → Gitee）；GitHub / Gitee / 蓝奏云三个下载入口 | 需点击 | 是（点击时） |

> 一句话：**默认状态下它只在本机做判断**，联网项要么默认关闭，要么必须你点一下才发生。

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

- **数据来源**：作者维护的 `whitelist.json` / `blacklist.json`（托管在作者的私有 GitHub 仓库，作者侧另有 Gitee 私有镜像仓库作为 GitHub 不可达时的服务端备源），经自建 Cloudflare Worker 的 `GET /list?type=white|black` 实时读取并转发。请求只带一个随扩展分发的只读 `X-API-Key`（用于 Worker 对扩展鉴权，不是你的身份标识），**不上传任何本地数据**。响应头 `X-Data-Source` 会注明这次数据取自 `GitHub` 还是 `Gitee`，设置页状态行显示为「数据源：云端接口·Gitee」。
- **备用通道**：Worker 域名被污染或线路不通时，改用公开仓库里的**加密快照**（`Cloud/*.json.enc`）——按「GitHub raw → 六个公共反代 → Gitee raw（最后一跳）」的顺序取回密文，前一跳成功即停，在扩展本机解密后再走同一套清洗/落盘流程。密文用 AES-256-GCM 保护，口令内置在扩展里，因此它挡住的是「随手点开链接看名单」和「改一个域名试试」，挡不住解包阅读源码的人；真正的保密仍然靠 Worker（GitHub 令牌只在服务端）。解密失败（口令不符 / 文件被改）会直接报错中止，绝不会把名单当空写入。快照的生成与发布方式见 [Cloud/README.md](./Cloud/README.md)。
- **落盘方式**：两份名单并行拉取、清洗校验后**整体覆盖**写入 `chrome.storage.local`（`sfCloudWhite` / `sfCloudBlack` / `sfCloudListMeta`）；后台收到 `storage.onChanged` 立即重新注入，内容脚本在下一次页面加载时读取。是「镜像覆盖」不是「合并追加」，所以云端删掉的误报条目会真正失效；任一份拉取失败则**两份都不写入**，不会出现半新半旧。空响应或全部条目非法时同样中止，不会把本地名单清空。
- **生效规则**：黑、白名单**都支持** `*` / `?` 同级别通配（`*` 不跨标签、`*.foo.com` 归一为后缀、TLD 位禁通配）；两份名单都支持路径条目。**通配与路径条目都不限条数**（2026-11-12 取消上限；通配按尾部标签分桶查找，条数只影响内存，不影响单页耗时）。被丢弃的条目及原因会在「关于 → 未生效条目」里列出，不会静默失效。
- **与内置名单的关系**：云端名单、`rules/iocs.js` 内置名单、你手写的名单始终是三份独立数据，互不覆盖；判定时由评分引擎做集合查找（内置 ∪ 云端）。
- **「访问正确的页面」官网映射（2026-11-12 起）**：拦截浮层的第三个出口。被拦的通常是仿冒域（`huorongsafe.com.cn`），它永远不会出现在白名单里，所以**不能靠白名单反查官网**；改为「品牌词 → 官网」映射：从被拦主机名里认出品牌，再打开该品牌的真实官网。数据以内置表 `rules/iocs.js` 的 `CORRECT_SITE_CATALOG` 为准（随发版，目前 **20 个大类 968 行映射 / 1052 个品牌词**，覆盖安全软件、浏览器、IM 与社交、输入法、办公与文档、影音娱乐、云盘与存储、AI 大模型、下载与压缩、系统工具、电商与支付、地图与出行、开发者与云服务、游戏与加速器、新闻与搜索、教育与考试、金融、企业机构、平台与生态、用户反馈与个人站点）；云端白名单的 `correct_sites` **只作补充**，仅收录「内置白名单未覆盖、官网确实存在」的品牌（当前 5 条：腾讯会议 / Chromium / 讯飞开放平台 / 金山词霸 / 火绒论坛），可热更新、不必发版。两级合并后按**最长品牌词**命中，同词**内置优先**；都认不出来就打开说明页 `ui/no-correct-site.html`（说明「暂未收录正确域名，或该页应被拦截」，并给出反馈入口）。**这张表不参与任何放行 / 拦截判定**，只决定一个按钮跳去哪儿，也不发起网络请求。
- **- **白名单域名按备注校正**：备注与域名严重不匹配时直接改域名（这是改判定，只在有确凿新域名、或“留着等于放行一个无关站点”时才做）。2026-11-12 处理了 8 处：`furmark.com`→`geek3d.com`（前者是皮草行业站）、`panda.com`→`pandasecurity.com`（前者是待售停放页）、`gdata.com`→`gdata-software.com`、补 `yhd.jd.com`（1 号店已并入京东）；移除 `safari.com`、`peerless.com`（美国嵌入式系统公司）、`returnbuy.com`（已挂出售页）、`zhangyu.com`（掌阅是 zhangyue.com）。其余只改备注文字的（如 `office.qq.com` 实为 TIM、`xinshuru.com` 是手心输入法、文心一言已更名「文心助手」、通义已统一称「千问」），域名均未动。没把握的映射不写进任何表，记在本地笔记 `rules/.README.md`（`.gitignore` 挡在仓库外），确认后再补。
- **自定义名单同样支持通配**：「规则与名单」里的自定义信任白名单 / 自定义恶意黑名单都是「一行一个主机名」，现在也接受 `*` / `?`（如 `cdn*.example.com`、`*bot.qpefh.com`），语义与内置、云端完全一致（同一套编译器与护栏）；只匹配主机名，要按链接级生效请用云端名单的 `主机名/路径` 写法。**不限条数**：名单改存 `storage.local`（`storage.sync` 单键只有 8KB，约 550 条，超出会静默失败），小体积时仍镜像一份到 sync 保留跨设备同步。
- **内置名单也支持通配**（随扩展发版）：`rules/iocs.js` 的官方域名表与恶意域名表都接受 `*` / `?` 写法，例如 `*bot.qpefh.com`（同标签内任意前缀）、`abi0?.8msg8.com`（单字符）。`*` 不跨 `.`，TLD 位禁止通配（`*.com` 会被丢弃）、`*.foo.com` 归一为后缀条目；通配只参与主机名命中判定，不参与「从官方域派生品牌词」，因此不会把 `*media` 变成一个仿冒品牌词。

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
| HaGeZi's TIF | 百万级 | IndexedDB 布隆过滤器位图（误判率 2.5e-5，无漏判） | 每日自动 / 手动（可选完整版 / 中等版） |
| uBlock Origin - Badware risks | 数千条整站域名 | IndexedDB 布隆过滤器位图（仅收录 `\|\|域名^` 规则） | 每日自动 / 手动 |
| Dandelion Sprout's Anti-Malware List | 万级整站域名 | IndexedDB 布隆过滤器位图（仅收录 `\|\|域名^` 规则） | 每日自动 / 手动 |

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

「关于 → 版本更新」提供三个入口：**GitHub 仓库**、**Gitee 镜像**（`gitee.com/bbjj12345/SilverFoxBlocker/releases/latest`，国内直连、内容与 GitHub Release 同步）与**蓝奏云镜像**（`wwavz.lanzout.com/b01gigjayb`，提取码 `2hxh`）。点击蓝奏云按钮时会把提取码复制到剪贴板，方便在分享页粘贴；三个入口跳转都是普通的 `<a target="_blank" rel="noreferrer">`，扩展不拦截、不改写导航，也不读取目标页内容。GitHub 入口额外做了「直连探测 → 公共镜像改道」两级兜底，Gitee 与蓝奏云本身就在国内可达，不需要这一层。同一张卡片里「隐私政策」与「项目仓库」两行也各带一条 Gitee 镜像地址（`gitee.com/bbjj12345/SilverFoxBlocker…`，与 GitHub 那条只差域名），GitHub 打不开时可以直接换这一行点开。

版本号右侧还有 **「检查更新」** 按钮：点击后向 `github.com/…/releases/latest` 查询最新 tag（GitHub 会 301 到 `/releases/tag/vX.Y.Z`，扩展直接读最终地址），与 `manifest.json` 里的版本号逐字节比对——不同且线上更高显示「检测到新版本：vX.Y.Z」，相同（或线上反而更低，例如本地测试版）显示「无可用更新」。

查询按四级接力，前一级成功即停：**① 直连 `github.com` → ② 直连 `api.github.com` 公开 JSON → ③ `gh-proxy.com` 反代同一 API → ④ Gitee 镜像**（Gitee OpenAPI，失败再读 `…/releases/latest` 的 302 跳转地址）。每级开跑前会看总预算（12s）还剩多少，不够就直接跳到下一级，因此最坏情况也不会让按钮转上半分钟；提示行会随阶段显示「正在查询（GitHub 直连 / 公共代理 / Gitee 镜像）」。四级都不通时明确提示「查询失败」，不会谎称无更新。全过程只读版本号，不下载安装包、不上传任何数据。

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
├── worker/index.js            # Cloudflare Worker：GET /list 转发云端名单（GitHub → Gitee 双源）+ POST 反馈/名单上报
├── wrangler.toml              # Worker 部署配置（KV 绑定、日志开关），不随扩展运行
├── tools/rescue-scripts/      # 急救工具直链的本地更新脚本（开发用，不参与打包运行）
├── tools/encrypt_cloud.js     # 把私有仓库的明文名单打包成公开仓库用的加密快照（方案 C，需 Node）
├── tools/pack-snapshot.html   # 同上，但零安装：双击用浏览器打包（加密逻辑内联，不依赖外部 js）
├── Cloud/*.json.enc           # 云端名单的加密快照（备用通道取它；内容不可直接阅读）
├── icons/                     # 扩展图标 16 / 48 / 128
├── fonts/                     # 界面字体（SmileySans，笑脸模式）
├── _locales/zh_CN/            # 扩展名称与描述
└── sponsors.json              # 赞助者名单
```

> `worker/` 与 `wrangler.toml` 用于部署作者侧的 Cloudflare Worker，`tools/` 只在维护直链时使用；扩展运行时都不会加载它们。云端名单的**内容**存放在独立的私有仓库中，不在本目录内。

---

## 🔑 权限说明

`manifest.json` 只申请 **6 项 API 权限 + 1 项主机权限**，每一条都对应一个你能直接看到的动作，没有「先申请着、以后可能用」的权限。

| 权限 | 具体用在哪 | 申请理由 | 不授予的后果 | 外发数据 |
|---|---|---|---|---|
| `storage` | `storage.sync` 存设置 / 权重 / 自定义名单 / 两个 API Key（AES-GCM 密文）；`storage.local` 存统计、云端名单快照、社区名单、下载黑名单；`storage.session` 存本会话的危险标签页 | MV3 的 Service Worker 空闲 30 秒即被回收，设置与状态只能放 storage；不存就无法「记住你调过的每一个开关」 | 每次重启恢复默认，名单与统计全丢 | 否（除非你开了浏览器账号同步，那是浏览器厂商的行为） |
| `unlimitedStorage` | 云端名单镜像、社区名单（PhishDestroy 域名表、HaGeZi 布隆位图、uBlock / Dandelion 的小位图）、自定义背景 | 这些体积超过扩展默认配额；超限时 `storage.local.set` 会**静默失败**，表现成「提示同步成功、名单却没变」 | 开启社区名单后可能写盘失败 | 否 |
| `downloads` | ① 命中黑名单 / 载荷特征时 `chrome.downloads.cancel` 真正阻断下载；② 「银狐急救」里你点工具时发起下载并指定文件名 | 只靠页面提示拦不住已经开始的下载；急救工具也需要一个可信的下载入口 | 只能弹提示，高危文件照样落地 | 否（只从官方域名下载，且必须你点击） |
| `webNavigation` | 顶层框架 `onCommitted`：页面开始加载即进入「检测中」，并把「危险页 → 新域名」串成跳转链 | 银狐常见「落地页再跳一次才下载」，只有导航时序能追上；DOM 就绪后才判会漏掉瞬间自动下载 | 快速自动下载漏拦、跳转链断裂 | 否（只读导航事件时序） |
| `notifications` | 高风险站点 / 下载被拦时发系统原生通知 | 页面被立刻关掉、或命中发生在后台标签页时，页面内横幅你看不到 | 只在页面里提示 | 否（内容本机生成） |
| `alarms` | 五份社区名单的每日更新 + 「立即更新」一次性任务 | MV3 不允许常驻定时器，`setInterval` 在 SW 回收后失效；**云端名单不使用 alarms，完全手动** | 社区名单无法自动更新 | 否 |
| `host_permissions: <all_urls>` | ① 内容脚本在 `document_start` 注入所有 http(s) 页面做实时检测与下载拦截；② 后台请求 RDAP / ICP / 情报源 / 名单 CDN / 工具官网；③ 扩展页面直接读名单镜像（Gitee raw 不带 CORS 头也能读） | 投放站每天换域名，无法预先枚举主机；要把「任意站点」都纳入检测，只能申请全站主机权限 | 只能对固定站点生效，等于没有防护 | 请求目标由代码里的固定清单决定（见下一节），该权限本身不产生任何请求 |
| `web_accessible_resources` | 页面内浮层加载打包字体 `fonts/SmileySans-Oblique.woff2`；「关于」页读 `sponsors.json` | 浮层渲染在第三方页面里，字体文件必须允许该页面请求 | 浮层回退系统字体，功能不受影响 | 否（只是把打包内静态文件暴露给页面，不含用户数据） |
| `content_security_policy` | `script-src 'self'`、`object-src 'self'`；`connect-src 'self' https:` | 前者保证「不执行远程代码」由浏览器强制；后者是连接 HTTPS 接口所必需，**没有做域名白名单**，实际目标仍由代码固定清单决定 | —— | 否 |

**未申请的敏感权限**：`tabs`（`tabs.create` / `tabs.sendMessage` 不需要它，读标签 URL 由主机权限覆盖）、`cookies`、`history`、`bookmarks`、`webRequest` / `declarativeNetRequest`（不做全量网络拦截，改用 `webNavigation` + 内容脚本）、`scripting`（内容脚本走 manifest 静态声明）、`nativeMessaging`、`identity`、`management`、`clipboardRead`、`geolocation`。

> 审核备注：全部权限均可用「关于」页与工具栏弹窗里的功能逐条复现；把任一权限移除，上表「不授予的后果」一栏描述的功能就会消失。完整的逐项理由（含可直接粘贴到商店表单的版本）见 [PRIVACY.md § 八](./PRIVACY.md)。

---

## 📦 发布到 Edge 加载项商店

1. **打包**：只压缩**运行时**文件（`manifest.json` 必须在压缩包根目录，不能再套一层文件夹）。下列目录是开发/后端产物，**不要**打进包：`tools/`（Node 打包脚本、网页加密工具）、`Cloud/`（密文快照与打包记录）、`worker/` + `wrangler.toml`（Cloudflare Worker 后端，跑在服务端、与扩展无关）、`.bak_*` 备份目录。
   ```bash
   # macOS / Linux / Git Bash
   zip -r SilverFoxBlocker-1.7.2.zip \
     manifest.json background.js crypto-helper.js sponsors.json \
     content rules ui icons fonts _locales \
     LICENSE README.md PRIVACY.md
   ```
   打包后核对：压缩包根目录第一层应只有上面这些条目；这些文件合计约 **2.3 MB**（字体占一半以上），压成 zip 约 1.5 MB。
   > Windows 若没有 `zip` 命令，可用资源管理器全选上述条目 → 右键「压缩为 ZIP 文件」，或在 PowerShell 里用 `Compress-Archive -Path <这些条目> -DestinationPath SilverFoxBlocker-1.7.2.zip`。
2. **商店表单**：
   - 隐私政策 URL：`https://github.com/bbjj12345/SilverFoxBlocker/blob/main/PRIVACY.md`（Gitee 镜像：`https://gitee.com/bbjj12345/SilverFoxBlocker/blob/main/PRIVACY.md`）。
   - 「权限理由」逐项粘贴 [PRIVACY.md § 8.5](./PRIVACY.md) 的表格内容。
   - 「是否收集用户数据」：全部选「否」，仅「用户主动提交的反馈文本」按实际情况勾选（可留空不填联系方式）。
3. **版本号**：商店要求每次上传的 `version` 严格递增，当前 `1.7.2`，下次改动记得同步 `README.md` 顶部与「关于」页显示（版本号由 `manifest.json` 读取，无需改代码）。
4. **审核可能追问的三点**（答案都已写在 `PRIVACY.md` 与本文件中）：
   - 为什么需要 `<all_urls>` —— 任意站点实时检测，见上表；
   - `connect-src https:` 为何不写死域名 —— 情报源/镜像可切换，实际目标由代码固定清单决定；
   - 为什么带 `web_accessible_resources` —— 页面内浮层字体与「关于」页鸣谢名单。

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
| 8 | `cdn.jsdelivr.net` / `fastly` / `gcore` / `testingcf` / `raw.githubusercontent.com` / `gh-proxy.com` | 开启社区名单并每日自动 / 手动更新时（多镜像回退）。五份名单依次为 OpenPhish、PhishDestroy、HaGeZi TIF、uBlock Badware risks（`uBlockOrigin/uAssets`）、Dandelion Sprout Anti-Malware（`DandelionSprout/adfilt`） | 无（GET 公开名单文件；后两份是 AdBlock 语法，扩展只解析 `\|\|域名^` 规则，不入库、不执行任何规则） |

### 用户主动触发

| # | 目标 | 触发条件 | 发送内容 |
|---|---|---|---|
| 9 | `api.silverfoxblocker.dpdns.org/list` | 点「从云端更新名单」（无自动定时） | GET，仅 `type=white\|black`、时间戳与只读 `X-API-Key`；**不上传本地数据** |
| 9b | `raw.githubusercontent.com` 及公共反代 `gh-proxy.com` / `ghfast.top` / `ghproxy.net` / `ghfile.geekertao.top` / `gh.geekertao.top` / `ghproxy.cc` | **仅当第 9 项直连失败（超时 / DNS 不通）时**自动重试，成功一次即停 | 只 GET 公开仓库 `Cloud/whitelist.json.enc` / `blacklist.json.enc`（**密文**）；这些是第三方代理，因此**不带 `X-API-Key`、不带任何本地数据**。反代只能转发、无法解密 |
| 9c | `gitee.com`（`…/raw/main/Cloud/*.json.enc`） | **仅当第 9 项与第 9b 项全部失败时**的最后一次重试（GitHub 域名、raw 与六个公共反代都不通） | 只 GET Gitee 公开仓库里同一份**加密快照**（密文）；**不带 `X-API-Key`、不带任何本地数据**，也不解密服务端任何东西——解密只在本机完成。Gitee 侧可能记录请求 IP |
| 10 | `api.silverfoxblocker.dpdns.org` | 点「发送反馈到作者邮箱」或「发送白/黑名单到作者邮箱」 | POST：反馈正文（≤2000 字）+ 选填联系方式，或仅域名清单；见 [PRIVACY.md](./PRIVACY.md) |
| 11 | `weishi.360.cn` / `baoku.360.cn` / `dl.360safe.com` / `*.huorong.cn` | 点击下载 360 急救箱 / 火绒专杀（先探测版本再下载） | 无 |
| 12 | `devbuilds.s.kaspersky-labs.com` / `adwcleaner.malwarebytes.com` | 点击下载 KVRT / AdwCleaner | 无 |
| 13 | 外链跳转：`wwavz.lanzout.com`（版本更新，提取码 2hxh）、`gitee.com`（版本更新 Gitee 镜像）、`free.lanzoux.com`（SoftcnKiller）、123 云盘、光牙盘、GitHub / GitHub Issues、爱发电 | 用户点击链接，普通新标签页打开 | 扩展不注入参数、不读取页面内容；后续行为受目标站点自身政策约束 |
| 13b | GitHub 全站镜像 `kkgithub.com` / `bgithub.xyz` | 点「前往 GitHub 查看更新」（落点 `…/releases/latest`）且直连 `github.com` 超时（先探测直连，1.5s 不通才改道） | 无。镜像只用来打开同一个更新页（内容与官网一致），不传键值、不传页面数据 |
| 13c | `gh-proxy.com` 反代 `api.github.com` | 直连与镜像**都**不通时，退一步只查「有没有新版」 | 无。GET `releases/latest` 公开信息（版本号 / 日期），4s 超时；不下载安装包、不携带任何本地数据 |
| 13d | `github.com/…/releases/latest`（先 HEAD 后 GET） | 点版本行右侧「检查更新」 | 无。只读 301 后的 `/releases/tag/vX.Y.Z` 版本号；失败依次改道 `api.github.com` → `gh-proxy.com`（同 13c）→ `gitee.com`（同 13e），全程不下载安装包、不上传数据 |
| 13e | `gitee.com`（OpenAPI `/api/v5/repos/…/releases/latest`，失败再读 `…/releases/latest` 的 302 落点） | 「检查更新」在 GitHub 直连、公共反代**都**不通时的最后一级；或用户点「前往 Gitee 查看更新」 | 无。只 GET 公开的发行版元数据（版本号 / 发布日期），5s 超时；不下载安装包、不携带任何本地数据、不带任何键值。Gitee 侧可能记录请求 IP |

### 后端链路（由 Worker 发起，不是扩展）

`GET /list` 由 Worker 先向 `api.github.com` 读取私有仓库里的 `whitelist.json` / `blacklist.json`（依次尝试仓库根目录与 `List/` 两种布局）；GitHub 不通或令牌失效时，自动改用 `gitee.com/api/v5/.../raw/...` 读取同一份文件的 Gitee 私有镜像仓库（依次尝试 `master` / `main` / 仓库默认分支）。时间分配上主源最多占 4.5s、总预算 9s（比扩展侧云端接口 10s 超时短），保证「GitHub 卡死」时备源一定还有时间跑。两个源都读不到、或拿回来的内容不是名单（没有 `domains` 数组）时返回 502 并附逐通道的失败原因，扩展侧据此提示「名单同步失败」，不会把本地名单清空。`POST` 由 Worker 经 `api.brevo.com` 发信到 `feedback@silverfoxblocker.dpdns.org`，再经邮件路由转给作者。**只有 POST**（反馈与名单上报）会走 KV 限流：按「IP + 日期」计数，60 次/天/IP、24 小时过期；Worker 同时开启了调用日志，因此两类请求在服务端都可能留下来源 IP 记录。

> 排查用（两者都要 `X-API-Key`）：
> - `GET /list?type=black&diag=1` 只返回逐通道的尝试结果（哪个源、哪条路径、哪个分支、HTTP 状态、耗时），不返回名单正文。
> - `GET /list?type=black&force=gitee&diag=1` 跳过 GitHub，**只**走 Gitee，用来验证备源是否真的可用；`force=github` 反之。扩展同步永远不带 `force`，线上行为仍是 GitHub 优先、Gitee 兜底。

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
