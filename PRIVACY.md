# 隐私政策 / Privacy Policy

**SilverFoxBlocker**（以下简称「本扩展」）

生效日期：2026-11-10　|　适用版本：v1.6.2（本次修订：两个情报源 API Key 均为 AES-GCM 密文存储）

---
## 一、概述

本扩展的**检测、评分、名单比对与拦截全部在你的设备上完成**；不建立账号、不收集浏览历史、不向分析平台上报数据。默认开启的 RDAP / ICP 辅助核验只发送**域名**。除此之外，只有你**主动开启**的威胁情报源 / 社区名单、**主动点击**的云端名单同步、工具下载、反馈与名单上报，才会产生对应的外部请求。

**请特别注意用户主动提交的数据（其中「名单上报」是 v1.6.1 新增）**：点击「发送反馈到作者邮箱」或「发送白/黑名单到作者邮箱」时，你填写的文字会发送到作者自建的后端并通过邮件送达作者，邮件中会包含来源 IP；不点击不会自动发送。完整的请求目标与内容见下文。

---

## 二、本地完成的部分

以下能力运行时**不产生任何外部请求**：

- 页面结构、下载入口、话术特征的采集与加权评分（`rules/analyzer.js`）；
- 官方域名表、恶意域名、可疑 TLD、话术词表等内置特征库（`rules/iocs.js`）；
- **六类名单的查表比对**（云端 / 扩展内置 / 自定义，各有黑、白两份）——包括优先级判断、域名后缀回溯、通配符与「主机名/路径」匹配。云端名单同步是一次性 GET，同步之后的判定全在本地；
- 下载拦截、跳转链追踪、拦截浮层与提示；
- 社区黑名单的比对（名单下载是一次性的 GET，比对本身全在本地）；
- 防护统计、界面设置、配置导入导出；
- 情报查询结果与评分结果的短期内存缓存（10 分钟）；
- API Key 的 AES-GCM 加密 / 解密（`crypto-helper.js`）：在扩展页面与后台 SW 内完成，不联网；两个需 Key 的情报源现在都只以密文落盘。

---

## 三、自动发出的网络请求

### 3.1 默认开启（可在设置页关闭）

**① 域名年龄查询（RDAP）**
为判断站点是否新注册（银狐常用新域名投递），扩展只把**注册域名**（例如 `example.com`，不含路径、参数、页面内容）发给公共 RDAP 服务（`rdap.org` 及各注册局）。不携带任何个人信息。

**② ICP 备案核验**
当页面存在可疑信号、需要判断「是否国内备案站」时，扩展把**域名**发给公开的备案查询接口（`uapis.cn`、`cn.apihz.cn`）。该功能可在「设置 → 检测维度」中关闭，关闭后不会有任何请求。

**③ 页面自身的资源解析**
为识别脚本跳转、内嵌直链、`.txt` 隐藏地址、meta refresh 等伪装投递，扩展会在**你所访问页面的上下文内**，对该页面已引用的资源发起有限的读取（同源或该页面原本就会访问的地址）。这类请求：只用于本地判定；不发往本扩展的运营方；跨域时不携带 Cookie / 登录凭据；不收集、不上传任何信息。

> 命中任意一份名单时会直接短路判定，上述 RDAP / ICP 请求**不会发生**。

### 3.2 默认关闭（需要手动开启）

| 情报源 | 发出的数据 | 说明 |
|---|---|---|
| VirusTotal | 域名的 base64url 或 URL 的 base64url（作为查询 ID） | 使用你自己的 API Key；不上传页面内容或文件 |
| Google Safe Browsing | **完整页面 URL**（v4 Lookup API 的查询方式） | 使用你自己的 API Key；命中只作「疑似」提示 |
| URLhaus | 域名、当前页面 URL | 公开接口，无需 Key |
| NetAPI | 域名 | 公开接口，无需 Key |

> 提示：上述服务由各自厂商运营，其数据处理受其隐私政策约束。若你极度在意 URL 外泄会导致隐私泄露，请勿开启 Google Safe Browsing，也请注意 URLhaus 会收到当前页面 URL。

**社区黑名单更新（默认关闭，需先开总开关）**
开启后，扩展会按天（或手动点击「立即更新」时）从 jsDelivr / fastly / gcore / testingcf / raw.githubusercontent.com / gh-proxy.com 等镜像**下载**公开名单文件（OpenPhish、PhishDestroy、HaGeZi's TIF）。这是单向 GET，**不上传任何内容**，也不包含你的访问记录。

### 3.3 云端黑 / 白名单同步（默认不发请求，需你手动点击）

这是 v1.6.1 新增的、由作者维护的名单，作者会不定时更新，**但浏览器扩展端不会自动定时同步**：只有在「关于」页点击「从云端更新名单」时，扩展才会并行发起两次 GET：

```
https://api.silverfoxblocker.dpdns.org/list?type=white&_=<时间戳>
https://api.silverfoxblocker.dpdns.org/list?type=black&_=<时间戳>
```

- **发出什么**：只有查询参数 `type`、缓存规避用的时间戳，以及一个随扩展分发的只读 `X-API-Key`（用于接口鉴权，**不是你的身份标识**）。**不发送你的浏览记录、本地名单、设置、设备标识或任何个人信息**。
- **收到什么**：作者维护的域名清单（纯数据，不含代码）。Worker 实时从作者的私有 GitHub 仓库读取后转发；GitHub 不可达时改从作者的私有 Gitee 镜像仓库读取同一份文件（此过程完全发生在服务端，你的浏览器不直接访问 Gitee）。响应经清洗校验后整体覆盖写入本机 `storage.local`，任一份失败则两份都不写入。
- **日志**：该 Worker 开启了 Cloudflare 调用日志，因此服务端可能记录请求时间、来源 IP 与请求路径；日志中不含有你填写的内容。
- **备用通道（仅当上述接口不通时）**：会改为从公开 GitHub 仓库（`raw.githubusercontent.com` 及其公共反代）GET 一份**加密快照**（`Cloud/*.json.enc`）。文件本身是密文，只有扩展用内置口令在本机解密后才能得到名单；此请求**不带 `X-API-Key`、不带任何本地数据**，但第三方反代能看到请求方 IP 与所取文件名。解密失败（口令不符 / 文件被篡改）时同步中止，不会把名单清空。

早期上游版本的第三方「云端官方域名库」（`site-directory-cache.pages.dev`）已于 2026-11-01 完整移除，当前版本拉取的是作者自行维护的黑 / 白名单，不含官方站点整库。

---

## 四、由你主动触发的请求

### 4.1 反馈与建议（两个通道）

**① GitHub Issue**：点击「发送反馈到 GitHub Issue」会在新标签页打开项目 Issues 新建页，并把问题类型与正文预填进 URL 的查询参数。这些文字会出现在浏览器地址栏、浏览器历史以及公开的 GitHub Issue 中；请在提交前自行确认内容，不要写账号密码等敏感信息。扩展本身不向第三方表单服务提交数据。

**② 邮件反馈**：点击「发送反馈到作者邮箱」会把 `{ message, contact }` POST 到作者自建的 Cloudflare Worker（`api.silverfoxblocker.dpdns.org`）：

- `message`：问题类型 + 你输入的正文，上限 2000 字符；
- `contact`：你**选填**的联系方式，留空则 Worker 记为「未提供」；
- Worker 通过 Brevo（`api.brevo.com`）把正文、联系方式与**来源 IP**（`CF-Connecting-IP`）写进邮件，发往 `feedback@silverfoxblocker.dpdns.org`，再经邮件路由转交作者。邮件会被邮件服务商与作者邮箱留存；
- Worker 用 Cloudflare KV 保存 `rate_limit_{IP}_{日期}` 的提交次数用于限流（每 IP 每天 60 次，24 小时过期），**不把反馈正文存入数据库**。不填联系方式时内容仍是匿名的，但网络层的 IP 依然会出现在邮件与限流键中。

### 4.2 名单上报（v1.6.1 新增）

在「规则与名单 → 自定义信任域名白名单 / 自定义恶意域名黑名单」页各有一个「发送白/黑名单到作者邮箱」按钮。点击后会：

- **只读取该文本框里的域名**，逐行去空、去重、剥离协议、统一小写，前面加一行「问题类型：自定义白名单 / 自定义黑名单」；
- POST 到与 4.1② 相同的 Worker，复用 `{ message, contact }` 契约，`contact` 为空字符串；
- **不发送**浏览记录、页面 URL、其它设置项、统计、Key 或设备信息；域名过多导致正文超过 2000 字符时会提示分批，不会静默截断；
- 经作者人工复核后，才可能择优并入云端名单；上报不等于立即生效。

> 这些域名是你自己填写的，可能间接反映你常访问或关注的站点。若你不想让作者看到这份清单，**不要点击这两个按钮**——除此之外，本地名单永远不会上传。名单上报与邮件反馈都会在作者侧附带来源 IP。
> 作者承诺不会收集用户的历史记录和IP，也不会以其他方式保留用户提交的涉及用户隐私的内容，但希望用户可以把他们在日常使用中遇到的误报、漏报定期反馈给作者。
> 这有助于改进浏览器扩展的检测规则，作者维护的黑/白名单也得以建立。

### 4.3 工具下载与更新源

全部为**用户点击才发生**，扩展不会自动下载或执行任何文件：

- 360 系统急救箱：先读取 `weishi.360.cn` / `baoku.360.cn` 页面探测最新直链，再由浏览器下载 API 从 `dl.360safe.com` 取回；失败时回退到内置备用直链。
- 火绒专杀（无签名版）：在 `down3 / down7 / update / down2 / down-tencent.huorong.cn` 间用 HEAD / Range 探测版本号，再从对应 CDN 下载。
- KVRT：`devbuilds.s.kaspersky-labs.com` 官方固定直链，始终指向最新版。
- AdwCleaner：`adwcleaner.malwarebytes.com` 官方 release 直链，保存为 `adwcleaner.exe`。
- 上述请求不含个人信息；扩展**不会执行、解压或读取**下载到的文件内容。

**普通外链跳转**（扩展只调用 `chrome.tabs.create` 或 `<a target="_blank" rel="noreferrer">`，不注入参数、不读取目标页内容）：
- 蓝奏云版本更新镜像 `wwavz.lanzout.com/b01gigjayb`（点击时把提取码 `2hxh` 复制到剪贴板）
- Gitee 版本更新镜像 `gitee.com/bbjj12345/SilverFoxBlocker/releases/latest`（国内直连）
- SoftcnKiller 蓝奏云分享页 `free.lanzoux.com`
- 123 云盘 / 迅雷光鸭云盘工具目录
- GitHub 仓库、GitHub Issues
- 爱发电赞助页
- 这些站点有自己的隐私政策与 Cookie；点击后你在其中的行为与本扩展无关。

**「检查更新」按钮（关于页版本行）**：只在点击时发一次请求，不打开任何标签页：

- 优先直连 `https://github.com/bbjj12345/SilverFoxBlocker/releases/latest`（先 HEAD，失败再 GET），从 GitHub 301 后跳转到的 `/releases/tag/vX.Y.Z` 地址里读取版本号；
- 直连不通时改问 `api.github.com` 的 `releases/latest`（公开 JSON）；
- 仍不通时经 `gh-proxy.com` 反代读取同一个公开 JSON；
- 以上都不通时，改为向 `gitee.com` 查询同一发布信息：先读 OpenAPI `api/v5/repos/bbjj12345/SilverFoxBlocker/releases/latest`，失败再读 `…/releases/latest` 的 302 落点地址。Gitee 是国内站点，该请求**不带任何键值、不带任何本地数据**，但 Gitee 侧可能记录请求 IP 与时间。
- 四级通道都只读取**公开的版本号**，不下载安装包、不发送任何本地数据；查询结果仅用于在你本机比对版本，不写入存储、不上报。四级都失败时只提示「查询失败」，不会谎称「无可用更新」。

> 下拉菜单里的「一键上报网站」只是快捷打开「关于」页，本身不发送任何数据。

---

## 五、本地存储了什么

| 位置 | 内容 | 说明 |
|---|---|---|
| `chrome.storage.sync` | 开关、权重、灵敏度、自定义信任域名白名单、自定义恶意域名黑名单、自定义关键词、界面偏好、情报源配置 | 由**浏览器账号**同步机制决定是否跨设备同步，**不经过作者服务器**；卸载扩展后本机副本被清除 |
| `chrome.storage.sync` | VirusTotal / Google Safe Browsing API Key（均为 **AES-GCM 密文**，含随机 salt 与 IV） | 明文只在后台 Service Worker 内短暂解密，内容脚本拿不到；设置页只显示圆点掩码，不回显明文或密文。v1.6.1 及更早版本明文保存的 VT Key 会在打开一次设置页时自动加密迁移（迁移前后台仍兼容明文查询）。两者都只用于向对应厂商鉴权，绝不发给作者 |
| `chrome.storage.local` | 防护统计（拦截/告警计数、近期记录）、OpenPhish 域名数组、PhishDestroy 域名文本、社区名单元数据、自动学习的下载黑名单、连坐域名集合 | 仅本机 |
| `chrome.storage.local` | `sfCloudWhite` / `sfCloudBlack`（云端名单快照）、`sfCloudListMeta`（同步时间、条数、被丢弃条目及原因）、自定义主题与背景 | 仅本机；由你手动同步产生，云端名单不含任何关于你的信息 |
| IndexedDB（`sfLocalLists`） | HaGeZi TIF 的布隆过滤器位图（约 4.8 MB） | 仅本机；不含明文域名 |
| 剪贴板 | 点击蓝奏云更新按钮时写入提取码 `2hxh` | 由浏览器接管，扩展不回读 |
| 内存 | 名单 Set / 位图、评分缓存、情报查询缓存（10 分钟） | 关闭浏览器或 SW 回收即消失 |

**除第四节所述的用户主动提交外，我们收集什么：无。** 不收集浏览历史、书签、Cookie、表单输入、账号凭据，也不收集姓名、邮箱、电话等信息（联系方式一栏完全由你选填）。**唯一的例外是 IP**：点击反馈 / 名单上报时会随邮件与限流计数到达作者侧，云端名单同步与所有 Worker 请求也会在 Cloudflare 调用日志中留下来源 IP；详见第三、四、六节。

---

## 六、远程代码与服务端链路

本扩展**不加载任何远程脚本**。所有检测逻辑、规则与评分引擎都随安装包发布；网络请求只用于取回**数据**（域名清单、情报查询结果、RDAP / ICP 响应），不会 `eval` 或注入远程代码。云端名单在写入前会经过格式清洗（白名单不支持通配、黑名单通配上限 200 条、路径条目上限 500 条），被丢弃的条目与原因在设置页可见。

`manifest.json` 的 CSP 为 `script-src 'self'; object-src 'self'; connect-src 'self' https:; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'`。**需要如实说明**：`connect-src` 允许连接任意 HTTPS 主机，并**没有**做域名级白名单；实际请求目标由代码内的固定清单决定，且默认关闭的项在未开启前不会请求。

服务端链路（由作者侧 Worker 发起）：
`api.github.com`（读取私有仓库的名单 JSON）、`gitee.com/api/v5`（GitHub 不可达时的私有镜像备源）、`api.brevo.com`（代发邮件）、Cloudflare KV（限流计数）与 Cloudflare 调用日志。Worker 不把反馈正文或名单内容写入数据库，但这些内容会留存在邮件服务商与作者邮箱中。

---

## 七、第三方清单

| 第三方 | 用途 | 默认 |
|---|---|---|
| RDAP 注册局 / `rdap.org` | 域名年龄 | 开 |
| `uapis.cn`、`cn.apihz.cn` | ICP 备案核验 | 开（可关） |
| VirusTotal | 域名/URL 信誉 | 关 |
| abuse.ch（URLhaus） | 恶意 URL 情报 | 关 |
| NetAPI | 失陷情报 | 关 |
| Google Safe Browsing | 安全浏览判定 | 关 |
| jsDelivr / GitHub Raw / gh-proxy 等镜像 | 社区名单分发 | 关 |
| Cloudflare（Worker） | 云端名单转发、反馈/名单上报邮件、限流与日志 | 需点击（无自动定时） |
| GitHub（私有仓库 / Issues） | 云端名单内容源、公开反馈 | 需点击 |
| `kkgithub.com` / `bgithub.xyz` / `gh-proxy.com`（GitHub 镜像与反代） | 直连 `github.com` 不通时打开同一更新页；点「检查更新」时作为兜底通道读取版本号 | 需点击 |
| `gitee.com`（版本更新镜像） | 「前往 Gitee 查看更新」跳转；「检查更新」在前几级都不通时读取公开版本号 | 需点击 |
| Brevo | 代发反馈邮件 | 需点击 |
| Kaspersky / Malwarebytes | KVRT / AdwCleaner 官方直链 | 需点击 |
| 360 / 火绒官方域名 | 急救工具版本探测与下载 | 需点击 |
| 蓝奏云 / 123 云盘 / 光牙盘 | 版本更新镜像、工具分享页 | 需点击（外链） |
| 爱发电 | 赞助入口 | 需点击（外链） |

**不接入**任何广告、统计（Analytics）、崩溃上报、热更新、用户画像或遥测服务。

---

## 八、权限与用途

| 权限 | 用途 |
|---|---|
| `storage` | 保存设置、统计、名单与名单元数据、云端名单快照 |
| `unlimitedStorage` | 云端名单 + 社区名单体积超过浏览器默认配额 |
| `downloads` | 取消高危下载；下载 360 / 火绒 / KVRT / AdwCleaner 工具 |
| `webNavigation` | 顶级导航时序（加载即检测）+ 跳转链追踪 |
| `notifications` | 高风险时的系统原生告警 |
| `alarms` | 社区名单每日自动更新 / 手动更新任务（云端名单不使用 alarms） |
| `<all_urls>` | 在所有 http(s) 页面运行内容脚本；并授权上述网络请求 |
| `web_accessible_resources` | 浮层字体与赞助者名单 |

未申请：`tabs`（`tabs.create` / `tabs.sendMessage` 无需该权限）、`cookies`、`history`、`bookmarks`、`webRequest`、`nativeMessaging`、`scripting`。

---

## 九、你的控制权

- 随时用工具栏弹窗关闭整体防护；「检测维度」里单独关闭 ICP 核验等会联网的检测项。
- 威胁情报 API 与社区黑名单默认关闭，不开启即不会产生对应请求；社区名单还有一道总开关，关闭后后台不加载、不更新、不比对并释放内存。
- **云端名单完全由你手动同步**：不主动点击「从云端更新名单」就永远只有本地名单；已同步的快照可随卸载扩展一并清除。
- **名单上报与反馈都是手动按钮**：不会主动上传任何文字；反馈可不填联系方式，也可改用公开的 GitHub Issue。
- 清空本地统计、删除白名单/黑名单、卸载扩展即清空本机数据；`storage.sync` 的跨设备副本由你的浏览器账号管理。
- 工具下载与网盘外链均需要主动点击。

---

## 十、儿童

本扩展不面向儿童，也不会收集儿童信息。

---

## 十一、政策变更

功能（尤其是联网功能）变化时会同步更新本文件与 `README.md` 的「网络请求清单」。重大变更会在扩展「关于」页与本文件中标注生效日期与适用版本。

---

## English Summary

**SilverFoxBlocker v1.6.1** runs all detection, scoring, list matching and blocking **on your device**. There are no accounts, no analytics, no telemetry, and no upload of browsing history, cookies, credentials or page content.

**Automatic requests (on by default, disableable):** registrable domain → public RDAP servers (domain age); domain → public ICP lookup services (`uapis.cn`, `cn.apihz.cn`); limited reads of resources already referenced by the page you are visiting for download discovery. Any list hit short-circuits these lookups.

**Optional requests (off by default):** VirusTotal receives base64url domain/URL IDs; Google Safe Browsing receives the **full page URL** (v4 Lookup). Both use your own API key, stored **only as AES-GCM ciphertext** (`v1.salt.iv.ciphertext`); plaintext exists only briefly inside the background service worker, never in storage or page scripts. URLhaus receives domain + page URL; NetAPI receives the domain; community blocklists (OpenPhish, PhishDestroy, HaGeZi TIF) are downloaded as one-way GETs from jsDelivr/GitHub mirrors. VT keys saved as plaintext by older versions are automatically re-encrypted once you open the options page; until then the background still accepts them.

**Author-maintained cloud allow/block lists (v1.6.1):** no automatic sync. Only when you click "从云端更新名单" are two GETs sent to our Cloudflare Worker (`api.silverfoxblocker.dpdns.org/list?type=white|black`) with a bundled read-only `X-API-Key`. Nothing about you or your device is uploaded. The Worker reads `whitelist.json` / `blacklist.json` from a private GitHub repository (falling back to a private Gitee mirror if GitHub is unreachable, server-side only) and returns plain domain strings, which are validated and stored locally in `chrome.storage.local` (`sfCloudWhite`, `sfCloudBlack`, `sfCloudListMeta`).

**User-initiated uploads:** posting feedback, or clicking "发送白/黑名单到作者邮箱", sends only the text you typed (feedback body + optional contact, or just your domain list; 2000-character cap) to the same Worker, which emails it to the author via Brevo. Those emails include the source **IP**; a Cloudflare KV key (`rate_limit_{IP}_{date}`, 60/day, 24h TTL) is used for rate limiting. Feedback text is not stored in a database, but it is retained by the mail provider and the author's mailbox. Browsing history, page URLs, settings, API keys and statistics are never included. Do not click these buttons if you do not want to share that content.

**Other user-initiated requests:** the version-row "检查更新" button (v1.6.2) reads only the public latest tag — first from `github.com/…/releases/latest` (via the post-redirect URL), then `api.github.com`, then the `gh-proxy.com` mirror — and compares it locally; nothing is uploaded and no installer is downloaded. Also rescue-tool downloads from 360 / Huorong / Kaspersky (KVRT) / Malwarebytes (AdwCleaner) official hosts, plus ordinary external links (Lanzou update mirror with a clipboard-copied extraction code, SoftcnKiller share page, 123pan, GitHub, GitHub Issues, Afdian) opened in new tabs without injected parameters.

**Local storage:** settings and custom lists in `chrome.storage.sync` (browser-account sync only, never via our servers), including the two API keys as AES-GCM ciphertext; statistics, downloaded lists, cloud-list snapshot and metadata in `chrome.storage.local`; HaGeZi's Bloom-filter bitmap (~4.8 MB) in IndexedDB. No remote code is loaded; the MV3 CSP is `script-src 'self'; object-src 'self'; connect-src 'self' https:` — note that `connect-src` **allows any HTTPS host** rather than a domain allowlist, so actual destinations are governed by the fixed list in code.

The extension requests only `storage`, `unlimitedStorage`, `downloads`, `webNavigation`, `notifications`, `alarms`, and `<all_urls>` — each with a concrete function described above. No ads, analytics, crash reporting, or telemetry. For questions, use the in-extension feedback form or open an issue on GitHub.
