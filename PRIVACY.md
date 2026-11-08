# 隐私政策 / Privacy Policy

**SilverFoxBlocker**（以下简称「本扩展」）

生效日期：2026-11-06　|　适用版本：v1.0.5

---

## 一、一句话概括

本扩展的**检测、评分、名单比对全部在你的设备上完成**；不建立账号、不收集浏览历史、不向作者或任何分析平台上传数据。只有你**主动开启**的威胁情报源、**主动点击**的急救下载与反馈，才会向第三方发出请求——每一类请求的目标与内容都在下文逐条列出。

---

## 二、本地完成的部分

以下能力运行时**不产生任何网络请求**：

- 页面结构、下载入口、话术特征的采集与加权评分（`rules/analyzer.js`）；
- 官方域名表、恶意域名、可疑 TLD、话术词表等内置特征库（`rules/iocs.js`）；
- 下载拦截、跳转链追踪、拦截浮层与提示；
- 社区黑名单的**比对**（名单下载是一次性的 GET，比对本身全在本地）；
- 防护统计、白名单/黑名单、界面设置。

---

## 三、自动发出的网络请求

### 3.1 默认开启（可在设置页关闭）

**① 域名年龄查询（RDAP）**
为判断站点是否新注册（银狐常用新域名投递），扩展只把**注册域名**（例如 `example.com`，不含路径、参数、页面内容）发给公共 RDAP 服务（`rdap.org` 及各注册局）。不携带任何个人信息。

**② ICP 备案核验**
当页面存在可疑信号、需要判断「是否国内备案站」时，扩展把**域名**发给公开的备案查询接口（`uapis.cn`、`cn.apihz.cn`）。该功能可在「设置 → 检测维度」中关闭，关闭后不会有任何请求。

**③ 页面自身的资源解析**
为识别脚本跳转、内嵌直链、`.txt` 隐藏地址、meta refresh 等伪装投递，扩展会在**你所访问页面的上下文内**，对该页面已引用的资源发起有限的读取（同源或该页面原本就会访问的地址）。这类请求：只用于本地判定；不发往本扩展运营方的服务器；跨域时不携带 Cookie / 登录凭据；不收集、不上传任何信息。

### 3.2 默认关闭（需你手动开启）

| 情报源 | 发出的数据 | 说明 |
|---|---|---|
| VirusTotal | 域名的 base64url 或 URL 的 base64url（作为查询 ID） | 使用你自己的 API Key；不上传页面内容或文件 |
| Google Safe Browsing | **完整页面 URL**（v4 Lookup API 的查询方式） | 使用你自己的 API Key；命中只作「疑似」提示 |
| URLhaus | 域名、当前页面 URL | 公开接口，无需 Key |
| NetAPI | 域名 | 公开接口，无需 Key |

> 提示：上述服务由各自厂商运营，其数据处理受其隐私政策约束。若你在意 URL 外泄，请勿开启 Google Safe Browsing。

### 3.3 社区黑名单更新（默认关闭，需先开总开关）

开启后，扩展会按天（或你点「立即更新」时）从 jsDelivr / fastly / gcore / testingcf / raw.githubusercontent.com / gh-proxy.com 等镜像**下载**公开名单文件（OpenPhish、PhishDestroy、HaGeZi's TIF）。这是单向 GET，**不上传任何内容**，也不包含你的访问记录。

> 曾经存在的「云端官方域名库」（`site-directory-cache.pages.dev`）已于 2026-11-01 完整移除，当前版本不再拉取任何第三方官方站点清单。

---

## 四、由你主动触发的请求

**① 银狐急救下载**
在「银狐急救」页点击下载按钮时，扩展会先访问 360 软件宝库 / 卫士页面探测最新直链，再通过浏览器下载 API 从 `dl.360safe.com`（360 系统急救箱）或 `down7.huorong.cn`（火绒专杀）拉取安装包。请求不含个人信息，扩展也不会执行或读取这些文件。

**② 反馈与建议**
点击「发送」后，反馈正文（以及你选填的联系方式）会 POST 到作者自建的 Cloudflare Worker（`api.silverfoxblocker.dpdns.org`），由它转发邮件。Worker 端仅做「每 IP 每日 60 次」的限流计数，不保存反馈内容到数据库。不填联系方式则完全匿名。

---

## 五、本地存储了什么

| 位置 | 内容 | 说明 |
|---|---|---|
| `chrome.storage.sync` | 开关、权重、灵敏度、白名单、自定义关键词、自定义恶意域名黑名单、界面偏好、情报源配置 | 由浏览器账号同步机制决定是否跨设备同步，**不经过作者服务器** |
| `chrome.storage.sync` | 情报源 API Key | 仅存 **AES-GCM 密文**（含随机 salt / IV），明文只在后台 SW 解密，内容脚本无法读取 |
| `chrome.storage.local` | 防护统计（拦截/告警计数、近期记录）、OpenPhish 域名数组、PhishDestroy 域名文本、名单元数据、自动学习的下载黑名单、连坐域名集合 | 仅本机 |
| IndexedDB（`sfLocalLists`） | HaGeZi TIF 的布隆过滤器位图（约 4.8 MB） | 仅本机；不含明文域名 |
| 内存 | 名单 Set / 位图、评分缓存、情报查询缓存（10 分钟） | 关闭浏览器或 SW 回收即消失 |

**我们收集什么：无。** 不收集浏览历史、书签、Cookie、表单输入、账号凭据，也不收集姓名、邮箱、电话、IP 等可识别个人身份的信息。

---

## 六、远程代码

本扩展**不加载任何远程脚本**。所有检测逻辑、规则与评分引擎都随安装包发布；网络请求只用于取回**数据**（域名清单、情报查询结果、RDAP/ICP 响应），不会 `eval` 或注入远程代码。MV3 的 CSP 同时把可连接域名限制在 `manifest.json` 的 `connect-src` 白名单内。

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
| jsDelivr / GitHub Raw / gh-proxy | 社区名单分发 | 关 |
| Cloudflare（Worker） | 反馈邮件转发 | 需点击 |
| 360 / 火绒官方域名 | 急救工具下载 | 需点击 |

**不接入**任何广告、统计（Analytics）、崩溃上报、热更新或用户画像服务。

---

## 八、权限与用途

| 权限 | 用途 |
|---|---|
| `storage` | 保存设置、统计、名单与名单元数据 |
| `unlimitedStorage` | 社区名单体积超过浏览器默认 10 MB 配额 |
| `downloads` | 取消高危下载；急救工具下载 |
| `webNavigation` | 顶级导航时序（加载即检测）+ 跳转链追踪 |
| `notifications` | 高风险时的系统原生告警 |
| `alarms` | 名单每日自动更新 / 手动更新任务 |
| `<all_urls>` | 在所有 http(s) 页面运行内容脚本；并授权上述网络请求 |
| `web_accessible_resources` | 浮层字体与赞助者名单 |

未申请：`tabs`（仅读当前标签）、`cookies`、`history`、`bookmarks`、`webRequest`、`nativeMessaging`、`scripting`。

---

## 九、你的控制权

- 随时用工具栏弹窗关闭整体防护；
- 「检测维度」里单独关闭 ICP 核验等会联网的检测项；
- 威胁情报 API 与社区黑名单默认关闭，不开启即不会产生对应请求；
- 清空本地统计、删除白名单/黑名单、卸载扩展即清空本地数据；
- 反馈可在不填联系方式的情况下匿名发送，或完全不用。

---

## 十、儿童

本扩展不面向儿童，也不会有意收集儿童信息。

---

## 十一、政策变更

功能（尤其是联网功能）变化时会同步更新本文件与 `README.md` 的「网络请求清单」。重大变更会在扩展「关于」页与本文件中标注生效日期。

---

## English Summary

**SilverFoxBlocker** runs all detection, scoring, and list matching **on your device**. There are no accounts, no analytics, no telemetry, and no upload of browsing history, cookies, credentials, or personal data.

**Automatic requests (on by default, can be disabled):** registrable domain → public RDAP servers (domain age); domain → public ICP lookup services (`uapis.cn`, `cn.apihz.cn`), disableable in settings; limited same-origin resource reads inside the page you are visiting for download discovery.

**Optional requests (off by default, only after you enable the source):** VirusTotal receives base64url domain/URL IDs (your own key); Google Safe Browsing receives the **full page URL** (v4 Lookup, your own key); URLhaus receives the domain and current page URL; NetAPI receives the domain; community blocklists (OpenPhish, PhishDestroy, HaGeZi TIF) are downloaded as one-way GETs from jsDelivr/GitHub mirrors.

**User-initiated only:** the "SilverFox Rescue" download from `dl.360safe.com` / `down7.huorong.cn`, and feedback submissions POSTed to our own Cloudflare Worker.

**Local storage:** settings in `chrome.storage.sync` (API keys stored only as AES-GCM ciphertext); statistics, downloaded blocklists, download blacklist and redirect-chain sets in `chrome.storage.local`; HaGeZi's Bloom-filter bitmap (~4.8 MB) in IndexedDB. Nothing is synced to or uploaded to the author's servers.

**No remote code.** All logic ships inside the package; the MV3 CSP restricts outbound connections to an explicit `connect-src` allowlist. No ads, analytics, crash reporting, or telemetry of any kind.

The extension requests only `storage`, `unlimitedStorage`, `downloads`, `webNavigation`, `notifications`, `alarms`, and `<all_urls>` — each with a concrete function described above. For questions, use the in-extension feedback form or open an issue on GitHub.
