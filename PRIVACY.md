# 隐私政策 / Privacy Policy

**SilverFoxBlocker**（以下简称"本扩展"）

生效日期 / Effective Date：2026-10-31（更新至 v1.0）

---

## 一、我们收集什么 / What we collect

本扩展的防护检测**以本地运行为主**：核心判定逻辑、特征库与评分引擎都随扩展打包，在您设备的内容脚本与后台服务中执行。为及时补充官方已知安全站点清单，扩展后台会按需实时拉取云端官方域名库（仅含官方域名清单、不含任何页面内容或用户访问记录）作为辅助；拉取的数据仅驻留在内存中、用完即清，绝不写入本地存储。

我们**不收集、不上传、不传输**您的浏览历史、书签、Cookie、登录凭据、表单输入，以及任何可识别个人身份的信息（姓名、邮箱、电话、IP 地址等）。

除用户主动触发的下载外，本扩展自动发出的网络请求主要包括：

1. **域名年龄查询。** 为判断一个网站是否新注册（银狐木马常使用新域名投递），本扩展仅将网站的**注册域名**（例如 `example.com`，不含路径、参数或页面内容）发送给公共 RDAP / WHOIS 服务器。该请求不包含您的任何个人信息，也不包含所访问页面的任何内容。

2. **资源解析请求。** 为识别经脚本跳转、页面内嵌直链、重定向转发、文本文件内藏匿地址等伪装的钓鱼或木马下载投递，扩展会在您访问的页面上下文内，按需向该网页所引用的资源地址发起有限的网络请求（如脚本内直链、meta refresh 跳转目标、iframe 内嵌资源、重定向目标、同域文本文件等），用于解析其真实指向。此类请求遵循以下原则：仅用于本地风险判定，请求不发往本扩展运营方的服务器；跨站请求不携带您的登录凭据（不发送 Cookie），仅读取资源响应以判断其真实地址；不收集、不上传任何个人信息。

3. **云端官方域名库拉取。** 为及时补充官方已知安全 / 官网域名清单，扩展后台服务会按需向云端官方静态站点实时请求 `official-domains.json`（托管于 Cloudflare Pages）。该请求仅拉取一份公开的官方域名清单，**不包含您访问的任何网址、页面内容或个人身份信息**；返回数据仅驻留内存（Set 结构）用于即时判定，判定完成后即释放，不写入 `storage.local`，也不向该云端回传任何信息。

**另有一次用户主动触发的下载行为。** 在「银狐急救」功能中，当用户点击下载按钮时，扩展通过浏览器标准下载 API 从 360 官方域名 `dl.360safe.com` 拉取 360 系统急救箱压缩包。该请求仅为文件下载、不含任何个人信息，扩展也不会执行或读取该文件内容。

The extension's protection runs primarily on-device: core detection logic, the signature library, and the scoring engine are all bundled and executed in your browser's content scripts and background service. To keep the official known-safe domain list up to date, the extension fetches a cloud-hosted official domain list on demand in the background (it contains only official domain names—no page content or user visit records) as a supplementary reference; the fetched data resides in memory only, is cleared immediately after use, and is never written to local storage.

We do not collect, upload, or transmit your browsing history, bookmarks, cookies, credentials, form inputs, or any personally identifiable information (name, email, phone, IP, etc.). The extension makes two kinds of automatic outbound network requests:

1. **Domain-age lookup.** To judge whether a site is newly registered (a common SilverFox delivery tactic), the extension sends **only the registrable domain** (e.g. `example.com`, without path, query, or page content) to public RDAP/WHOIS servers. This request contains no personal data and no page content.

2. **Resource-resolution requests.** To detect phishing or trojan download delivery disguised through script redirects, in-page direct links, redirect forwarding, or addresses hidden inside text files, the extension may, within the context of the page you are visiting, issue limited network requests to resource URLs referenced by that page (such as script-embedded links, meta-refresh targets, iframe-embedded resources, redirect targets, and same-origin text files) in order to resolve their true destination. These requests follow these principles: they are used only for on-device risk assessment and are not sent to the extension operator's servers; cross-origin requests carry no login credentials (no cookies are sent) and only read the resource response to determine its real address; no personal data is collected or uploaded.

3. **Cloud official-domain-list fetch.** To keep the official known-safe/official domain list current, the extension's background service fetches `official-domains.json` from a cloud-hosted static site (Cloudflare Pages) on demand. This request only retrieves a public list of official domain names; it contains none of the URLs you visit, no page content, and no personal data. The returned data lives only in memory (a Set) for immediate matching, is released right after use, is never written to `storage.local`, and nothing is sent back to that cloud endpoint.

**There is also one user-initiated download.** In the "SilverFox Rescue" feature, when the user clicks the download button, the extension uses the browser's standard download API to fetch the 360 System Rescue Box archive from 360's official domain `dl.360safe.com`. This request is purely a file download carrying no personal data, and the extension does not execute or read the file's contents.

---

## 二、数据存储 / Data storage

- 您的设置通过浏览器本地 `storage` 保存，仅存于本机，不与任何服务器同步。
- 拦截统计仅保存在本地，用于扩展内展示，不上传任何服务器。

Your settings are stored locally via the browser's `storage` API and never synced to any server. Blocking statistics remain on-device and are never uploaded.

---

## 三、远程代码 / Remote code

本扩展**不包含任何远程托管的脚本**。所有检测逻辑、规则与评分引擎都随扩展一并打包，运行时不从网络加载任何可执行脚本。

The extension **does not use any remotely hosted executable scripts**. All detection logic, rules, and the scoring engine are bundled with the package; no executable script is loaded from the network at runtime. 

---

## 四、第三方共享 / Third parties

我们不与任何第三方共享、出售或交易您的个人数据。除上文所述的公共 RDAP 查询、资源解析请求（仅本地读取响应以判定真实地址，不构成数据共享）、后台按需拉取的云端官方域名库（仅取回一份公开官方域名清单、不向该云端回传任何信息）、「银狐急救」中用户主动触发的 急救工具 下载外，本扩展不调用任何第三方服务、广告或分析平台。

We do not share, sell, or trade your personal data with any third party. Apart from the public RDAP lookup, the resource-resolution requests described above (read locally only), the on-demand cloud official-domain-list fetch (retrieves only a public domain list and sends nothing back), the user-initiated download of those rescue tools, the extension calls no third-party services, advertising, or analytics platforms.

---

## 五、用户控制 / Your controls

- 可随时关闭扩展；
- 可将信任的网站加入白名单；
- 可清除本地统计。

You may disable protection globally at any time, add trusted sites to the allowlist, and clear local statistics.
---

## 六、权限说明 / Permissions

本扩展在 `manifest.json` 中仅声明**实际使用**的权限，遵循"最小权限"原则。各权限的用途如下：

- **storage（本地存储）**：保存您的设置（拦截开关、各项权重、白名单）与防护统计、拦截记录，数据仅存于浏览器本地，不与任何服务器同步或上传。
- **downloads（下载管理）**：核心防护能力——后台监听下载事件并取消高危 / 恶意下载；同时用于「银狐急救」中按用户主动点击，从 360 官方域名拉取急救工具压缩包。
- **webNavigation（网页导航）**：监听顶级框架导航，在页面加载瞬间进入"检测中"状态并识别"危险页 → 新域名"跳转链污染，是实时拦截闸门的关键环节。
- **notifications（通知）**：检测到高风险网站或下载时，弹出系统原生告警（相比声音提示更可靠，且无需用户手势解锁）。
- **&lt;all_urls&gt;（主机权限）**：内容脚本需在用户访问的所有 http(s) 页面上运行以做实时检测与拦截；同时为 RDAP 域名年龄查询、官方域名库拉取、360 急救下载等必要的网络请求提供主机授权。

The extension declares **only the permissions it actually uses**, following the principle of least privilege. Their purposes:

- **storage**: stores your settings (blocking toggles, per-dimension weights, allowlist) and on-device statistics; never synced to or uploaded to any server.
- **downloads**: core protection—monitors download events to cancel malicious ones; also used for the user-initiated Rescue download from 360's official domain.
- **webNavigation**: watches top-level navigations to enter "scanning" state on page load and to detect "risky-page → new-domain" redirect-chain pollution—a key part of the real-time blocking gate.
- **notifications**: shows native system alerts when a high-risk site or download is detected.
- **&lt;all_urls&gt; (host permission)**: lets the content script run on all http(s) pages for real-time detection/blocking and authorizes the necessary network requests (RDAP lookup, official-domain fetch, Rescue download).

> 说明：此前 `manifest.json` 中的 `activeTab`、`unlimitedStorage`、`nativeMessaging` 三项因无对应功能实现，已按"最小权限"原则移除。

---

## 七、儿童 / Children

本扩展不面向 儿童，也不故意收集儿童信息。

The extension is not directed to children and does not knowingly collect their information.
