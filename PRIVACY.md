# 隐私政策 / Privacy Policy

**SilverFoxBlocker**（以下简称「本扩展」）

生效日期：2026-11-29　|　适用版本：v1.15.10（本次修订（2026-11-29）分两段：下面这段是 2026-11-28 的完整说明：关于页新增两枚**默认开启**的自动开关——「自动检查更新」（每 6 小时读一次公开版本号）、「自动更新」（每天同步一次云端名单），它们是本扩展**唯一不等你点击**的周期请求，关掉即不再发起，详见 §4.4；（2026-11-29 晚补充：这两项在**浏览器启动时**会按「上次成功时间」补跑一次，**每次打开设置页**也会向后台问一句「到点了没」—— 都是同一道闸门的又一次触发机会，不增加请求次数、不新增权限、不新增第三方、不上送任何字段，只多两个本地时间戳 `sfAutoLastRunVer` / `sfAutoLastRunCloud`；「稍后」改为仅本次页面内记忆，**不再写任何存储**）；v1.14.10 只修了**内置官网表里的一条数据**（希沃白板条目字段错位，已与同品牌另一条合并）和**一句本地控制台日志**（不再对空字段打内容为空的告警）——权限、第三方、网络请求、上送字段、本地存储键**全部没有变化**，判定与拦截结果也不变；下面这段仍是 v1.14.9 起的完整说明。**权限仍是 7 项 API + 1 项主机权限，没有新增存储项，也没有新增任何上送字段；但相对上一份公开版本（v1.13.9），新增了一个第三方 Cloudflare Turnstile（人机验证），反馈接口的鉴权方式也整体换掉了**。这一版把此前文档里 `v1.13.10`–`v1.13.15` 六个**从未合法发布**的版本号所对应的改动全部并入，逐项说明如下。① **反馈接口改为共享密钥 + HMAC-SHA256 签名**：扩展端用内置密钥对「路径 + 毫秒时间戳 + 请求体」算一次签名，放在 `X-SF-Sig` / `X-SF-Ts` 两个请求头里，Worker 用只有服务端知道的 `SECRET_DATA` 复算并比对，时间戳须在 ±5 分钟内。这把密钥随扩展包分发、解包可见（与内置的云端名单 API Key 同一性质），不含任何用户信息，作用只是让没有密钥的脚本与网页无法调用该接口。② **人机验证（Cloudflare Turnstile，服务端开启时）**：点击发送后，扩展会嵌一张由作者 Worker 提供的验证页（`GET /challenge`，同域 `api.silverfoxblocker.dpdns.org`），该页再去加载 Cloudflare 的验证组件；**Cloudflare 因此会看到你的 IP 与常规请求头，但看不到你填的正文与联系方式**（正文要等验证通过后才由扩展单独发出）。通过后得到的凭据单次有效、5 分钟过期，不落盘、不进邮件正文、不写日志。验证过不了（组件加载失败、超时、服务端没配好）时**不再等于发不出去**：请求会带一个布尔标记 `turnstileFallback: true` 走降级通道，每 IP 每天 3 次（作者可配，最高 60），服务端只记一条「降级放行」用于统计。③ **失败提示与诊断**：发送失败时的提示改为固定版式，并按失败阶段分层显示；在**主请求失败、且同址 `HEAD` 探测也不通**时，会额外发**最多一次**公共 DNS-over-HTTPS 查询（`dns.alidns.com`，不通退 `cloudflare-dns.com`，各 2.5 秒），查询对象**只有反馈接口自己的域名**，不带 Cookie、不带标识、不落盘。失败提示里会显示**本机扩展 ID**，该值只渲染在设置页上，不随任何请求外发。④ **服务端 CORS 白名单支持 `*` 通配**（`chrome-extension://*`，默认放行任意扩展来源），被拒的 403 也回显 `Access-Control-Allow-Origin`（只回显 Origin 与 `Vary`，不返回任何名单数据）。这是服务端行为，不影响你的设备。⑤ **`GET /list` 增加 5 分钟缓存**：同一份名单在 5 分钟内被多次请求时，Worker 直接返回缓存副本，不再向 GitHub / Gitee 重复拉取；KV 里存的就是那份**公开名单文件本身**（与云端仓库内容相同），不含 IP、不含扩展 ID、不含任何与你有关的信息，最长留存 24 小时后自动过期，只用于「上游故障时还能把旧副本发给你」。⑥ **人机验证的等待窗口由 12 秒放宽到 30 秒**，第一次超时只显示「点击重试」，最多重试 1 次（合计 60 秒），两次都超时才降级为 3 次/天。**这只是等待时间变长**：请求目标、请求次数与上送内容都没有变化，重试仍然只加载 Cloudflare 的验证组件。⑦ **版本号只认 `manifest.json`**：本文件的「适用版本」与 README 的「当前版本」都跟随它，不再凭记忆或按文档推算。上一版（v1.13.9）：上一版（v1.13.9）：**权限没有增减**，仍为 7 项 API 权限 + 1 项主机权限，没有新增第三方、没有新增网络请求、没有新增数据外发。改动集中在**下载闸门的判定方式**：① 你在「继续下载」时记下的放行条目，从「完整 URL、整个会话、全局有效」改为「`host + path`、10 分钟后失效、只对当时那个标签页生效」，键值只存在**本会话内存**里，不落盘、不上传；② `blob:` / `data:` 形式的下载补上 MIME 与文件名兜底（`application/zip`、`application/x-msdownload` 等），只用于判断「这条下载是否属于高危文件类型」，不读取文件内容、不发起请求；③ 取消下载后复查条目状态，被第三方下载器接走时不再显示「已拦截」。**新增一个本地存储键 `sfDlUnattributed`**：把「走完全部判定却未被任何规则接住」的高危下载记下来（URL、载荷主机、来源、判定等级、发起者扩展 id），**上限 20 条、仅存本机、不上传、不参与任何判定**，只为事后定位「为什么没拦住」；随「清空统计」一并清除。上一版（v1.13.8）：**权限没有增减**，仍为 7 项 API 权限 + 1 项主机权限，也没有新增任何第三方、没有新增任何网络请求、没有新增任何数据外发、没有新增任何存储键。变化只在**本地下载状态的操作方式**：命中分析闸门或「每站首次确认」时，不再 `cancel` + `erase` 之后重新发起一次下载，而是用 `chrome.downloads.pause()` 暂停**同一条**下载、你点「继续下载」时用 `resume()` 续传。全程只操作浏览器下载列表里的状态位，不读取文件内容、不写入新文件、不产生新请求；待确认队列（`storage.session`，关闭浏览器即清空）里多记一个本条下载的数字 id，仍是原有键、不新增存储项。新增的两条页面内提示（「已被下载器接管」「安全检查通过，已继续」）与系统通知上的两个按钮均为本机生成、不外发。上一版（v1.13.7）：**权限没有增减**，仍为 7 项 API 权限 + 1 项主机权限，也没有新增任何第三方、没有新增任何网络请求、没有新增任何数据外发。变化只有一处**本地交互与写入时机**：设置页「社区维护的本地黑名单」里的五个「立即更新」按钮，现在会先把你在这个区块勾选的开关状态（社区名单总开关 + 五份名单的子开关 + HaGeZi 名单版本，共 6 个键）写入 `chrome.storage.sync`，再发起抓取——等价于点一次「保存设置」，但只写这 6 个键，不触碰白名单、自定义名单、评分权重、外观等任何其它设置，也不是新增的存储项（这 6 个键本来就在设置里）；不点这个按钮就不会有任何写入。数据仍然只存在浏览器本地，不上传、不外发。上一版（v1.13.6）的变化在**本地域名仿冒的评分规则**：把仿冒检测拆成「精确匹配」与「重排 / 插字 / 分片拼接变体」两条独立判定线（取最高分并短路，变体分支没有独立开关、随「域名仿冒」维度），新增「数字形近」判定（把域名里的数字当作字母的多种读法，只有与品牌词等长且非数字位逐字相同才命中），并修掉四个既有判定缺陷（形近折叠吃掉数字、剥词缀的严格比较、typo 结构护栏造成的漏检、窗口拼接对「品牌词 + 站点性质词」的误伤）；缓存淘汰由「整表清空」改为 LRU 单条淘汰；仿冒判定对「通用行业缩写 + 裸域」（如 erp.com）不再计分；并适配 ICP 备案查询接口的改版（「无备案」由 200 文案改为 HTTP 404）与应答延迟差异（有备案约 200ms、无备案要 8~10 秒），查询改为两个原有接口对冲并发、权威结论可能晚于首屏判定到达；仍然只查原来那两个公共接口，没有新增请求目标、没有新增任何存储。以上全部只读内容脚本**已经在读取**的域名与页面内容，不新增外部请求、不新增存储项。另修正三处**本地评分误报**（下载文件名里的 `.msi` 扩展名被当作品牌词、路径段 `android` 被当作品牌词、`office` 作为通用名词参与拼接判定），只调整判定规则，不涉及任何新的数据采集、请求或存储。「发送反馈到作者邮箱 / 名单上报」在**失败后**会额外向同一接口发一次 `HEAD` 探测（用于区分「网络不通」与「跨域被拒」），只在失败时发生、无请求体、不新增目标地址；失败提示里会显示**本机扩展 ID**，该值只渲染在设置页上，不会随任何请求外发。上一版（v1.12.6）新增的 8 个「诱导下载 / 灰产推广」维度与 v1.11.6 引入的三层「例外」放行层语义均不变，见 §3.3）

**2026-11-29 补充**：关于页新增第三枚开关「**检查到更新时发送系统通知**」（**默认关闭**，`storage.sync.notifyOnUpdate`）。它只控制本机的一条系统提醒（`chrome.notifications`，用的是原本就有的 `notifications` 权限），**不发起任何请求、不上送任何字段、不新增权限、不新增第三方**；同一版本只提醒一次（`storage.local.sfNotifiedVersion`），点通知只打开本机「关于」页。同日还修了一处**纯本地**的显示问题：扩展重载 / 浏览器重启后，工具栏的「新」字红点会按 `sfAutoUpdate` 里缓存的版本号自动还原（只读本地，不联网）。详见 §4.4 与 §5。

---
## 一、概述

本扩展的**检测、评分、名单比对与拦截全部在你的设备上完成**；不建立账号、不收集浏览历史、不向分析平台上报数据。默认开启的 RDAP / ICP 辅助核验只发送**域名**；「解析器跟随」只在**已被判危**的页面上、用一个不激活的后台标签页重访该页自己的跳转端点（见 3.1④）。除此之外，只有你**主动开启**的威胁情报源 / 社区名单、**主动点击**的云端名单同步、工具下载、反馈与名单上报，才会产生对应的外部请求。

**请特别注意用户主动提交的数据（「名单上报」自 v1.6.1 起提供，未改动其数据范围）**：点击「发送反馈到作者邮箱」或「发送白/黑名单到作者邮箱」时，你填写的文字会发送到作者自建的后端并通过邮件送达作者，邮件中会包含来源 IP；不点击不会自动发送。完整的请求目标与内容见下文。

---

## 二、本地完成的部分

以下能力运行时**不产生任何外部请求**：

- 页面结构、下载入口、话术特征的采集与加权评分（`rules/analyzer.js`）；
- 官方域名表、恶意域名、可疑 TLD、话术词表等内置特征库（`rules/iocs.js`）；
- **六类名单的查表比对**（云端 / 扩展内置 / 自定义，各有黑、白两份）——包括优先级判断、域名后缀回溯、通配符与「主机名/路径」匹配。云端名单同步是一次性 GET，同步之后的判定全在本地；
- **三层「例外」的查表比对**（2026-11-23 起：云端 / 扩展内置 / 自定义）——用来把被名单误伤的站点放回来，规则同样是纯字符串、纯本地比对。自定义例外只写在本机（`storage.local` 的 `exceptionDomains`），云端例外随 `whitelist.json` 的 `exceptions` 字段一次取回（见 §3.3），内置例外随扩展打包；
- 下载拦截、跳转链追踪、拦截浮层与提示；
- **下载授权与「用户手势」判定**（2026-11-23 起）：内容脚本在你真实点击 / 回车时向本扩展后台发一条消息（只含「发生了一次点击」的时间戳，以及被点元素上的链接地址、主机名、文件名——用于判断这次下载是不是你点的），后台只在内存 / `storage.session` 里做比对，**不写日志、不上传、不落盘**；页面脚本用 `a.click()` 合成的事件不算手势；
- **「每站首次确认」名单**（2026-11-23 起）：只在本机记「哪些站点的第一次可执行文件下载已经问过」，见第五节；
- 判定为「用户意图」而放行时的左下角轻提示（纯本地 UI，10 秒自动关闭）；
- 社区黑名单的比对（名单下载是一次性的 GET，比对本身全在本地）；
- 防护统计、界面设置、配置导入导出；
- 情报查询结果与评分结果的短期内存缓存（10 分钟）；
- API Key 的 AES-GCM 加密 / 解密（`crypto-helper.js`）：在扩展页面与后台 SW 内完成，不联网；三个需 Key 的情报源（VirusTotal / Google Safe Browsing / FoxAPI）现在都只以密文落盘。

---

## 三、自动发出的网络请求

### 3.1 默认开启（可在设置页关闭）

**① 域名年龄查询（RDAP）**
为判断站点是否新注册（银狐常用新域名投递），扩展只把**注册域名**（例如 `example.com`，不含路径、参数、页面内容）发给公共 RDAP 服务（`rdap.org` 及各注册局）。不携带任何个人信息。

**② ICP 备案核验**
当页面存在可疑信号、需要判断「是否国内备案站」时，扩展把**域名**发给公开的备案查询接口（`uapis.cn`、`cn.apihz.cn`）。该功能可在「设置 → 检测维度」中关闭，关闭后不会有任何请求。

**③ 页面自身的资源解析**
为识别脚本跳转、内嵌直链、`.txt` 隐藏地址、meta refresh 等伪装投递，扩展会在**你所访问页面的上下文内**，对该页面已引用的资源发起有限的读取（同源或该页面原本就会访问的地址）。这类请求：只用于本地判定；不发往本扩展的运营方；跨域时不携带 Cookie / 登录凭据；不收集、不上传任何信息。

**④ 解析器跟随（「运行时取链探测」，2026-11-20 起，仅对已判危页面，可在设置中关闭）**
银狐常见的投递方式是「同源跳转端点」：页面上的下载按钮指向本站一个 `/go/`、`download.php?id=…` 之类的地址，真正的载荷域藏在它的 302 跳转里，DOM 上看不到、hover 也看不到。为验证这类端点，扩展会在**已判定为危险、且下载入口已被禁用**的页面上，用一个**不激活的后台标签页**重新打开该端点（每页最多 2 个、5 秒超时、同一地址 1 分钟内只探一次），只观察它最终跳到哪个域名、请求了哪些文件，命中后写入本机「自动学习下载黑名单」。

- **没有新增任何第三方**：请求发往的仍是**该页面自己（同注册域）**的地址，与你自己点一下那个按钮等价；若它跳转到别的域名，那个域名收到的也只是一次普通页面 / 文件请求，扩展不额外附带参数、标识或本地数据。
- **扩展不上传任何东西**：结果只写进本机 `chrome.storage.local`，不发给作者，也不进任何请求体。
- **可关闭**：在「设置 → 拦截行为」关掉「运行时取链探测」后，不再创建任何后台标签页、不再发生这类请求（内容脚本与后台各判一次该开关）。

> 命中任意一份名单时会直接短路判定，上述 RDAP / ICP 请求**不会发生**；④ 只在页面**已判危**之后才触发，关掉「运行时取链探测」开关即完全停止。

### 3.2 默认关闭（需要手动开启）

| 情报源 | 发出的数据 | 说明 |
|---|---|---|
| VirusTotal | 域名的 base64url 或 URL 的 base64url（作为查询 ID） | 使用你自己的 API Key；不上传页面内容或文件 |
| Google Safe Browsing | **完整页面 URL**（v4 Lookup API 的查询方式） | 使用你自己的 API Key；命中只作「疑似」提示 |
| URLhaus | 域名、当前页面 URL | 公开接口，无需 Key |
| NetAPI | 域名 | 公开接口，无需 Key |
| 银狐防护云端名单（FoxAPI） | 域名（`/v1/domain/lookup`） | 使用你自己的 API Key；合作者 Yinbo 维护的云端官网/信任名单。**不显示横幅**，只用于本地评分：`official:false` 时 +45 分，`official:true` 时不影响本地判断。扩展侧每秒最多 1 次、单域名缓存 10 分钟，只取回 `official / matched / source` |

> 提示：上述服务由各自厂商运营，其数据处理受其隐私政策约束。若你极度在意 URL 外泄会导致隐私泄露，请勿开启 Google Safe Browsing，也请注意 URLhaus 会收到当前页面 URL。

**社区黑名单更新（默认关闭，需先开总开关）**
开启后，扩展会按天（或手动点击「立即更新」时）从 jsDelivr / fastly / gcore / testingcf / raw.githubusercontent.com / gh-proxy.com 等镜像**下载**公开名单文件（OpenPhish、PhishDestroy、HaGeZi's TIF、uBlock Origin - Badware risks、Dandelion Sprout's Anti-Malware List）。这是单向 GET，**不上传任何内容**，也不包含你的访问记录。

点击某份名单的「立即更新」时，扩展会**先**把本区块的开关状态（总开关 + 五份名单子开关 + HaGeZi 名单版本共 6 个键）写入 `chrome.storage.sync`，再发起下载——等价于点一次「保存设置」，但只写这 6 个键，不触碰白名单、自定义名单、权重与外观，也不会因此产生任何额外请求。

### 3.3 云端黑 / 白名单同步（默认不发请求，需你手动点击）

这是由作者维护的名单（v1.6.1 起提供，v1.7.2 增加 Gitee 兜底通道），作者会不定时更新，**但浏览器扩展端不会自动定时同步**：只有在「关于」页点击「从云端更新名单」时，扩展才会并行发起两次 GET：

```
https://api.silverfoxblocker.dpdns.org/list?type=white&_=<时间戳>
https://api.silverfoxblocker.dpdns.org/list?type=black&_=<时间戳>
```

- **发出什么**：只有查询参数 `type`、缓存规避用的时间戳，以及一个随扩展分发的只读 `X-API-Key`（用于接口鉴权，**不是你的身份标识**）。**不发送你的浏览记录、本地名单、设置、设备标识或任何个人信息**。
- **收到什么**：作者维护的域名清单（纯数据，不含代码）。自 2026-11-12 起，白名单文件还可附带一份「品牌词 → 正确官网」映射（`correct_sites`），同样是纯数据，仅用于拦截浮层的「访问正确的页面」按钮，不参与放行 / 拦截判定；自 2026-11-23 起，白名单文件还可附带一份 exceptions（云端例外：可推翻云端黑名单的放行规则），同样是纯域名数据，在本地参与放行判定。Worker 实时从作者的私有 GitHub 仓库读取后转发；GitHub 不可达时改从作者的私有 Gitee 镜像仓库读取同一份文件（此过程完全发生在服务端，你的浏览器不直接访问 Gitee）。响应经清洗校验后整体覆盖写入本机 `storage.local`，任一份失败则两份都不写入。
- **日志**：该 Worker 开启了 Cloudflare 调用日志，因此服务端可能记录请求时间、来源 IP 与请求路径；日志中不含有你填写的内容。
- **备用通道（仅当上述接口不通时）**：会改为从公开仓库（GitHub 的 `raw.githubusercontent.com` 及其公共反代；都失败时再改用 `gitee.com` 上的同一份文件）GET 一份**加密快照**（`Cloud/*.json.enc`），顺序上始终是「GitHub 优先、Gitee 兜底」。文件本身是密文，只有扩展用内置口令在本机解密后才能得到名单；此请求**不带 `X-API-Key`、不带任何本地数据**，但第三方反代能看到请求方 IP 与所取文件名。解密失败（口令不符 / 文件被篡改）时同步中止，不会把名单清空。

早期上游版本的第三方「云端官方域名库」（`site-directory-cache.pages.dev`）已于 2026-11-01 完整移除，当前版本拉取的是作者自行维护的黑 / 白名单，不含官方站点整库。

---

### 3.4 「访问正确的页面」按钮（点击后也不联网）

拦截浮层上的「访问正确的页面」按钮**不发起任何网络请求**：扩展在本机用「品牌词 → 官网」映射表（内置 `rules/iocs.js` 的 `CORRECT_SITE_CATALOG`，加上云端白名单同步下来的 `correct_sites`）从被拦主机名推断品牌，然后**打开扩展自带的说明页**（`ui/no-correct-site.html`），在页面上列出该品牌全部已收录的官方入口（自 2026-11-18 起不再直接跳转：一个品牌常有多个官网，直接挑一个跳等于替用户做选择；说明页读到的是同一份本地数据，同样不联网）；一条都没收录时，说明页显示「暂未收录」与反馈入口。整个判断在本地完成，不向作者、也不向任何第三方发送被拦域名或其它数据——之后发生的只是你浏览一个普通网页，与直接输入网址没有区别。

---

## 四、由你主动触发的请求

### 4.1 反馈与建议（三个通道）

**① GitHub Issue**：点击「发送反馈到 GitHub Issue」会在新标签页打开项目 Issues 新建页，并把问题类型与正文预填进 URL 的查询参数。这些文字会出现在浏览器地址栏、浏览器历史以及公开的 GitHub Issue 中；请在提交前自行确认内容，不要写账号密码等敏感信息。为防预填参数被浏览器或平台拦掉时丢内容，扩展在点击的同一瞬间把这段文字写入**本机剪贴板**——这是本地操作，不上传、不落盘、不读取剪贴板里的任何旧内容；提示语会告诉你「若标题/正文为空，直接粘贴即可」。扩展本身不向第三方表单服务提交数据。

**①b Gitee Issue（2026-11-28 新增）**：点击「发送反馈到 Gitee Issue」会在新标签页打开 Gitee 上同名仓库的 Issues 新建页，同样把问题类型与正文预填进 URL 的查询参数。Gitee 的新建页要求登录，未登录会先跳到登录页、登录后再跳回；剪贴板兜底与 ① 完全相同（点击时把标题与正文写入本机剪贴板，不上传、不落盘、不回读）。提交后内容会公开在 Gitee Issue 中，同样会留在地址栏与浏览器历史里。

**② 邮件反馈**：点击「发送反馈到作者邮箱」会把 `{ message, contact }` POST 到作者自建的 Cloudflare Worker（`api.silverfoxblocker.dpdns.org`）：

- `message`：问题类型 + 你输入的正文，上限 2000 字符；
- `contact`：你**选填**的联系方式，留空则 Worker 记为「未提供」；
- Worker 通过 Brevo（`api.brevo.com`）把正文、联系方式与**来源 IP**（`CF-Connecting-IP`）写进邮件，发往 `feedback@silverfoxblocker.dpdns.org`，再经邮件路由转交作者。邮件会被邮件服务商与作者邮箱留存；
- Worker 用 Cloudflare KV 保存 `rate_limit_{IP}_{日期}` 的提交次数用于限流（每 IP 每天 60 次，24 小时过期），**不把反馈正文存入数据库**。不填联系方式时内容仍是匿名的，但网络层的 IP 依然会出现在邮件与限流键中。
- **人机验证（v1.14.9 起，服务端开启时）**：发送前会先在你点击的位置嵌一张由 Worker 提供的验证页（`GET /challenge`），页面只加载 Cloudflare Turnstile 的官方组件。你在组件里完成的验证由 Cloudflare 判定，它能看到你的 IP 与常规请求头，但**看不到你填写的正文与联系方式**（这些要等验证通过后才由扩展单独发出）。验证凭据（token）随反馈提交给 Worker 并由 Worker 调 `siteverify` 核对，**单次有效、5 分钟后过期**，不写入数据库、不进入邮件正文。验证页在完成或失败后立即从页面移除；不点发送就不会创建它。服务端未开启时这一步完全不存在。

### 4.2 名单上报（v1.6.1 起提供）

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
- Gitee 仓库镜像 `gitee.com/bbjj12345/SilverFoxBlocker`（「关于」页的隐私政策与项目仓库两行各附一条，内容与 GitHub 相同、仅域名不同）
- SoftcnKiller 蓝奏云分享页 `free.lanzoux.com`
- 123 云盘 / 迅雷光鸭云盘工具目录
- GitHub 仓库、GitHub Issues、Gitee 仓库与 Gitee Issues
- 爱发电赞助页
- 这些站点有自己的隐私政策与 Cookie；点击后你在其中的行为与本扩展无关。

**「检查更新」按钮（关于页版本行）**：只在点击时发一次请求，不打开任何标签页：

- 优先直连 `https://github.com/bbjj12345/SilverFoxBlocker/releases/latest`（先 HEAD，失败再 GET），从 GitHub 301 后跳转到的 `/releases/tag/vX.Y.Z` 地址里读取版本号；
- 直连不通时改问 `api.github.com` 的 `releases/latest`（公开 JSON）；
- 仍不通时经 `gh-proxy.com` 反代读取同一个公开 JSON；
- 以上都不通时，改为向 `gitee.com` 查询同一发布信息：先读 OpenAPI `api/v5/repos/bbjj12345/SilverFoxBlocker/releases/latest`，失败再读 `…/releases/latest` 的 302 落点地址。Gitee 是国内站点，该请求**不带任何键值、不带任何本地数据**，但 Gitee 侧可能记录请求 IP 与时间。
- 四级通道都只读取**公开的版本号**，不下载安装包、不发送任何本地数据；查询结果仅用于在你本机比对版本，不写入存储、不上报。四级都失败时只提示「查询失败」，不会谎称「无可用更新」。

> 下拉菜单里的「一键上报网站」只是快捷打开「关于」页，本身不发送任何数据。

### 4.4 自动检查更新 / 自动更新云端名单（2026-11-28 新增，默认开启；系统通知开关 2026-11-29 新增，默认关闭）

这是本扩展**唯一会不等你点击、自己发起的周期性请求**，因此在「关于」页给了两枚开关（都可以随时关掉，关掉后只剩上面那些手动按钮的行为）：

- **自动检查更新**（开关名「自动检查更新」，默认开，每 6 小时一次）：用 `GET https://api.github.com/repos/bbjj12345/SilverFoxBlocker/releases/latest` 读公开的 `tag_name`，与本机 `manifest.json` 的版本号比对。**只读取公开版本号**：不上传任何本地数据、不带任何键值、不下载安装包。GitHub 侧能看到你的 IP 与请求时间。发现新版本时，仅在工具栏图标上显示一个「新」字并更新图标提示文字，同时在 `chrome.storage.local.sfAutoUpdate` 记一条 `{时间, 最新版本号, 本机版本号, 是否更新}`，供「关于」页显示一行提示并弹出「发现新版本」窗（与手动「检查更新」共用同一个窗）；按「稍后」**不写任何存储**（2026-11-29 晚起改为仅本次页面加载内记忆，刷新即忘；此前写入的 `sfUpdatePopupDismissed` 旧值不再被读取，也不影响判定）。不会自动安装、不会打开任何页面。**浏览器启动时若距上次成功检查已超过周期的 90%，会先补跑一次**（`chrome.runtime.onStartup` / `onInstalled` 触发，目标、内容与周期内那次完全相同，失败则下个周期继续补）。**打开设置页时**，页面会向后台问一句「到点了没」（内部消息，不联网）：没到点直接跳过，到点才走上面这次请求 —— 因此多开几个设置页不会增加请求次数。页面同时会显示约 0.5~2.2 秒的「正在检查更新……」提示条与一层只拦截鼠标的透明挡板，纯本地渲染，不上送任何内容。
- **检查到更新时发送系统通知**（开关名「检查到更新时发送系统通知」，**默认关闭**，2026-11-29 新增）：这是一个纯本地的提醒开关，**不发起任何请求、不增加任何上送字段**。打开后，只要查到比当前更新的版本（后台自动检查那一轮，或你手动点「检查更新」），就由 `chrome.notifications` 在本机弹一条 Windows 系统通知（标题为最新版本号、正文为当前版本号，带一个「查看更新」按钮）；点通知或按钮只会打开本机的「关于」页并高亮「版本更新」一行，不联网、不跳转第三方。**同一版本只提醒一次**：已提醒过的版本号记在 `chrome.storage.local.sfNotifiedVersion` 里，之后每 6 小时的检查不会重复打扰你；装上该版本后这条记录自然失效。关掉开关后一条通知都不会弹，也不读写 `sfNotifiedVersion`。
- **自动更新云端名单**（开关名「自动更新」，默认开，每 24 小时一次）：用 `GET https://api.silverfoxblocker.dpdns.org/list?type=white|black` 拉取与手动同步**完全相同**的两份公开名单（请求头带内置的 `X-API-Key`，与手动同步同一把密钥，随扩展包分发、不含任何用户信息），写入 `chrome.storage.local` 的 `sfCloudWhite` / `sfCloudBlack` / `sfCloudCorrect` / `sfCloudException` 与同步元数据 `sfCloudListMeta`（多一个 `auto: true` 标记）。请求经 Cloudflare，因此 Cloudflare 调用日志里会有来源 IP，与手动同步时完全一样；名单本身是公开数据，不含任何关于你的信息。**失败就整轮跳过**（两份名单同时成功才写盘，不会出现半新半旧），下个周期再试。
- 三枚开关的状态存在 `chrome.storage.sync` 的 `autoCheckUpdate` / `autoCloudUpdate` / `notifyOnUpdate` 三个布尔键里（前两枚默认 `true`、第三枚默认 `false`，老版本升级后没有对应键时按默认值处理）；关掉开关时后台闹钟只是空转一次就返回，不产生任何网络请求，也没有残留的定时任务被删除——重新打开即刻恢复。**工具栏「新」字徽标**在扩展重载 / 浏览器重启后会自动按 `sfAutoUpdate` 里缓存的版本号重新点亮（纯本地读取，不联网）。
- 这两个周期都从扩展安装 / 浏览器启动后开始计时（分别延迟 2 分钟与 5 分钟首次执行），周期本身写在 `chrome.alarms` 里，由浏览器调度；浏览器关闭时不运行。手动点「检查更新」「从云端更新名单」的行为、请求目标与频率都不受这两个开关影响。

---

## 五、本地存储了什么

| 位置 | 内容 | 说明 |
|---|---|---|
| `chrome.storage.sync` | 开关、权重、灵敏度、自定义关键词、界面偏好、情报源配置 | 由**浏览器账号**同步机制决定是否跨设备同步，**不经过作者服务器**；卸载扩展后本机副本被清除 |
| `chrome.storage.sync` | VirusTotal / Google Safe Browsing / FoxAPI 的 API Key（均为 **AES-GCM 密文**，含随机 salt 与 IV） | 明文只在后台 Service Worker 内短暂解密，内容脚本拿不到；设置页只显示圆点掩码，不回显明文或密文。v1.6.1 及更早版本明文保存的 VT Key 会在打开一次设置页时自动加密迁移（迁移前后台仍兼容明文查询）。三者都只用于向对应服务鉴权，绝不发给作者 |
| `chrome.storage.local` | 防护统计（拦截/告警计数、近期记录）、OpenPhish 域名数组、PhishDestroy 域名文本、社区名单元数据、自动学习的下载黑名单（含在已判危页面上静态嗅探到的载荷域；共享对象存储只记桶级主机名）、连坐域名集合、自定义例外名单（exceptionDomains） | 仅本机 |
| `chrome.storage.local` | `sfDlUnattributed`：未被任何规则接住的高危下载诊断记录（URL、载荷主机、来源、判定等级、发起者扩展 id） | 仅本机、**最多 20 条**、不上传、不参与任何判定；用于事后定位「为什么没拦住」，随「清空统计」一并清除 |
| `chrome.storage.local` | 「每站首次确认」名单 `sfSiteFirstSeen`：注册域名 + 最近一次确认时间 | 仅本机。只用来决定「该站这次下载是否要先问一次」，**不含链接、文件名或访问记录**；180 天未再确认自动失效，最多保留 2000 条 |
| `chrome.storage.session` | 页面级下载授权、「强手势」时间戳（最多 12 条、只留 10 秒内的）、待确认下载队列（含那条下载的数字 id，用于「继续下载」时续传同一条）、本会话的危险标签页 | 存在浏览器的**会话存储**里，关闭浏览器即清空，不落盘、不跨设备、不上传 |
| `chrome.storage.local` | 自定义信任域名白名单 / 自定义恶意域名黑名单（2026-11-12 起以本地为准） | `storage.sync` 单键上限 8KB（约 550 个域名），超出会**静默写入失败**，故名单改存本地；体积小于 8KB 时仍镜像一份到 sync 以保留跨设备同步，超过则只存本机 |
| `chrome.storage.local` | `sfCloudWhite` / `sfCloudBlack`（云端名单快照）、`sfCloudListMeta`（同步时间、条数、被丢弃条目及原因）、自定义主题与背景 | 仅本机；由你手动同步产生，云端名单不含任何关于你的信息 |
| `chrome.storage.local` | `sfUpdatePopupDismissed`：旧版「稍后」记录（2026-11-29 起写入，同日晚起**不再写入也不再读取**） | 仅本机、只是一个版本字符串；旧值可留可删，不参与任何判定，不含时间、URL 或任何浏览信息 |
| `chrome.storage.local` | `sfAutoLastRunVer` / `sfAutoLastRunCloud`：上一轮自动检查 / 自动同步**成功**的毫秒时间戳（2026-11-29 晚起） | 仅本机两个数字；用于「浏览器启动时是否该补跑一次」的判断，不含任何浏览信息 |
| `chrome.storage.sync` | `notifyOnUpdate`：「检查到更新时发送系统通知」开关（2026-11-29 起，默认 `false`） | 仅一个布尔值；纯本地提醒，不发起任何请求 |
| `chrome.storage.local` | `sfNotifiedVersion`：已经弹过系统通知的版本号（2026-11-29 起） | 仅本机一个版本字符串；唯一用途是「同一版本不重复打扰」，不上传、不参与任何判定 |
| IndexedDB（`sfLocalLists`） | 三份布隆过滤器位图：HaGeZi TIF（约 4.8 MB）、uBlock Badware（约 7 KB）、Dandelion Sprout（约 24 KB） | 仅本机；不含明文域名，离线无法还原名单 |
| 剪贴板 | 点击蓝奏云更新按钮时写入提取码 `2hxh`；点击「发送反馈到 GitHub Issue」/「发送反馈到 Gitee Issue」时写入该条反馈的标题与正文 | 由浏览器接管，扩展不回读 |
| 内存 | 名单 Set / 位图、评分缓存、情报查询缓存（10 分钟） | 关闭浏览器或 SW 回收即消失 |

**除第四节所述的用户主动提交外，我们收集什么：无。** 不收集浏览历史、书签、Cookie、表单输入、账号凭据，也不收集姓名、邮箱、电话等信息（联系方式一栏完全由你选填）。**唯一的例外是 IP**：点击反馈 / 名单上报时会随邮件与限流计数到达作者侧，云端名单同步与所有 Worker 请求也会在 Cloudflare 调用日志中留下来源 IP；详见第三、四、六节。

---

## 六、远程代码与服务端链路

本扩展**不加载任何远程脚本**。所有检测逻辑、规则与评分引擎都随安装包发布；网络请求只用于取回**数据**（域名清单、情报查询结果、RDAP / ICP 响应），不会 `eval` 或注入远程代码。云端名单在写入前会经过格式清洗（黑白名单都允许通配，但 `*` 不跨标签、TLD 位禁通配；通配与路径条目均不设条数上限），被丢弃的条目与原因在设置页可见。

`manifest.json` 的 CSP 为 `script-src 'self'; object-src 'self'; connect-src 'self' https:; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'`。**需要如实说明**：`connect-src` 允许连接任意 HTTPS 主机，并**没有**做域名级白名单；实际请求目标由代码内的固定清单决定，且默认关闭的项在未开启前不会请求。

服务端链路（由作者侧 Worker 发起）：
`api.github.com`（读取私有仓库的名单 JSON）、`gitee.com/api/v5`（GitHub 不可达时的私有镜像备源）、`api.brevo.com`（代发邮件）、Cloudflare KV（限流计数）与 Cloudflare 调用日志。Worker 不把反馈正文写入数据库；名单文件会在 KV 里缓存最多 24 小时（v1.14.9 起，仅为减少对上游的重复拉取，内容就是那份公开名单本身）。这些内容会留存在邮件服务商与作者邮箱中。

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
| 银狐防护云端名单（FoxAPI） | 云端官网/信任名单判据（不成横幅，只影响评分） | 关 |
| jsDelivr / GitHub Raw / gh-proxy 等镜像 | 社区名单分发 | 关 |
| Cloudflare（Worker） | 云端名单转发、反馈/名单上报邮件、限流与日志 | 需点击（无自动定时） |
| Cloudflare Turnstile（`challenges.cloudflare.com`） | 反馈/名单上报前的人机验证：挑战页加载其验证组件，Worker 调 `siteverify` 核对凭据。**只在你点击发送后发生，且不携带你填写的任何内容**；Cloudflare 会看到你的 IP 与常规请求头 | 服务端开启时生效（作者可关，关掉即退回纯签名） |
| GitHub（私有仓库 / Issues） | 云端名单内容源、公开反馈 | 需点击 |
| `kkgithub.com` / `bgithub.xyz` / `gh-proxy.com`（GitHub 镜像与反代） | 直连 `github.com` 不通时打开同一更新页；点「检查更新」时作为兜底通道读取版本号 | 需点击 |
| `gitee.com`（版本更新镜像、公开仓库加密快照） | 「前往 Gitee 查看更新」跳转；「检查更新」在前几级都不通时读取公开版本号；「从云端更新名单」在 GitHub 与公共反代全部失败时取 `Cloud/*.json.enc` 密文（仅本机解密） | 需点击 |
| Brevo | 代发反馈邮件 | 需点击 |
| Kaspersky / Malwarebytes | KVRT / AdwCleaner 官方直链 | 需点击 |
| 360 / 火绒官方域名 | 急救工具版本探测与下载 | 需点击 |
| 蓝奏云 / 123 云盘 / 光牙盘 | 版本更新镜像、工具分享页 | 需点击（外链） |
| 爱发电 | 赞助入口 | 需点击（外链） |

**不接入**任何广告、统计（Analytics）、崩溃上报、热更新、用户画像或遥测服务。

---

## 八、权限与用途

本扩展只申请 **7 项 API 权限 + 1 项主机权限**。原则很简单：**每一项权限都对应一个你能直接看到的功能，移除任何一项，对应的功能就会消失**；没有「先申请着、以后可能用」的权限。

### 8.1 API 权限

| 权限 | 用来做什么 | 为什么必须 | 不授予会怎样 |
|---|---|---|---|
| `storage` | `storage.sync`：设置、权重、自定义关键词、三个情报源 API Key（VirusTotal / GSB / FoxAPI，**AES-GCM 密文**）；`storage.local`：自定义黑白名单（默认本地，小体积镜像回 sync）、防护统计、云端名单快照、社区名单、下载黑名单；`storage.session`：本会话内的危险标签页、页面级下载授权、「强手势」时间戳与待确认下载队列（关闭浏览器即清空） | MV3 的 Service Worker 空闲 30 秒即被回收，所有状态必须落到 storage；否则「记住你的每一次开关」无从实现 | 重启即恢复默认，名单与统计全部丢失 |
| `unlimitedStorage` | 云端名单镜像、社区名单（PhishDestroy 域名表、HaGeZi 布隆位图、uBlock / Dandelion 位图）、自定义背景 | 这些数据超过扩展默认配额；超限时 `storage.local.set` 会**静默失败**，用户会看到「同步成功但名单没变」 | 开启社区名单后可能写盘失败 |
| `downloads` | ① 命中黑名单 / 载荷特征时 `chrome.downloads.cancel` 真正阻断下载；② 命中分析闸门 / 每站首次确认时 `pause` 暂停、`resume` 续传**同一条**下载（v1.13.8 起，不再取消后重下）；③ 「银狐急救」中你点击工具时发起下载并指定文件名 | 仅靠页面提示拦不住已经开始的高危下载；急救工具也需要可信下载入口 | 只能提示、不能阻断；急救工具需自行去官网找 |
| `webNavigation` | 只在顶层框架 `onCommitted` 记录时序：页面开始加载即进入「检测中」，并把「危险页 → 新域名」串成跳转链 | 银狐常见「落地页再跳一次才自动下载」，只有导航事件能追上；等到 DOM 就绪已经晚了 | 瞬间自动下载漏拦、跳转链断裂 |
| `notifications` | 高风险网站 / 下载被拦时发系统原生通知 | 页面被立刻关闭、或命中发生在后台标签页时，页面内横幅看不到 | 只在页面内提示 |
| `alarms` | 四组每日更新任务（OpenPhish / PhishDestroy / HaGeZi / uBlock 与 Dandelion 两份 AdBlock 格式名单共用一组，合计覆盖 **5 份**社区黑名单），以及「立即更新」的一次性任务。**云端名单不使用 alarms，完全由你手动点击** | MV3 不允许常驻定时器，`setInterval` 在 SW 回收后失效 | 社区名单无法自动更新，只能手动刷新 |
| `webRequest` | **只读、非阻塞**地监听本扩展自己开的「取链探测」后台标签页请求（`onBeforeRequest` 观察）。**不阻断、不改写、不注入请求头**（因此不需要 `webRequestBlocking`） | 「同源跳转端点」的落点要靠请求本身才能看到：`webNavigation` 只给顶层导航，拿不到解析器自己发出的 XHR / fetch | 「运行时取链」维度失效，端点后面的载荷域只能等它真正落地后才看得见 |

### 8.2 主机权限、可访问资源与 CSP

| 项目 | 用途 | 为什么必须 | 说明 |
|---|---|---|---|
| `host_permissions: <all_urls>` | ① 内容脚本在 `document_start` 注入所有 http / https 页面做实时检测与下载拦截；② 后台请求 RDAP / ICP / 情报源 / 名单 CDN / 工具官网；③ 扩展页面直接读取名单镜像（Gitee 的 raw 响应不带 CORS 头，靠主机权限才可读） | 银狐投放站每天更换域名，无法预先枚举；检测必须在**任意**站点现场完成，否则防护无意义 | 该权限本身**不产生任何请求**；所有外部请求的目标都在代码的固定清单里（见第七节），不会因为权限宽就四处连接 |
| `web_accessible_resources` | 页面内拦截浮层加载打包字体 `fonts/SmileySans-Oblique.woff2`；「关于」页读取 `sponsors.json` 鸣谢名单 | 浮层渲染在第三方页面里，字体必须允许该页面请求 | 只暴露打包内的静态文件，其中**不含任何用户数据** |
| `content_security_policy`（`extension_pages`） | `script-src 'self'`、`object-src 'self'`：禁止远程脚本与插件对象；`connect-src 'self' https:`：允许连接 HTTPS 接口 | 前者让「不执行远程代码」成为浏览器强制约束，而不只是口头承诺；后者是跨域读取公开接口所必需 | `connect-src` **未做域名白名单**，实际目标由代码固定清单决定；默认关闭的项在开启前一次都不会请求 |

### 8.3 未申请的敏感权限

`tabs`（`tabs.create` / `tabs.sendMessage` 不需要该权限，读取标签页 URL 由主机权限覆盖）、`cookies`、`history`、`bookmarks`、`declarativeNetRequest` / `webRequestBlocking`（不做全量网络拦截、不阻断或改写任何请求；`webRequest` 已申请，但只作**非阻塞**观察）、`scripting`（内容脚本由 manifest 静态声明）、`nativeMessaging`、`identity`、`management`、`clipboardRead`、`clipboardWrite`（复制提取码走 `navigator.clipboard.writeText`，扩展页面自带该能力）、`geolocation`、`downloads.open`、`proxy`。

### 8.4 数据分类声明（商店「是否收集用户数据」表单逐项）

| 数据类别 | 是否收集 | 说明 |
|---|---|---|
| 个人身份信息（姓名、邮箱、地址、电话） | **否** | 不建账号；只有你主动点「发送反馈到作者邮箱」时才可**自愿**填写一个联系方式，它随邮件发给作者，不进入任何数据库，也无从关联到你 |
| 健康 / 财务 / 支付信息 | **否** | 不涉及 |
| 身份验证信息（密码、凭据、Cookie） | **否** | 不读取、不存储、不上传；未申请 `cookies` 权限 |
| 个人通信（邮件、短信、聊天内容） | **否** | 不读取页面内的私信、邮件正文 |
| 位置信息 | **否** | 不申请地理定位；不使用 IP 反查位置 |
| 网页浏览历史 | **是（仅本机处理，不上传、不落盘）** | 只有读取**当前这一页**的 URL 与导航时序，才能判断它是不是「刚换域名就跑」的仿冒站；扩展**不写历史记录、不保存访问列表**，也不上传（RDAP / ICP 只发送当前页面的**域名**；VirusTotal / URLhaus / NetAPI / Google Safe Browsing / FoxAPI 发送当前页面的域名或 URL，且默认关闭）。商店表单勾选此项是在如实声明**访问范围**，与「是否外传」是两件事 |
| 用户活动（点击、滚动、鼠标轨迹） | **否** | 不埋点、不统计交互 |
| 网站内容（页面正文、超链接、内联脚本） | **是（仅本机处理，读完即弃）** | 评分需要读当前页的 DOM（下载入口、话术文本、内联脚本）；结果只留在内存，页面内容不进任何请求体、不落盘。**表单里输入的内容从不读取**（不申请 `clipboardRead`，也不监听输入事件取值） |
| 设备标识符 | **否** | 不生成、不读取设备指纹 |

**其余承诺**：不售卖、不出租、不共享用户数据；不用于广告、信贷、保险或信用评估；不接入任何第三方分析 / 崩溃上报 SDK。

### 8.5 商店审核用权限理由（可直接粘贴）

| Permission | Justification | 中文 |
|---|---|---|
| `storage` | Persists user settings, custom allow/block lists, statistics, the cloud-list snapshot, and the per-site first-download confirmation list (registrable domain + timestamp only); per-page download grants, gesture timestamps and pending downloads live in session storage and are cleared when the browser closes. MV3 service workers are terminated when idle, so state cannot live in memory. No personal data is stored off-device. | 保存设置、自定义名单、统计、云端名单快照与「每站首次确认」名单（仅注册域名 + 时间戳）；页面授权 / 手势 / 待确认下载存会话存储，关浏览器即清（MV3 后台会被回收，状态必须落盘） |
| `unlimitedStorage` | Blocklist data (≈140k domains plus a ~4.8 MB Bloom-filter bitmap) exceeds the default storage quota; without it, writes fail silently. | 社区黑名单体积超过默认配额，超限会静默写入失败 |
| `downloads` | Cancels high-risk downloads (`.exe`/`.msi` payloads) after local detection, and downloads cleanup tools from official vendor domains only when the user clicks. | 取消高危下载；仅在用户点击时从官方域名下载查杀工具 |
| `webNavigation` | Reads top-level navigation timing to detect a page as soon as it starts loading and to follow redirect chains; used only for local decisions. | 读取顶级导航时序，页面开始加载即检测并追踪跳转链，仅用于本地判定 |
| `notifications` | Shows a native warning when a risky page or download is blocked, in case the tab is closed or in the background. | 风险页 / 下载被拦时发系统通知，防止标签页已关闭或处于后台 |
| `alarms` | Schedules the daily refresh of the 5 optional community blocklists (4 alarm groups); MV3 service workers cannot keep timers. | 为可选的社区名单安排每日更新（MV3 无法常驻定时器） |
| `webRequest` | Read-only, **non-blocking** observation (`onBeforeRequest`, no `webRequestBlocking`) of the single hidden probe tab the extension opens on an already-blocked page, to see which domain a same-origin download redirect endpoint finally lands on. It never blocks, rewrites, or injects headers, and no third-party request is added: the probe loads the page own endpoint, exactly as if the user had clicked it. Can be disabled entirely in Settings → Behavior. | 只读、非阻塞地观察扩展自己开的取链探测标签页，看同源跳转端点最终落到哪个域名；不阻断、不改写、不注入请求头，也不新增第三方 |
| `host_permissions: <all_urls>` | The content script must analyze any http(s) page the user opens, because phishing domains rotate daily and cannot be enumerated in advance. The permission also lets the extension read public blocklist endpoints that do not send CORS headers. No requests are made because of the permission alone. | 内容脚本需在任意页面实时检测（投放域名每天更换、无法预先枚举），并读取不带 CORS 头的公开名单；权限本身不产生任何请求 |
| `web_accessible_resources` | Exposes a bundled font (used by the in-page warning overlay) and a static credits JSON to pages; no user data. | 仅暴露打包内的字体与静态鸣谢文件，不含用户数据 |
| `content_security_policy` | Enforces `script-src 'self'` / `object-src 'self'` (no remote code) and allows HTTPS connections required by the documented endpoints. | 强制不加载远程代码，并允许访问文档中列出的 HTTPS 接口 |


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

**SilverFoxBlocker v1.15.10** runs all detection, scoring, list matching and blocking **on your device**. There are no accounts, no analytics, no telemetry, and no upload of browsing history, cookies, credentials or page content.

**Built-in list data fix (v1.14.10):** one entry in the built-in "correct official site" table (Seewo / EasiNote) had its columns misaligned (a domain written into the brand-word column, the site column left empty), so it was dropped at load and the console showed an empty warning on every page. It is now merged with the existing Seewo entry (three sites) and empty values are skipped silently instead of being logged. Local list data and one console message only: **no permission, third-party, request, uploaded field or storage key is added or changed**, and detection results are unchanged.
**Version alignment (v1.14.9):** that release only aligned the version number with `manifest.json` (`1.13.15` → `1.14.9`). Permissions, third parties, network requests, uploaded fields and stored keys are unchanged.

**Download-gate hardening (v1.13.9):** the allow-list entry created when you press \"continue\" is no longer keyed by the full URL for the whole session; it is normalized to `host + path`, expires after 10 minutes, and is bound to the tab that approved it (in-memory only, never persisted). Downloads whose URL is a `blob:` / `data:` URI are now classified by MIME type and suggested filename as well, so a `fetch → blob → a.click()` package can no longer lose its "high-risk" status; no file content is read. After cancelling, the entry state is re-checked, and if a native download manager already grabbed it the UI no longer claims it was blocked. One new local key, `sfDlUnattributed`, stores up to 20 diagnostic records of high-risk downloads that no rule caught (URL, payload host, source, verdict level, initiator extension id) — local only, never uploaded, never used for any decision, cleared together with the counters.. Three local scoring false positives were also fixed (the `.msi` file extension being read as a brand word, the path segment `android` being read as a brand word, and the generic noun `office` taking part in the "brand + filler" concatenation test); these only change local decision rules — no new data collection, request or storage; and a failed "send feedback by email / report list" now performs one extra `HEAD` probe to the same endpoint (to tell "network unreachable" apart from "blocked by CORS"), which only happens after a failure, carries no body and targets no new host. The failure message shows your local extension ID on the settings page only - it is never sent anywhere. **Soft fallback (v1.14.9):** if the human-check widget cannot load (e.g. your network cannot reach `challenges.cloudflare.com`), feedback can still be sent through a degraded channel limited to 3 submissions per IP per day (configurable by the maintainer, max 60). No new request, no new data field: the only difference is a boolean `turnstileFallback: true` in the request body, and the server logs that the fallback was used. The maintainer can switch back to strict mode (`TURNSTILE_ENFORCE = "strict"`), in which case such submissions are rejected as before. **Human check (Turnstile, v1.14.9):** when the maintainer enables it server-side, "send feedback / report list" now requires a Cloudflare Turnstile challenge. After you click send, the extension first tries the normal signed request; if the Worker answers `TURNSTILE_REQUIRED`, it embeds a tiny page served by the Worker itself (`GET /challenge`, same origin as the feedback endpoint) in an iframe. That page loads Cloudflare's official widget and, once you pass it, hands a one-time token back via `postMessage`; the extension then adds that token to the request body and signs it again. Cloudflare therefore sees your IP and ordinary request headers (exactly as on any Turnstile-protected site) but **never the text you typed** - the feedback body is only sent afterwards, by the extension, directly to the Worker. The token is single-use, expires after 5 minutes, is not stored, and never appears in the email body or logs. The challenge page is created only after you click send and is removed as soon as it succeeds or fails; if the maintainer does not configure it, this step does not exist at all. **Feedback authentication (v1.14.9):** the feedback endpoint no longer identifies the extension by Origin / extension ID; each request carries an HMAC-SHA256 signature (`X-SF-Sig`) over "path + timestamp + body" plus the timestamp itself (`X-SF-Ts`), and the Worker verifies it against `SECRET_DATA`, a server-side Cloudflare Secret, within a ±5 minute window. The shared key ships inside the extension package and is readable by anyone who unzips it (same nature as the bundled cloud-list API key) - it contains no user data and is not a secret you need to guard; it only prevents scripts and web pages that lack the key from calling the endpoint. What is sent, when it is sent, and where it goes are all unchanged. **Failure-diagnostic copy (v1.14.9):** the failure message of "send feedback / report list" now follows a fixed layout (four lines for network failures, two for HTTP errors, including your local extension ID, shown on the settings page only). On the same failure path, at most one public DNS-over-HTTPS lookup (`dns.alidns.com`, falling back to `cloudflare-dns.com`, 2.5 s each) is performed to tell "DNS resolution failed" apart from "resolved but the connection is blocked"; it is sent **only after the main request failed and a same-origin `HEAD` probe also failed**, it queries **only the feedback endpoint's own hostname** (never any site you visit), carries no cookies and no identifier, and is never stored. The server-side CORS allow-list (Cloudflare Worker, not the extension) now supports `*` wildcards and allows any `chrome-extension://` origin by default; rejected 403 responses echo `Access-Control-Allow-Origin` (plus `Vary`) but still return no list data.

**Download gating (v1.13.8):** when a download is held by the analysis gate or by the first-executable-per-site confirmation, the extension now **pauses that very download** with `chrome.downloads.pause()` and resumes it with `resume()` when you press "continue" — it no longer cancels and re-issues the request through `chrome.downloads.download()`. This only flips a state bit on an existing entry in the browser's download list: no file content is read, no new file is written, and no new request is made. The pending-confirmation queue (session storage, cleared when the browser closes) additionally records the numeric download id of that entry — same key as before, no new storage item. Two new in-page notices ("already taken over by a download manager", "check passed, download resumed") and two buttons on the system notification are generated locally and never leave the device. No permission, no third party and no new network request was added.

**Community blocklists (v1.13.7):** the five "update now" buttons in Settings → Community-maintained local blocklists now first persist the toggles of that very section (master switch + five per-list switches + the HaGeZi variant — six keys that already exist in your settings) into `chrome.storage.sync`, then start the fetch. It is the same write as pressing "Save settings", but limited to those six keys: allowlists, custom lists, scoring weights and appearance are untouched, nothing new is stored, nothing is uploaded, and no request is made unless you press one of those buttons.

**Automatic requests (on by default, disableable):** registrable domain → public RDAP servers (domain age); domain → public ICP lookup services (`uapis.cn`, `cn.apihz.cn`); limited reads of resources already referenced by the page you are visiting for download discovery. Any list hit short-circuits these lookups.

**Download handling (v1.10.x, updated v1.13.8):** high-risk files (`.exe`/`.msi`/`.zip`/`.dmg` and cloud-disk share links) are **not** exempted by allowlists any more. A download that starts without a matching user gesture is paused and a small non-blocking bar offers "keep blocked / continue"; one confirmation authorizes the rest of that page (revoked on navigation or reload), and the **first** executable download from each site must be confirmed once (registrable domain + timestamp kept locally, 180-day expiry, ≤2,000 entries, never uploaded; declining does not record it). Page grants, gesture timestamps and pending downloads live in `chrome.storage.session` and are cleared when the browser closes. When a download is allowed as user intent, a 10-second dismissible notice appears in the bottom-left corner. After a **safe** verdict, previously held downloads are **resumed in place** (the same entry continues downloading; nothing is re-requested); if the verdict is `danger` they are cancelled and erased; if the check times out they stay paused so you can resume or delete them yourself in the download list. Since v1.13.8 the hold is a pause, not a cancel — see the paragraph above. The resolver-follow probe (dangerous pages only) now has an explicit on/off switch (Settings → Behavior, on by default).

**Domain-spoofing scoring (v1.13.6):** spoof detection now runs two independent lines — exact matching (segment / substring / edit distance / de-hyphenation) and a variant line (letter-set anagrams, brand word plus 2–3 non-affix letters, brand split by hyphens and re-joined), the higher-scoring line wins and the other is skipped. A digit-lookalike rule treats digits in a hostname as alternative readings of letters (`1` → `l` or `i`, `5` → `s`, `3` → `e`, …) and only fires when the label has the same length as the brand word and every non-digit position matches exactly. Four existing defects were fixed along the way (homoglyph folding swallowing digits, a strict comparison when stripping affixes, edit-distance guards that dropped 23% of one-character variants, and token-joining false positives on "brand + site-nature word" hosts). Everything reads only the hostname and page data the content script already collects — no new request, no new storage key, no new permission. A generic-abbreviation rule now exempts bare hostnames that consist solely of an industry abbreviation (e.g. erp.com). The ICP lookup parser was also adapted to an upstream API change ("no record" now comes back as HTTP 404 instead of a 200 message) and to very different response times (about 200 ms when a record exists, 8-10 s when it does not): the two existing endpoints are now queried concurrently and an authoritative answer may arrive after the first verdict. It still talks to the same two public endpoints and stores nothing new.

**Detection scoring (v1.12.6, unchanged):** eight additional local heuristics target lure-download and greyware-promotion pages — placeholder "download" buttons, a single scripted download endpoint reused by every button, one archive offered as the "Windows / Mac / Android" build, `href` values rewritten at runtime, a spoofed brand claiming to be "official", a malformed ICP licence number shown in the footer, references to known blackhat infrastructure, and anti-devtools scripts. All of them read only what the content script already collects from the page you are on (DOM, anchor `href` and text, inline script text, the licence string displayed in the footer). No new request, no new storage key, no new permission.

**Lists and exceptions (v1.11.6, unchanged in v1.12.6):** beyond the six local lists (cloud / builtin / custom, each with a block and an allow side), three "exception" layers can override blocklists: **cloud exceptions** arrive as the `exceptions` field inside the same `whitelist.json` you already fetch only when you click "update from cloud" (plain domain strings, no new request), **builtin exceptions** ship inside the extension, and **your own exceptions** are typed into the options page and kept in `chrome.storage.local` (`exceptionDomains`) — never uploaded. Your own exceptions override only your own blocklist, never the cloud or builtin ones. No new permissions, no new network requests, no new data collection.

**Optional requests (off by default):** VirusTotal receives base64url domain/URL IDs; Google Safe Browsing receives the **full page URL** (v4 Lookup); FoxAPI receives the **domain**. All three use your own API key, stored **only as AES-GCM ciphertext** (`v1.salt.iv.ciphertext`); plaintext exists only briefly inside the background service worker, never in storage or page scripts. FoxAPI results never render a banner — they only adjust the local score (`official:false` adds 45 points), and calls are throttled to 1/second with a 10-minute per-domain cache. URLhaus receives domain + page URL; NetAPI receives the domain; community blocklists (OpenPhish, PhishDestroy, HaGeZi TIF, uBlock Origin Badware risks, Dandelion Sprout Anti-Malware) are downloaded as one-way GETs from jsDelivr/GitHub mirrors; the two AdBlock-format lists are reduced to `||domain^` host rules only — IPs, paths, regexes, cosmetic and exception rules are discarded and never executed. VT keys saved as plaintext by older versions are automatically re-encrypted once you open the options page; until then the background still accepts them.

**Author-maintained cloud allow/block lists (v1.7.2, manual sync only):** no automatic sync. Only when you click "从云端更新名单" are two GETs sent to our Cloudflare Worker (`api.silverfoxblocker.dpdns.org/list?type=white|black`) with a bundled read-only `X-API-Key`. Nothing about you or your device is uploaded. The Worker reads `whitelist.json` / `blacklist.json` from a private GitHub repository (falling back to a private Gitee mirror if GitHub is unreachable, server-side only) and returns plain domain strings, which are validated and stored locally in `chrome.storage.local` (`sfCloudWhite`, `sfCloudBlack`, `sfCloudListMeta`).

**User-initiated uploads:** posting feedback, or clicking "发送白/黑名单到作者邮箱", sends only the text you typed (feedback body + optional contact, or just your domain list; 2000-character cap) to the same Worker, which emails it to the author via Brevo. Those emails include the source **IP**; a Cloudflare KV key (`rate_limit_{IP}_{date}`, 60/day, 24h TTL) is used for rate limiting. Feedback text is not stored in a database, but it is retained by the mail provider and the author's mailbox. Browsing history, page URLs, settings, API keys and statistics are never included. Do not click these buttons if you do not want to share that content.

**Automatic (opt-out) requests since 2026-11-28:** two About-page switches, both ON by default. "Auto check for updates" reads the public release tag from `api.github.com` every 6 hours (no payload, no local data, no installer download; a "新" badge on the toolbar icon, one line on the About page, and an in-page "new version" dialog shared with the manual check button when a newer tag exists; dismissing it now stores nothing — the dismissal is kept in memory for the current page load only, so a refresh or a newly opened settings tab will offer the update again until you actually update); on browser startup a catch-up run happens when the last successful check is older than 90% of the period, and opening the settings page sends an internal "is it due?" message to the same gate (no network request unless due) while showing a short local "checking for updates…" bar with a mouse-only shield. "Auto update cloud lists" pulls the same two public lists from `api.silverfoxblocker.dpdns.org/list` every 24 hours and stores them locally (the built-in list API key is sent, no user data; both lists must succeed or nothing is written). Turning either switch off stops its requests immediately; the boolean flags live in `chrome.storage.sync` as `autoCheckUpdate` / `autoCloudUpdate`. **A third, OFF-by-default switch since 2026-11-29** ("send a system notification when an update is found", `storage.sync.notifyOnUpdate`) only controls a local `chrome.notifications` toast — no request, no upload, no new permission; the same version is announced at most once (`storage.local.sfNotifiedVersion`), and clicking it merely opens the local About page.

**Other user-initiated requests:** the version-row "检查更新" button reads only the public latest tag — first from `github.com/…/releases/latest` (via the post-redirect URL), then `api.github.com`, then the `gh-proxy.com` mirror — and compares it locally; nothing is uploaded and no installer is downloaded. Also rescue-tool downloads from 360 / Huorong / Kaspersky (KVRT) / Malwarebytes (AdwCleaner) official hosts, plus ordinary external links (Lanzou update mirror with a clipboard-copied extraction code, SoftcnKiller share page, SilverFoxCleaner share page, 123pan, GitHub, GitHub Issues, Afdian) opened in new tabs without injected parameters.

**Local storage:** settings and custom lists in `chrome.storage.sync` (browser-account sync only, never via our servers), including the three API keys (VirusTotal, Google Safe Browsing, FoxAPI) as AES-GCM ciphertext; statistics, downloaded lists, cloud-list snapshot and metadata, plus the per-site first-download confirmation list, in `chrome.storage.local`; HaGeZi's Bloom-filter bitmap (~4.8 MB) plus two much smaller bitmaps for the uBlock and Dandelion lists in IndexedDB. No remote code is loaded; the MV3 CSP is `script-src 'self'; object-src 'self'; connect-src 'self' https:` — note that `connect-src` **allows any HTTPS host** rather than a domain allowlist, so actual destinations are governed by the fixed list in code.

**Permissions.** The extension requests only `storage`, `unlimitedStorage`, `downloads`, `webNavigation`, `notifications`, `alarms`, `webRequest` (read-only, non-blocking observation of the extension own probe tab) and `<all_urls>` — nothing else (no `cookies`, `history`, `tabs`, `bookmarks`, `declarativeNetRequest`/`webRequestBlocking`, `scripting`, `nativeMessaging`). Each permission maps to a user-visible feature: persisting settings and lists; storing blocklists that exceed the default quota; cancelling malicious downloads and pausing/resuming the same entry while a verdict is pending; reading top-level navigation timing; showing a native warning; scheduling daily community-list refreshes; and injecting the detection content script into any http(s) page (required because phishing domains are rotated daily). A ready-to-paste justification for every permission is in section 8.5 above.

**Data categories.** Nothing is transmitted off the device except the documented lookups. Because the content script does read the current page URL, its navigation timing and its DOM in order to score it, the store form discloses **Web history** and **Website content** as processed locally (never stored as a history list, never uploaded, discarded right after scoring). The extension does **not** collect personal identity, health, financial, authentication, communications, location, user activity or device identifiers; it does not sell, rent or share data, and does not use it for advertising, credit or insurance. The only user-supplied content is text you explicitly submit via the feedback / list-report buttons, which is emailed to the author and not stored in a database. No ads, analytics, crash reporting or telemetry.

For questions, use the in-extension feedback form or open an issue on GitHub or Gitee.
