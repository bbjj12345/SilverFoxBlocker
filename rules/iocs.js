/*
 * iocs.js — 银狐(Silver Fox / 游蛇)木马投递网站特征库
 * 数据来源：CNCERT / 安天 的官方通报 + 参考 VirusDetector 开源实现(domain-database / icp-utils)。
 * 同时被 content script 与 background service worker 加载，兼容 window / self / node。
 */
(function () {
  'use strict';

  // ============ 本地名单目录（大类 → 小项 → 域名）============
  // 结构：CATALOG = [ [大类, [ [小项, '域名 域名 …', '备注'], … ]], … ]
  //  · 大类 = 业务领域（安全软件类 / 浏览器类 / 金融类 …）
  //  · 小项 = 该领域下的品牌系或机构子类（360系 / 腾讯系 / 银行 / 证券 …）
  //  · 域名一律小写、空格分隔；同一域名只允许出现在一个小项里（首次出现生效，重复会被丢弃并告警）
  //  · 条目可含 `*` / `?` 通配（写法与护栏见下方「通配符写法」）
  // 下方 OFFICIAL_DOMAINS / KNOWN_BAD_DOMAINS 全部由目录派生，判定逻辑（analyzer.js）无需改动。
  // 维护方式：只改本目录，不要再单独往扁平数组里塞域名——扁平数组是派生产物。
  //
  // 判定语义（与派生前完全一致）：
  //   WHITELIST_CATALOG → OFFICIAL_DOMAINS → 精确 + 子域后缀命中即「早期退出」判安全，永不拦截
  //   BLACKLIST_CATALOG → KNOWN_BAD_DOMAINS → 命中即判 danger，永不豁免
  //   EXCEPTION_DOMAINS → 内置「黑名单例外」→ 可推翻内置黑名单，不能推翻云端黑名单（2026-11-23）
  //
  // ============ 通配符写法（2026-11-11 新增）============
  // 两个目录的域名串里都可以直接写通配，由 analyzer.js 的 _splitBuiltinList 编译成主机名正则：
  //   `*`  匹配**同一个域名标签内**的任意字符（不跨 `.`）
  //   `?`  匹配单个非点字符
  //   例：'*bot.qpefh.com'      → 命中 7f3abot.qpefh.com / xbot.qpefh.com
  //       'abi0?.8msg8.com'    → 命中 abi04.8msg8.com / abi0x.8msg8.com
  //       '*.cdn-bad.top'      → 归一为后缀条目 cdn-bad.top（覆盖全部子域），与直接写域名等价
  //   护栏：TLD 位禁通配（`*.com` / `foo.*` / 裸 `*` 会被丢弃），条目必须 ≥2 个标签、长度 4–253；
  //        被拒条目只进诊断，不报错、不影响其余条目。
  // 2026-11-12：取消「每条名单最多 400 条通配」的上限——通配改为按尾部标签分桶查找，
  //   条数只影响内存，不影响单个页面判定的耗时，因此不再需要截断（截断＝静默失效）。
  // ⚠️ 写通配时不要做任何「清洗」：`?` 是通配符不是 query 起点，`*` 也不能被 split/replace 掉。
  //   目录串按空白分词、整串小写化后原样传给编译器，中间不做 URL 解析或解码，故不会被截断。
  // ⚠️ 通配只参与「主机名命中」判定，**不参与**品牌词派生（从官方域自动抽取品牌词时只认精确条目），
  //   所以往白名单里加 `*media.foo.com` 不会让 `*media` 变成一个仿冒品牌词。

  // ---------- 白名单目录 ----------
  const WHITELIST_CATALOG = [
    // ========== 安全软件类 ==========
    ['安全软件类', [
      ['360系', '360.cn 360.com', '安全卫士 / 手机助手 / 手机卫士 / 搜索'],
      ['火绒系', 'huorong.cn', '火绒安全软件'],
      ['腾讯电脑管家', 'guanjia.qq.com gj.qq.com', ''],
      ['瑞星系', 'rising.com.cn', '瑞星杀毒 / 瑞星个人防火墙'],
      ['金山系', 'duba.net ijinshan.com', '金山毒霸 / 金山卫士'],
      ['卡巴斯基', 'kaspersky.com kaspersky.com.cn', 'Kaspersky/卡巴斯基，来自俄罗斯的反恶意软件厂商'],
      ['Bitdefender', 'bitdefender.com bitdefender-cn.com', '来自罗马尼亚的反恶意软件厂商'],
      ['Avast / AVG / 诺顿', 'avast.com avg.com norton.com', '同属 Gen Digital'],
      ['ESET', 'eset.com', '来自斯洛伐克的反恶意软件厂商'],
      ['赛门铁克', 'symantec.com', '属于Broadcom的企业端反恶意软件厂商'],
      ['Avira', 'avira.com iavira.com', '来自德国的反恶意软件厂商'],
      ['Malwarebytes', 'malwarebytes.com', '来自美国的反恶意软件厂商'],
      ['Dr.Web', 'drweb.com drweb.cn', '大蜘蛛，来自俄罗斯的反恶意软件厂商'],
      ['McAfee', 'mcafee.com', '迈克菲，来自美国的反恶意软件厂商'],
      ['F-Secure', 'f-secure.com withsecure.com', '来自芬兰的反恶意软件厂商'],
      ['Trend Micro', 'trendmicro.com', '趋势科技，来自日本的云端反恶意软件厂商'],
      ['Sophos', 'sophos.com', '来自英国的反恶意软件厂商'],
      ['G Data', 'gdata-software.com', '歌德塔，来自德国的反恶意软件厂商（2026-11-12 修正：原收录的 gdata.com 归属无法确认，已换为实测官网 gdata-software.com）'],
      ['Comodo', 'comodo.com', '科摩多，又称毛豆，来自美国的反恶意软件厂商'],
      ['微步在线', 'threatbook.cn threatbook.com safeskill.cn', '微步在线威胁情报平台'],
      ['VirusTotal', 'virustotal.com', 'VirusTotal 是 Google 旗下的聚合扫描服务平台，提供在线文件 / URL 扫描'],
      ['ANY.RUN', 'any.run', 'ANY.RUN 云沙箱分析平台，提供在线文件 / URL 扫描'],
      ['AdGuard', 'adguard.com adguardteam.com adguard-vpn.com adguard-dns.io adguard-wallet.com adguard-mail.com', '广告拦截 / 隐私保护'],
      ['其他海外安全软件', 'pandasecurity.com zonealarm.com emsisoft.com', 'Panda / ZoneAlarm / Emsisoft 等（2026-11-12 修正：原收录的 panda.com 是待售停放页，已换为官网 pandasecurity.com）'],
      ['官网表补录', '360totalsecurity.com', '来源：CORRECT_SITE_CATALOG 同名大类（2026-11-21 两表合并），均为官网表已核实的官方主机名'],
    ]],

    // ========== 浏览器类 ==========
    ['浏览器类', [
      ['360系', 'browser.360.cn se.360.cn chromex.360.cn', '360 安全浏览器 / 360 极速浏览器 / 360 浏览器'],
      ['腾讯系', 'browser.qq.com liulanqi.qq.com', 'QQ 浏览器 / QQ 极速浏览器'],
      ['搜狗系', 'ie.sogou.com', '搜狗浏览器'],
      ['猎豹系', 'liebao.cn', '猎豹浏览器'],
      ['傲游系', 'maxthon.cn maxthon.com', '傲游浏览器'],
      ['UC系', 'uc.cn ucweb.com', 'UC 浏览器 / UC 手机助手'],
      ['Mozilla', 'mozilla.org firefox.com', 'Firefox'],
      ['Google', 'google.com google.cn google.com.hk googlemail.com gmail.com', 'Google / Gmail'],
      ['其他海外浏览器', 'brave.com opera.com vivaldi.com yandex.com torproject.org apple.com apple.com.cn', 'Brave / Opera / Vivaldi / Yandex / Tor / Safari（2026-11-12 移除 safari.com：归属无法确认，Safari 官网在 apple.com/safari，已由 apple.com 覆盖）'],
      // 新（2026-11-22）：云端 correct_sites 迁入，整站放行
      ['Chromium', 'chromium.org', 'Chromium 开源项目官网，Chrome / Edge 的上游'],
      ['官网表补录', 'vivaldi.net yandex.ru', '来源：CORRECT_SITE_CATALOG 同名大类（2026-11-21 两表合并），均为官网表已核实的官方主机名'],
    ]],

    // ========== IM 与社交类 ==========
    ['IM与社交类', [
      ['微信系', 'weixin.qq.com wechat.com action.weixin.qq.com', '微信 / WeChat'],
      ['企业微信', 'work.weixin.qq.com office.qq.com', '企业微信 / TIM（office.qq.com 实为 TIM 官网，企业邮箱在 exmail.qq.com）'],
      ['QQ系', 'im.qq.com qq.com', 'QQ / QQ 邮箱 / QQ 轻聊版'],
      ['腾讯系', 'tencent.com', ''],
      ['钉钉', 'dingtalk.com', ''],
      ['飞书系', 'feishu.cn larkoffice.com', '飞书（larkoffice.com 307 到 feishu.cn）/ Lark 国际版官网为 larksuite.com'],
      ['陌陌', 'immomo.com', ''],
      ['Soul', 'soulapp.cn', ''],
      ['网易邮箱', 'netease.com 126.com yeah.net', '网易 / 126 / Yeah 邮箱'],
      ['微博', 'weibo.com weibo.cn', ''],
      ['知乎', 'zhihu.com', ''],
      ['小红书', 'xiaohongshu.com xhs.com', ''],
      ['豆瓣', 'douban.com douban.fm ruguoapp.com mtime.com', '豆瓣 / 豆瓣FM / 即刻 / 时光网'],
      ['社区论坛', 'tianya.cn hupu.com', '天涯 / 虎扑'],
      ['官网表补录', 'larksuite.com okjike.com', '来源：CORRECT_SITE_CATALOG 同名大类（2026-11-21 两表合并），均为官网表已核实的官方主机名'],
    ]],

    // ========== 输入法类 ==========
    ['输入法类', [
      ['搜狗系', 'pinyin.sogou.com shurufa.sogou.com', '搜狗输入法'],
      ['百度系', 'shurufa.baidu.com ime.baidu.com', '百度输入法'],
      ['讯飞系', 'srf.xunfei.cn xinshuru.com', '讯飞输入法（srf.xunfei.cn）/ 手心输入法（xinshuru.com，与讯飞无关）'],
      ['QQ系', 'qq.pinyin.cn', 'QQ 拼音输入法'],
      ['官网表补录', 'iflytek.com', '来源：CORRECT_SITE_CATALOG 同名大类（2026-11-21 两表合并），均为官网表已核实的官方主机名'],
    ]],

    // ========== 办公与文档类 ==========
    ['办公与文档类', [
      ['希沃白板', 'seewo.com', ''],
      ['金山系', 'wps.cn wps.com wps-linux.com kdocs.cn', 'WPS Office / WPS 云文档 / 金山文档'],
      ['腾讯系', 'docs.qq.com', '腾讯文档'],
      ['LibreOffice', 'libreoffice.org', ''],
      ['OnlyOffice', 'onlyoffice.com', ''],
      ['OpenOffice', 'openoffice.org', ''],
      ['石墨文档', 'shimo.im', ''],
      ['有赞文档', 'yozosoft.com', '实为永中 Office（yozosoft.com），与「有赞 youzan.com」无关；条目名待作者决定是否改'],
      ['微软系', 'microsoft.com microsoft.cn office.com microsoft365.com live.com outlook.com onenote.com office365.com hotmail.com msn.com', 'Windows / Office / Outlook（含 Edge 下载页）'],
      ['微软身份认证', 'microsoftonline.com windows.net login.windows.net azure.com passport.com passport.microsoft.com azureedge.net', 'OAuth / SSO / 登录中转'],
      ['协作工具', 'zoom.us webex.com slack.com discord.com telegram.org skype.com thunderbird.net', 'Zoom / Webex / Slack / Discord / Telegram'],
      // 新（2026-11-22）：云端 correct_sites 迁入，整站放行
      ['腾讯会议', 'meeting.tencent.com voovmeeting.com', '腾讯会议 / 国际版 VooV'],
      ['金山词霸 / 金山软件', 'iciba.com kingsoft.com', '金山词霸（iciba）与金山软件集团站（kingsoft.com）'],
      ['官网表补录', 'azure.cn zoom.com', '来源：CORRECT_SITE_CATALOG 同名大类（2026-11-21 两表合并），均为官网表已核实的官方主机名'],
    ]],

    // ========== 影音娱乐类 ==========
    ['影音娱乐类', [
      ['腾讯视频', 'v.qq.com', ''],
      ['爱奇艺', 'iqiyi.com iq.com', ''],
      ['优酷', 'youku.com tudou.com', '优酷 / 土豆'],
      ['哔哩哔哩', 'bilibili.com bilibili.tv', ''],
      ['芒果TV', 'mgtv.com', ''],
      ['字节系', 'ixigua.com xigua.com douyin.com bytedance.com tiktok.com capcut.com', '西瓜视频 / 抖音 / TikTok / 剪映'],
      ['搜狐视频', 'tv.sohu.com sohu.com', ''],
      ['直播平台', 'huya.com douyu.com yy.com panda.tv zhanqi.tv', '虎牙 / 斗鱼 / YY / 熊猫（已停运）/ 战旗（已停运）'],
      ['快手', 'kuaishou.com', ''],
      ['网易云音乐', 'music.163.com', ''],
      ['QQ音乐', 'y.qq.com music.qq.com', ''],
      ['酷狗 / 酷我', 'kugou.com kuwo.cn', ''],
      ['咪咕音乐', 'music.migu.cn migu.cn', ''],
      ['喜马拉雅', 'ximalaya.com', ''],
      ['汽水音乐', 'qishui.com', '抖音音乐版'],
      ['图片与二次元', 'meitu.com meituinc.com xima.tv acfun.cn', '美图（meituinc.com 为母公司站）/ 喜马拉雅（xima.tv 301 到 ximalaya.com）/ AcFun'],
      ['网络文学', 'qidian.com yuewen.com zhangyue.com duokan.com cmread.com sfacg.com', '起点 / 阅文 / 掌阅 / 多看 / 咪咕阅读 / SFACG'],
      ['音视频工具', 'adobe.com photoshop.com adobe.io videolan.org obsproject.com audacityteam.org ffmpeg.org', 'Adobe / VLC / OBS / Audacity / FFmpeg'],
      ['官网表补录', 'wetv.vip jianying.com joyy.com kwai.com fanqienovel.com obsproject.org potplayer.daum.net', '来源：CORRECT_SITE_CATALOG 同名大类（2026-11-21 两表合并），均为官网表已核实的官方主机名'],
    ]],

    // ========== 云盘与存储类 ==========
    ['云盘与存储类', [
      ['百度网盘', 'pan.baidu.com', ''],
      ['阿里云盘', 'aliyundrive.com alipan.com', '2024 年起更名「夸克网盘」，aliyundrive.com 301 到 alipan.com'],
      ['腾讯微云', 'weiyun.com', ''],
      ['115网盘', '115.com', '现名「115 生活」，原 115 网盘'],
      ['天翼云盘', 'cloud.189.cn', ''],
      ['夸克网盘', 'pan.quark.cn', ''],
      ['迅雷云盘', 'pan.xunlei.com', ''],
      ['蓝奏云', 'lanzou.com lanzous.com lanzoux.com lanzouw.com lanzoui.com ilanzou.com', '蓝奏云主站 / 优享版'],
      ['蓝奏云镜像', 'pc.woozooo.com wwda.lanzouj.com wwn.lanzouy.com wwtr.lanzouw.com', '网友自建镜像站（误报反馈）'],
      ['官网表补录', 'quark.cn yun.139.com 123pan.com 123684.com jianguoyun.com dropbox.com onedrive.com mega.nz', '来源：CORRECT_SITE_CATALOG 同名大类（2026-11-21 两表合并），均为官网表已核实的官方主机名'],
    ]],

    // ========== AI 大模型类 ==========
    ['AI大模型类', [
      ['百度文心', 'yiyan.baidu.com chat.baidu.com', '现名「文心助手」（原文心一言），两入口均 302 到 wenxin.baidu.com'],
      ['阿里通义', 'tongyi.aliyun.com qianwen.aliyun.com qianwen.com qianwenai.com dashscope.console.aliyun.com', '千问（原通义千问，tongyi 入口 301 到 qianwen.aliyun.com）/ 千问AI 企业平台（原阿里云百炼 DashScope）'],
      ['字节豆包', 'doubao.com volcengine.com', '豆包 / 火山引擎'],
      ['科大讯飞', 'xinghuo.xfyun.cn agent.xfyun.cn', '讯飞星火'],
      ['360纳米AI', 'chat.360.com ai.360.com ai.360.cn', ''],
      ['月之暗面 Kimi', 'kimi.moonshot.cn kimi.com platform.kimi.com api.moonshot.cn moonshot.cn', ''],
      ['DeepSeek', 'chat.deepseek.com deepseek.com platform.deepseek.com', ''],
      ['智谱 ChatGLM', 'chatglm.cn bigmodel.cn open.bigmodel.cn', ''],
      ['OpenAI', 'openai.com chatgpt.com platform.openai.com', 'ChatGPT / API'],
      ['MiniMax', 'minimaxi.com', 'minimaxi.com 301 到 minimax.cn；海螺 AI（hailuoai.com）为同公司产品'],
      ['官网表补录', 'xfyun.cn zhipuai.cn minimax.cn hailuoai.com baichuan-ai.com tiangong.cn skywork.ai stepfun.com lingyiwanwu.com klingai.com jimeng.jianying.com anthropic.com claude.ai copilot.com x.ai grok.com perplexity.ai mistral.ai huggingface.co modelscope.cn ollama.com midjourney.com stability.ai runwayml.com suno.com', '来源：CORRECT_SITE_CATALOG 同名大类（2026-11-21 两表合并），均为官网表已核实的官方主机名'],
    ]],

    // ========== 下载与压缩类 ==========
    ['下载与压缩类', [
      ['迅雷', 'xunlei.com dl.xunlei.com mobile.xunlei.com', '迅雷 / 迅雷下载 / 迅雷手机助手'],
      ['IDM', 'internetdownloadmanager.com secure.internetdownloadmanager.com', ''],
      ['BitComet', 'bitcomet.com wiki-zh.bitcomet.com', ''],
      ['WinRAR', 'rarlab.com win-rar.com winrar.com.cn', 'rarlab.com 与 win-rar.com 为同一官网（后者欧洲站），winrar.com.cn 为中国站'],
      ['7-Zip', '7-zip.org', ''],
      ['Bandizip', 'bandisoft.com bandizip.com', ''],
      ['2345好压', 'haozip.2345.cc', ''],
      ['360压缩', 'yasuo.360.cn', ''],
      ['其他压缩', 'winzip.com peazip.com', 'WinZip / PeaZip'],
      ['其他下载器', 'freedownloadmanager.org qbittorrent.org utorrent.com bittorrent.com transmissionbt.com aria2.github.io motrix.app xdown.org', 'FDM / qBittorrent / uTorrent / Motrix 等'],
      ['传输工具', 'putty.org winscp.net filezilla-project.org', 'PuTTY / WinSCP / FileZilla'],
      ['下载站', 'pcsoft.com.cn onlinedown.net duote.com crsky.com zol.com.cn skycn.com xiazaiba.com a67.com greenxf.com rj.baidu.com software.qq.com mydown.com znds.com', '太平洋 / 华军 / 多特 / 中关村在线 / 智能电视网等'],
      ['官网表补录', 'bc.36102025.xyz cometbbs.com peazip.github.io ultraiso.com ezbsystems.com', '来源：CORRECT_SITE_CATALOG 同名大类（2026-11-21 两表合并），均为官网表已核实的官方主机名'],
    ]],

    // ========== 系统工具类 ==========
    ['系统工具类', [
      ['卸载工具', 'crystalidea.com iobit.com revouninstaller.com geekuninstaller.com martau.com hibitsoft.ir bcuninstaller.com', 'Uninstall Tool / IObit Uninstaller / Revo Uninstaller / Geek Uninstaller / Total Uninstall / HiBit Uninstaller / Bulk Crap Uninstaller'],
      ['远程控制', 'todesk.com todeskai.com sunlogin.oray.com oray.com teamviewer.com anydesk.com', 'ToDesk / 向日葵 / TeamViewer / AnyDesk'],
      ['驱动与硬件检测', 'drivergenius.com ludashi.com cpuid.com cpu-z.com hwmonitor.com aida64.com crystaldiskmark.info crystaldiskinfo.info prime95.com geek3d.com memtest86.com techpowerup.com gpuz.com afterburner.com', '驱动精灵 / 鲁大师 / CPU-Z / AIDA64 等（2026-11-12 修正：furmark.com 实为皮草行业站，已换为 FurMark 官网 geek3d.com）'],
      ['整机与主板', 'dell.com hp.com acer.com asus.com xiaomi.com gigabyte.com msi.com asrock.com corsair.com kingston.com logitech.com razer.com coolermaster.com noctua.at nzxt.com seasonic.com antec.com phanteks.com lian-li.com gskill.com teamgroupinc.com adata.com crucial.com micron.com lenovo.com lenovo.com.cn', 'Dell / HP / 华硕 / 微星 / 联想 / 金士顿 等'],
      ['存储与外设', 'samsung.com westerndigital.com seagate.com toshiba.com', '三星 / 西数 / 希捷 / 东芝'],
      ['官网表补录', '160.com hwinfo.com crystalmark.info mersenne.org diskgenius.cn diskgenius.com disktool.cn aomeitech.com rufus.ie ventoy.net voidtools.com ccleaner.com wepe.com.cn asus.com.cn msi.cn gigabyte.cn acer.com.cn logitechg.com razer.com.cn', '来源：CORRECT_SITE_CATALOG 同名大类（2026-11-21 两表合并），均为官网表已核实的官方主机名'],
    ]],

    // ========== 电商与支付类 ==========
    ['电商与支付类', [
      ['阿里系', 'taobao.com tmall.com alibaba.com alimama.com 1688.com alitrip.com fliggy.com cainiao.com antgroup.com antfin.com', '淘宝 / 天猫 / 阿里巴巴 / 飞猪 / 菜鸟 / 蚂蚁'],
      ['京东', 'jd.com jd.hk', ''],
      ['拼多多', 'pinduoduo.com pdd.com xunmeng.com', ''],
      ['美团系', 'meituan.com dianping.com waimai.meituan.com koubei.com ele.me', '美团 / 大众点评 / 口碑 / 饿了么'],
      ['苏宁 / 国美', 'suning.com gome.com.cn', ''],
      ['二手与导购', 'goofish.com smzdm.com fanli.com whatsmoney.com haitao.com kaola.com xiji.com', '闲鱼 / 什么值得买 / 返利网 / 考拉 等（2026-11-12 移除 returnbuy.com：域名已挂出售停放页）'],
      ['电商长尾', 'dangdang.com book.com amazon.cn amazon.com jumei.com vancl.com yhd.com yhd.jd.com yihaodian.com vip.com vipshop.com sasa.com sephora.cn uniqlo.com hm.com zara.com nike.com adidas.com.cn li-ning.com anta.com 361.com xtep.com erke.com 55bbs.com moonbasa.com mi.com', '当当 / 亚马逊 / 唯品会 / 优衣库 / 耐克 等（2026-11-12：1 号店已并入京东，补 yhd.jd.com；移除 peerless.com——它是美国嵌入式系统公司，与「匹克」无关）'],
      ['美妆与健康', 'kimiss.com onlylady.com yoka.com pclady.com 39.net 120ask.com', ''],
      ['支付平台', 'alipay.com alipayplus.com open.alipay.com p.alipay.com zhifubao.com unionpay.com unionpayintl.com up.com.cn chinapay.com 95516.com', '支付宝 / 银联 / 银联国际 / 中国银联在线'],
      ['微信支付', 'pay.weixin.qq.com api.mch.weixin.qq.com api2.mch.weixin.qq.com payapp.weixin.qq.com api.wechatpay.cn api2.wechatpay.cn', '支付中转页 / 商户 API'],
      ['官网表补录', 'tmall.hk temu.com sephora.com uniqlo.cn zara.cn nike.com.cn adidas.com', '来源：CORRECT_SITE_CATALOG 同名大类（2026-11-21 两表合并），均为官网表已核实的官方主机名'],
    ]],

    // ========== 地图与出行类 ==========
    ['地图与出行类', [
      ['百度地图', 'map.baidu.com', ''],
      ['高德系', 'amap.com gaode.com autonavi.com ditu.amap.com mobile.amap.com', ''],
      ['腾讯地图', 'map.qq.com', ''],
      ['滴滴出行', 'didiglobal.com', ''],
    ]],

    // ========== 开发者与云服务类 ==========
    ['开发者与云服务类', [
      ['阿里云', 'aliyun.com aliyuncs.com alibabacloud.com', ''],
      ['腾讯云', 'cloud.tencent.com tencentcloud.com', ''],
      ['华为云', 'huaweicloud.com huawei.com', ''],
      ['百度智能云', 'cloud.baidu.com intl.cloud.baidu.com', ''],
      ['代码托管', 'github.com gitee.com gitlab.com github.dev githubcopilot.com githubassets.com githubusercontent.com', 'GitHub / Gitee / GitLab 及资源域'],
      ['技术社区', 'csdn.net oschina.net juejin.cn v2ex.com cnblogs.com blogjava.net iteye.com talkwithtrend.com stackoverflow.com', ''],
      ['教程与题库', 'runoob.com w3school.com.cn w3cschool.cn tool.oschina.net c.runoob.com freecodecamp.org code.org leetcode.cn leetcode.com leetcode-cn.com', '菜鸟教程 / W3School / LeetCode'],
      ['编程教育', 'codemao.cn shequ.codemao.cn codechat.codemao.64mowan.top', '编程猫'],
      ['工具站', 'tool.lu 52pojie.cn 52pojie.com ghxi.com crxsoso.com appinn.com 51cto.com', '吾爱破解 / 果核剥壳 / 异次元 / 小众软件'],
      ['站长联盟与统计', 'admin5.com im286.com a5.net webmasterhome.cn cnzz.com umeng.com talkingdata.com mob.com bugly.qq.com getui.com', '站长之家 / 阿里妈妈 / 友盟 / TalkingData / 个推'],
      ['测速与 IP', 'ipip.net ip.cn whatismyip.com ip138.com boce.com chinaz.com', ''],
      ['设计素材', 'ui.cn zcool.com.cn poocss.com aigei.com', ''],
      ['语言与框架', 'python.org nodejs.org golang.org rust-lang.org php.net java.com oracle.com vuejs.org reactjs.org', ''],
      ['操作系统发行版', 'ubuntu.com debian.org archlinux.org fedoraproject.org centos.org opensuse.org kali.org kali-linux.com deepin.org ubuntukylin.com uniontech.com uos.com linglong.cn', 'Ubuntu / Debian / Arch / Fedora / CentOS / Kali / 深度 / 统信 UOS'],
      ['数据库与中间件', 'mysql.com mariadb.org postgresql.org mongodb.com redis.io nginx.org nginx.com apache.org', ''],
      ['建站程序', 'wordpress.org typecho.org hexo.io discuz.net phpwind.com zblogcn.com dedecms.com phpcms.com empirecms.com', ''],
      ['文档站', 'readthedocs.io gitbook.io', ''],
      ['编辑器与 IDE', 'notepad-plus-plus.org sublimetext.com jetbrains.com code.visualstudio.com visualstudio.com atom.io', ''],
      ['官网表补录', 'w3schools.com go.dev react.dev wordpress.com gitbook.com', '来源：CORRECT_SITE_CATALOG 同名大类（2026-11-21 两表合并），均为官网表已核实的官方主机名'],
    ]],

    // ========== 游戏与加速器类 ==========
    ['游戏与加速器类', [
      ['腾讯游戏', 'wegame.com.cn wegame.com game.163.com neteasegames.com tencentgames.com', ''],
      ['Steam 与 PC 平台', 'steamchina.com store.steamchina.com help.steamchina.com steampowered.com steamgames.com epicgames.com gog.com origin.com ea.com ubisoft.com uplay.com', ''],
      ['主机平台', 'playstation.com xbox.com nintendo.com battle.net blizzard.com', ''],
      ['拳头与二次元', 'riotgames.com leagueoflegends.com genshin.com mihoyo.com hoyoverse.com taptap.com taptap.cn', ''],
      ['Minecraft', 'minecraft.net minecraft.wiki mojang.com', ''],
      ['主机模拟器', 'rpcs3.net rpcs3.org pcsx2.net ppsspp.org yuzu-emu.org ryujinx.org cemu.info dolphin-emu.org citra-emu.org duckstation.org xenia.jp', 'RPCS3 / PCSX2 / PPSSPP / Yuzu / Ryujinx 等'],
      ['游戏社区', 'curseforge.com cngal.org bangumi.tv bgm.tv animenewsnetwork.com myanimelist.net acg.178.com 17173.com duowan.com nga.cn wowar.com wowhead.com mcmod.cn battlelog.battlefield.com', 'NGA / 多玩 / 17173 / CurseForge / MC百科 等'],
      ['加速器', 'uu.163.com xunyou.com leigod.com qiyou.cn yuelun.com xianniu.com jiasu.bohe.com fnjiasu.com golinkcn.com xiaoheihe.cn acc.xiaoheihe.cn tmgalite.qq.com nn.com akspeedy.com', 'UU / 迅游 / 雷神 / 奇游 / 小黑盒 等'],
      ['官网表补录', 'steamcommunity.com nintendo.com.hk miyoushe.com', '来源：CORRECT_SITE_CATALOG 同名大类（2026-11-21 两表合并），均为官网表已核实的官方主机名'],
    ]],

    // ========== 新闻与搜索类 ==========
    ['新闻与搜索类', [
      ['搜索引擎', 'bing.com sogou.com so.com soso.com yahoo.com duckduckgo.com ask.com', 'Bing / 搜狗 / 360搜索 / Yahoo / DuckDuckGo'],
      ['门户与综合', 'baidu.com baidu.cn toutiao.com 163.com sina.com.cn sina.com china.com', ''],
      ['中央媒体', 'people.com.cn xinhuanet.com cctv.com cctv.cn chinanews.com.cn china.org.cn cnr.cn cri.cn cntv.cn huanqiu.com globaltimes.com.cn', '人民 / 新华 / 央视 / 中新 / 环球'],
      ['财经媒体', 'thepaper.cn yicai.com caixin.com caixin.com.cn stcn.com cs.com.cn jrj.com.cn eastmoney.com 21jingji.com 21cbh.com wallstreetcn.com cls.cn fx168.com', '澎湃 / 第一财经 / 财新 / 证券时报 / 东方财富 等'],
      ['科技媒体', 'yesky.com zdnet.com.cn pconline.com.cn it168.com pcpop.com donews.com techweb.com.cn leiphone.com 36kr.com huxiu.com ifanr.com pingwest.com qdaily.com jiemian.com lanjinger.com', ''],
      ['综合互联网', 'guokr.com mozhua.net jiakaobaodian.com', '果壳 / 墨花 / 驾考宝典（2026-11-12 移除 zhangyu.com：掌阅官网是 zhangyue.com，此域归属未确认）'],
      ['地方媒体', 'bjnews.com.cn bjd.com.cn eastday.com news365.com.cn southcn.com gdtoday.com zjol.com.cn jschina.com.cn yangtse.com sdnews.com.cn dzwww.com qlwb.com.cn dahe.cn hnby.com.cn hebnews.cn yzdsb.com.cn voc.com.cn hnrednet.cn cnhubei.com scol.com.cn sctv.com fjsen.com sxdaily.com.cn cnwest.com ahwang.cn anhuinews.com jxnews.com.cn lnrb.com.cn hljnews.cn hrbrent.com.cn jlnews.com.cn gog.cn gzdaily.com.cn yunnan.cn hinews.cn hndaily.cn gansudaily.com.cn gscn.com.cn qhnews.com.cn nxnet.cn nxdaily.com ts.cn nmgnews.com.cn nmrb.com.cn gxnews.com.cn gxrb.com.cn sxrb.com sxgov.cn cqnews.net cqwb.cn tjnews.cn enorth.com.cn tibet.cn nbweekly.com', '各省党报 / 都市报 / 新闻网'],
      ['官网表补录', 'yahoo.co.jp cgtn.com yicaiglobal.com caixinglobal.com kr-asia.com', '来源：CORRECT_SITE_CATALOG 同名大类（2026-11-21 两表合并），均为官网表已核实的官方主机名'],
    ]],

    // ========== 教育与考试类 ==========
    ['教育与考试类', [
      ['全国招生平台', 'chsi.com.cn moe.gov.cn cer.net ncss.cn chaoxing.com', '学信网 / 阳光高考 / 教育部 / 超星'],
      ['省级考试院', 'bjeea.cn zhaokao.net hebeea.edu.cn sxkszx.cn zsks.cn lnzsks.com jleea.com.cn jleea.edu.cn lzk.hl.cn hljea.cn shmeea.edu.cn jseea.cn zjzs.net ahzsks.cn eeafj.cn jxeea.cn sdzk.cn haeea.cn hbea.edu.cn hubzs.com.cn hneao.cn hneeb.cn gd.gov.cn gxeea.cn hainan.gov.cn cqksy.cn sceea.cn guizhou.gov.cn ynzs.cn sneac.com sneea.cn ganseea.cn gszs.edu.cn qhjyks.com nxjyks.cn xjzk.gov.cn hunan.gov.cn xizang.gov.cn eea.gd.gov.cn', '各省教育考试院 / 招生考试院（2026-11-12：广东省考试院原写 eeagd.edu.cn 不可达，已换为实测真站 eea.gd.gov.cn；其中的 hainan/guizhou/hunan/xizang 为省政府门户，考试院在其子域）'],
      ['培训与留学', 'eol.cn eol.com.cn cnedu.cn kaoyan.com kaoyan365.com yuloo.com studyabroad.com.cn liuxue.com applysquare.com zhixue.com xueersi.com neworiental.org xdf.cn koolearn.com tpedutest.com baijia.com aofan.com zikao365.com', '中国教育在线 / 考研 / 学而思 / 新东方 / 自考365（2026-11-12：baijia.com 实测跳 about.gaotu.cn，是高途集团；liuxue.com 实测跳 admin.qz100.com，疑似易主）'],
      ['高校', 'edu.cn cuc.edu.cn bit.edu.cn tsinghua.edu.cn pku.edu.cn fudan.edu.cn sjtu.edu.cn zju.edu.cn nju.edu.cn ustc.edu.cn sysu.edu.cn whu.edu.cn hit.edu.cn scut.edu.cn', ''],
      ['官网表补录', 'tal.com gaotu.cn', '来源：CORRECT_SITE_CATALOG 同名大类（2026-11-21 两表合并），均为官网表已核实的官方主机名'],
    ]],

    // ========== 金融类 ==========
    ['金融类', [
      ['银行', 'icbc.com.cn abchina.com boc.cn ccb.com bankcomm.com psbc.com.cn cmbchina.com cmbc.com.cn cib.com.cn citicbank.com spdb.com.cn cebbank.com bank.pingan.com hxb.com.cn cgbchina.com.cn czbank.com cbhb.com.cn eximbank.gov.cn cdb.com.cn adbc.com.cn bankofbeijing.com.cn bosc.cn jshbchina.com njcb.com.cn nib.com.cn hzbank.com.cn qdccb.com.cn bankofdl.com xmccb.com tccb.com.cn hrbcb.com.cn bankofgy.com.cn ccbank.cn cqcbank.com zzbank.cn cscb.cn suzhoubank.com lzbank.com nccbank.com.cn hebbank.com qlbank.com.cn whccb.com.cn sxccb.com.cn jinzhoubank.com.cn bsbchina.com lhbchina.com srcb.com.cn bjrcb.com.cn gzrcbank.com cqrcb.com.cn dongguanbank.cn hzcbank.com.cn jxbank.com.cn bhb.cn jcbank.com.cn bohs.cn jhccb.com.cn hsbank.com.cn', '政策性 / 国有大行 / 股份制 / 城商 / 农商'],
      ['外资银行', 'hsbc.com.cn citibank.com.cn sc.com standardchartered.com.cn hangseng.com.cn bnpparibas.com.cn jpmorgan.com.cn ubs.com mufg.jp mizuhobank.com ocbc.com uob.com.sg maybank.com bankofamerica.com deutschebank.com.cn ing.com rabobank.com db.com', '汇丰 / 花旗 / 渣打 / 摩根 / 瑞银 等'],
      ['银行客服短号', '95588.com 95599.com 95555.com 95533.com 95559.com 95561.com 95595.com 95568.com 95528.com 95580.com 95577.com 400.com', '工行 / 农行 / 招行 / 建行 等客服站'],
      ['证券', 'guosen.com.cn gf.com.cn gtja.com htsec.com csc108.com swhy.com cicc.com.cn cijsc.com.cn zts.com.cn ebscn.com gyzq.com.cn dgzq.com.cn htzq.com.cn jyzq.com.cn dwzq.com.cn qlzq.com.cn sxzb.com.cn i618.com.cn newone.com.cn cmschina.com tfzq.com.cn huatai.com hongyuan.com chinalongsun.com lhzq.com.cn yzq.newone.com.cn haitong.com guotaijunan.com shdjt.com stocke.com sw2000.com.cn swhysc.com cs.ecitic.com citic.com china-invs.cn orientsec.com.cn wzq.com.cn xzq.com.cn citics.com citic-tai.com ctitic.com', '国信 / 广发 / 国泰君安 / 海通 / 中信 / 华泰 等'],
      ['保险与基金', 'china-life.com.cn picc.com piccnet.com.cn cpic.com cpic.com.cn taikang.com taikang.com.cn pingan.com pa18.com ccic-net.com.cn sinosig.com sunlife.com.cn metlife.com.cn aia.com.cn allianz.com.cn generali.com.cn chubb.com fwd.com manulife.com.cn prudential.com.hk pru.com.hk chinaamc.com eestone.com jjmmw.com fund.eastmoney.com tiantianfunds.com licai.com chinafund.cn csfunds.com.cn wtfund.com ourku.com', '国寿 / 人保 / 太保 / 平安 / 泰康 / 华夏基金 等（2026-11-12：中国大地保险原写 ccic.com.cn，那是中国检验认证集团，已换为 ccic-net.com.cn）'],
      ['期货与交易所', 'cffex.com.cn shfe.com.cn dce.com.cn czce.com.cn ine.com.cn cme.com', '中金所 / 上期所 / 大商所 / 郑商所 / 能源中心'],
      ['资管与 AMC', 'huarong.com amc.cinda.com gxfc.com.cn', '华融（已更名中信金融资产）/ 信达 / 国海证券（gxfc 原归在此，实为券商）'],
      ['官网表补录', 'icbcasia.com bochk.com hsbc.com hangseng.com gtht.com chinalife.com.cn cinda.com.cn', '来源：CORRECT_SITE_CATALOG 同名大类（2026-11-21 两表合并），均为官网表已核实的官方主机名'],
    ]],

    // ========== 企业机构类 ==========
    ['企业机构类', [
      ['通信运营商', '10086.cn 10010.com 189.cn 10000.com chinamobile.com chinaunicom.com chinatelecom.com cmcc.com chinamobileltd.com chinaunicom.com.hk ctm.com.mo cmhk.com one2free.com pccw.com smartone.com three.com.hk csl.com 1010.com cmlink.com', '移动 / 联通 / 电信 / 广电及港澳运营商'],
      ['能源电力', 'cnpc.com petrochina.com.cn sinopec.com cnooc.com cnpc.com.cn shenergy.com huadian.com chng.com.cn spic.com.cn cgdc.com.cn cgnpc.com.cn statepower.com.cn guodian.com ceec.net.cn chinapower.com.cn', '中石油 / 中石化 / 中海油 / 华能 / 大唐 / 国电投 等'],
      ['钢铁有色', 'baosteel.com shsteel.com ansteel.com wusteel.com hbisco.com shougang.com taigang.com chinalco.com chalco.com.cn jiangxi-copper.com tongling.com yunlu.com zijinmining.com cmoc.com jnyl.com yanzhoucoal.com china-coal.com shenhua.com camce.com powerchina.cn', '宝武 / 鞍钢 / 中国铝业 / 江西铜业 / 紫金 等'],
      ['化工', 'chemchina.com sinochem.com syngenta.cn yara.com bluestar.com wanhua.com haihua.com', '中国化工 / 中化 / 先正达 / 万华'],
      ['汽车', 'saicmotor.com faw.com dongfeng.com geely.com chery.cn greatwallmotor.com byd.com gac.com.cn gac-toyota.com gac-honda.com bmw.com.cn benz.com.cn audi.cn volkswagen.com.cn toyota.com.cn honda.com.cn nissan.com.cn ford.com.cn gm.com.cn hyundai.com.cn kia.com.cn mazda.com.cn subaru.com.cn mitsubishi.com.cn volvo.com.cn tesla.cn nio.cn xpeng.com lixiang.com wmotor.com levdeo.com enovate.com arcfox.com', '上汽 / 一汽 / 东风 / 比亚迪 / 蔚小理及合资品牌'],
      ['家电', 'haier.com hisense.com tcl.com skyworth.com gree.com midea.com meidi.com changhong.com konka.com galanz.com robam.com vatti.com oppel.com supor.com joyoung.com casarte.com leader.com littleswan.com beko.com', '海尔 / 海信 / TCL / 格力 / 美的 / 老板 等'],
      ['央企综合', 'sasac.gov.cn china-mae.com csg.cn sgcc.com.cn', '国资委 / 国机集团 / 南方电网 / 国家电网'],
      ['航空与铁路', 'airchina.com csair.com ceair.com muair.com shenzhenair.com hainanairlines.com xiamenair.com shanghaiair.com springairlines.com juneyaoair.com westair.cn okair.net chinaexpressair.com 12306.cn china-railway.com.cn crh.com.cn railway.com.cn tiqianx.com mtr.com.hk', '国航 / 南航 / 东航 / 12306 / 港铁 等'],
      ['物流快递', 'sfbchina.com sf-express.com zto.com yto8000.com yundaex.com sto.cn jt-express.com deppon.com dblogistics.com ems.com.cn china-post.com.cn post.com.cn yimidida.com huolala.com kuaibao.com zhongtong.com yunda.com shentong.com youzheng.com.cn', '顺丰 / 中通 / 圆通 / 韵达 / 申通 / 德邦 / 中国邮政 等'],
      ['地产与建筑', 'vanke.com countrygarden.com evergrande.com poly.com.cn cem.com.cn crland.com.hk longfor.com greentown.com.cn seazen.com.cn sunac.com.cn gemdale.com logan.com.hk shimao.com rsh.com.cn zhongliang.com zhongjun.com agile.com.cn bgy.com.cn csc.com.cn cscec.com crec.com crcc.cn ccccltd.cn cmc.com.cn cnccc.com xcmg.com zoomlion.com sany.com liugong.com sunward.com bjjs.com shfc.gov.cn szhome.com', '万科 / 碧桂园 / 保利 / 中建 / 中铁 / 徐工 / 三一 等（2026-11-12 移除 zoomliion.com：zoomlion 的错拼抢注域，正确域 zoomlion.com 已收录）'],
      ['医疗医药', 'nmpa.gov.cn nhc.gov.cn chinacdc.cn icdc.cn pharmnet.com.cn yaozh.com dxy.com dxy.cn haodf.com xywy.com familydoctor.com.cn jkkp.com jianke.com 111.com.cn yao123.com yaofang.cn medsci.cn biocompare.com bioon.com syphu.com sphic.com sinopharm.com unionmed.com snp.com.cn cspc.com hualanbio.com wantai.com kangtai.com zhifeishengwu.com fosunpharma.com hutian.com nhwa.com hansoh.cn hengrui.com 3sbio.com innobic.com minhai.com bchot.com tongfang.com jxqx.com zjgpharma.com zhejiangdisease.com', '药监 / 疾控 / 丁香园 / 国药 / 石药 / 恒瑞 等'],
      ['旅游与酒店', 'ctrip.com trip.com qunar.com elong.com ly.com tuniu.com mafengwo.cn lvmama.com 17u.cn tongcheng.com easemob.com huazhu.com jinjiang.com btg.com.cn homeinns.com 7daysinn.com vn.hotels.com marriott.com hilton.com ihg.com accor.com wyndham.com shangri-la.com kempinski.com lv.com visa.com mastercard.cn', '携程 / 去哪儿 / 同程 / 华住 / 万豪 / Visa 等'],
      ['食品饮料与快消', 'moutai.com.cn wuliangye.com.cn luzhoulaojiao.com yanghe.com gujing.com.cn jnc.com.cn niulanshan.com.cn qingdao.com tsingtao.com snowbeer.com.cn yanjing.com.cn zjbeer.com coca-colacompany.com pepsi.com nestle.com.cn nestle.com yili.com yili.com.cn mengniu.com mengniu.cn want-want.com masterkong.com.cn cofco.com beijinghy.com sanxing.com nongfu-spring.com nongfusanquan.com wahaha.com toly.com glico.com meiji.com brightdairy.com sanyuan.com', '茅台 / 五粮液 / 青岛啤酒 / 可口可乐 / 伊利 / 蒙牛 / 农夫山泉 等'],
      ['公共事业与政务', 'waterchina.com bewg.com.cn bdc.com.cn bjwater.com shanghaiwater.com gw.com.cn gas.com.cn chinagashub.com pipechina.com bjgas.com shgas.com gzzhgd.com cin.gov.cn mohurd.gov.cn mohrss.gov.cn mof.gov.cn mofcom.gov.cn ndrc.gov.cn miit.gov.cn samr.gov.cn customs.gov.cn tax.gov.cn', '自来水 / 燃气 / 管网 / 各部委'],
      ['外企中国', 'ibm.com ibm.com.cn intel.com intel.cn amd.com nvidia.com nvidia.cn dell.com.cn hp.com.cn samsung.com.cn lg.com sony.com sony.com.cn panasonic.cn hitachi.com sharp.cn philips.com.cn bosch.com siemens.com ge.com ge.com.cn honeywell.com 3m.com dupont.com basf.com bayer.com novartis.com pfizer.com roche.com gsk.com jnj.com unilever.com pg.com danone.com ikea.com ikea.cn carrefour.com walmart.com walmart.cn metro.com.cn auchan.com rt-mart.com yum.com kfc.com.cn yumchina.com mcd.com.cn starbucks.com.cn uni-president.com jnsn.com', 'IBM / Intel / 英伟达 / 索尼 / 西门子 / 宜家 / 麦当劳 等'],
      ['官网表补录', 'chinatelecom.com.cn sinopecgroup.com.cn 95598.cn shasteel.com dfmc.com.cn gwm-global.com gacgroup.com gacmotor.com midea.cn galanz.com.cn airchina.com.cn chinapost.com.cn crland.com.cn crec.cn sany.com.cn chinacdc.com yaofang.com medsci.com fosun.com hworld.com jinjianghotels.com tsingtao.com.cn pepsico.com bosch.com.cn dupont.cn bayer.com.cn novartis.com.cn pfizer.com.cn jnj.com.cn unilever.com.cn pg.com.cn danone.com.cn carrefour.com.cn mcdonalds.com.cn starbucks.com', '来源：CORRECT_SITE_CATALOG 同名大类（2026-11-21 两表合并），均为官网表已核实的官方主机名'],
    ]],

    // ========== 平台与生态类 ==========
    ['平台与生态类', [
      ['静态托管与 PaaS', 'vercel.com vercel.dev netlify.com cloudflare.com cloudflare-cn.com render.com heroku.com replit.com', '厂商官网本体（用户内容子域另见 TRUSTED_PLATFORMS）'],
      ['证书与认证', 'letsencrypt.org digicert.com sectigo.com globalsign.com ssl.com entrust.com geotrust.com thawte.com verisign.com identrust.com zerossl.com', 'CA 与证书链'],
      ['人机验证与前端 CDN', 'hcaptcha.com recaptcha.net gstatic.com googleapis.com', 'reCAPTCHA / hCaptcha / Google 静态资源'],
      ['项目自有站点', 'silverfoxguard.dpdns.org silverfoxguard.top workbuddy.cn', 'SilverFox Guard 分发页 / WorkBuddy 官网'],
      ['开发者个人站', 'cloud.gjhdr.xyz', '个人开发者凯德荣官方域'],
      ['官网表补录', 'globalsign.cn workbuddy.ai', '来源：CORRECT_SITE_CATALOG 同名大类（2026-11-21 两表合并），均为官网表已核实的官方主机名'],
    ]],

    // ========== 用户反馈与个人站点类 ==========
    ['用户反馈与个人站点类', [
      ['个人站点', 'technologyehco.us.ci lycheeledger.cn 0bcjstko9509h.space.mcode.cn uiso44xg1go9p.space.mcode.cn ae0kcokdy1z45.space.mcode.cn 360.xiaomai.cc.cd d.seewo.com', '评论区 / Issues 反馈确认加白'],
      ['误报反馈加白', '8kmm.com bingdiancn.com geogebra.org gunsaw-level-codes.jimmyking.dev jfglzs.com mcapks.net mumu-dili.pages.dev shijuezu.com sparanoid.com spestech.com store.rg-adguard.net bbs.kafan.cn', '用户报告的合法站点'],
    ]],

    // ========== 用户指定信任（整站跳过检测）==========
    // ⚠️ 语义说明：本大类等价于旧版的 EXCEPTION_DOMAINS / 官方白名单，
    //   命中即「早期退出」——不评分、不拦截、不参与连坐、不参与下载计数。
    //   只放用户明确要求放行的站点，且必须是该站点真实持有者/使用者提出的。
    ['用户指定信任', [
      ['个人站点', 'example.com', ' 用户指定（示例域名）'],
    ]],

    // ========== 与「访问正确的页面」官网表（CORRECT_SITE_CATALOG）的合并（2026-11-21）==========
    // 背景：两张表长期各自维护，官网表 20 个大类、1115 个主机名级站点，白名单却只覆盖其中一部分，
    //   结果「官网表说这是官网、白名单却当陌生站检测」——两份数据自相矛盾。
    // 本轮做了**单向合并**：官网表里有、白名单里没有的主机名级站点，按同名大类补进本表，
    //   每个大类末尾新增一行 `['官网表补录', '域名…', '来源：…']`，共 18 个大类 138 个主机名
    //   （白名单主机名 1347 → 1485）。用户反馈与个人站点类两表本来就一致，没有补录行。
    // 合并规则（以后同步时照此执行，避免把两表又改歪）：
    //   · 只搬**主机名级**站点（不带路径的域名）；主机名统一小写并去掉前导 `www.`
    //     —— 白名单按「精确 + 标签对齐后缀」匹配，查询侧也会先去掉 www.，写 `www.temu.com`
    //     只会放行 www.temu.com 这一个写法、放不过 temu.com，统一写成 `temu.com`。
    //   · 已经能被白名单现有条目覆盖的主机名（自身或父域在表里）不重复写，否则控制台会刷
    //     「域名重复归类」告警，且首次出现生效的语义会让重复项静默失效。
    //   · 反向不搬：白名单里那些「只信任、不对外称官网」的站点（社区反馈、镜像、个人站）
    //     没有品牌词可映射，写进官网表只会污染按钮的候选列表。
    // ★ **链接级官网一律不复制**（本轮 13 条全部跳过）。原因：白名单是主机名粒度的
    //   「整站免检」，表达不了路径；把 `https://github.com/pbatard/rufus/releases` 这种条目
    //   降级成主机名 `github.com` 塞进来，等于放行 GitHub 上**任何人**的仓库与用户页，
    //   正是钓鱼站最爱蹭的托管域，绝不能整站免检。
    //   这 13 条的落点分两类：
    //     · 主机名本来就在白名单里（github.com / google.com / apple.com / browser.360.cn /
    //       cloud.tencent.com / sep.securitycloud.symantec.com / hk.maxthon.com）——无需处理，
    //       按钮直接打开具体路径，白名单按主机名照常命中；
    //     · 主机名不在白名单里（broadcom.com、git.hiwiki.org、chiark.greenend.org.uk、
    //       codebuddy.cn）——**故意不加**，其中 broadcom.com 是赛门铁克被收购后的企业站入口、
    //       codebuddy.cn 是 WorkBuddy 的下载路径，整站放进白名单的收益远小于「多一个可被托管
    //       任意内容的大域免检」的风险；这几个入口只通过「访问正确的页面」按钮到达，
    //       用户手动访问主站时照常走检测（正常企业站本来也不会被拦）。
    //   · 副作用备忘：白名单域名会自动派生成仿冒词（取紧邻 TLD 的标签、长度 ≥4 且非通用词），
    //     所以本轮补进来的 temu / grok / suno / mega / dropbox 等会成为新的仿冒词，
    //     `temu-shop.top` 这类域名从此能命中「域名段精确匹配品牌词」。这是预期收益；
    //     短标签（x.ai 的 x、pg.com.cn 的 pg、jnj.com.cn 的 jnj）不足 4 字符，不会进仿冒词库。
  ];

  // ============ 「访问正确的页面」官网映射（2026-11-12）============
  // 用途：拦截浮层上的「访问正确的页面」按钮，把用户送到被仿冒品牌的**真实官网**。
  //   被拦的是仿冒域（huorongsafe.com.cn 这类），它永远不在白名单里，因此不能用白名单反查；
  //   只能反过来做「品牌词 → 官网」的映射：从被拦主机名里认出品牌，再给出该品牌的官网。
  //
  // 结构：CORRECT_SITE_CATALOG = [ [大类, [ [产品名, 品牌词, 正确域名, 备注], … ]], … ]
  //   · 产品名  —— 只给人看（说明页标题用它，用于维护与排查）
  //   · 品牌词  —— 空格分隔，可多个；**小写 ASCII 片段**，命中主机名即认为「这是该品牌」
  //   · 正确域名 —— 必须是一个真实可达的官网主机名（不带协议 / 路径）
  //   · 备注    —— 同品牌的其它官方域名、验证结论、⚠️ 存疑项（存疑项同时记在 rules/.README.md）
  //
  // ★ 2026-11-18：第三个字段升级为「可写多个站点」，三种写法都合法（旧写法行为不变）：
  //   'huorong.cn'                                    ← 单站点，主机名级（旧写法，兼容）
  //   ['win-rar.com', 'rarlab.com']                   ← 多站点，全部主机名级
  //   ['win-rar.com', { url: 'http://www.winrar.com.cn', label: '中国官网' }]
  //   站点规格（数组元素）两种形态：
  //     · 字符串：'example.com' 或 'https://example.com/download'
  //         —— 不带路径 = 主机名级；带路径 / 查询串 = 链接级（如 GitHub Releases 页面）
  //     · 对象：{ url, label, kind }
  //         url   必填，可省略协议（默认补 https://），只允许 http / https
  //         label 可选，自定义文案（如「中国官网」「GitHub 发布页」）；留空时由说明页自动编号
  //         kind  可选，'host' | 'link'；留空时按 url 有没有路径自动判断
  //   ⚠️ **不支持** [url, label] 这种两元素数组简写：`['a.com','b.com']` 到底是两个站点还是
  //      「站点 + 文案」无法区分，容易把官网写成标签。要文案请用对象形态。
  //   ⚠️ 主机名级只保证「这是官网域名」；链接级必须自己确认路径仍然有效（站点改版会 404）。
  //   两个字段最终都会进 CORRECT_DOMAIN_MAP[品牌词].sites，顺序即说明页展示顺序；
  //   `.domain` 仍保留为「第一个主机名级站点」，供只需要一个域名的旧调用方使用。
  //
  // ★ 2026-11-22：新增**可选的第 5 个字段「关联品牌词」**（rel）—— 一个品牌词带出同一产品的其他版本：
  //   ['qBittorrent', 'qbittorrent', ['qbittorrent.org'], '…', ['qbittorrent-enhanced']]
  //   合并时会把对方条目**自己的**站点追加到本条目末尾，并打上 group（对方产品名）；说明页据此
  //   渲染成「相关：qBittorrent Enhanced Edition」小节，标题仍是本条目产品名。
  //   · 双向生效：A 写了 B，B 也自动认 A —— 只补一边不会出现「点 A 看得到 B、点 B 看不到 A」。
  //   · 去重与上限不变：按 url 去重，合并后仍受 8 条上限，自己条目的站点永远排在前面。
  //   · 跨数据源（2026-11-22 方案二）：iocs 里的合并只发生在「内置表内部」；analyzer 拿到
  //     「内置 + 云端」合并表后会**再跑一遍**同一套规则（读 IOCS.CORRECT_SITE_RELATIONS），
  //     因此 rel 也能连到只存在于云端补录里的条目。两边都跑是幂等的（按 url 去重）。
  //   · 用途边界：只连「同一产品的不同发行版 / 官方分支」。同公司不同产品（如 uTorrent 与
  //     BitTorrent）不要连 —— 那会让页面标题和列表自相矛盾，用户反而更容易点错。
  //   · 2026-11-22 第十一轮扩围：除「发行版 / 官方分支」外，也连「同一产品的区域版 / 国际版」——
  //     飞书 ↔ Lark、Steam ↔ 蒸汽平台、抖音 ↔ TikTok、支付宝 ↔ 支付宝国际、银联 ↔ 银联国际。
  //     判据：两者是**同一个产品**的两套站点（共用账号体系 / 同一品牌授权 / 表里已自称「国际版」），
  //     用户被拦在任一方的仿冒站上时，看到对方的官网是有用的。
  //     同公司但不同产品（微信 ↔ QQ、淘宝 ↔ 天猫、百度 ↔ 百度网盘、阿里云 ↔ 阿里云盘、
  //     360 安全卫士 ↔ 360 极速浏览器）仍然不连。
  //
  // 品牌词匹配规则（analyzer.js 的 resolveCorrectDomain 实现）：
  //   1) 主机名小写、去掉前导 www. 后，逐个品牌词做**子串查找**；
  //   2) 品牌词左侧必须是「标签边界」（开头 / `.` / `-` / `_`），避免 myhuorong.com 这类前缀粘连；
  //      右侧不限（huorongsafe / huorong-safe / huorong1 都能命中，仿冒站正是在品牌词后加后缀）；
  //   3) 长度 ≤ 3 且不含数字的品牌词额外要求右侧是非字母（`qq` 命中 qq.com / qq2013.com，但不命中 qqq.com；
  //      `360` 这类含数字的品牌词不受此限，否则 360safe.com 会漏）；
  //   4) 多个品牌词同时命中时**取最长的那一个**（sogoubrowser 优先于 sogou），再按本表顺序取先出现的；
  //   5) 同一品牌词在本表里出现多次时，只有第一次生效（重复项仅作文档，不会覆盖）。
  //   ⚠️ 品牌词不要写 `com` `cn` `www` `mail` `office` 这类通名：会把无关站点错指到某品牌官网。
  //   ⚠️ 通配符（`*` `?`）在品牌词里没有意义，会按字面处理，不会命中任何真实主机名。
  //
  // 与白名单的关系：本表**不参与**任何放行/拦截判定，只服务这一个按钮。
  //   白名单（WHITELIST_CATALOG）决定「谁不用检测」，本表决定「被拦之后该去哪儿」。
  //   两者数据源相同但用途不同，故意分开维护：白名单要求「整站可信」，本表只要「官网能用」。
  //
  // 收录范围：安全软件类 / 浏览器类 / IM 与社交类 / 输入法类 / 办公与文档类（第一轮）；
  //   影音娱乐类 / 云盘与存储类 / AI 大模型类 / 下载与压缩类 / 系统工具类（第二轮）。
  //   其余大类（电商、出行、金融、政务…）下一轮再补，不影响本表按大类追加。
  //
  // ★ 2026-11-21（第二轮）：办公与文档类 / 影音娱乐类 / 云盘与存储类 / AI 大模型类
  //   已逐条判定「是否存在不止一个官网」，存在多个的已拆成多站点。
  //   判定标准：主域或子域**各自独立成页**（标题 / 内容 / 会员体系不同）才算第二个官网；
  //   纯 301 跳到同一页的只当别名，写进备注而不单列（如 hotmail.com、imgo.tv、yiyan.baidu.com）。
  //   「国际版 / 中国站 / 开放平台 / 公司官网」都算独立站点 —— 用户点进去看到的是不同页面。
  //
  // ★ 2026-11-21（第三轮）：下载与压缩类 / 系统工具类 / 地图与出行类（跳过电商与支付类）。
  //   同一轮把 Microsoft 365 的 office.com → m365.cloud.microsoft 跳转写进备注，
  //   并给该条补了两个品牌词 `m365` / `cloud.microsoft`（品牌词总数 1052 → 1054）。
  //   新增条目前务必先查重 —— 携程 / 去哪儿 / 12306 已在「企业机构类」注册过，
  //   在别的大类再写一次会被判重忽略（控制台会打印「品牌词重复」），只能在原条目上补站点。

  // ★ 2026-11-21（第四轮）：电商与支付类 / 开发者与云服务类 / 游戏与加速器类。
  //   本轮只改已有条目的站点，不新增品牌词（条目数 968、品牌词 1054 均未变）。
  //   顺手修正两个过时主域：React reactjs.org → react.dev、GitBook gitbook.io → gitbook.com。
  //   多站点判定同前：标题 / 内容不同才算第二个站；wegame.com 与 wegame.com.cn 标题一致，仍算别名。
  //
  // ★ 2026-11-21（第五轮）：新闻与搜索类 / 教育与考试类 / 金融类。
  //   条目 968 → 969（新增「中国教育考试网」），品牌词 1054 → 1060（含 bank.pingan 这条防抢注词）。
  //   新增品牌词：chinalife（中国人寿主域无连字符）/ cinda（中国信达）/ pingan（中国平安）/
  //     gtht（国泰海通合并后新域）/ neea（中国教育考试网）—— 这几个都是「主域换了，
  //     旧品牌词匹配不到新域名」，不补就会让正确官网自己都查不到映射。
  //   主域修正：高途 baijia.com → gaotu.cn、国泰海通 gtja.com → gtht.com、
  //     中国人寿 china-life.com.cn → chinalife.com.cn、中国信达 amc.cinda.com → cinda.com.cn、
  //     中国平安 pa18.com → pingan.com（旧值均注释保留）。
  //   已复核「同标题 = 同一站」，因此不单列：news.cn / xinhuanet.com、chinanews.com(.cn)、
  //     tiantianfunds.com / fund.eastmoney.com、cn.bing.com、paper.people.com.cn。
  //   跨条目指路（避免重复展示）：360.cn 在「360系」、netease.com 在「网易邮箱」、微博单独成条。
  //
  // ★ 2026-11-21（第六轮）：企业机构类 / 平台与生态类 + 云端 correct_sites。
  //   条目数不变（969），品牌词 1060 → 1066：dfmc / hworld / mcdonalds / gacgroup / gacmotor / gwm。
  //   多站点条目：企业机构类 1 → 32 条、平台与生态类 1 → 3 条，全部先实测标题再拆。
  //   ★ 本轮抓到三个「域名已不属于原公司」的硬错误（都是原数据，已改）：
  //     crec.com  → 美国高力国际 Colliers（中国中铁真站是 www.crec.cn）
  //     mcd.com.cn → NXDOMAIN（麦当劳中国真站是 mcdonalds.com.cn）
  //     sany.com  → NXDOMAIN（三一真站是 sany.com.cn）
  //   另修 4 处主域迁移：东风 dongfeng.com → dfmc.com.cn、广汽 gac.com.cn → gacgroup.com、
  //     格兰仕 galanz.com → galanz.com.cn、国航 airchina.com → airchina.com.cn、
  //     华住 huazhu.com → hworld.com、中国石油 cnpc.com → cnpc.com.cn。
  //   经验：新增品牌词若与官网域名不是「整段相等」（如 pingan / mcd / gac / gwm），
  //     边界校验会让官网自己都匹配不到，必须同时补全域名里真正出现的那一段。
  // =====================================================================
  const CORRECT_SITE_CATALOG = [
    // ========== 安全软件类 ==========
    ['安全软件类', [
      ['360', '360', [
        { url: '360.cn', label: '360官网' },
        { url: '360.com', label: '360官网备用路线' },
        { url: 'weishi.360.cn', label: '360安全卫士官网' },
        { url: 'sd.360.cn', label: '360杀毒官网' },
        { url: '360totalsecurity.com', label: '360 Total Security海外官网' }
      ], '手机助手 / 手机卫士 / 安全浏览器同属 360.cn'],
      // 旧（单域名，2026-11-12）：只有主站，官网页面上看不到官方论坛入口
      // ['火绒安全软件', 'huorong', 'huorong.cn', ''],
      // 新（2026-11-22）：主站 + 关联「火绒安全论坛」（第 5 个字段；论坛是同一产品的官方社区站）
      ['火绒安全软件', 'huorong', 'huorong.cn', '官方主站；官方论坛是同一产品的社区站，入口见下方「相关」小节', ['huorongbbs']],
      // 新（2026-11-22）：迁自云端白名单 correct_sites 的「火绒安全论坛 / huorongbbs」
      //   云端原来同时写了 bbs.huorong.cn 与 www.huorong.cn；迁移后只留论坛自己的地址，
      //   回指主站交给上面的 rel（双向），否则同一页会出现 huorong.cn 与 www.huorong.cn 两条重复入口。
      // 备注（2026-11-22）：论坛不是「官网」，文案写成「官方论坛」；标签上限见 CORRECT_LABEL_MAX
      ['火绒安全论坛', 'huorongbbs', [
        { url: 'bbs.huorong.cn', label: '官方论坛' }
      ], '火绒官方社区；冒充论坛的仿冒域（如 huorongbbs.com）点按钮会落到这里'],
      ['腾讯电脑管家', 'guanjia', [
        'guanjia.qq.com',
        'gj.qq.com'
      ], ''],
      ['瑞星杀毒', 'rising', 'rising.com.cn', '瑞星网'],
      ['金山毒霸', 'duba', [
        'duba.net',
        'ijinshan.com'
      ], ''],
      ['卡巴斯基', 'kaspersky', [
        { url: 'kaspersky.com.cn', label: '中国官网' },
        { url: 'kaspersky.com', label: '官网' }
      ], ''],
      ['Bitdefender 比特梵德', 'bitdefender', [
        { url: 'bitdefender.com', label: '官网' },
        { url: 'bitdefender-cn.com', label: '中国官网' }
      ], 'bitdefender-cn.com 为中国官网，提供企业级产品'],
      ['Avast', 'avast', 'avast.com', '与 AVG / 诺顿同属 Gen Digital'],
      ['AVG', 'avg', 'avg.com', '与 Avast / 诺顿同属 Gen Digital；中国大陆用户无法直接访问该网站'],
      ['诺顿 Norton', 'norton', [
        { url: 'norton.com', label: '官网' },
        { url: 'cn.norton.com', label: '中国官网' }
      ], '与 Avast / AVG 同属 Gen Digital'],
      ['ESET', 'eset', 'eset.com', ''],
      ['赛门铁克 Symantec', 'symantec', [
        { url: 'https://www.broadcom.com/products/cybersecurity', label: '企业级产品官网' },
        { url: 'https://sep.securitycloud.symantec.com/v2/landing', label: '备用站点' }
      ], '企业级产品现由 Broadcom 运营'],
      ['Avira 小红伞', 'avira', [
        { url: 'avira.com', label: 'Avira官网' },
        { url: 'iavira.com', label: '爱红伞中国代理商官网' }
      ], ''],
      ['Malwarebytes', 'malwarebytes', 'malwarebytes.com', '中国大陆用户无法直接下载Malwarebytes'],
      ['Dr.Web 大蜘蛛', 'drweb', [
        { url: 'drweb.com', label: '官网' },
        { url: 'drweb.cn', label: '中国官网' }
      ], ''],
      ['McAfee 迈克菲', 'mcafee', 'mcafee.com', ''],
      ['F-Secure', 'f-secure fsecure', [
        { url: 'f-secure.com', label: '个人版官网' },
        { url: 'withsecure.com', label: '企业版官网' }
      ], '中国大陆用户无法下载F-Secure'],
      ['趋势科技 Trend Micro', 'trendmicro', 'trendmicro.com', ''],
      ['Sophos', 'sophos', 'sophos.com', ''],
      ['G DATA 歌德塔', 'gdata', 'gdata-software.com', '白名单已于 2026-11-12 从 gdata.com 修正为 gdata-software.com'],
      ['Comodo 科摩多', 'comodo', 'comodo.com', '企业产品已更名 Xcitium'],
      ['微步在线', 'threatbook', 'threatbook.cn', 'threatbook.com 会 301 跳转到 threatbook.cn'],
      ['VirusTotal', 'virustotal VT', 'virustotal.com', 'VirusTotal 是 Google 旗下的聚合扫描服务平台，提供在线文件 / URL 扫描'],
      ['ANY.RUN', 'any.run anyrun', 'any.run', 'ANY.RUN 云沙箱分析平台，提供在线文件 / URL 扫描'],
      ['AdGuard', 'adguard', [
        { url: 'adguard.com', label: 'AdGuard官网' },
        { url: 'adguard-dns.io', label: 'AdGuard DNS官网' },
        { url: 'adguard-mail.com', label: 'AdGuard Mail官网' },
        { url: 'adguard-vpn.com', label: 'AdGuard VPN官网' },
        { url: 'adguard-wallet.com', label: 'AdGuard Wallet官网' }
      ], ''],
      ['Panda 熊猫安全', 'pandasecurity panda-security', 'pandasecurity.com', '白名单已于 2026-11-12 从 panda.com（待售停放页）修正为 pandasecurity.com'],
      ['ZoneAlarm', 'zonealarm', 'zonealarm.com', ''],
      ['Emsisoft', 'emsisoft', 'emsisoft.com', ''],
    ]],

    // ========== 浏览器类 ==========
    ['浏览器类', [
      ['360 安全浏览器', '360se se.360', 'browser.360.cn', 'se.360.cn 301 跳转到 browser.360.cn（同一页，不再单列）'],
      ['360 极速浏览器', '360chrome chromex', [
        { url: 'chromex.360.cn', label: '360 极速 X 浏览器官网' },
        { url: 'browser.360.cn/ee/', label: '360 极速浏览器旧版官网' }
      ], '现名「360 极速 X 浏览器」；旧版仍在 /ee/ 目录提供下载'],
      ['QQ 浏览器', 'qqbrowser liulanqi', [
        { url: 'browser.qq.com', label: 'QQ 浏览器官网' },
        { url: 'liulanqi.qq.com', label: 'QQ 浏览器下载页（含手机版）' }
      ], '两个入口独立成页，均为官方'],
      // 旧（2026-11-22 前）：只有 ie.sogou / sogouie / sogoubrowser，带连字符的 sogou-browser.top 会误落到「搜狗搜索」
      // ['搜狗高速浏览器', 'ie.sogou sogouie sogoubrowser', 'sogou.browser.qq.com', 'ie.sogou.com 现 301 跳转到 sogou.browser.qq.com（腾讯收购后并入 QQ 浏览器域名）'],
      // 新（2026-11-22）：并入冗余条目「搜狗浏览器（新域）」的 sogou.browser，并补带连字符写法
      ['搜狗高速浏览器', 'ie.sogou sogouie sogoubrowser sogou-browser sogou.browser', 'sogou.browser.qq.com', 'ie.sogou.com 现 301 跳转到 sogou.browser.qq.com（腾讯收购后并入 QQ 浏览器域名）'],
      // 旧（2026-11-22 前）：与「搜狗高速浏览器」同站点，品牌词 sogou.browser 已并入那条
      // ['搜狗浏览器（新域）', 'sogou.browser', 'sogou.browser.qq.com', '腾讯收购后的新入口'],
      ['猎豹浏览器', 'liebao', 'liebao.cn', '项目已停止更新，但官网仍在线'],
      ['傲游浏览器', 'maxthon', [
        { url: 'maxthon.com', label: '国际官网' },
        { url: 'hk.maxthon.com/zh', label: '香港站（中文）' }
      ], '⚠️ 2026-11-21 实测：主域 maxthon.cn 的 A 记录已消失、www.maxthon.cn 返回 403「Non-compliance ICP Filing」，中国站实质下线，故主域名改指 maxthon.com'],
      ['UC 浏览器', 'ucweb', [
        { url: 'uc.cn', label: '中国官网' },
        { url: 'ucweb.com', label: '国际官网' }
      ], '国际站 ucweb.com；UC 手机助手同属阿里'],
      ['Firefox 火狐', 'firefox', 'firefox.com', '⚠️ 2026-11-21 实测：firefox.com 本身就是产品官网（mozilla.org/firefox 反过来 302 到它）；firefox.com.cn 已变成 Markmonitor 停放页，不再是国内站'],
      ['Mozilla', 'mozilla', 'mozilla.org', ''],
      // 旧（2026-11-22 前）：只有 google，chrome-setup.xyz 这类纯「Chrome」仿冒站命中不了
      // ['Google / Chrome', 'google', [
      // 新（2026-11-22）：补 chrome；判定侧词表（BRAND_KEYWORDS）早就有 chrome，官网表补词不新增拦截面
      ['Google / Chrome', 'google chrome', [
        { url: 'google.com', label: 'Google 官网' },
        { url: 'google.com/chrome', label: 'Chrome 浏览器下载页' },
        { url: 'google.cn', label: 'Google 中国站' }
      ], 'google.com.hk 同属官方入口，不再单列'],
      ['Gmail', 'gmail', 'gmail.com', ''],
      ['Brave', 'brave', 'brave.com', ''],
      ['Opera', 'opera', 'opera.com', ''],
      ['Vivaldi', 'vivaldi', [
        { url: 'vivaldi.com', label: '浏览器官网' },
        { url: 'vivaldi.net', label: '官方社区' }
      ], 'vivaldi.net 是官方社区/论坛站'],
      ['Yandex', 'yandex', [
        { url: 'yandex.com', label: '国际官网' },
        { url: 'yandex.ru', label: '俄罗斯站' }
      ], ''],
      ['Tor 浏览器', 'torproject', 'torproject.org', ''],
      ['Safari', 'safari', [
        { url: 'apple.com/safari/', label: 'Safari 官网' }
      ], '白名单已于 2026-11-12 移除 safari.com（归属无法确认）；Safari 只有 apple.com 下的产品页，没有独立域名'],
      ['Apple 苹果', 'apple', [
        { url: 'apple.com', label: '国际官网' },
        { url: 'apple.com.cn', label: '中国官网' }
      ], ''],
      // 新（2026-11-22）：迁自云端白名单 correct_sites（Chromium / chromium）
      ['Chromium', 'chromium', 'chromium.org', 'Chromium 开源项目官网（Chrome / Edge 的上游项目）'],
    ]],

    // ========== IM 与社交类 ==========
    ['IM与社交类', [
      ['微信', 'weixin wechat', [
        { url: 'weixin.qq.com', label: '中国版官网' },
        { url: 'wechat.com', label: '国际版官网' }
      ], 'WeChat 国际版官网 wechat.com，与中国版分属不同站点'],
      ['企业微信', 'wxwork work.weixin', 'work.weixin.qq.com', ''],
      ['TIM', 'office.qq', 'office.qq.com', '⚠️ 白名单原备注写「企业邮箱」，实测 office.qq.com 是 TIM 官网；腾讯企业邮箱在 exmail.qq.com'],
      ['QQ', 'qq', 'im.qq.com', '主站 qq.com；邮箱 mail.qq.com'],
      ['腾讯', 'tencent', 'tencent.com', ''],
      ['钉钉', 'dingtalk', 'dingtalk.com', ''],
      // 旧（2026-11-22 前）：单站点，国际版只写在别人的条目里
      // ['飞书', 'feishu', 'feishu.cn', ''],
      // 新（2026-11-22）：国际版 Lark 单列一行，这里用 rel 双向带出，两边都能看到对方
      ['飞书', 'feishu', 'feishu.cn', '国际版为 Lark（larksuite.com），两家共用同一产品线但站点独立', ['larksuite']],
      ['Lark（飞书国际版）', 'larkoffice larksuite', 'larksuite.com', '⚠️ 白名单收录 larkoffice.com，实测 307 跳 feishu.cn；国际版官网实为 larksuite.com'],
      ['陌陌', 'immomo', 'immomo.com', ''],
      ['Soul', 'soulapp', 'soulapp.cn', ''],
      ['网易邮箱', 'netease', [
        { url: 'netease.com', label: '网易官网' },
        { url: 'mail.163.com', label: '163 免费邮' }
      ], '企业邮 qiye.163.com'],
      ['126 邮箱', '126', '126.com', ''],
      ['Yeah 邮箱', 'yeah.net', 'yeah.net', ''],
      ['微博', 'weibo', [
        { url: 'weibo.com', label: '主站' },
        { url: 'weibo.cn', label: '手机版' }
      ], 'weibo.cn 为独立的手机版站点'],
      ['知乎', 'zhihu', 'zhihu.com', ''],
      ['小红书', 'xiaohongshu', 'xiaohongshu.com', '⚠️ 2026-11-21 实测：短域 xhs.com 解析存在但无法建立连接，不再列出'],
      ['豆瓣', 'douban', 'douban.com', ''],
      ['豆瓣 FM', 'douban.fm', 'douban.fm', '⚠️ 实测不可达，业务可能已下线'],
      ['即刻', 'ruguoapp', [
        { url: 'okjike.com', label: '现官网' },
        { url: 'ruguoapp.com', label: '旧域名' }
      ], '主域已迁至 okjike.com，旧域 ruguoapp.com 仍可访问'],
      ['时光网', 'mtime', 'mtime.com', '⚠️ 实测不可达，站点可能已停止运营'],
      ['天涯社区', 'tianya', 'tianya.cn', '⚠️ 实测不可达（社区长期停摆），收录仅为品牌对应关系'],
      ['虎扑', 'hupu', 'hupu.com', ''],
      ['QQ 邮箱', 'mail.qq qqmail', 'mail.qq.com', '迁自云端补录'],
      ['腾讯企业邮箱', 'exmail', 'exmail.qq.com', '迁自云端补录'],
      // 旧（2026-11-22 前）：与「网易」同站点，品牌词 163 已并入企业机构类的「网易」条目
      // ['网易 163 邮箱', '163', '163.com', '迁自云端补录；白名单「网易邮箱」只收了 netease/126/yeah'],
    ]],

    // ========== 输入法类 ==========
    ['输入法类', [
      ['搜狗输入法', 'shurufa.sogou pinyin.sogou sogoushurufa sogou-pinyin', 'shurufa.sogou.com', 'pinyin.sogou.com 301 到 shurufa.sogou.com；裸词 sogou 会吃掉搜狗浏览器/搜索，故不用'],
      ['百度输入法', 'baidushurufa baiduime', [
        { url: 'shurufa.baidu.com', label: '输入法官网' },
        { url: 'ime.baidu.com', label: '旧入口' }
      ], '两个域名各自独立成页、内容一致'],
      ['讯飞输入法', 'xunfei', [
        { url: 'srf.xunfei.cn', label: '输入法官网' },
        { url: 'iflytek.com', label: '科大讯飞官网' }
      ], '讯飞开放平台 xfyun.cn；xunfei.cn 是官方商城'],
      ['手心输入法', 'xinshuru', 'xinshuru.com', '⚠️ 白名单原备注写「讯飞新输入法」，实测 xinshuru.com 是「手心输入法」，与讯飞无关'],
      ['QQ 输入法', 'qq.pinyin', 'qq.pinyin.cn', '原名 QQ 拼音输入法'],
      // 旧（2026-11-22 前）：只有 shurufa.baidu，下面另有一条「百度输入法（旧入口）/ ime.baidu」重复条目
      // ['百度输入法', 'shurufa.baidu', 'shurufa.baidu.com', ''],
      ['百度输入法', 'shurufa.baidu ime.baidu', 'shurufa.baidu.com', 'ime.baidu.com 是旧入口（现在 302 到本域）'],
      // 旧（2026-11-22 前）：与「百度文心」同站点，品牌词 chat.baidu 已并入上面那行
      // ['百度文心（旧入口）', 'chat.baidu', 'wenxin.baidu.com', ''],
      // 旧（2026-11-22 前）：与「百度输入法」同站点，品牌词 ime.baidu 已并入上面那行
      // ['百度输入法（旧入口）', 'ime.baidu', 'shurufa.baidu.com', ''],
    ]],

    // ========== 办公与文档类 ==========
    ['办公与文档类', [
      // 旧（2026-11-28 修）：从白名单表照抄成三段。WHITELIST_CATALOG 的结构是
      //   [名称, 主机名, 备注]，本表的结构是 [产品名, 品牌词, 官网, 备注] ——
      //   于是「品牌词」位置写成了域名、「官网」位置留空，normalizeCorrectSites
      //   解析不出站点把整条丢掉（希沃白板 这条映射等于不存在），且每次页面加载
      //   都会打一条内容为空的告警「正确官网条目无法解析，已忽略: 」。
      // ['希沃白板', 'seewo.com', ''],
      // 2026-11-28：品牌词 seewo 在「用户反馈与个人站点类」已有 d.seewo.com（教学终端页）一条，
      //   两条同品牌会触发「品牌词重复，已忽略后出现的条目」并丢掉其中一条 —— 合并成一条，
      //   把教学终端页一并收进来，原处那条已注释。
      ['希沃白板（希沃）', 'seewo', [
        { url: 'easinote.seewo.com', label: '希沃白板官网' },
        { url: 'www.seewo.com', label: '希沃官网' },
        { url: 'd.seewo.com', label: '教学终端页' }
      ], '希沃白板（EasiNote）客户端下载页为 easinote.seewo.com，seewo.com 为希沃品牌站（2026-11-28 经希沃帮助中心核实）'],
      // 旧（单域名，2026-11-12）：中国站与国际站只在备注里各提一句
      // ['WPS Office', 'wps', 'wps.cn', '国际站 wps.com；Linux 版 wps-linux.com'],
      // 新（2026-11-21）：中国站 / 国际站各自独立成页（标题不同），全部列出
      ['WPS Office', 'wps', [
        { url: 'wps.cn', label: '中国官网' },
        { url: 'wps.com', label: '国际官网' }
      ], '⚠️ 2026-11-21 实测 wps-linux.com 无响应，不再列出'],
      ['金山文档（WPS 云文档）', 'kdocs', 'kdocs.cn', ''],
      // 新（2026-11-22）：迁自云端白名单 correct_sites（金山词霸 / iciba）
      ['金山词霸', 'iciba', [
        { url: 'iciba.com', label: '产品官网' },
        { url: 'kingsoft.com', label: '金山软件集团' }
      ], 'kingsoft.com 是金山软件集团站（WPS / 毒霸 / 词霸同属），与 iciba.com 各自独立成页'],
      ['腾讯文档', 'docs.qq qqdocs', 'docs.qq.com', ''],
      // 新（2026-11-22）：迁自云端白名单 correct_sites（腾讯会议 / meeting.tencent）
      ['腾讯会议', 'meeting.tencent tencentmeeting voovmeeting', [
        { url: 'meeting.tencent.com', label: '中国官网' },
        { url: 'voovmeeting.com', label: '国际版 VooV' }
      ], 'meeting.qq.com 实测 301 到 meeting.tencent.com（同一站，不单列）'],
      ['OnlyOffice', 'onlyoffice', 'onlyoffice.com', ''],
      ['LibreOffice', 'libreoffice', 'libreoffice.org', ''],
      ['OpenOffice', 'openoffice', 'openoffice.org', ''],
      ['石墨文档', 'shimo', 'shimo.im', ''],
      ['永中 Office', 'yozosoft', 'yozosoft.com', '⚠️ 白名单原备注写「有赞文档」，实测 yozosoft.com 属永中软件（Yozo Office），与「有赞 youzan.com」无关'],
      // 旧（2026-11-22 前）：只有 microsoft，Microsoft Teams 的仿冒站落到说明页
      // ['Microsoft 微软', 'microsoft', 'microsoft.com', '中国站 microsoft.com.cn 301 到 microsoft.com/zh-cn（同一页，不单列）'],
      ['Microsoft 微软', 'microsoft teams', 'microsoft.com', '中国站 microsoft.com.cn 301 到 microsoft.com/zh-cn（同一页，不单列）'],
      // 新（2026-11-21）：office.com 与 microsoft365.com 是两个仍各自在用的入口，全部列出
      // 旧（2026-11-22 前）：只有套件名，Excel / PowerPoint 的破解站命中不了
      // ['Microsoft Office / 365', 'office365 microsoft365 m365 cloud.microsoft', [
      ['Microsoft Office / 365', 'office365 microsoft365 m365 cloud.microsoft excel powerpoint', [
        { url: 'microsoft365.com', label: 'Microsoft 365 官网' },
        { url: 'office.com', label: 'Office 经典入口' }
      ], '⚠️ 2026-11-21 实测：office.com 会自动跳转到 https://m365.cloud.microsoft/zh-hans/（即 Microsoft 365 的中文新首页），两者是同一个订阅入口的两个门牌；microsoft365.com 同样 301 到 m365.cloud.microsoft；本机代理链路抓不到 office.com 的响应，浏览器直连可正常打开'],
      ['Outlook', 'outlook hotmail', 'outlook.com', 'hotmail.com 301 到 outlook.live.com（同一服务，不单列）'],
      ['OneNote', 'onenote', 'onenote.com', '2026-11-21 实测 onenote.com 307 到 onenote.cloud.microsoft（同一官方入口）'],
      ['MSN', 'msn', 'msn.com', ''],
      ['Microsoft 账户登录', 'microsoftonline', 'microsoftonline.com', '登录入口 login.microsoftonline.com'],
      ['Azure', 'azure', [
        { url: 'azure.com', label: '国际官网' },
        { url: 'azure.cn', label: '中国站（世纪互联运营）' }
      ], '管理门户 portal.azure.com；azure.cn 是独立运营的中国站，产品线与计费均不同'],
      // 旧（2026-11-12）：zoom.us 已 301 到 zoom.com，主域应改
      // ['Zoom', 'zoom', 'zoom.us', ''],
      ['Zoom', 'zoom', 'zoom.com', '⚠️ 2026-11-21 实测：zoom.us 301 到 www.zoom.com；zoom.com.cn 返回 503（服务受限），不单列'],
      ['Webex', 'webex', 'webex.com', ''],
      ['Slack', 'slack', 'slack.com', ''],
      ['Discord', 'discord', 'discord.com', ''],
      ['Telegram', 'telegram', 'telegram.org', ''],
      ['Skype', 'skype', 'skype.com', ''],
      ['Thunderbird', 'thunderbird', 'thunderbird.net', 'Mozilla 旗下；mozilla.org/thunderbird 为同一官方入口'],
      ['Windows / Surface', 'windows surface', 'microsoft.com', '迁自云端补录；白名单「微软系」已含 microsoft.com'],
    ]],
    // ========== 影音娱乐类 ==========
    ['影音娱乐类', [
      // 旧（2026-11-22 前）：只有 v.qq / vqq / qqvideo，国际版 WeTV 的仿冒站命中不了
      // ['腾讯视频', 'v.qq vqq qqvideo', [
      ['腾讯视频', 'v.qq vqq qqvideo wetv', [
        { url: 'v.qq.com', label: '中国官网' },
        { url: 'wetv.vip', label: '国际版 WeTV' }
      ], '腾讯视频与极速版共用 v.qq.com；QQ 音乐另见 y.qq.com'],
      ['爱奇艺', 'iqiyi aiqiyi iq.com', [
        { url: 'iqiyi.com', label: '中国官网' },
        { url: 'iq.com', label: '国际版 iQIYI' }
      ], 'iq.com 为独立国际站，内容库与会员体系分开'],
      ['优酷', 'youku', 'youku.com', '优酷与土豆同属阿里大文娱'],
      ['土豆网', 'tudou', 'tudou.com', '已并入优酷，域名仍解析到优酷短视频页'],
      ['哔哩哔哩', 'bilibili', [
        { url: 'bilibili.com', label: '中国官网' },
        { url: 'bilibili.tv', label: '国际版' }
      ], 'bilibili.tv 为独立海外站'],
      ['芒果TV', 'mgtv', 'mgtv.com', '湖南广电旗下；国际版 imgo.tv 301 到 mgtv.com（同一页，不单列）'],
      // 旧（2026-11-22 前）：国际版只在备注里提一句，点按钮看不到
      // ['抖音', 'douyin', 'douyin.com', '国际版 TikTok 已单列（tiktok.com）'],
      ['抖音', 'douyin', 'douyin.com', '国际版为 TikTok（tiktok.com），内容池与运营主体独立', ['tiktok']],
      ['TikTok', 'tiktok', 'tiktok.com', '抖音国际版'],
      ['西瓜视频', 'ixigua xigua', 'ixigua.com', '字节跳动旗下；xigua.com 与 ixigua.com 同页'],
      ['剪映', 'capcut jianying', [
        { url: 'jianying.com', label: '中国官网' },
        { url: 'capcut.com', label: '国际版 CapCut' }
      ], 'capcut.cn 与 jianying.com 同为国内官网入口（页面标题一致）；国际版为 capcut.com'],
      ['字节跳动', 'bytedance', 'bytedance.com', ''],
      ['搜狐视频', 'sohu', 'sohu.com', '视频频道 tv.sohu.com'],
      ['虎牙直播', 'huya', 'huya.com', ''],
      ['斗鱼直播', 'douyu', 'douyu.com', ''],
      ['YY 直播', 'yy.com', [
        { url: 'yy.com', label: '中国官网' },
        { url: 'joyy.com', label: '欢聚集团（海外站）' }
      ], 'joyy.com 为母公司 JOYY 的海外站'],
      // 旧（2026-11-22 前）：只有 kuaishou，国际版 Kwai 的仿冒站（kwai-vip.top）命中不了
      // ['快手', 'kuaishou', [
      ['快手', 'kuaishou kwai', [
        { url: 'kuaishou.com', label: '中国官网' },
        { url: 'kwai.com', label: '国际版 Kwai' }
      ], ''],
      ['网易云音乐', 'music.163 163music', 'music.163.com', '门户站 163.com；企业邮 qiye.163.com'],
      ['QQ 音乐', 'y.qq qqmusic music.qq', 'y.qq.com', 'music.qq.com 301 到 y.qq.com'],
      ['酷狗音乐', 'kugou', 'kugou.com', ''],
      ['酷我音乐', 'kuwo', 'kuwo.cn', ''],
      ['咪咕', 'migu', 'migu.cn', '咪咕音乐 music.migu.cn；咪咕视频 / 咪咕阅读同属中国移动；migu.cn 301 到 www.migu.cn'],
      ['喜马拉雅', 'ximalaya', 'ximalaya.com', '短域 xima.tv 301 到主站'],
      ['汽水音乐', 'qishui', 'qishui.com', '抖音音乐版'],
      ['番茄小说', 'fanqienovel', 'fanqienovel.com', '字节跳动旗下'],
      ['AcFun', 'acfun', 'acfun.cn', ''],
      ['美图', 'meitu', 'meitu.com', '美图秀秀 xiuxiu.meitu.com；⚠️ 2026-11-21 实测 meituinc.com 无响应，不再列为母公司站'],
      ['起点中文网', 'qidian', 'qidian.com', '阅文集团旗下'],
      ['阅文集团', 'yuewen', 'yuewen.com', ''],
      ['掌阅', 'zhangyue', 'zhangyue.com', ''],
      ['多看阅读', 'duokan', 'duokan.com', '小米生态；站点维护停滞，仅作品牌对应'],
      ['咪咕阅读', 'cmread', 'cmread.com', '中国移动旗下'],
      ['SFACG 漫画', 'sfacg', 'sfacg.com', ''],
      ['VLC', 'videolan', 'videolan.org', ''],
      ['OBS Studio', 'obsproject', 'obsproject.org', ''],
      ['Audacity', 'audacity', 'audacityteam.org', ''],
      ['FFmpeg', 'ffmpeg', 'ffmpeg.org', ''],
      // 旧（2026-11-22 前）：备注写着「Photoshop / Acrobat / Premiere 同属」，品牌词却只有 adobe
      // ['Adobe', 'adobe', 'adobe.com', 'Photoshop / Acrobat / Premiere 同属'],
      ['Adobe', 'adobe photoshop acrobat premiere aftereffects illustrator lightroom', 'adobe.com', 'Photoshop / Acrobat / Premiere / Illustrator / Lightroom 同属'],
      ['PotPlayer', 'potplayer', 'potplayer.daum.net', 'Daum（Kakao）旗下'],
    ]],

    // ========== 云盘与存储类 ==========
    ['云盘与存储类', [
      ['百度网盘', 'pan.baidu baidupan baiduwangpan', [
        { url: 'pan.baidu.com', label: '个人版' },
        { url: 'yun.baidu.com', label: '企业版' }
      ], '两个入口各自独立成页'],
      ['阿里云盘', 'aliyundrive alipan', 'alipan.com', '2024 年起更名「夸克网盘」，aliyundrive.com 301 到 alipan.com'],
      ['夸克网盘', 'pan.quark', 'pan.quark.cn', '夸克浏览器 / 夸克 App 官网 quark.cn'],
      ['夸克浏览器', 'quark.cn quarkpan', 'quark.cn', '阿里旗下；AI 旗舰应用夸克 App 同域'],
      ['腾讯微云', 'weiyun', 'weiyun.com', ''],
      ['115', '115.com', '115.com', '现名「115 生活」，原 115 网盘'],
      ['天翼云盘', 'cloud.189', 'cloud.189.cn', '中国电信，189.cn 为天翼品牌域'],
      ['迅雷云盘', 'pan.xunlei', 'pan.xunlei.com', '客户端在 xunlei.com'],
      ['蓝奏云', 'lanzou ilanzou', [
        { url: 'lanzou.com', label: '主站' },
        { url: 'lanzoux.com', label: '备用域名' },
        { url: 'lanzous.com', label: '备用域名（旧）' }
      ], '主站被屏蔽时官方轮换到 lanzoux / lanzous 等备用域（同主体、同后台）'],
      ['中国移动云盘', 'caiyun', 'yun.139.com', '原「和彩云」，caiyun.139.com 301 到 yun.139.com'],
      ['123 云盘', '123pan', [
        { url: '123pan.com', label: '主站' },
        { url: '123684.com', label: '备用域名' }
      ], '123684.com 与主站同标题、同业务，为官方保留的备用入口'],
      ['坚果云', 'jianguoyun', 'jianguoyun.com', ''],
      ['Dropbox', 'dropbox', 'dropbox.com', ''],
      ['Google Drive', 'drive.google', 'drive.google.com', ''],
      ['OneDrive', 'onedrive', [
        { url: 'onedrive.com', label: '产品官网' },
        { url: 'onedrive.live.com', label: '个人版网页入口' }
      ], 'onedrive.live.com 为 Web 端登录入口（本轮代理链路下握手失败，浏览器可正常打开）'],
      ['MEGA', 'mega.nz', 'mega.nz', '⚠️ 2026-11-21 实测中国大陆网络无法直连（无响应）'],
    ]],

    // ========== AI 大模型类 ==========
    ['AI大模型类', [
      // 旧（2026-11-22 前）：备注写着 chat.baidu.com 已在备注里，但另有一条「百度文心（旧入口）」重复条目
      // ['百度文心', 'wenxin yiyan', 'wenxin.baidu.com', '原「文心一言」现名「文心助手」；yiyan.baidu.com / chat.baidu.com 均 302 到本站（同一页，不单列）'],
      ['百度文心', 'wenxin yiyan chat.baidu', 'wenxin.baidu.com', '原「文心一言」现名「文心助手」；yiyan.baidu.com / chat.baidu.com 均 302 到本站（同一页，不单列）'],
      ['千问（通义）', 'qianwen tongyi', [
        { url: 'qianwen.com', label: '官网' },
        { url: 'qianwen.aliyun.com', label: '阿里云产品入口' }
      ], '原名通义千问；tongyi.aliyun.com 301 到 qianwen.aliyun.com；两站内容不同（官网为千问 App / 网页版，阿里云入口为云上产品页）'],
      ['千问AI 企业平台', 'qianwenai', 'qianwenai.com', '原「阿里云百炼 / DashScope」，控制台 dashscope.console.aliyun.com'],
      ['豆包', 'doubao', 'doubao.com', ''],
      ['火山引擎', 'volcengine', 'volcengine.com', '豆包大模型的企业侧平台'],
      ['讯飞星火', 'xinghuo', [
        { url: 'xinghuo.xfyun.cn', label: '产品官网' },
        { url: 'xfyun.cn', label: '讯飞开放平台' },
        { url: 'iflytek.com', label: '科大讯飞公司官网' }
      ], '输入法见 srf.xunfei.cn'],
      // 新（2026-11-22）：迁自云端白名单 correct_sites（讯飞开放平台 / xfyun）
      //   注意与「讯飞星火」分开：星火是产品（xinghuo），开放平台是开发者站（xfyun），品牌词不冲突。
      ['讯飞开放平台', 'xfyun', [
        { url: 'xfyun.cn', label: '开放平台' },
        { url: 'iflytek.com', label: '科大讯飞公司官网' }
      ], 'srf.xunfei.cn 是讯飞输入法站，与开放平台不同'],
      ['360 纳米AI', 'nami 360nami', 'chat.360.com', 'ai.360.com / ai.360.cn 与本站同页'],
      ['Kimi', 'kimi moonshot', [
        { url: 'kimi.com', label: '产品官网' },
        { url: 'moonshot.cn', label: '月之暗面公司官网' }
      ], '旧域 kimi.moonshot.cn 301 到 kimi.com；开放平台 platform.moonshot.cn'],
      ['DeepSeek', 'deepseek', [
        { url: 'deepseek.com', label: '公司官网' },
        { url: 'chat.deepseek.com', label: 'DeepSeek 网页版' }
      ], ''],
      // 新（2026-11-24）：DeepSeek Harness —— 官方产品页，挂在主站路径下（无独立域名），
      //   因此只能写成**链接级**站点；与 DeepSeek 主条目用第 5 个字段「双向关联」：
      //   从 DeepSeek 条目能看到 Harness 入口，从 Harness 条目也能拿到主站 / 网页版。
      //   品牌词取 `deepseek-harness`（整段、含连字符）而**不单收 `harness`**：
      //   harness 是英文常用词（CI 工具站 harness.io 之类），单收会把无关站点也判成这个品牌。
      //   命中范围：cnds-deepseek-harness / 382web.cnds-deepseek-harness.com.cn 这类主机名。
      ['DeepSeek Harness', 'deepseek-harness', [
        { url: 'https://www.deepseek.com/harness/', label: 'Harness 产品页' }
      ], 'DeepSeek 官方子页面（无独立域名）；链接级条目，路径改版需复核', ['deepseek']],
      // 旧（2026-11-22 前）：只有 chatglm / zhipu，开放平台 bigmodel.cn 的仿冒站命中不了（判定词表已有 bigmodel）
      // ['智谱清言', 'chatglm zhipu', [
      ['智谱清言', 'chatglm zhipu bigmodel', [
        { url: 'chatglm.cn', label: '产品官网' },
        { url: 'zhipuai.cn', label: '智谱（Z.ai）公司官网' },
        { url: 'bigmodel.cn', label: '开放平台' }
      ], ''],
      ['MiniMax', 'minimax', 'minimax.cn', '海螺 AI 为同公司产品（已单列）；minimaxi.com 301 到 minimax.cn（同一页，不单列）'],
      ['海螺 AI', 'hailuo', 'hailuoai.com', 'MiniMax 旗下'],
      ['腾讯元宝', 'yuanbao', 'yuanbao.tencent.com', ''],
      ['百川智能', 'baichuan', 'baichuan-ai.com', ''],
      // 旧（2026-11-22 前）：只有 tiangong，国际版 suno 的仿冒写法 skywork-* 命中不了
      // ['天工 Skywork', 'tiangong', [
      ['天工 Skywork', 'tiangong skywork', [
        { url: 'tiangong.cn', label: '国内官网' },
        { url: 'skywork.ai', label: '国际版 Skywork' }
      ], '昆仑万维旗下；tiangong.ai 同为官方入口'],
      ['阶跃星辰', 'stepfun', 'stepfun.com', ''],
      ['零一万物', 'lingyiwanwu', 'lingyiwanwu.com', ''],
      ['可灵 AI', 'kling', 'klingai.com', '快手旗下；国内站 kling.kuaishou.com 301 到 app.klingai.com/cn/（同一站，不单列）'],
      ['即梦 AI', 'jimeng', 'jimeng.jianying.com', '字节跳动旗下'],
      ['OpenAI / ChatGPT', 'openai chatgpt', [
        { url: 'openai.com', label: 'OpenAI 公司官网' },
        { url: 'chatgpt.com', label: 'ChatGPT 网页版' }
      ], '公司与产品已分家为两个独立站点'],
      ['Anthropic / Claude', 'anthropic claude', [
        { url: 'anthropic.com', label: 'Anthropic 公司官网' },
        { url: 'claude.ai', label: 'Claude 网页版' }
      ], ''],
      ['Google Gemini', 'gemini', 'gemini.google.com', ''],
      // 旧（2026-11-12）：copilot.microsoft.com 已 301 到 copilot.com
      // ['Microsoft Copilot', 'copilot', 'copilot.microsoft.com', ''],
      ['Microsoft Copilot', 'copilot', 'copilot.com', '⚠️ 2026-11-21 实测 copilot.microsoft.com 301 到 copilot.com，主域已迁移'],
      ['xAI Grok', 'grok x.ai', [
        { url: 'x.ai', label: 'xAI 公司官网' },
        { url: 'grok.com', label: 'Grok 网页版' }
      ], '⚠️ 2026-11-21 实测中国大陆网络无法直连（均无响应）'],
      ['Perplexity', 'perplexity', 'perplexity.ai', ''],
      ['Mistral AI', 'mistral', 'mistral.ai', ''],
      ['Hugging Face', 'huggingface', 'huggingface.co', ''],
      ['ModelScope 魔搭', 'modelscope', 'modelscope.cn', '阿里开源模型社区'],
      ['Ollama', 'ollama', 'ollama.com', ''],
      ['Midjourney', 'midjourney', 'midjourney.com', ''],
      ['Stability AI', 'stability', 'stability.ai', ''],
      ['Runway', 'runway', 'runwayml.com', ''],
      ['Suno', 'suno.com', 'suno.com', ''],
    ]],

    // ========== 下载与压缩类 ==========
    ['下载与压缩类', [
      ['迅雷', 'xunlei', [
        { url: 'xunlei.com', label: '首页' },
        { url: 'dl.xunlei.com', label: '下载页' },
        { url: 'pan.xunlei.com', label: '迅雷云盘' }
      ], ''],
      ['IDM', 'idm internetdownloadmanager', 'internetdownloadmanager.com', ''],
      ['BitComet', 'bitcomet', [
        { url: 'bitcomet.com', label: 'BitComet官网' },
        { url: 'https://bc.36102025.xyz', label: 'BitComet资源导航页' },
        {url: 'https://www.cometbbs.com', label: 'BitComet论坛' }
      ], ''],
      // 旧（单域名，2026-11-12）：只留一个主站，说明页无法体现「中国站 / 欧洲站」的区别
      // ['WinRAR', 'winrar rarlab', 'rarlab.com', 'win-rar.com 为同一官网的欧洲站；中国站 winrar.com.cn'],
      // 新（2026-11-18）：三个站点全部列出，中国站带自定义文案（示例要求的三行样式）
      ['WinRAR', 'winrar rarlab', [
        'https://www.win-rar.com',
        'https://www.rarlab.com',
        { url: 'https://www.winrar.com.cn', label: '中国官网' }
      ], 'win-rar.com 为欧洲站、rarlab.com 为原厂主站（同一官网两个入口）；winrar.com.cn 为中国站'],
      ['7-Zip', '7-zip 7zip', '7-zip.org', ''],
      ['Bandizip', 'bandizip bandisoft', 'bandisoft.com', 'bandizip.com 是同一官网的别名（301 到 bandisoft.com/bandizip/），不单列'],
      ['2345 好压', 'haozip', 'haozip.2345.cc', ''],
      ['360 压缩', '360yasuo', 'yasuo.360.cn', ''],
      ['WinZip', 'winzip', 'winzip.com', ''],
      // 新（2026-11-21）：主站之外还有一个官方 GitHub Pages 站
      ['PeaZip', 'peazip', [
        { url: 'peazip.com', label: '官网' },
        { url: 'peazip.github.io', label: '官方下载页（GitHub Pages）' }
      ], '⚠️ 2026-11-21 实测：peazip.github.io 可访问且有官方下载链接；peazip.com 解析正常但本机抓不到响应'],
      // 新（2026-11-21）：软件站与开发商站分成两条，用户两条都能核对身份
      ['UltraISO', 'ultraiso', [
        { url: 'ultraiso.com', label: '软件官网' },
        { url: 'ezbsystems.com', label: '开发商 EZB Systems' }
      ], ''],
      ['Free Download Manager', 'freedownloadmanager', 'freedownloadmanager.org', ''],
      // 旧（单域名，2026-11-12）：只列官方原版，命中增强版仿冒站时看不到 qBEE 的真入口
      // ['qBittorrent', 'qbittorrent', 'qbittorrent.org', ''],
      // 新（2026-11-22）：官方原版 + 关联「增强版」条目（第 5 个字段，双向生效）
      //   背景：qBittorrent 是仿冒站重灾区，且仿冒站把「原版 / 增强版」两个名字混着用
      //   （qbittorrent.org.cn、qbittorrent-enhanced.cc …）。原版用户想装增强版、增强版
      //   用户想回原版都很常见，两个入口一次给全，比让用户自己再搜一遍安全得多。
      ['qBittorrent', 'qbittorrent', ['qbittorrent.org'], '官方原版；增强版（qBEE）是社区分支，入口见下方「相关」小节', ['qbittorrent-enhanced']],
      // 旧（单域名，2026-11-12）：该项目**没有主机名意义上的官网**，旧值 qbittorrent-enhanced.org
      //   并非官方持有（社区镜像常用名），会把用户送到第三方站。
      // ['qBittorrent Enhanced Edition', 'qbittorrent-enhanced', 'qbittorrent-enhanced.org', ''],
      // 新（2026-11-22）：与 qBittorrent 的关联写在上面那行（双向生效），本行站点与顺序不变
      // 新（2026-11-18）：链接级官网 —— 官方唯一的发布渠道是 GitHub Releases
      ['qBittorrent Enhanced Edition', 'qbittorrent-enhanced', [
        { url: 'https://github.com/c0re100/qBittorrent-Enhanced-Edition/releases', label: 'GitHub 发布页' },
        { url: 'https://git.hiwiki.org/zh-CN/repo/c0re100/qbittorrent-enhanced-edition', label: 'HiWiki 镜像' }
      ], '社区维护分支，无独立官网； GitHub 发布页即 Releases 列表'],
      ['uTorrent', 'utorrent', 'utorrent.com', ''],
      ['BitTorrent', 'bittorrent', 'bittorrent.com', ''],
      ['Transmission', 'transmission', 'transmissionbt.com', ''],
      // 旧（2026-11-22 前）：品牌词只有 aria2，下面另有一条 aria2.github 重复条目
      // ['Aria2', 'aria2', 'aria2.github.io', ''],
      // 新（2026-11-22）：两条合并为一条，aria2.github 作为品牌词并入（并非两个产品）
      ['Aria2', 'aria2 aria2.github', 'aria2.github.io', '项目主页挂在 GitHub Pages；aria2.github.io 与 aria2.github 是同一站'],
      ['Motrix', 'motrix', 'motrix.app', ''],
      ['XDown', 'xdown', 'xdown.org', ''],
      ['PuTTY', 'putty', [
        { url: 'putty.org', label: '常用入口' },
        { url: 'https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html', label: '开发者官方发布页' }
      ], 'PuTTY 由 Simon Tatham 维护，官方发布页挂在他本人的 chiark 站点上；putty.org 只是长期存在的社区入口，不是开发者主站'],
      ['WinSCP', 'winscp', 'winscp.net', ''],
      ['FileZilla', 'filezilla', 'filezilla-project.org', ''],
      // 旧（2026-11-22 前）：与上面那条完全重复（同产品、同站点、品牌词互为子串）
      // ['Aria2', 'aria2.github', 'aria2.github.io', ''],
    ]],

    // ========== 系统工具类 ==========
    ['系统工具类', [
      ['Uninstall Tool', 'uninstalltool', [
        { url: 'https://crystalidea.com/uninstall-tool', label: 'Uninstall Tool 官网' }
      ], 'Uninstall Tool 是 Geek Uninstaller 的增强版，开发者 CrystalIDEA 也出品其他软件'],
      ['Geek Uninstaller', 'geekuninstaller', [
        { url: 'https://geekuninstaller.com/download', label: 'Geek Uninstaller 官网下载页' }
      ], ''],
      ['Revo Uninstaller', 'revo', [
        { url: 'https://www.revouninstaller.com/', label: 'Revo Uninstaller 官网' },
        { url: 'https://www.revouninstaller.com/products/revo-uninstaller-pro/', label: 'Revo Uninstaller Pro 下载页' },
        { url: 'https://www.revouninstaller.com/products/revo-uninstaller-free/', label: 'Revo Uninstaller Free 下载页' },
        { url: 'https://www.revouninstaller.com/products/revo-registry-cleaner-pro/', label: 'Revo Registry Cleaner Pro 下载页' },
        { url: 'https://www.revouninstaller.com/products/revo-registry-cleaner-free/', label: 'Revo Registry Cleaner Free 下载页' }
      ], 'Revo Uninstaller 官网有多个产品下载页，均为官方入口'],
      ['IObit Uninstaller', 'iobit', [
        { url: 'https://www.iobit.com/en/advanceduninstallerpro.php', label: 'IObit Uninstaller 官网' }
      ], 'IObit 旗下产品，官网有多个版本；软件本身行为流氓，介意者慎用'],
      ['Total Uninstall', 'totaluninstall', [
        { url: 'https://www.martau.com/uninstaller-download.php', label: 'Total Uninstall 官网' }
      ], 'Total Uninstall 官网'],
      ['Hibit Uninstaller', 'hibit', [
        { url: 'https://hibitsoft.ir/Uninstaller.html', label: 'Hibit Uninstaller 官网' }
      ], 'Hibit Uninstaller 官网;伊朗站点，访问可能超时'],
      ['Bulk Crap Uninstaller', 'bulkcrapuninstaller bcu', [
        { url: 'https://www.bcuninstaller.com/', label: 'Bulk Crap Uninstaller 官网' },
        { url: 'https://github.com/BCUninstaller/Bulk-Crap-Uninstaller/releases', label: 'BC Uninstaller 的 GitHub 发布页' }
      ], 'Bulk Crap Uninstaller 官网'],
      ['ToDesk', 'todesk', [
        { url: 'todesk.com', label: '中国官网' },
        { url: 'todeskai.com', label: '国际站' }
      ], ''],
      ['向日葵远程控制', 'sunlogin oray', [
        { url: 'sunlogin.oray.com', label: '产品官网' },
        { url: 'oray.com', label: '贝锐（Oray）母公司站' }
      ], ''],
      ['TeamViewer', 'teamviewer', 'teamviewer.com', '⚠️ 2026-11-21 实测：teamviewer.cn 有 DNS 记录但抓不到任何响应，未列为中国站'],
      ['AnyDesk', 'anydesk', 'anydesk.com', '⚠️ 2026-11-21 实测：anydesk.cn 只有别名记录、没有 A 记录，不列为中国站'],
      ['驱动精灵', 'drivergenius', 'drivergenius.com', ''],
      ['驱动人生', '160.com', '160.com', '官网 160.com；避开捆绑下载器页面'],
      ['鲁大师', 'ludashi', 'ludashi.com', ''],
      ['CPU-Z', 'cpuid cpuz', 'cpuid.com', 'CPU-Z / HWMonitor 同属 CPUID；cpu-z.com 同页'],
      ['HWMonitor', 'hwmonitor', 'cpuid.com', 'CPUID 出品'],
      ['HWiNFO', 'hwinfo', 'hwinfo.com', ''],
      ['AIDA64', 'aida64', 'aida64.com', ''],
      ['CrystalDiskMark / DiskInfo', 'crystaldiskmark crystaldiskinfo', 'crystalmark.info', '现主域 crystalmark.info，crystaldiskmark.info 为旧域'],
      ['Prime95', 'prime95 mersenne', 'mersenne.org', 'GIMPS 项目官网'],
      ['FurMark', 'furmark geek3d', 'geek3d.com', '白名单已于 2026-11-12 从 furmark.com（皮草行业站）修正为 geek3d.com；FurMark 由 Geeks3D 出品'],
      ['MemTest86', 'memtest86', 'memtest86.com', ''],
      ['TechPowerUp / GPU-Z', 'techpowerup gpuz', 'techpowerup.com', ''],
      ['MSI Afterburner', 'afterburner', 'msi.com', '微星官方工具页 msi.com/Landing/afterburner'],
      ['DiskGenius', 'diskgenius', [
        { url: 'diskgenius.cn', label: '中国站' },
        { url: 'diskgenius.com', label: '国际站（英文）' }
      ], '两站语言与安装包不同，均为官方'],
      ['傲梅分区助手', 'disktool aomei', [
        { url: 'disktool.cn', label: '中国站' },
        { url: 'aomeitech.com', label: '国际站 AOMEI' }
      ], '⚠️ 2026-11-21 实测：aomei.cn 已 301 到 chinaaomei.com（天津奥美自动化，与傲梅无关），不要拿它当官网'],
      ['Rufus', 'rufus', [
        { url: 'rufus.ie', label: '官网' },
        { url: 'https://github.com/pbatard/rufus/releases', label: 'GitHub 发布页' }
      ], '开发者 pbatard 的 GitHub Releases 即官方下载源'],
      ['Ventoy', 'ventoy', [
        { url: 'ventoy.net', label: '官网' },
        { url: 'https://github.com/ventoy/Ventoy/releases', label: 'GitHub 发布页' }
      ], ''],
      ['Everything', 'voidtools', 'voidtools.com', ''],
      ['CCleaner', 'ccleaner', 'ccleaner.com', '开发方 Piriform（piriform.com）现属 Gen Digital，piriform.com 只作旧域跳转'],
      ['微PE 工具箱', 'wepe', 'wepe.com.cn', ''],
      ['联想', 'lenovo', [
        { url: 'lenovo.com', label: '国际官网' },
        { url: 'lenovo.com.cn', label: '中国官网' }
      ], ''],
      ['戴尔', 'dell', 'dell.com', '中国站 dell.com.cn 301 到 dell.com/zh-cn（同一页，不单列）'],
      ['惠普', 'hp', [
        { url: 'hp.com', label: '国际官网' },
        { url: 'hp.com.cn', label: '中国官网' }
      ], '品牌词两个字母，右侧必须是非字母（hp-driver 命中、shop 不命中）'],
      ['华硕', 'asus', [
        { url: 'asus.com', label: '国际官网' },
        { url: 'asus.com.cn', label: '中国官网' },
        { url: 'rog.asus.com', label: 'ROG 玩家国度' }
      ], 'ROG 是华硕电竞子品牌，独立成站'],
      ['微星', 'msi', [
        { url: 'msi.com', label: '国际官网' },
        { url: 'msi.cn', label: '中国官网' }
      ], 'msi.cn 页面标题为「微星科技」，与全球站内容不同'],
      ['技嘉', 'gigabyte', [
        { url: 'gigabyte.com', label: '国际官网' },
        { url: 'gigabyte.cn', label: '中国官网' }
      ], 'gigabyte.cn 页面标题为「GIGABYTE 技嘉科技」，独立成站'],
      ['宏碁', 'acer', [
        { url: 'acer.com', label: '国际官网' },
        { url: 'acer.com.cn', label: '中国官网' }
      ], ''],
      // 旧（2026-11-22 前）：只有 xiaomi，下面另有一条「小米商城 / mi.com」重复条目
      // ['小米', 'xiaomi', [
      // 新（2026-11-22）：并入 mi.com 品牌词（带点写法，接 mi.com / mi.com.cn / mi.com-xxx 这类仿冒），商城站点本来就在本站点列表里
      ['小米', 'xiaomi mi.com', [
        { url: 'xiaomi.com', label: '官网' },
        { url: 'mi.com', label: '小米商城' }
      ], ''],
      ['三星', 'samsung', [
        { url: 'samsung.com', label: '国际官网' },
        { url: 'samsung.com.cn', label: '中国官网' }
      ], ''],
      ['西部数据', 'westerndigital', 'westerndigital.com', ''],
      ['希捷', 'seagate', 'seagate.com', ''],
      ['东芝', 'toshiba', 'toshiba.com', ''],
      ['金士顿', 'kingston', 'kingston.com', ''],
      ['罗技', 'logitech', [
        { url: 'logitech.com', label: '官网' },
        { url: 'logitechg.com', label: '罗技 G 游戏外设' }
      ], '中国站 logitech.com.cn 302 到 logitech.com/zh-cn（同一页，不单列）'],
      ['雷蛇', 'razer', [
        { url: 'razer.com', label: '国际官网' },
        { url: 'razer.com.cn', label: '中国官网' }
      ], ''],
      ['海盗船', 'corsair', 'corsair.com', ''],
      ['酷冷至尊', 'coolermaster', 'coolermaster.com', ''],
      ['猫头鹰 Noctua', 'noctua', 'noctua.at', ''],
      ['NZXT', 'nzxt', 'nzxt.com', ''],
      ['海韵 Seasonic', 'seasonic', 'seasonic.com', ''],
      ['安钛克 Antec', 'antec', 'antec.com', ''],
      ['追风者 Phanteks', 'phanteks', 'phanteks.com', ''],
      ['联力 Lian Li', 'lian-li', 'lian-li.com', ''],
      ['芝奇 G.SKILL', 'gskill', 'gskill.com', ''],
      ['十铨 TeamGroup', 'teamgroup', 'teamgroupinc.com', ''],
      ['威刚 ADATA', 'adata', 'adata.com', ''],
      ['英睿达 Crucial', 'crucial', 'crucial.com', ''],
      ['美光 Micron', 'micron', 'micron.com', ''],
      ['华擎 ASRock', 'asrock', 'asrock.com', ''],
    ]],
    // ========== 电商与支付类 ==========
    ['电商与支付类', [
      ['淘宝', 'taobao', 'taobao.com', ''],
      ['天猫', 'tmall', [
        { url: 'tmall.com', label: '中国站' },
        { url: 'tmall.hk', label: '天猫国际' }
      ], '天猫国际 tmall.hk 为独立站点（海外直供）'],
      ['阿里巴巴', 'alibaba', 'alibaba.com', '国内批发站 1688.com 已单列；alibabacloud.com 见「阿里云国际站」'],
      ['阿里云国际站', 'alibabacloud', 'alibabacloud.com', ''],
      ['阿里妈妈', 'alimama', 'alimama.com', ''],
      ['1688', '1688', '1688.com', ''],
      ['飞猪', 'fliggy alitrip', 'fliggy.com', ''],
      ['菜鸟网络', 'cainiao', 'cainiao.com', ''],
      ['蚂蚁集团', 'antgroup antfin', 'antgroup.com', ''],
      ['京东', 'jd jd.com jingdong', [
        { url: 'jd.com', label: '主站' },
        { url: 'global.jd.com', label: '京东全球售' },
        { url: 'jd.hk', label: '京东香港站' }
      ], ''],
      // 旧（2026-11-22 前）：只有 pinduoduo / pdd，跨境站 Temu 的仿冒站命中不了
      // ['拼多多', 'pinduoduo pdd', [
      ['拼多多', 'pinduoduo pdd temu', [
        { url: 'pinduoduo.com', label: '中国站' },
        { url: 'www.temu.com', label: '国际版 Temu' }
      ], 'Temu 为拼多多控股的跨境平台，站点完全独立；裸域 temu.com 会 302 到 http，写 www 才走 HTTPS'],
      ['寻梦信息', 'xunmeng', 'xunmeng.com', ''],
      ['美团', 'meituan', 'meituan.com', ''],
      ['大众点评', 'dianping', 'dianping.com', ''],
      ['口碑', 'koubei', 'koubei.com', ''],
      ['饿了么', 'ele.me', 'ele.me', ''],
      ['苏宁易购', 'suning', 'suning.com', ''],
      ['国美', 'gome', 'gome.com.cn', ''],
      ['闲鱼', 'goofish', 'goofish.com', ''],
      ['什么值得买', 'smzdm', 'smzdm.com', ''],
      ['返利网', 'fanli', 'fanli.com', ''],
      ['考拉海购', 'kaola', 'kaola.com', ''],
      ['当当网', 'dangdang', 'dangdang.com', ''],
      // 旧（单域名，2026-11-12）：只写了 amazon.cn，国际站无处可去
      // ['亚马逊', 'amazon', 'amazon.cn', ''],
      ['亚马逊', 'amazon', [
        { url: 'amazon.cn', label: '中国站' },
        { url: 'amazon.com', label: '国际站' }
      ], '⚠️ 2026-11-21 实测：amazon.cn 现在只剩「海外购」业务（首页标题为「海外购改版通知」）；短域 z.cn 301 到 amazon.cn（同一站，不单列）'],
      ['聚美优品', 'jumei', 'jumei.com', ''],
      ['凡客诚品', 'vancl', 'vancl.com', ''],
      ['唯品会', 'vipshop', 'vip.com', ''],
      ['莎莎', 'sasa.com', 'sasa.com', ''],
      ['丝芙兰', 'sephora', [
        { url: 'sephora.cn', label: '中国官网' },
        { url: 'sephora.com', label: '国际官网' }
      ], ''],
      ['优衣库', 'uniqlo', [
        { url: 'uniqlo.com', label: '国际官网' },
        { url: 'uniqlo.cn', label: '中国官网' }
      ], 'uniqlo.cn 标题为「优衣库网络旗舰店」，独立运营'],
      ['H&M', 'hm.com', 'hm.com', ''],
      ['ZARA', 'zara', [
        { url: 'zara.com', label: '国际官网' },
        { url: 'zara.cn', label: '中国官网' }
      ], 'zara.cn 标题为「飒拉（ZARA Online）」，为中国站'],
      ['耐克', 'nike', [
        { url: 'nike.com', label: '国际官网' },
        { url: 'nike.com.cn', label: '中国官网' }
      ], ''],
      ['阿迪达斯', 'adidas', [
        { url: 'adidas.com.cn', label: '中国官网' },
        { url: 'adidas.com', label: '国际官网' }
      ], ''],
      ['李宁', 'li-ning', 'li-ning.com', ''],
      ['安踏', 'anta', 'anta.com', ''],
      ['361 度', '361.com', '361.com', ''],
      ['特步', 'xtep', 'xtep.com', ''],
      ['鸿星尔克', 'erke', 'erke.com', ''],
      ['1 号会员店', 'yhd yhd.jd.com', 'yhd.jd.com', ''],
      // 旧（2026-11-22 前）：与「小米」条目同站点同产品，品牌词 mi.com 已并入上面那行
      // ['小米商城', 'mi.com', 'mi.com', ''],
      // 旧（2026-11-22 前）：国际版单独一行，从支付宝这边看不到
      // ['支付宝', 'alipay', 'alipay.com', '⚠️ 2026-11-21 实测 alipay.cn 返回 404，不是官网；国际版 alipayplus.com 已单列'],
      // 旧（2026-11-22 前）：只有 alipay，下面另有一条「支付宝（拼音域名）/ zhifubao」重复条目
      // ['支付宝', 'alipay', 'alipay.com', '⚠️ 2026-11-21 实测 alipay.cn 返回 404，不是官网；国际版为 Alipay+（alipayplus.com）', ['alipayplus']],
      ['支付宝', 'alipay zhifubao', 'alipay.com', '⚠️ 2026-11-21 实测 alipay.cn 返回 404，不是官网；国际版为 Alipay+（alipayplus.com）；zhifubao.com 是拼音写法', ['alipayplus']],
      ['支付宝国际', 'alipayplus', 'alipayplus.com', ''],
      // 旧（2026-11-22 前）：银联国际单独一行，从中国银联这边看不到
      // ['中国银联', 'unionpay', 'unionpay.com', '银联国际 unionpayintl.com、银联在线 up.com.cn、云闪付客服 95516.com 均已单列'],
      ['中国银联', 'unionpay', 'unionpay.com', '银联在线 up.com.cn、云闪付客服 95516.com 已单列；境外业务为银联国际（unionpayintl.com）', ['unionpayintl']],
      ['银联国际', 'unionpayintl', 'unionpayintl.com', ''],
      ['银联在线', 'up.com.cn', 'up.com.cn', ''],
      ['银联电子支付', 'chinapay', 'chinapay.com', ''],
      ['银联客服', '95516', '95516.com', ''],
      // 旧（2026-11-22 前）：只有 pay.weixin，下面另有一条「微信支付（商户）/ wechatpay wxpay」重复条目
      // ['微信支付', 'pay.weixin', 'pay.weixin.qq.com', ''],
      ['微信支付', 'pay.weixin wechatpay wxpay', 'pay.weixin.qq.com', 'wechatpay / wxpay 是商户侧的英文与缩写写法，站点与个人版同一个'],
      // 旧（2026-11-22 前）：与「支付宝」同站点，品牌词 zhifubao 已并入上面那行
      // ['支付宝（拼音域名）', 'zhifubao', 'alipay.com', ''],
      // 旧（2026-11-22 前）：与「微信支付」同站点，品牌词已并入上面那行
      // ['微信支付（商户）', 'wechatpay wxpay', 'pay.weixin.qq.com', '迁自云端补录'],
    ]],

    // ========== 地图与出行类 ==========
    ['地图与出行类', [
      ['百度地图', 'map.baidu baidumap', [
        { url: 'map.baidu.com', label: '网页版' },
        { url: 'lbsyun.baidu.com', label: '地图开放平台' }
      ], ''],
      ['高德地图', 'amap gaode autonavi', [
        { url: 'amap.com', label: '官网' },
        { url: 'ditu.amap.com', label: '网页版' },
        { url: 'lbs.amap.com', label: '开放平台' }
      ], ''],
      ['腾讯地图', 'map.qq', [
        { url: 'map.qq.com', label: '网页版' },
        { url: 'lbs.qq.com', label: '位置服务开放平台' }
      ], ''],
      ['滴滴出行', 'didi didiglobal', 'didiglobal.com', '⚠️ 2026-11-21 实测：didi.cn 只是一个「小桔备案」说明页，不是产品官网'],
      // 2026-11-21：本想在本类补「携程 / 去哪儿 / 12306」，但这三个品牌词已在「企业机构类」存在，
      //   本类若再写一次会被判重（先出现的生效、后出现的忽略），故只在原条目上补多站点。
    ]],

    // ========== 开发者与云服务类 ==========
    ['开发者与云服务类', [
      ['阿里云', 'aliyun aliyuncs', [
        { url: 'aliyun.com', label: '中国站' },
        { url: 'alibabacloud.com', label: '国际站' }
      ], '国际站账号、计费与中国站分开'],
      ['腾讯云', 'tencentcloud cloud.tencent', [
        { url: 'cloud.tencent.com', label: '中国站' },
        { url: 'tencentcloud.com', label: '国际站' }
      ], 'intl.cloud.tencent.com 301 到 www.tencentcloud.com'],
      ['华为云', 'huaweicloud', 'huaweicloud.com', 'huaweicloud.cn 301 到 huaweicloud.com（同一页，不单列）'],
      ['百度智能云', 'baiducloud cloud.baidu', 'cloud.baidu.com', ''],
      ['GitHub', 'github', 'github.com', ''],
      ['Gitee', 'gitee', 'gitee.com', ''],
      ['GitLab', 'gitlab', 'gitlab.com', ''],
      ['GitHub Copilot', 'githubcopilot', 'github.com', ''],
      ['CSDN', 'csdn', 'csdn.net', ''],
      ['开源中国', 'oschina', 'oschina.net', ''],
      ['掘金', 'juejin', 'juejin.cn', ''],
      ['V2EX', 'v2ex', 'v2ex.com', ''],
      ['博客园', 'cnblogs', 'cnblogs.com', ''],
      ['Stack Overflow', 'stackoverflow', 'stackoverflow.com', ''],
      ['菜鸟教程', 'runoob', 'runoob.com', ''],
      ['W3School', 'w3school', [
        { url: 'w3school.com.cn', label: '中文站' },
        { url: 'w3schools.com', label: '国际站' }
      ], 'w3schools.com 为英文原站，与中文站内容各自维护'],
      ['LeetCode', 'leetcode', [
        { url: 'leetcode.cn', label: '中国站' },
        { url: 'leetcode.com', label: '国际站' }
      ], '两站题库与账号体系独立'],
      ['编程猫', 'codemao', 'codemao.cn', ''],
      ['吾爱破解', '52pojie', '52pojie.cn', ''],
      ['果核剥壳', 'ghxi', 'ghxi.com', ''],
      ['小众软件', 'appinn', 'appinn.com', ''],
      ['扩展迷', 'crxsoso', 'crxsoso.com', ''],
      ['Ubuntu', 'ubuntu', [
        { url: 'ubuntu.com', label: '国际官网' },
        { url: 'cn.ubuntu.com', label: '中文站' }
      ], ''],
      ['Debian', 'debian', 'debian.org', ''],
      ['Arch Linux', 'archlinux', 'archlinux.org', ''],
      ['Fedora', 'fedoraproject', 'fedoraproject.org', ''],
      ['CentOS', 'centos', 'centos.org', ''],
      ['openSUSE', 'opensuse', 'opensuse.org', ''],
      ['Kali Linux', 'kali', 'kali.org', ''],
      ['deepin 深度', 'deepin', 'deepin.org', ''],
      ['优麒麟', 'ubuntukylin', 'ubuntukylin.com', ''],
      ['统信 UOS', 'uniontech uos', 'uniontech.com', ''],
      ['Python', 'python', 'python.org', ''],
      ['Node.js', 'nodejs', 'nodejs.org', ''],
      ['Go', 'golang', [
        { url: 'go.dev', label: '官网（go.dev）' },
        { url: 'golang.org', label: '旧官网 / 文档域' }
      ], '2023 年起官方主站迁到 go.dev，golang.org 仍保留文档与下载'],
      ['Rust', 'rust-lang', 'rust-lang.org', ''],
      ['PHP', 'php', 'php.net', ''],
      ['Java', 'java', 'java.com', ''],
      ['Oracle', 'oracle', 'oracle.com', ''],
      ['Vue.js', 'vuejs', 'vuejs.org', ''],
      // 旧（2026-11-12）：reactjs.org 已 301 到 react.dev，主域应改
      // ['React', 'reactjs', 'reactjs.org', ''],
      // 旧（2026-11-22 前）：只有 reactjs，react-official.top 这类用 react 的仿冒站命中不了
      // ['React', 'reactjs', 'react.dev', '⚠️ 2026-11-21：reactjs.org 已 301 到 react.dev（官方新文档站）'],
      ['React', 'reactjs react', 'react.dev', '⚠️ 2026-11-21：reactjs.org 已 301 到 react.dev（官方新文档站）'],
      ['MySQL', 'mysql', 'mysql.com', ''],
      ['MariaDB', 'mariadb', 'mariadb.org', ''],
      ['PostgreSQL', 'postgresql', 'postgresql.org', ''],
      ['MongoDB', 'mongodb', 'mongodb.com', ''],
      ['Redis', 'redis', 'redis.io', ''],
      ['Nginx', 'nginx', [
        { url: 'nginx.org', label: '开源项目官网' },
        { url: 'nginx.com', label: '商业公司官网（F5）' }
      ], '两个站分属开源项目与商业实体，内容不同'],
      ['Apache', 'apache', 'apache.org', ''],
      ['WordPress', 'wordpress', [
        { url: 'wordpress.org', label: '开源项目官网' },
        { url: 'wordpress.com', label: '托管建站服务' }
      ], 'wordpress.com 是 Automattic 的托管服务，与 .org 分开'],
      ['Typecho', 'typecho', 'typecho.org', ''],
      ['Hexo', 'hexo', 'hexo.io', ''],
      ['Discuz', 'discuz', 'discuz.net', ''],
      ['Z-Blog', 'zblog', 'zblogcn.com', ''],
      ['DedeCMS', 'dedecms', 'dedecms.com', ''],
      ['PHPCMS', 'phpcms', 'phpcms.com', ''],
      ['帝国 CMS', 'empirecms', 'empirecms.com', ''],
      ['Notepad++', 'notepad-plus-plus', 'notepad-plus-plus.org', ''],
      ['Sublime Text', 'sublimetext', 'sublimetext.com', ''],
      ['JetBrains', 'jetbrains', 'jetbrains.com', ''],
      ['Visual Studio Code', 'visualstudio vscode', 'code.visualstudio.com', ''],
      ['Atom', 'atom.io', 'atom.io', '⚠️ 2026-11-21 实测 atom.io 已 301 到 GitHub 的「Sunsetting Atom」公告，项目 2022 年停止开发'],
      ['站长之家', 'chinaz', 'chinaz.com', ''],
      ['友盟', 'umeng', 'umeng.com', ''],
      ['TalkingData', 'talkingdata', 'talkingdata.com', ''],
      ['个推', 'getui', 'getui.com', ''],
      ['腾讯 Bugly', 'bugly', 'bugly.qq.com', ''],
      ['IPIP', 'ipip', 'ipip.net', ''],
      ['拨测', 'boce', 'boce.com', ''],
      ['站酷', 'zcool', 'zcool.com.cn', ''],
      ['UI 中国', 'ui.cn', 'ui.cn', ''],
      ['爱给网', 'aigei', 'aigei.com', ''],
      // 旧（2026-11-12）：gitbook.io 为旧域，现主域 gitbook.com
      // ['GitBook', 'gitbook', 'gitbook.io', ''],
      ['GitBook', 'gitbook', 'gitbook.com', '⚠️ gitbook.io 为旧域（现跳转到 gitbook.com），不单列'],
    ]],

    // ========== 游戏与加速器类 ==========
    ['游戏与加速器类', [
      // 2026-11-21：原来是多站点，实测 www.wegame.com 与 www.wegame.com.cn 页面标题完全一致（同一站），改回单域名
      ['腾讯游戏', 'wegame', 'wegame.com.cn', 'wegame.com 是同一站的别名（标题一致），不单列'],
      // 旧（2026-11-22 前）：中国区「蒸汽平台」是另一行，两边互不可见
      // ['Steam', 'steam', [
      //   { url: 'steampowered.com', label: '商店官网' },
      //   { url: 'steamcommunity.com', label: '社区官网' }
      // ], '社区与商店是两个独立站点，账号通用'],
      ['Steam', 'steam', [
        { url: 'steampowered.com', label: '商店官网' },
        { url: 'steamcommunity.com', label: '社区官网' }
      ], '社区与商店是两个独立站点，账号通用；中国区合规版为蒸汽平台（steamchina.com），账号互通', ['steamchina']],
      ['蒸汽平台', 'steamchina', 'steamchina.com', ''],
      ['Epic Games', 'epicgames', 'epicgames.com', ''],
      ['GOG', 'gog.com', 'gog.com', ''],
      ['EA', 'ea', 'ea.com', ''],
      ['育碧', 'ubisoft', 'ubisoft.com', ''],
      ['PlayStation', 'playstation', 'playstation.com', ''],
      ['Xbox', 'xbox', 'xbox.com', ''],
      ['任天堂', 'nintendo', [
        { url: 'nintendo.com', label: '国际官网' },
        { url: 'nintendo.com.hk', label: '香港官网' }
      ], ''],
      ['暴雪', 'blizzard battle.net', [
        { url: 'blizzard.com', label: '公司官网' },
        { url: 'battle.net', label: '暴雪战网' }
      ], 'battle.net 为游戏平台，与公司站分开'],
      ['拳头游戏', 'riotgames', 'riotgames.com', ''],
      ['英雄联盟', 'leagueoflegends', 'leagueoflegends.com', ''],
      ['米哈游', 'mihoyo', 'mihoyo.com', '国际品牌 HoYoverse 已单列（hoyoverse.com）'],
      ['原神', 'genshin', [
        { url: 'ys.mihoyo.com', label: '中国官网' },
        { url: 'mihoyo.com', label: '米哈游官网' }
      ], ''],
      ['米游社', 'miyoushe', 'miyoushe.com', ''],
      ['HoYoverse', 'hoyoverse', 'hoyoverse.com', ''],
      ['TapTap', 'taptap', 'taptap.com', ''],
      ['我的世界', 'minecraft', 'minecraft.net', ''],
      ['Mojang', 'mojang', 'mojang.com', ''],
      ['NGA', 'nga nga.cn', 'nga.cn', ''],
      ['17173', '17173', '17173.com', ''],
      ['多玩', 'duowan', 'duowan.com', ''],
      ['MC 百科', 'mcmod', 'mcmod.cn', ''],
      ['CurseForge', 'curseforge', 'curseforge.com', ''],
      ['小黑盒', 'xiaoheihe', 'xiaoheihe.cn', ''],
      ['网易 UU 加速器', 'uu.163 uu.163.com', 'uu.163.com', ''],
      ['迅游加速器', 'xunyou', 'xunyou.com', ''],
      ['雷神加速器', 'leigod', 'leigod.com', ''],
      ['奇游加速器', 'qiyou', 'qiyou.cn', ''],
    ]],

    // ========== 新闻与搜索类 ==========
    ['新闻与搜索类', [
      ['百度', 'baidu', 'baidu.com', ''],
      ['360 搜索', 'so.com', 'so.com', '360 公司官网 360.cn 已收在「360系」条目（安全软件类），此处不重复列出'],
      ['搜狗搜索', 'sogou soso', 'sogou.com', '搜狗已被腾讯收购，soso.com 为同主体废弃域'],
      ['DuckDuckGo', 'duckduckgo', 'duckduckgo.com', '迁自云端补录'],
      ['Bing', 'bing.com', 'bing.com', '2026-11-21 实测 cn.bing.com 跳转到 bing.com/?mkt=zh-CN（同一页，不单列）'],
      // 新（2026-11-21）：日本雅虎是独立公司运营的站点，页面与内容库完全分开
      ['Yahoo', 'yahoo', [
        { url: 'yahoo.com', label: '全球站' },
        { url: 'www.yahoo.co.jp', label: '日本雅虎' }
      ], '日本雅虎由 LY Corporation 独立运营（雅虎品牌授权），与全球站不是同一套编辑与账号体系'],
      ['今日头条', 'toutiao', [
        { url: 'toutiao.com', label: '主站' },
        { url: 'mp.toutiao.com', label: '头条号创作者平台' }
      ], '创作者后台独立成页，登录入口与主站分开'],
      // 旧（2026-11-22 前）：只有 163.com，下面另有一条「网易 163 邮箱 / 163」重复条目（同站点）
      // ['网易', '163.com', '163.com', '网易公司官网 netease.com 已收在「网易邮箱」条目（IM 与社交类），此处不重复列出'],
      // 新（2026-11-22）：并入纯数字品牌词 163（163vip.top / 163mail.top 这类仿冒靠它），门户与邮箱共用 163.com
      ['网易', '163.com 163', '163.com', '网易公司官网 netease.com 已收在「网易邮箱」条目（IM 与社交类），此处不重复列出；163 是邮箱域名的纯数字写法'],
      ['新浪', 'sina', 'sina.com.cn', '门户主站；微博 weibo.com 已单列（IM 与社交类），sina.cn 为移动版同站'],
      ['中华网', 'china.com', 'china.com', ''],
      ['人民网', 'people.com.cn', 'people.com.cn', '人民日报电子版 paper.people.com.cn 为同站子域，不单列'],
      ['新华网', 'xinhuanet', 'xinhuanet.com', '⚠️ 2026-11-21 实测：官网主域名已是 news.cn（标题与 xinhuanet.com 完全一致，同一站），两个域名都可用，故仍按单站点处理'],
      ['央视网', 'cctv', [
        { url: 'cctv.com', label: '央视网' },
        { url: 'cgtn.com', label: 'CGTN 国际台' }
      ], 'CGTN 为中央广播电视总台国际传播机构，独立站点、独立编辑'],
      ['中国新闻网', 'chinanews', 'chinanews.com.cn', '2026-11-21 实测 chinanews.com 与 chinanews.com.cn 标题完全一致（同一站，互为别名），不单列'],
      ['澎湃新闻', 'thepaper', 'thepaper.cn', ''],
      ['第一财经', 'yicai', [
        { url: 'yicai.com', label: '中国站' },
        { url: 'yicaiglobal.com', label: '一财全球 Yicai Global' }
      ], '英文站标题为「一财全球Yicai Global」，内容与中文站分开'],
      ['财新', 'caixin', [
        { url: 'caixin.com', label: '中文站' },
        { url: 'caixinglobal.com', label: '财新国际 Caixin Global' }
      ], '英文站独立编辑；⚠️ 2026-11-21 本机代理链路抓不到 caixinglobal.com 的响应，浏览器直连可开'],
      ['证券时报', 'stcn', 'stcn.com', ''],
      ['金融界', 'jrj', 'jrj.com.cn', ''],
      ['东方财富', 'eastmoney', 'eastmoney.com', '天天基金（fund.eastmoney.com）与股吧（guba.eastmoney.com）为同集团独立站点，天天基金已在金融类单列'],
      ['21 世纪经济报道', '21jingji', '21jingji.com', ''],
      ['华尔街见闻', 'wallstreetcn', 'wallstreetcn.com', ''],
      ['财联社', 'cls.cn', 'cls.cn', ''],
      ['天极网', 'yesky', 'yesky.com', ''],
      ['太平洋电脑网', 'pconline', 'pconline.com.cn', '太平洋汽车 pcauto.com.cn 是同集团另一品牌站，与本站内容无关，不列为第二官网'],
      ['IT168', 'it168', 'it168.com', ''],
      ['36 氪', '36kr', [
        { url: '36kr.com', label: '中文站' },
        { url: 'kr-asia.com', label: '英文站 KrASIA' }
      ], 'KrASIA 为 36 氪旗下英文科技媒体，独立域名独立编辑'],
      ['虎嗅', 'huxiu', 'huxiu.com', ''],
      ['爱范儿', 'ifanr', 'ifanr.com', ''],
      ['好奇心日报', 'qdaily', 'qdaily.com', '⚠️ 2026-11-21 实测：域名仍有 A 记录，但 https/http 均无任何响应（本机代理链路与直连均如此），站点实际已停运'],
      ['界面新闻', 'jiemian', 'jiemian.com', ''],
      ['蓝鲸财经', 'lanjinger', 'lanjinger.com', ''],
      ['果壳', 'guokr', 'guokr.com', ''],
    ]],

    // ========== 教育与考试类 ==========
    ['教育与考试类', [
      ['学信网', 'chsi', 'chsi.com.cn', '中国高等教育学生信息网（学历/学籍查询）'],
      ['阳光高考', 'gaokao.chsi', 'gaokao.chsi.com.cn', '教育部高校招生阳光工程指定平台'],
      ['教育部', 'moe', 'moe.gov.cn', '教育部教育考试院（四六级 / 教资 / 考研报名）另有站点，已单列「中国教育考试网」'],
      ['中国教育考试网', 'neea', 'neea.edu.cn', '教育部教育考试院官网：四六级、教师资格、考研等报名与成绩查询'],
      ['国家大学生就业服务平台', 'ncss', 'ncss.cn', '24365 校园招聘'],
      ['超星', 'chaoxing', 'chaoxing.com', '超星学习通 / 尔雅通识课'],
      ['中国教育在线', 'eol', 'eol.cn', ''],
      ['考研网', 'kaoyan', 'kaoyan.com', ''],
      ['考研365', 'kaoyan365', 'kaoyan365.com', ''],
      ['学而思', 'xueersi', [
        { url: 'xueersi.com', label: '学而思官网' },
        { url: 'tal.com', label: '好未来集团官网' }
      ], '好未来（TAL）为学而思母公司，集团站与业务站分开'],
      ['新东方', 'xdf neworiental', [
        { url: 'xdf.cn', label: '课程报名官网' },
        { url: 'neworiental.org', label: '新东方企业网' }
      ], '两站标题不同（「新东方官网」/「新东方企业网」），集团信息与课程报名分开'],
      ['新东方在线', 'koolearn', 'koolearn.com', ''],
      ['知学云', 'zhixue', 'zhixue.com', '实测跳 CAS 统一登录'],
      ['申请方', 'applysquare', 'applysquare.com', ''],
      // 旧（2026-11-12）：主域写的是 baijia.com，实测它 301 到 about.gaotu.cn，真正的主域是 gaotu.cn
      // ['高途', 'gaotu', 'baijia.com', 'baijia.com 实测跳 about.gaotu.cn（高途集团）'],
      ['高途', 'gaotu', 'gaotu.cn', '⚠️ baijia.com（原跟谁学域名）301 到 about.gaotu.cn，只作旧入口'],
      ['奥鹏教育', 'aofan', 'aofan.com', '⚠️ 2026-11-21 实测：域名有 A 记录但无任何响应，站点可能已停运'],
      ['自考365', 'zikao365', 'zikao365.com', ''],
      ['育路教育', 'yuloo', 'yuloo.com', ''],
      ['留学网', 'studyabroad', 'studyabroad.com.cn', ''],
      ['留学', 'liuxue', 'liuxue.com', '2026-11-21 实测：现在打开是「学而思留学」（出国留学咨询），已归入学而思体系；旧记录里跳 admin.qz100.com 的情况已不存在'],
      ['普通话水平测试', 'tpedutest', 'tpedutest.com', ''],
      ['驾考宝典', 'jiakaobaodian', 'jiakaobaodian.com', '迁自云端补录'],
      ['北京教育考试院', 'bjeea', 'bjeea.cn', ''],
      ['天津招考资讯网', 'zhaokao', 'zhaokao.net', ''],
      ['河北省教育考试院', 'hebeea', 'hebeea.edu.cn', ''],
      ['山西招生考试网', 'sxkszx', 'sxkszx.cn', ''],
      ['辽宁招生考试之窗', 'lnzsks', 'lnzsks.com', '实测确认'],
      ['吉林省教育考试院', 'jleea', 'jleea.com.cn', '备用域 jleea.edu.cn'],
      ['黑龙江省招生考试院', 'hljea lzk.hl', 'lzk.hl.cn', '备用域 hljea.cn'],
      ['上海市教育考试院', 'shmeea', 'shmeea.edu.cn', ''],
      ['江苏省教育考试院', 'jseea', 'jseea.cn', ''],
      ['浙江省教育考试院', 'zjzs', 'zjzs.net', ''],
      ['安徽省教育招生考试院', 'ahzsks', 'ahzsks.cn', ''],
      ['福建省教育考试院', 'eeafj', 'eeafj.cn', '实测确认'],
      ['江西省教育考试院', 'jxeea', 'jxeea.cn', ''],
      ['山东省教育招生考试院', 'sdzk', 'sdzk.cn', ''],
      ['河南省教育考试院', 'haeea', 'haeea.cn', ''],
      ['湖北省教育考试院', 'hbea', 'hbea.edu.cn', ''],
      ['湖南省教育考试院', 'hneao', 'hneao.cn', ''],
      ['广东省教育考试院', 'eeagd', 'eea.gd.gov.cn', '2026-11-12 修正：白名单原写 eeagd.edu.cn（不可达），真站为 eea.gd.gov.cn'],
      ['广西招生考试院', 'gxeea', 'gxeea.cn', '实测确认'],
      ['海南省考试局', 'hainan', 'hainan.gov.cn', '考试局在 ea.hainan.gov.cn'],
      ['重庆市教育考试院', 'cqksy', 'cqksy.cn', ''],
      ['四川省教育考试院', 'sceea', 'sceea.cn', ''],
      ['贵州省招生考试院', 'guizhou', 'guizhou.gov.cn', '考试院在 zsksy.guizhou.gov.cn'],
      ['云南省招生考试院', 'ynzs', 'ynzs.cn', '实测确认（云南省招考频道）'],
      ['陕西省教育考试院', 'sneea', 'sneea.cn', '实测确认'],
      ['甘肃省教育考试院', 'ganseea', 'ganseea.cn', ''],
      ['青海省教育考试网', 'qhjyks', 'qhjyks.com', ''],
      ['宁夏教育考试院', 'nxjyks', 'nxjyks.cn', ''],
      ['新疆教育考试院', 'xjzk', 'xjzk.gov.cn', '实测确认'],
      ['清华大学', 'tsinghua', 'tsinghua.edu.cn', ''],
      ['北京大学', 'pku', 'pku.edu.cn', ''],
      ['复旦大学', 'fudan', 'fudan.edu.cn', ''],
      ['上海交通大学', 'sjtu', 'sjtu.edu.cn', ''],
      ['浙江大学', 'zju', 'zju.edu.cn', ''],
      ['南京大学', 'nju', 'nju.edu.cn', ''],
      ['中国科学技术大学', 'ustc', 'ustc.edu.cn', ''],
      ['中山大学', 'sysu', 'sysu.edu.cn', ''],
      ['武汉大学', 'whu', 'whu.edu.cn', ''],
      ['哈尔滨工业大学', 'hit', 'hit.edu.cn', ''],
      ['华南理工大学', 'scut', 'scut.edu.cn', ''],
      ['中国传媒大学', 'cuc', 'cuc.edu.cn', ''],
      ['北京理工大学', 'bit', 'bit.edu.cn', ''],
      ['中国教育和科研网', 'edu', 'edu.cn', '高校统一域名（.edu.cn），短词护栏要求右侧非字母'],
    ]],

    // ========== 金融类 ==========
    ['金融类', [
      ['工商银行', 'icbc', [
        { url: 'icbc.com.cn', label: '中国官网' },
        { url: 'icbcasia.com', label: '工银亚洲（香港）' }
      ], '工银亚洲为工行香港子公司，独立站点与网银体系'],
      ['农业银行', 'abchina', 'abchina.com', ''],
      ['中国银行', 'boc', [
        { url: 'boc.cn', label: '中国银行' },
        { url: 'bochk.com', label: '中银香港' }
      ], '中银香港为独立上市子公司，独立站点；⚠️ 2026-11-21 本机代理链路抓不到 bochk.com 的响应，浏览器直连可开'],
      ['建设银行', 'ccb ccbchina', 'ccb.com', ''],
      ['交通银行', 'bankcomm', 'bankcomm.com', ''],
      ['邮储银行', 'psbc', 'psbc.com.cn', ''],
      ['招商银行', 'cmbchina', 'cmbchina.com', ''],
      ['民生银行', 'cmbc', 'cmbc.com.cn', ''],
      ['兴业银行', 'cib', 'cib.com.cn', ''],
      ['中信银行', 'citicbank', 'citicbank.com', ''],
      ['浦发银行', 'spdb', 'spdb.com.cn', ''],
      ['光大银行', 'cebbank', 'cebbank.com', ''],
      ['平安银行', 'pingan-bank bank.pingan', 'bank.pingan.com', '2026-11-21：补品牌词 bank.pingan —— 否则新增的 pingan（中国平安集团）会先命中，把 bank.pingan.com 认成集团站'],
      ['华夏银行', 'hxb', 'hxb.com.cn', ''],
      ['广发银行', 'cgbchina', 'cgbchina.com.cn', ''],
      ['浙商银行', 'czbank', 'czbank.com', ''],
      ['渤海银行', 'cbhb', 'cbhb.com.cn', ''],
      ['中国进出口银行', 'eximbank', 'eximbank.gov.cn', ''],
      ['国家开发银行', 'cdb', 'cdb.com.cn', ''],
      ['农业发展银行', 'adbc', 'adbc.com.cn', ''],
      ['北京银行', 'bankofbeijing', 'bankofbeijing.com.cn', ''],
      ['上海银行', 'bosc', 'bosc.cn', ''],
      ['江苏银行', 'jshbchina', 'jshbchina.com', ''],
      ['南京银行', 'njcb', 'njcb.com.cn', ''],
      ['宁波银行', 'nib', 'nib.com.cn', ''],
      ['杭州银行', 'hzbank', 'hzbank.com.cn', ''],
      ['青岛银行', 'qdccb', 'qdccb.com.cn', ''],
      ['大连银行', 'bankofdl', 'bankofdl.com', ''],
      ['厦门银行', 'xmccb', 'xmccb.com', ''],
      ['天津银行', 'tccb', 'tccb.com.cn', ''],
      ['哈尔滨银行', 'hrbcb', 'hrbcb.com.cn', ''],
      ['贵阳银行', 'bankofgy', 'bankofgy.com.cn', ''],
      ['重庆银行', 'cqcbank', 'cqcbank.com', ''],
      ['郑州银行', 'zzbank', 'zzbank.cn', ''],
      ['长沙银行', 'cscb', 'cscb.cn', ''],
      ['苏州银行', 'suzhoubank', 'suzhoubank.com', ''],
      ['兰州银行', 'lzbank', 'lzbank.com', ''],
      ['河北银行', 'hebbank', 'hebbank.com', ''],
      ['齐鲁银行', 'qlbank', 'qlbank.com.cn', ''],
      ['威海市商业银行', 'whccb', 'whccb.com.cn', ''],
      ['锦州银行', 'jinzhoubank', 'jinzhoubank.com.cn', ''],
      ['龙江银行', 'lhbchina', 'lhbchina.com', ''],
      ['上海农商银行', 'srcb', 'srcb.com.cn', ''],
      ['北京农商银行', 'bjrcb', 'bjrcb.com.cn', ''],
      ['广州农商银行', 'gzrcbank', 'gzrcbank.com', ''],
      ['重庆农商行', 'cqrcb', 'cqrcb.com.cn', ''],
      ['东莞银行', 'dongguanbank', 'dongguanbank.cn', ''],
      ['杭州联合银行', 'hzcbank', 'hzcbank.com.cn', ''],
      ['江西银行', 'jxbank', 'jxbank.com.cn', ''],
      ['广西北部湾银行', 'bhb', 'bhb.cn', ''],
      ['九江银行', 'jcbank', 'jcbank.com.cn', ''],
      ['徽商银行', 'hsbank', 'hsbank.com.cn', ''],
      ['山西银行', 'sxccb', 'sxccb.com.cn', '原晋商银行域名，2021 年山西银行承接'],
      ['南昌银行', 'nccbank', 'nccbank.com.cn', '2015 年已并入江西银行，白名单暂留'],
      ['包商银行', 'bsbchina', 'bsbchina.com', '2020 年已进入破产清算，白名单暂留'],
      ['汇丰银行', 'hsbc', [
        { url: 'hsbc.com.cn', label: '汇丰中国' },
        { url: 'hsbc.com', label: '汇丰集团' }
      ], '集团站（HSBC Holdings plc）与中国内地站内容、产品分开'],
      ['花旗银行', 'citibank', 'citibank.com.cn', ''],
      ['渣打银行', 'standardchartered', 'sc.com', ''],
      ['恒生银行', 'hangseng', [
        { url: 'hangseng.com.cn', label: '恒生中国' },
        { url: 'hangseng.com', label: '恒生银行（香港）' }
      ], '香港总行与内地法人银行为两套站点与网银'],
      ['法国巴黎银行', 'bnpparibas', 'bnpparibas.com.cn', ''],
      ['摩根大通', 'jpmorgan', 'jpmorgan.com.cn', ''],
      ['瑞银集团', 'ubs', 'ubs.com', ''],
      ['三菱日联银行', 'mufg', 'mufg.jp', ''],
      ['瑞穗银行', 'mizuhobank', 'mizuhobank.com', ''],
      ['华侨银行', 'ocbc', 'ocbc.com', ''],
      ['大华银行', 'uob', 'uob.com.sg', ''],
      ['马来亚银行', 'maybank', 'maybank.com', ''],
      ['美国银行', 'bankofamerica', 'bankofamerica.com', ''],
      ['德意志银行', 'deutschebank', 'deutschebank.com.cn', ''],
      ['荷兰国际集团', 'ing', 'ing.com', ''],
      ['荷兰合作银行', 'rabobank', 'rabobank.com', ''],
      ['工行客服', '95588', '95588.com', '客服短号站'],
      ['农行客服', '95599', '95599.com', '客服短号站'],
      ['招行客服', '95555', '95555.com', '客服短号站'],
      ['建行客服', '95533', '95533.com', '客服短号站'],
      ['交行客服', '95559', '95559.com', '客服短号站'],
      ['兴业客服', '95561', '95561.com', '客服短号站'],
      ['光大客服', '95595', '95595.com', '客服短号站'],
      ['民生客服', '95568', '95568.com', '客服短号站'],
      ['浦发客服', '95528', '95528.com', '客服短号站'],
      ['邮储客服', '95580', '95580.com', '客服短号站'],
      ['中信客服', '95577', '95577.com', '客服短号站'],
      ['国信证券', 'guosen', 'guosen.com.cn', ''],
      ['广发证券', 'gf', 'gf.com.cn', ''],
      // 旧（2026-11-12）：合并后主域已换，gtja.com 现在只做 301
      // ['国泰海通', 'gtja', 'gtja.com', '原国泰君安，2025 年与海通合并'],
      ['国泰海通', 'gtja gtht', 'gtht.com', '⚠️ 2026-11-21 实测：gtja.com 301 到 www.gtht.com（合并后新主域，标题「国泰海通证券」）；原国泰君安与海通证券 2025 年合并'],
      ['海通证券', 'haitong', 'haitong.com', '已并入国泰海通'],
      ['中信建投', 'csc108', 'csc108.com', ''],
      ['申万宏源', 'swhy swhysc', 'swhy.com', '备用域 sw2000.com.cn'],
      ['中金公司', 'cicc', 'cicc.com.cn', ''],
      ['长江证券', 'cijsc', 'cijsc.com.cn', ''],
      ['中泰证券', 'zts', 'zts.com.cn', '原齐鲁证券'],
      ['光大证券', 'ebscn', 'ebscn.com', ''],
      ['国元证券', 'gyzq', 'gyzq.com.cn', ''],
      ['东莞证券', 'dgzq', 'dgzq.com.cn', ''],
      ['华泰证券', 'htsec', 'htsec.com', 'huatai.com 证书已过期，不作官网'],
      ['华泰联合证券', 'htzq', 'htzq.com.cn', ''],
      ['东吴证券', 'dwzq', 'dwzq.com.cn', ''],
      ['齐鲁证券', 'qlzq', 'qlzq.com.cn', '已更名中泰证券，白名单暂留'],
      ['山西证券', 'sxzb', 'sxzb.com.cn', ''],
      ['国海证券', 'gxfc', 'gxfc.com.cn', '白名单原归「资管与 AMC」，实为券商'],
      ['招商证券', 'cmschina', 'cmschina.com', ''],
      ['天风证券', 'tfzq', 'tfzq.com.cn', ''],
      ['东方证券', 'orientsec', 'orientsec.com.cn', ''],
      ['中信证券', 'citics', 'citics.com', ''],
      ['中投公司', 'china-invs', 'china-invs.cn', '中国投资有限责任公司'],
      // 旧（2026-11-12）：主域拼写有误（带连字符），该域已无响应
      // ['中国人寿', 'china-life', 'china-life.com.cn', ''],
      ['中国人寿', 'china-life chinalife', 'chinalife.com.cn', '⚠️ 2026-11-21 实测：真正的主域是 chinalife.com.cn（无连字符，标题「中国人寿官网-保险·投资·银行」）；旧记录 china-life.com.cn 无任何响应'],
      ['中国人保', 'picc piccnet', 'picc.com', ''],
      ['中国太保', 'cpic', 'cpic.com.cn', ''],
      ['泰康保险', 'taikang', 'taikang.com', ''],
      // 旧（2026-11-12）：主域写成了旧入口 pa18.com
      // ['中国平安', 'pa18', 'pa18.com', 'pingan.com 为主站，此处收录旧入口'],
      ['中国平安', 'pa18 pingan', 'pingan.com', '⚠️ pa18.com 为早期旧入口，2026-11-21 实测无响应；主站是 pingan.com'],
      ['中国大地保险', 'ccic-net', 'ccic-net.com.cn', '2026-11-12 修正：白名单原写 ccic.com.cn，那是中国检验认证集团'],
      ['中宏保险', 'sunlife', 'sunlife.com.cn', ''],
      ['大都会人寿', 'metlife', 'metlife.com.cn', ''],
      ['友邦保险', 'aia', 'aia.com.cn', ''],
      ['安联保险', 'allianz', 'allianz.com.cn', ''],
      ['忠利保险', 'generali', 'generali.com.cn', ''],
      ['安达保险', 'chubb', 'chubb.com', ''],
      ['富卫保险', 'fwd', 'fwd.com', ''],
      ['宏利人寿', 'manulife', 'manulife.com.cn', ''],
      ['保诚', 'prudential', 'prudential.com.hk', ''],
      ['华夏基金', 'chinaamc', 'chinaamc.com', ''],
      ['基金买卖网', 'jjmmw', 'jjmmw.com', ''],
      ['天天基金', 'tiantianfunds', 'tiantianfunds.com', ''],
      ['天天基金（东财）', 'fund.eastmoney', 'fund.eastmoney.com', '2026-11-21 实测与 tiantianfunds.com 标题完全一致（同一站，互为别名）'],
      ['中国基金网', 'chinafund', 'chinafund.cn', ''],
      ['万家基金', 'wtfund', 'wtfund.com', ''],
      ['酷基金网', 'ourku', 'ourku.com', ''],
      ['中金所', 'cffex', 'cffex.com.cn', '中国金融期货交易所'],
      ['上期所', 'shfe', 'shfe.com.cn', '上海期货交易所'],
      ['大商所', 'dce', 'dce.com.cn', '大连商品交易所'],
      ['郑商所', 'czce', 'czce.com.cn', '郑州商品交易所'],
      ['上海国际能源交易中心', 'ine', 'ine.com.cn', ''],
      ['芝加哥商品交易所', 'cme', 'cme.com', ''],
      ['中国华融', 'huarong', 'huarong.com', '⚠️ 2026-11-21 实测：huarong.com 只返回「This is the default server vhost」默认页，站点已不再服务；公司已更名「中信金融资产」（新官网域名未确认，故不填写）'],
      // 旧（2026-11-12）：amc.cinda.com 已不可用，主域是 cinda.com.cn
      // ['中国信达', 'amc.cinda', 'amc.cinda.com', ''],
      ['中国信达', 'amc.cinda cinda', 'cinda.com.cn', '⚠️ 2026-11-21 实测：amc.cinda.com 无响应，中国信达官网为 cinda.com.cn'],
    ]],

    // ========== 企业机构类 ==========
    ['企业机构类', [
      ['中国移动', '10086 chinamobile', [
        { url: '10086.cn', label: '客户服务 / 网上营业厅' },
        { url: 'chinamobile.com', label: '集团官网' }
      ], '两站分工不同：10086.cn 面向个人业务办理，chinamobile.com 是集团公司站'],
      ['中国联通', '10010 chinaunicom', [
        { url: '10010.com', label: '客户服务 / 网上营业厅' },
        { url: 'chinaunicom.com', label: '集团官网' }
      ], ''],
      ['中国电信', 'chinatelecom', [
        { url: '189.cn', label: '网上营业厅' },
        { url: 'chinatelecom.com.cn', label: '集团官网' }
      ], '⚠️ 2026-11-21 实测：10000.com 现在是一家家装展会网站（「万有网」），与中国电信无关，原备注「10000.com 为客服站」有误'],
      ['澳门电讯', 'ctm', 'ctm.com.mo', '中国澳门'],
      ['中国移动香港', 'cmhk', 'cmhk.com', '中国香港'],
      ['数码通', 'smartone', 'smartone.com', '中国香港'],
      ['3 香港', 'three', 'three.com.hk', '中国香港'],
      ['香港电讯', 'pccw', 'pccw.com', '中国香港'],
      ['CSL', 'hkcsl', 'csl.com', '中国香港'],
      ['1O1O', '1010', '1010.com', '中国香港'],
      ['中国移动国际', 'cmlink', 'cmlink.com', ''],
      ['中国石油', 'cnpc petrochina', [
        { url: 'cnpc.com.cn', label: '集团公司站' },
        { url: 'petrochina.com.cn', label: '股份公司站' }
      ], '中国石油集团（CNPC）与上市主体中国石油股份（PetroChina）各自成站'],
      ['中国石化', 'sinopec', [
        { url: 'sinopec.com', label: '中国石化（股份）' },
        { url: 'sinopecgroup.com.cn', label: '集团公司站' }
      ], '2026-11-21 实测 sinopecgroup.com.cn 标题为「中国石化集团公司网站」'],
      ['中国海油', 'cnooc', 'cnooc.com', ''],
      ['申能集团', 'shenergy', 'shenergy.com', ''],
      ['华电集团', 'huadian', 'huadian.com', ''],
      ['中国华能', 'chng', 'chng.com.cn', ''],
      ['国家电投', 'spic', 'spic.com.cn', ''],
      ['国家能源集团', 'cgdc', 'cgdc.com.cn', ''],
      ['中广核', 'cgnpc', 'cgnpc.com.cn', ''],
      ['国家电网', 'sgcc', [
        { url: 'sgcc.com.cn', label: '公司官网' },
        { url: '95598.cn', label: '网上国网（客服）' }
      ], '95598.cn 为国家电网统一客户服务网站（电费查询 / 缴费）'],
      ['南方电网', 'csg', 'csg.cn', ''],
      ['中国电建', 'powerchina', 'powerchina.cn', ''],
      ['中国能建', 'ceec', 'ceec.net.cn', ''],
      ['宝武钢铁', 'baosteel', 'baosteel.com', ''],
      ['沙钢', 'shasteel', 'shasteel.com', ''],
      ['鞍钢', 'ansteel', 'ansteel.com', ''],
      ['武钢', 'wusteel', 'wusteel.com', '已并入宝武'],
      ['河北钢铁', 'hbisco', 'hbisco.com', ''],
      ['首钢', 'shougang', 'shougang.com', ''],
      ['太钢', 'taigang', 'taigang.com', ''],
      ['中国铝业', 'chinalco', 'chinalco.com', ''],
      ['江西铜业', 'jiangxi-copper', 'jiangxi-copper.com', ''],
      ['铜陵有色', 'tongling', 'tongling.com', ''],
      ['云铝股份', 'yunlu', 'yunlu.com', ''],
      ['紫金矿业', 'zijinmining', 'zijinmining.com', ''],
      ['洛阳钼业', 'cmoc', 'cmoc.com', ''],
      ['兖矿能源', 'yanzhoucoal', 'yanzhoucoal.com', ''],
      ['中国中煤', 'china-coal', 'china-coal.com', ''],
      ['神华集团', 'shenhua', 'shenhua.com', ''],
      ['中工国际', 'camce', 'camce.com', ''],
      ['中国化工', 'chemchina', 'chemchina.com', ''],
      ['中化集团', 'sinochem', 'sinochem.com', ''],
      ['先正达', 'syngenta', 'syngenta.cn', ''],
      ['雅苒', 'yara', 'yara.com', ''],
      ['蓝星', 'bluestar', 'bluestar.com', ''],
      ['万华化学', 'wanhua', 'wanhua.com', ''],
      ['海化集团', 'haihua', 'haihua.com', ''],
      ['上汽集团', 'saicmotor', 'saicmotor.com', ''],
      ['一汽集团', 'faw', 'faw.com', '2026-11-21 实测 faw.com 与 faw.com.cn 标题一致（「中国第一汽车集团有限公司」），同一站，不单列'],
      // 旧（2026-11-12）：dongfeng.com 裸域没有 A 记录、www 也无响应
      // ['东风汽车', 'dongfeng', 'dongfeng.com', ''],
      ['东风汽车', 'dongfeng dfmc', 'dfmc.com.cn', '⚠️ 2026-11-21 实测：dongfeng.com 裸域无 A 记录、www.dongfeng.com 无响应；东风汽车集团官网为 dfmc.com.cn（标题「东风汽车集团有限公司」）'],
      ['吉利汽车', 'geely', 'geely.com', ''],
      ['奇瑞汽车', 'chery', 'chery.cn', ''],
      ['长城汽车', 'greatwallmotor gwm', [
        { url: 'greatwallmotor.com', label: '中国官网' },
        { url: 'gwm-global.com', label: '海外官网 GWM' }
      ], '⚠️ 2026-11-21 实测 gwm-global.com 为长城汽车海外集团站（GWM Group）；greatwallmotor.com 在本机链路抓不到响应'],
      ['比亚迪', 'byd', 'byd.com', '2026-11-21 实测 bydauto.com 301 到 byd.com/cn（同一站，不单列）'],
      // 旧（2026-11-12）：gac.com.cn 已 301 到 gacgroup.com
      // ['广汽集团', 'gac', 'gac.com.cn', ''],
      ['广汽集团', 'gac gacgroup gacmotor', [
        { url: 'gacgroup.com', label: '集团官网' },
        { url: 'gacmotor.com', label: '广汽传祺' }
      ], '⚠️ gac.com.cn 301 到 gacgroup.com（新主域）；gacmotor.com 是乘用车品牌传祺的独立站；品牌词补 gacgroup / gacmotor（gac 在 gacgroup 里会被字母边界挡住）'],
      ['广汽丰田', 'gac-toyota', 'gac-toyota.com', ''],
      ['广汽本田', 'gac-honda', 'gac-honda.com', ''],
      ['宝马中国', 'bmw', 'bmw.com.cn', ''],
      ['奔驰中国', 'benz', 'benz.com.cn', ''],
      ['奥迪中国', 'audi', 'audi.cn', ''],
      ['一汽大众', 'volkswagen', 'volkswagen.com.cn', ''],
      ['丰田中国', 'toyota', 'toyota.com.cn', ''],
      ['本田中国', 'honda', 'honda.com.cn', ''],
      ['日产中国', 'nissan', 'nissan.com.cn', ''],
      ['福特中国', 'ford', 'ford.com.cn', ''],
      ['通用中国', 'gm', 'gm.com.cn', ''],
      ['现代汽车', 'hyundai', 'hyundai.com.cn', ''],
      ['起亚汽车', 'kia', 'kia.com.cn', ''],
      ['马自达', 'mazda', 'mazda.com.cn', ''],
      ['斯巴鲁', 'subaru', 'subaru.com.cn', ''],
      ['三菱汽车', 'mitsubishi', 'mitsubishi.com.cn', ''],
      ['沃尔沃中国', 'volvo', 'volvo.com.cn', ''],
      ['特斯拉中国', 'tesla', 'tesla.cn', ''],
      ['蔚来汽车', 'nio', 'nio.cn', ''],
      ['小鹏汽车', 'xpeng', 'xpeng.com', ''],
      ['理想汽车', 'lixiang', 'lixiang.com', ''],
      ['威马汽车', 'wmotor', 'wmotor.com', ''],
      ['雷丁汽车', 'levdeo', 'levdeo.com', ''],
      ['天际汽车', 'enovate', 'enovate.com', ''],
      ['极狐汽车', 'arcfox', 'arcfox.com', ''],
      ['海尔', 'haier', 'haier.com', '2026-11-21 实测 haier.cn 302 到 haier.com/cn（同一站，不单列）'],
      ['海信', 'hisense', 'hisense.com', ''],
      ['TCL', 'tcl', 'tcl.com', ''],
      ['创维', 'skyworth', 'skyworth.com', ''],
      ['格力', 'gree', 'gree.com', '2026-11-21 实测 gree.com.cn 跳回 gree.com（同一站，不单列）'],
      ['美的', 'midea meidi', [
        { url: 'midea.com', label: '集团官网' },
        { url: 'midea.cn', label: '美的商城' }
      ], 'midea.cn 是美的官方直营商城（标题「美的商城 - 美的集团官方商城网站」），与集团站内容不同'],
      ['长虹', 'changhong', 'changhong.com', '2026-11-21 实测跳转 cn.changhong.com（同一站的中文域，不单列）'],
      ['康佳', 'konka', 'konka.com', ''],
      // 旧（2026-11-12）：galanz.com 已 301 到 galanz.com.cn
      // ['格兰仕', 'galanz', 'galanz.com', ''],
      ['格兰仕', 'galanz', 'galanz.com.cn', '⚠️ 2026-11-21 实测 galanz.com 301 到 galanz.com.cn（主域已换）'],
      ['老板电器', 'robam', 'robam.com', ''],
      ['华帝', 'vatti', 'vatti.com', ''],
      ['欧派', 'oppel', 'oppel.com', ''],
      ['苏泊尔', 'supor', 'supor.com', ''],
      ['九阳', 'joyoung', 'joyoung.com', ''],
      ['卡萨帝', 'casarte', 'casarte.com', ''],
      ['统帅', 'leader', 'leader.com', ''],
      ['小天鹅', 'littleswan', 'littleswan.com', ''],
      ['国资委', 'sasac', 'sasac.gov.cn', ''],
      ['国机集团', 'china-mae', 'china-mae.com', ''],
      // 旧（2026-11-12）：airchina.com 已无响应，国航官网是 airchina.com.cn
      // ['国航', 'airchina', 'airchina.com', ''],
      ['国航', 'airchina', 'airchina.com.cn', '⚠️ 2026-11-21 实测：airchina.com 无响应；官网为 airchina.com.cn（标题「中国国际航空公司」）'],
      ['南航', 'csair', 'csair.com', ''],
      ['东航', 'ceair', 'ceair.com', ''],
      ['深航', 'shenzhenair', 'shenzhenair.com', ''],
      ['海南航空', 'hainanairlines', 'hainanairlines.com', ''],
      ['厦门航空', 'xiamenair', 'xiamenair.com', ''],
      ['上海航空', 'shanghaiair', 'shanghaiair.com', ''],
      ['春秋航空', 'springairlines', 'springairlines.com', ''],
      ['吉祥航空', 'juneyaoair', 'juneyaoair.com', ''],
      ['西部航空', 'westair', 'westair.cn', ''],
      ['奥凯航空', 'okair', 'okair.net', ''],
      ['华夏航空', 'chinaexpressair', 'chinaexpressair.com', ''],
      ['中国铁路 12306', '12306', 'www.12306.cn', '⚠️ 2026-11-21 实测：裸域 12306.cn 会 302 到 http://www.12306.cn（降级到 HTTP），写 www.12306.cn 才能直接走 HTTPS'],
      ['中国铁路', 'china-railway', 'china-railway.com.cn', ''],
      ['中国高铁', 'crh', 'crh.com.cn', ''],
      ['港铁', 'mtr', 'mtr.com.hk', '中国香港'],
      ['顺丰速运', 'sf-express', 'sf-express.com', '2026-11-21 实测 sf-express.com.cn 跳回 sf-express.com（同一站，不单列）'],
      ['顺丰（旧域）', 'sfbchina', 'sfbchina.com', ''],
      ['中通快递', 'zto', 'zto.com', ''],
      ['圆通速递', 'yto8000', 'yto8000.com', ''],
      ['韵达速递', 'yundaex', 'yundaex.com', ''],
      ['申通快递', 'sto', 'sto.cn', ''],
      ['极兔速递', 'jt-express', 'jt-express.com', ''],
      ['德邦快递', 'deppon', 'deppon.com', ''],
      ['日日顺', 'dblogistics', 'dblogistics.com', ''],
      ['中国邮政 EMS', 'ems', 'ems.com.cn', ''],
      ['中国邮政', 'chinapost', 'chinapost.com.cn', ''],
      ['壹米滴答', 'yimidida', 'yimidida.com', ''],
      ['货拉拉', 'huolala', 'huolala.com', ''],
      ['快宝', 'kuaibao', 'kuaibao.com', ''],
      ['万科', 'vanke', 'vanke.com', ''],
      ['碧桂园', 'countrygarden bgy', 'countrygarden.com', ''],
      ['恒大', 'evergrande', 'evergrande.com', ''],
      ['保利发展', 'poly', 'poly.com.cn', ''],
      ['中冶集团', 'cem', 'cem.com.cn', ''],
      ['华润置地', 'crland', [
        { url: 'crland.com.hk', label: '香港上市站' },
        { url: 'crland.com.cn', label: '中国内地站' }
      ], '两站分别为港股与内地业务入口'],
      ['龙湖', 'longfor', 'longfor.com', ''],
      ['绿城', 'greentown', 'greentown.com.cn', ''],
      ['新城控股', 'seazen', 'seazen.com.cn', ''],
      ['融创中国', 'sunac', 'sunac.com.cn', ''],
      ['金地集团', 'gemdale', 'gemdale.com', ''],
      ['龙光集团', 'logan', 'logan.com.hk', ''],
      ['世茂集团', 'shimao', 'shimao.com', ''],
      ['荣盛发展', 'rsh', 'rsh.com.cn', ''],
      ['中梁控股', 'zhongliang', 'zhongliang.com', ''],
      ['中骏集团', 'zhongjun', 'zhongjun.com', ''],
      ['雅居乐', 'agile', 'agile.com.cn', ''],
      ['中国建筑', 'cscec', 'cscec.com', '2026-11-21 实测 cscec.com.cn 与 cscec.com 标题一致（都是「中国建筑」），同一站，不单列'],
      // 旧（2026-11-12）：crec.com 是错的 —— 实测该域已属美国高力国际（Colliers）
      // ['中国中铁', 'crec', 'crec.com', ''],
      ['中国中铁', 'crec', 'www.crec.cn', '⚠️ 2026-11-21 实测：crec.com 已指向美国高力国际（Colliers）的页面，与中国中铁无关；官网为 www.crec.cn（中国中铁股份有限公司），裸域无 A 记录'],
      ['中国铁建', 'crcc', 'crcc.cn', ''],
      ['中交建', 'ccccltd', 'ccccltd.cn', ''],
      ['徐工集团', 'xcmg', 'xcmg.com', ''],
      ['中联重科', 'zoomlion', 'zoomlion.com', '白名单另有 zoomliion.com（错拼，已移除）'],
      // 旧（2026-11-12）：sany.com 实测不存在（NXDOMAIN）
      // ['三一重工', 'sany', 'sany.com', ''],
      ['三一重工', 'sany', 'sany.com.cn', '⚠️ 2026-11-21 实测：sany.com 为 NXDOMAIN（域名不存在）；官网为 sany.com.cn（标题「三一集团 | 三一重工」）'],
      ['柳工', 'liugong', 'liugong.com', ''],
      ['山河智能', 'sunward', 'sunward.com', ''],
      ['北京建工', 'bjjs', 'bjjs.com', ''],
      ['药监局', 'nmpa', 'nmpa.gov.cn', ''],
      ['卫健委', 'nhc', 'nhc.gov.cn', ''],
      ['疾控中心', 'chinacdc', 'chinacdc.com', ''],
      ['丁香园', 'dxy', 'dxy.com', ''],
      ['好大夫', 'haodf', 'haodf.com', ''],
      ['寻医问药', 'xywy', 'xywy.com', ''],
      ['家庭医生在线', 'familydoctor', 'familydoctor.com.cn', ''],
      ['健康科普', 'jkkp', 'jkkp.com', ''],
      ['健客网', 'jianke', 'jianke.com', ''],
      ['药房网', 'yaofang', 'yaofang.com', ''],
      ['梅斯医学', 'medsci', 'medsci.com', ''],
      ['生物谷', 'bioon', 'bioon.com', ''],
      ['沈阳药科大学', 'syphu', 'syphu.com', ''],
      ['国药集团', 'sinopharm', 'sinopharm.com', ''],
      ['石药集团', 'cspc', 'cspc.com', ''],
      ['华兰生物', 'hualanbio', 'hualanbio.com', ''],
      ['万泰生物', 'wantai', 'wantai.com', ''],
      ['康泰生物', 'kangtai', 'kangtai.com', ''],
      ['智飞生物', 'zhifeishengwu', 'zhifeishengwu.com', ''],
      ['复星医药', 'fosunpharma', [
        { url: 'fosunpharma.com', label: '复星医药' },
        { url: 'fosun.com', label: '复星集团' }
      ], '集团站与上市子公司站分开'],
      ['恒瑞医药', 'hengrui', 'hengrui.com', ''],
      ['翰森制药', 'hansoh', 'hansoh.cn', ''],
      ['三生制药', '3sbio', '3sbio.com', ''],
      ['同方药业', 'tongfang', 'tongfang.com', ''],
      ['携程', 'ctrip trip', [
        { url: 'ctrip.com', label: '中国站' },
        { url: 'trip.com', label: '国际站 Trip.com' }
      ], '国际站 trip.com 的内容、币种、客服与中国站分开'],
      ['去哪儿', 'qunar', 'qunar.com', ''],
      ['艺龙', 'elong', 'elong.com', ''],
      ['同程旅行', 'ly tongcheng', 'ly.com', ''],
      ['途牛', 'tuniu', 'tuniu.com', ''],
      ['马蜂窝', 'mafengwo', 'mafengwo.cn', ''],
      ['驴妈妈', 'lvmama', 'lvmama.com', ''],
      // 旧（2026-11-12）：huazhu.com 已 301 到 hworld.com
      // ['华住集团', 'huazhu', 'huazhu.com', ''],
      ['华住集团', 'huazhu hworld', 'hworld.com', '⚠️ 2026-11-21 实测：huazhu.com 301 到 hworld.com（集团英文品牌 H World 的新主域）'],
      ['锦江酒店', 'jinjiang', [
        { url: 'jinjiang.com', label: '锦江国际集团' },
        { url: 'jinjianghotels.com', label: '锦江酒店' }
      ], '集团站与酒店业务站分开'],
      ['首旅集团', 'btg', 'btg.com.cn', ''],
      ['如家', 'homeinns', 'homeinns.com', ''],
      ['7 天酒店', '7daysinn', '7daysinn.com', ''],
      ['万豪', 'marriott', 'marriott.com', ''],
      ['希尔顿', 'hilton', 'hilton.com', ''],
      ['洲际', 'ihg', 'ihg.com', ''],
      ['雅高', 'accor', 'accor.com', ''],
      ['温德姆', 'wyndham', 'wyndham.com', ''],
      ['香格里拉', 'shangri-la', 'shangri-la.com', ''],
      ['凯宾斯基', 'kempinski', 'kempinski.com', ''],
      ['路易威登', 'lv', 'lv.com', ''],
      ['Visa', 'visa', 'visa.com', ''],
      ['万事达', 'mastercard', 'mastercard.cn', ''],
      ['贵州茅台', 'moutai', 'moutai.com.cn', ''],
      ['五粮液', 'wuliangye', 'wuliangye.com.cn', ''],
      ['泸州老窖', 'luzhoulaojiao', 'luzhoulaojiao.com', ''],
      ['洋河', 'yanghe', 'yanghe.com', ''],
      ['古井贡酒', 'gujing', 'gujing.com.cn', ''],
      ['剑南春', 'jnc', 'jnc.com.cn', ''],
      ['牛栏山', 'niulanshan', 'niulanshan.com.cn', ''],
      ['青岛啤酒', 'tsingtao', [
        { url: 'tsingtao.com.cn', label: '中国官网' },
        { url: 'tsingtao.com', label: '英文官网（股份公司）' }
      ], '2026-11-21 实测两站标题不同（「青岛啤酒官方网站」/「Tsingtao Brewery Co.,Ltd.」）'],
      ['雪花啤酒', 'snowbeer', 'snowbeer.com.cn', ''],
      ['燕京啤酒', 'yanjing', 'yanjing.com.cn', ''],
      ['珠江啤酒', 'zjbeer', 'zjbeer.com', ''],
      ['可口可乐', 'coca-cola', 'coca-colacompany.com', '2026-11-21 实测 coca-cola.com 301 到 coca-colacompany.com（同一站的两个门牌，不单列）'],
      ['百事', 'pepsi', [
        { url: 'pepsi.com', label: '品牌官网' },
        { url: 'pepsico.com', label: '百事公司' }
      ], '品牌站与百事公司（PepsiCo）集团站分开'],
      ['雀巢', 'nestle', [
        { url: 'nestle.com.cn', label: '雀巢中国' },
        { url: 'nestle.com', label: '全球官网' }
      ], '⚠️ 2026-11-21 本机访问 nestle.com 被浏览器校验页拦截（403），站点本身正常'],
      ['伊利', 'yili', 'yili.com', ''],
      ['蒙牛', 'mengniu', 'mengniu.com', ''],
      ['旺旺', 'want-want', 'want-want.com', ''],
      ['康师傅', 'masterkong', 'masterkong.com.cn', ''],
      ['中粮', 'cofco', 'cofco.com', ''],
      ['农夫山泉', 'nongfu-spring', 'nongfu-spring.com', ''],
      ['娃哈哈', 'wahaha', 'wahaha.com', ''],
      ['统一企业', 'uni-president', 'uni-president.com', ''],
      ['光明乳业', 'brightdairy', 'brightdairy.com', ''],
      ['三元食品', 'sanyuan', 'sanyuan.com', ''],
      ['国家电影局', 'cin', 'cin.gov.cn', ''],
      ['住建部', 'mohurd', 'mohurd.gov.cn', ''],
      ['人社部', 'mohrss', 'mohrss.gov.cn', ''],
      ['财政部', 'mof', 'mof.gov.cn', ''],
      ['商务部', 'mofcom', 'mofcom.gov.cn', ''],
      ['发改委', 'ndrc', 'ndrc.gov.cn', ''],
      ['工信部', 'miit', 'miit.gov.cn', ''],
      ['市场监管总局', 'samr', 'samr.gov.cn', ''],
      ['海关总署', 'customs', 'customs.gov.cn', ''],
      ['税务总局', 'tax', 'tax.gov.cn', ''],
      ['IBM', 'ibm', 'ibm.com', ''],
      ['Intel', 'intel', [
        { url: 'intel.com', label: '全球官网' },
        { url: 'intel.cn', label: '英特尔中国' }
      ], ''],
      ['AMD', 'amd', 'amd.com', '2026-11-21 实测 amd.com.cn 301 到 amd.com/zh-cn（同一站，不单列）'],
      ['英伟达', 'nvidia', [
        { url: 'nvidia.com', label: '全球官网' },
        { url: 'nvidia.cn', label: '英伟达中国' }
      ], ''],
      ['LG', 'lg', 'lg.com', ''],
      ['索尼', 'sony', [
        { url: 'sony.com', label: '全球官网' },
        { url: 'sony.com.cn', label: '索尼中国' }
      ], 'sony.com.cn 标题为「索尼（中国）有限公司企业官网」'],
      ['松下', 'panasonic', 'panasonic.cn', ''],
      ['日立', 'hitachi', 'hitachi.com', ''],
      ['夏普', 'sharp', 'sharp.cn', ''],
      ['飞利浦', 'philips', 'philips.com.cn', '2026-11-21 实测 philips.com 301 到 philips.com.cn（中国站才是主域，全球站为 philips.com/global）'],
      ['博世', 'bosch', [
        { url: 'bosch.com', label: '全球官网' },
        { url: 'bosch.com.cn', label: '博世中国' }
      ], 'bosch.com.cn 标题为「主页 | 博世在中国」'],
      ['西门子', 'siemens', 'siemens.com', '2026-11-21 实测 siemens.com.cn 301 到 siemens.com/zh-cn（同一站，不单列）'],
      ['通用电气', 'ge', 'ge.com', ''],
      ['霍尼韦尔', 'honeywell', 'honeywell.com', ''],
      ['3M', '3m', '3m.com', ''],
      ['杜邦', 'dupont', [
        { url: 'dupont.com', label: '全球官网' },
        { url: 'dupont.cn', label: '杜邦中国' }
      ], 'dupont.cn 标题为「DuPont China 中国」'],
      ['巴斯夫', 'basf', 'basf.com', ''],
      ['拜耳', 'bayer', [
        { url: 'bayer.com', label: '全球官网' },
        { url: 'bayer.com.cn', label: '拜耳中国' }
      ], ''],
      ['诺华', 'novartis', [
        { url: 'novartis.com', label: '全球官网' },
        { url: 'novartis.com.cn', label: '诺华中国' }
      ], 'novartis.com.cn 标题为「诺华集团中文官方网站」'],
      ['辉瑞', 'pfizer', [
        { url: 'pfizer.com', label: '全球官网' },
        { url: 'pfizer.com.cn', label: '辉瑞中国' }
      ], ''],
      ['罗氏', 'roche', 'roche.com', ''],
      ['葛兰素史克', 'gsk', 'gsk.com', ''],
      ['强生', 'jnj', [
        { url: 'jnj.com', label: '全球官网' },
        { url: 'jnj.com.cn', label: '强生中国' }
      ], '⚠️ 2026-11-21 本机取不到 jnj.com.cn 的标题（页面由 JS 渲染），域名与站点均存在'],
      ['联合利华', 'unilever', [
        { url: 'unilever.com', label: '全球官网' },
        { url: 'unilever.com.cn', label: '联合利华中国' }
      ], '⚠️ 2026-11-21 本机访问 unilever.com.cn 返回 403（WAF 拦截），站点存在'],
      ['宝洁', 'pg', [
        { url: 'pg.com', label: '全球官网' },
        { url: 'pg.com.cn', label: '宝洁中国' }
      ], ''],
      ['达能', 'danone', [
        { url: 'danone.com', label: '全球官网' },
        { url: 'danone.com.cn', label: '达能中国' }
      ], '2026-11-21 实测 danone.com.cn 标题为「达能：知名跨国食品饮料公司」'],
      ['宜家', 'ikea', [
        { url: 'ikea.com', label: '全球官网' },
        { url: 'ikea.cn', label: '宜家中国（含电商）' }
      ], 'ikea.cn 为中国区官网兼官方商城，价格与配送只适用于中国内地'],
      ['家乐福', 'carrefour', [
        { url: 'carrefour.com', label: '全球官网' },
        { url: 'carrefour.com.cn', label: '家乐福中国' }
      ], '⚠️ 2026-11-21 本机访问 carrefour.com.cn 返回 403（WAF 拦截），站点存在'],
      ['沃尔玛', 'walmart', [
        { url: 'walmart.com', label: '全球官网' },
        { url: 'walmart.cn', label: '沃尔玛中国' }
      ], ''],
      ['麦德龙', 'metro', 'metro.com.cn', ''],
      ['欧尚', 'auchan', 'auchan.com', ''],
      ['大润发', 'rt-mart', 'rt-mart.com', '2026-11-21 实测 rt-mart.com.cn 与 rt-mart.com 标题一致（同一站，不单列）'],
      ['百胜', 'yum', 'yum.com', ''],
      ['肯德基', 'kfc', 'kfc.com.cn', ''],
      // 旧（2026-11-12）：mcd.com.cn 实测 NXDOMAIN（域名不存在）
      // ['麦当劳', 'mcd', 'mcd.com.cn', ''],
      ['麦当劳', 'mcd mcdonalds', 'mcdonalds.com.cn', '⚠️ 2026-11-21 实测：mcd.com.cn 为 NXDOMAIN（域名不存在）；麦当劳中国官网为 mcdonalds.com.cn；品牌词补 mcdonalds 才能让官方域名自己命中（mcd 在 mcdonalds 里会被字母边界挡住）'],
      ['星巴克', 'starbucks', [
        { url: 'starbucks.com.cn', label: '星巴克中国' },
        { url: 'starbucks.com', label: '全球官网' }
      ], ''],
    ]],

    // ========== 平台与生态类 ==========
    ['平台与生态类', [
      ['Vercel', 'vercel', 'vercel.com', ''],
      ['Netlify', 'netlify', 'netlify.com', ''],
      ['Cloudflare', 'cloudflare', [
        { url: 'cloudflare.com', label: '全球官网' },
        { url: 'cloudflare-cn.com', label: '中国区合作站' }
      ], 'cloudflare-cn.com 为中国区合作运营站点（标题同为 Cloudflare），面向中国大陆的接入与备案咨询'],
      ['Render', 'render', 'render.com', ''],
      ['Heroku', 'heroku', 'heroku.com', ''],
      ['Replit', 'replit', 'replit.com', ''],
      ['Let\'s Encrypt', 'letsencrypt', 'letsencrypt.org', ''],
      ['DigiCert', 'digicert', 'digicert.com', ''],
      ['Sectigo', 'sectigo', 'sectigo.com', ''],
      ['GlobalSign', 'globalsign', [
        { url: 'globalsign.com', label: '全球官网' },
        { url: 'globalsign.cn', label: 'GlobalSign 中国' }
      ], ''],
      ['SSL.com', 'ssl.com', 'ssl.com', ''],
      ['Entrust', 'entrust', 'entrust.com', ''],
      ['GeoTrust', 'geotrust', 'geotrust.com', ''],
      ['Thawte', 'thawte', 'thawte.com', ''],
      ['VeriSign', 'verisign', 'verisign.com', ''],
      ['IdenTrust', 'identrust', 'identrust.com', ''],
      ['ZeroSSL', 'zerossl', 'zerossl.com', ''],
      ['hCaptcha', 'hcaptcha', 'hcaptcha.com', ''],
      ['reCAPTCHA', 'recaptcha', 'recaptcha.net', ''],
      ['Google 静态资源', 'gstatic', 'gstatic.com', '前端公共库'],
      ['Google API', 'googleapis', 'googleapis.com', 'OAuth / 公共 API'],
      ['SilverFox Guard', 'silverfoxguard', 'silverfoxguard.dpdns.org', '项目自有分发页'],
      ['SilverFox Guard（主域）', 'silverfoxguard.top', 'silverfoxguard.top', '项目自有分发页'],
      // 旧（单域名，2026-11-12）：只显示 workbuddy.cn，CodeBuddy 那一半用户找不到入口
      // ['WorkBuddy', 'workbuddy', 'workbuddy.cn', 'WorkBuddy 官网'],
      // 新（2026-11-18）：同品牌两个官网，第二个是链接级（挂在 codebuddy.cn 的 /work/ 路径）
      ['WorkBuddy', 'workbuddy', [
        'https://www.workbuddy.cn',
        'https://www.workbuddy.ai',
        { url: 'https://cloud.tencent.com/product/workbuddy', label: '腾讯云产品页' },
        { url: 'https://www.codebuddy.cn/work/', label: 'CodeBuddy 站点' }
      ], 'WorkBuddy 有两个官方入口：workbuddy.cn 主站与 codebuddy.cn/work/（同一产品的另一域名）'],
      ['凯德荣个人域', 'cloud.gjhdr', 'cloud.gjhdr.xyz', '个人开发者官方域'],
    ]],

    // ========== 用户反馈与个人站点类 ==========
    ['用户反馈与个人站点类', [
      ['个人站点', 'technologyehco', 'technologyehco.us.ci', '反馈确认加白'],
      ['个人站点（荔枝账本）', 'lycheeledger', 'lycheeledger.cn', '反馈确认加白'],
      ['个人站点（mcode）', 'mcode.space', '0bcjstko9509h.space.mcode.cn', '反馈确认加白'],
      ['个人站点（mcode 2）', 'mcode2.space', 'uiso44xg1go9p.space.mcode.cn', '反馈确认加白'],
      ['个人站点（mcode 3）', 'mcode3.space', 'ae0kcokdy1z45.space.mcode.cn', '反馈确认加白'],
      ['个人站点（小麦）', 'xiaomai.cc', '360.xiaomai.cc.cd', '反馈确认加白'],
      // 旧（2026-11-28）：与「办公与文档类」的希沃白板条目重复（品牌词同为 seewo），
      //   已合并到那条，站点里保留了本行的 d.seewo.com（教学终端页）。
      // ['希沃', 'seewo', 'd.seewo.com', '教学终端页'],
      ['8kmm', '8kmm', '8kmm.com', '反馈确认加白'],
      ['冰点文库', 'bingdian', 'bingdiancn.com', '反馈确认加白'],
      ['GeoGebra', 'geogebra', 'geogebra.org', '数学教学工具'],
      ['JimmyKing 个人站', 'jimmyking', 'gunsaw-level-codes.jimmyking.dev', '反馈确认加白'],
      ['机房管理助手', 'jfglzs', 'jfglzs.com', '反馈确认加白'],
      ['MCAPKS', 'mcapks', 'mcapks.net', '反馈确认加白'],
      ['木木地理', 'mumu-dili', 'mumu-dili.pages.dev', '个人教学站（Pages）'],
      ['视觉族', 'shijuezu', 'shijuezu.com', '反馈确认加白'],
      ['Sparanoid', 'sparanoid', 'sparanoid.com', '反馈确认加白'],
      ['SPES 科技', 'spestech', 'spestech.com', '反馈确认加白'],
      ['AdGuard 商店镜像', 'rg-adguard', 'store.rg-adguard.net', '第三方商店镜像（非 AdGuard 官方）'],
      ['卡饭论坛', 'kafan', 'bbs.kafan.cn', '安全软件社区'],
    ]],

  ];

  // ★ 2026-11-18：站点规格归一化（支持「多官网」与「链接级官网」）
  //   背景：一个品牌常有不止一个官网（WorkBuddy 有 workbuddy.cn 与 codebuddy.cn/work/），
  //   也有软件根本没有「主机名意义上的官网」（qBittorrent-Enhanced-Edition 只发 GitHub Releases）。
  //   旧的「一个品牌 → 一个主机名」表达不了这两种情况，于是在**数据层**加一层归一化，
  //   analyzer / 说明页 / 云端补录三处共用同一个函数，避免各写一套校验。
  //   返回统一结构 { url, host, label, kind }：
  //     url   —— 带协议的完整地址（主机名级固定为 https://host，链接级保留原协议与路径）
  //     host  —— 主机名（小写、去端口），供「同注册域」判定与 .domain 兼容字段使用
  //     label —— 自定义文案，空串表示「由说明页自动编号（官网1 / 官网2 …）」
  //     kind  —— 'host' 主机名级 / 'link' 链接级
  //   校验刻意保守：只收 http(s)、必须有点号分隔的域名、不允许空白 / 引号 / 反斜杠 / 通配符。
  //   宁可让一条脏数据被丢弃并在控制台告警，也不要把 `javascript:` 或半截说明文字塞进 href。
  var CORRECT_SITE_MAX = 8;           // 单个品牌最多展示几个站点（再多说明页也看不过来）
  var CORRECT_LABEL_MAX = 24;         // 自定义文案长度上限

  function _normCorrectSite(raw) {
    var url = '', label = '', kind = '';
    if (typeof raw === 'string') {
      url = raw;
    } else if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
      // 兼容简写键：url/u/domain/d、label/l/text、kind/k
      var u = (raw.url != null) ? raw.url : (raw.u != null ? raw.u : (raw.domain != null ? raw.domain : raw.d));
      var l = (raw.label != null) ? raw.label : (raw.l != null ? raw.l : raw.text);
      var k = (raw.kind != null) ? raw.kind : raw.k;
      url = String(u == null ? '' : u);
      label = String(l == null ? '' : l);
      kind = String(k == null ? '' : k).toLowerCase();
    } else {
      // 数组形态一律不收：[url, label] 与「两个站点」无法区分，容易把官网写成文案
      return null;
    }

    url = String(url).trim();
    if (!url) return null;

    // 协议：只认 http/https；没写协议时按 https 补
    var proto = 'https:';
    var m = /^([a-z][a-z0-9+.-]*):\/\//i.exec(url);
    if (m) {
      var sch = m[1].toLowerCase();
      if (sch !== 'http' && sch !== 'https') return null;
      proto = sch + ':';
      url = url.slice(m[0].length);
    }
    // 含空白 / 引号 / 尖括号 / 反斜杠 / 通配符 → 不是地址（多半是把说明文字写进来了）
    if (/[\s<>"'`\\*?]/.test(url)) return null;

    // 拆出查询串（# 与 ? 之后原样保留，链接级站点经常靠它定位）
    var tailAt = url.search(/[?#]/);
    var tail = '';
    if (tailAt !== -1) { tail = url.slice(tailAt); url = url.slice(0, tailAt); }

    var slash = url.indexOf('/');
    var host = (slash === -1) ? url : url.slice(0, slash);
    var path = (slash === -1) ? '' : url.slice(slash);
    host = host.toLowerCase().replace(/:\d+$/, '');      // 去端口
    if (host.indexOf('.') === -1) return null;           // 必须有点号（裸 localhost / IP 不收）
    if (host.length > 253) return null;
    if (!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(host)) return null;

    // kind：显式优先，否则「有路径或有查询串」= 链接级
    var hasPath = !!(path && path !== '/') || !!tail;
    if (kind !== 'host' && kind !== 'link') kind = hasPath ? 'link' : 'host';
    // 声明成主机名级却写了路径：按主机名级处理并丢掉路径（数据写错时以 kind 为准，行为可预期）
    if (kind === 'host') { path = ''; tail = ''; }

    label = String(label).replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim();
    if (label.length > CORRECT_LABEL_MAX) label = label.slice(0, CORRECT_LABEL_MAX) + '…';

    return {
      url: (kind === 'link') ? (proto + '//' + host + (path || '/') + tail) : (proto + '//' + host),
      host: host,
      label: label,
      kind: kind
    };
  }

  // 一个字段 → 站点数组。接受：'a.com' / ['a.com', {url:…,label:…}] / {url:…} / []
  // ★ 2026-11-28：空字段静默跳过 + 告警带上上下文
  //   旧实现只要 _normCorrectSite 返回 null 就告警，而「这条本来就没写站点」
  //   （第三字段是 '' / null / 缺省 / []）同样走这条路 —— String('') 是空串，
  //   控制台里只剩一句「正确官网条目无法解析，已忽略: 」，既看不出是哪条，
  //   又会在每个页面加载时刷一遍（iocs.js 是随内容脚本加载的）。
  //   现在：空值静默跳过（这条映射本来就没有站点，不是错误）；真写错了才告警，
  //   并带上产品名与原始值，方便回表定位。ctx 为可选参数，旧调用方不受影响。
  function normalizeCorrectSites(field, ctx) {
    var list = [];
    if (typeof field === 'string') list = [field];
    else if (Array.isArray(field)) list = field;
    else if (field && typeof field === 'object') list = [field];
    else return [];
    var out = [];
    var seen = Object.create(null);
    for (var i = 0; i < list.length && out.length < CORRECT_SITE_MAX; i++) {
      var s = _normCorrectSite(list[i]);
      if (!s) {
        // 旧（2026-11-28 前）：空字段也告警，且只打 String(list[i]) —— 空值打出空文案
        // if (typeof console !== 'undefined' && console.warn) {
        //   console.warn('[SF_IOCS] 正确官网条目无法解析，已忽略: ' + String(list[i]));
        // }
        // continue;
        // 新：先区分「本来就没写站点」与「写了但解析不了」，只有后者值得告警
        var rawItem = list[i];
        var rawEmpty = (rawItem === undefined) || (rawItem === null) ||
          (typeof rawItem === 'string' && !rawItem.trim()) ||
          (Array.isArray(rawItem) && rawItem.length === 0);
        if (!rawEmpty && typeof console !== 'undefined' && console.warn) {
          console.warn('[SF_IOCS] 正确官网条目无法解析，已忽略: ' + JSON.stringify(rawItem) +
            (ctx ? '（产品：' + String(ctx) + '）' : ''));
        }
        continue;
      }
      if (seen[s.url]) continue;      // 同一个地址写两遍只留一条
      seen[s.url] = 1;
      out.push(s);
    }
    return out;
  }

  // 扁平化：品牌词 → { domain, sites, product, cat }
  // 只做「首次出现生效」，与 WHITELIST_CATALOG 的域名去重语义一致；
  // 重复项在控制台告警，方便发现「同一个品牌词写了两行」的维护错误。
  // 旧（单域名，2026-11-12）：整块停用、保留备查 —— 第三个字段只当字符串处理，
  //   写成数组会被 `String(['a','b'])` 拼成 "a,b" 再被 `indexOf('.')` 判成脏数据丢掉。
  /*
  function _flattenCorrectSites(catalog) {
    const index = Object.create(null);
    const order = [];
    for (let i = 0; i < catalog.length; i++) {
      const cat = catalog[i][0];
      const items = catalog[i][1] || [];
      for (let j = 0; j < items.length; j++) {
        const product = String(items[j][0] || '');
        const brands = String(items[j][1] || '').toLowerCase().split(/\s+/);
        const domain = String(items[j][2] || '').toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
        if (!domain || domain.indexOf('.') === -1) continue;
        for (let k = 0; k < brands.length; k++) {
          const b = brands[k].trim();
          if (!b) continue;
          if (index[b]) {
            if (typeof console !== 'undefined' && console.warn) {
              console.warn('[SF_IOCS] 正确官网映射的品牌词重复，已忽略后出现的条目: ' + b);
            }
            continue;
          }
          index[b] = { domain: domain, product: product, cat: cat };
          order.push(b);
        }
      }
    }
    return { index: index, order: order };
  }
  */
  // 旧（2026-11-18）：支持多站点 / 链接级站点
  //   2026-11-22 停用：不认识第 5 个字段「关联品牌词」，换成下面那版。
  /*
  function _flattenCorrectSites(catalog) {
    const index = Object.create(null);
    const order = [];
    for (let i = 0; i < catalog.length; i++) {
      const cat = catalog[i][0];
      const items = catalog[i][1] || [];
      for (let j = 0; j < items.length; j++) {
        const product = String(items[j][0] || '');
        const brands = String(items[j][1] || '').toLowerCase().split(/\s+/);
        const sites = normalizeCorrectSites(items[j][2]);
        if (!sites.length) continue;                       // 一条站点都没有 → 这条映射没有意义
        // .domain 兼容字段 = 第一个「主机名级」站点；全是链接级时退回第一个站点的主机名
        let domain = '';
        for (let s = 0; s < sites.length; s++) {
          if (sites[s].kind === 'host') { domain = sites[s].host; break; }
        }
        if (!domain) domain = sites[0].host;
        for (let k = 0; k < brands.length; k++) {
          const b = brands[k].trim();
          if (!b) continue;
          if (index[b]) {
            if (typeof console !== 'undefined' && console.warn) {
              console.warn('[SF_IOCS] 正确官网映射的品牌词重复，已忽略后出现的条目: ' + b);
            }
            continue;
          }
          index[b] = { domain: domain, sites: sites, product: product, cat: cat };
          order.push(b);
        }
      }
    }
    return { index: index, order: order };
  }
  */
  // 新（2026-11-22）：支持多站点 / 链接级站点 / 关联品牌词（第 5 个字段，见文件头说明）
  function _flattenCorrectSites(catalog) {
    const index = Object.create(null);
    const order = [];
    const entries = [];              // 去重后的条目（关联合并以条目为单位，而不是以品牌词为单位）
    for (let i = 0; i < catalog.length; i++) {
      const cat = catalog[i][0];
      const items = catalog[i][1] || [];
      for (let j = 0; j < items.length; j++) {
        const product = String(items[j][0] || '');
        const brands = String(items[j][1] || '').toLowerCase().split(/\s+/);
        // 旧（2026-11-28 前）：不传上下文，告警里只剩一句空文案
        // const sites = normalizeCorrectSites(items[j][2]);
        // 新：把产品名传进去，告警能指回具体条目
        const sites = normalizeCorrectSites(items[j][2], product);
        if (!sites.length) continue;                       // 一条站点都没有 → 这条映射没有意义
        // .domain 兼容字段 = 第一个「主机名级」站点；全是链接级时退回第一个站点的主机名
        let domain = '';
        for (let s = 0; s < sites.length; s++) {
          if (sites[s].kind === 'host') { domain = sites[s].host; break; }
        }
        if (!domain) domain = sites[0].host;
        // 第 5 个字段：关联品牌词（空格分隔字符串，或字符串数组）；写错只跳过、不抛异常
        const relRaw = items[j][4];
        const relList = Array.isArray(relRaw)
          ? relRaw
          : String(relRaw == null ? '' : relRaw).split(/\s+/);
        const rel = [];
        for (let r = 0; r < relList.length; r++) {
          const t = String(relList[r] == null ? '' : relList[r]).trim().toLowerCase();
          if (t && rel.indexOf(t) === -1) rel.push(t);
        }
        const entry = { domain: domain, sites: sites, product: product, cat: cat, brands: [], rel: rel };
        entries.push(entry);
        for (let k = 0; k < brands.length; k++) {
          const b = brands[k].trim();
          if (!b) continue;
          if (index[b]) {
            if (typeof console !== 'undefined' && console.warn) {
              console.warn('[SF_IOCS] 正确官网映射的品牌词重复，已忽略后出现的条目: ' + b);
            }
            continue;
          }
          index[b] = entry;
          entry.brands.push(b);
          order.push(b);
        }
      }
    }
    _applyCorrectRelations(entries, index);
    return { index: index, order: order };
  }
  // 关联品牌词 → 双向追加站点（2026-11-22 新增）
  //   · 双向：A 声明 B，则 B 也认 A —— 一边漏写不会造成「单向可见」
  //   · 只追加「对方条目自己的」站点，且按 url 去重：自己条目永远排在前面，不会被顶掉
  //   · 追加进来的站点带 group = 对方产品名，说明页据此分段展示；对方无产品名时 group 为空
  //   · 合并后仍受 CORRECT_SITE_MAX 限制，超出部分丢弃并在控制台告警（宁可少一条，不要刷屏）
  function _applyCorrectRelations(entries, index) {
    const pairs = [];
    for (let i = 0; i < entries.length; i++) {
      const from = entries[i];
      for (let r = 0; r < from.rel.length; r++) {
        const to = index[from.rel[r]];
        if (!to || to === from) continue;
        pairs.push([from, to]);
        pairs.push([to, from]);        // 反向也认
      }
    }
    for (let p = 0; p < pairs.length; p++) {
      const from = pairs[p][0];
      const to = pairs[p][1];
      const merged = from.sites.slice();
      const seen = Object.create(null);
      for (let s = 0; s < merged.length; s++) seen[merged[s].url] = 1;
      let overflow = 0;
      for (let s = 0; s < to.sites.length; s++) {
        const src = to.sites[s];
        if (seen[src.url]) continue;
        if (merged.length >= CORRECT_SITE_MAX) { overflow++; continue; }
        seen[src.url] = 1;
        merged.push({
          url: src.url, host: src.host, label: src.label, kind: src.kind,
          group: src.group || to.product || ''      // 链式关联时沿用它原来的分组名
        });
      }
      from.sites = merged;
      if (overflow && typeof console !== 'undefined' && console.warn) {
        console.warn('[SF_IOCS] 关联官网合并超出 ' + CORRECT_SITE_MAX + ' 条上限，已丢弃 ' + overflow + ' 条: ' + (from.product || ''));
      }
    }
  }
  const _CORRECT_FLAT = _flattenCorrectSites(CORRECT_SITE_CATALOG);
  // 品牌词 → { domain, sites, product, cat }
  //   .domain 第一个主机名级站点（兼容「只想要一个域名」的旧调用方）
  //   .group  仅「关联品牌词」带出来的站点才有：值为来源条目的产品名，说明页据此分段
  //   .sites  [{ url, host, label, kind }]，顺序即说明页展示顺序
  //   .sites[].group（2026-11-22）：仅「关联品牌词」带出来的站点才有，值为来源条目的产品名
  const CORRECT_DOMAIN_MAP = _CORRECT_FLAT.index;
  // 新（2026-11-22 方案二）：品牌词 → 关联品牌词列表，交给 analyzer 在「内置 + 云端」合并表上再跑一遍。
  //   为什么 iocs 里做不完：这里只能看到内置表，够不到云端补录的独立条目 ——
  //   例：火绒论坛若只存在于云端（品牌词 huorongbbs），给内置 huorong 写 rel 在 iocs 内不会有任何效果。
  const CORRECT_SITE_RELATIONS = Object.create(null);
  (function () {
    for (let i = 0; i < _CORRECT_FLAT.order.length; i++) {
      const b = _CORRECT_FLAT.order[i];
      const e = CORRECT_DOMAIN_MAP[b];
      if (e && e.rel && e.rel.length) CORRECT_SITE_RELATIONS[b] = e.rel.slice();
    }
  })();
  // 品牌词列表（按长度降序：长词优先命中，sogoubrowser 先于 sogou）
  const CORRECT_BRANDS = _CORRECT_FLAT.order.slice().sort(function (a, b) {
    return b.length - a.length;
  });

  // ---------- 黑名单目录 ----------
  const BLACKLIST_CATALOG = [
    ['恶意投递站', [
      ['仿冒下载站', 'chrome-china.net appsl-360.com app-360weishi.com.cn deepvseek.com.cn qissmusic.com.cn ggfanyi.com', '仿 Chrome / 仿 360 / 仿 DeepSeek / 仿音乐平台 / 仿谷歌翻译'],
      ['载荷 CDN', 'coreapps.cc oentvu8xii.com', '跳转分发 .zip 木马安装包 / 下载中转页'],
      ['APT-Q-27 C2', 'jackadmin1.cn jackadmin2.cn jackadmin3.cn jackadmin4.cn jackadmin5.cn jackbank1.cn jackbank2.cn jackbank3.cn jackbank4.cn jackbank5.cn', '银行木马 C2 面板 / 欺诈页'],
    ]],
    ['钓鱼与恶意 AI 站', [
      ['仿冒 B 站', 'net-bcutbilibili.com.cn', ''],
      ['恶意 AI 站', 'chat.51mitu.com 108ai.com', '多次举报的 AI 钓鱼站'],
      ['随机子域投递', '88vyvwbt.qpefh.com abi04.8msg8.com es.wlygrowth.com', '随机子域投递 / C2 / 落地页'],
    ]],
    ['历史收录', [
      ['综合', 'wy-mmusic.com.cn', '早期用户上报'],
    ]],
  ];

  // ---------- 由目录派生扁平数组（等价于旧版逐条枚举，仅去重）----------
  // 为什么要派生而不是直接维护扁平数组：1344 条域名原本散落在 400 行注释里，
  // 同一个品牌（如 360）被拆到「安全软件」「浏览器」两处且大量重复（原表重复 163 条）。
  // 目录化后「品牌 → 大类/小项」一目了然，扁平数组退化成派生产物，不再手改。
  function _catalogFlatten(catalog, out, index) {
    for (let i = 0; i < catalog.length; i++) {
      const catName = catalog[i][0];
      const items = catalog[i][1] || [];
      for (let j = 0; j < items.length; j++) {
        const itemName = items[j][0];
        const doms = String(items[j][1] || '').split(/\s+/);
        for (let k = 0; k < doms.length; k++) {
          const dom = doms[k].trim().toLowerCase();
          if (!dom) continue;
          if (index[dom]) {
            if (typeof console !== 'undefined' && console.warn) {
              console.warn('[SF_IOCS] 域名重复归类，已忽略后出现的条目: ' + dom);
            }
            continue;
          }
          index[dom] = { cat: catName, item: itemName };
          out.push(dom);
        }
      }
    }
    return out;
  }

  const DOMAIN_CATALOG_INDEX = Object.create(null);
  const OFFICIAL_DOMAINS = _catalogFlatten(WHITELIST_CATALOG, [], DOMAIN_CATALOG_INDEX);
  const KNOWN_BAD_DOMAINS = _catalogFlatten(BLACKLIST_CATALOG, [], Object.create(null));

  // ---------- 内置「黑名单例外」（2026-11-23）----------
  // 三层例外中的第二层，判定优先级（自高到低）：
  //   ① 云端例外  ② 云端黑名单  ③ 内置例外  ④ 内置黑名单  ⑤ 用户例外  ⑥ 用户自定义黑名单
  // 语义：命中本表的主机名，即便同时命中**内置黑名单**也放行；但**不能**推翻云端黑名单
  //   （云端黑名单是远端可变数据，优先级更高；要推翻它只能用云端例外，由作者在云端下发）。
  // 用途：内置黑名单（BLACKLIST_CATALOG）里出现「误伤已知正规站」的硬冲突时，把它写在这里，
  //   随发版一起生效，不必等云端下发。日常为空数组即为「当前没有已知冲突」。
  // 写法与内置白名单一致：精确主机名或子域后缀；可写 `*` / `?`（护栏同 builtinWhite）：
  //   `*` 只吃同一标签内的字符，`?` 吃单个非点字符，`*.foo.com` 归一为后缀条目，
  //   TLD 位禁通配（`*.com` 不生效）。条目会在 analyzer 里编译成与黑名单同构的匹配表。
  const EXCEPTION_DOMAINS = [
    // 例：'download.example-official.com',
  ];

  // 域名 → { cat, item }（精确或父域命中）；未收录返回 null。
  // ⚠️ 通配条目在本索引里只是一个字面 key，实际命中的子域查不到分类（返回 null）。
  //   这是有意的：分类只用于设置页展示与误报排查，通配条目本身没有「唯一品牌归属」。
  function categoryOfDomain(host) {
    let h = String(host || '').toLowerCase().replace(/^www\./, '');
    if (!h) return null;
    let hit = DOMAIN_CATALOG_INDEX[h];
    if (hit) return hit;
    let i = h.indexOf('.');
    while (i !== -1) {
      hit = DOMAIN_CATALOG_INDEX[h.slice(i + 1)];
      if (hit) return hit;
      i = h.indexOf('.', i + 1);
    }
    return null;
  }

  // ============ UGC 平台白名单（仅跳过「域名仿冒」判定，其余规则照常运行）============
  // 合入自 VirusDetector 的 TRUSTED_PLATFORMS（44 个），并补齐我们原有覆盖。
  //
  // 与 OFFICIAL_DOMAINS 的本质区别：
  //   OFFICIAL_DOMAINS   → 完全豁免、早期退出、永不拦截（只放真正的品牌官网本体）
  //   TRUSTED_PLATFORMS  → 只跳过「域名仿冒」这一条规则，其余检测（混淆脚本 / 沙箱探测 /
  //                        木马安装包 / 双扩展名 / 网盘分发 / 诱饵话术…）全部照常运行
  //
  // 为什么必须区分：Wiki 农场、代码托管 Pages、静态托管 PaaS、博客平台这类站点，
  // 子域由用户自由创建（如 wechat-download.vercel.app），因此
  //   ① 子域名里出现品牌词是常态 → 不该判「域名仿冒」，否则海量合法页面误报；
  //   ② 但页面内容完全不可信 → 银狐可白嫖免费 HTTPS 托管投递木马，绝不能整体豁免。
  const TRUSTED_PLATFORMS = [
    // ---- Wiki 平台 ----
    'fandom.com', 'wikia.com', 'wikimedia.org', 'miraheze.org', 'wiki.gg', 'gamepedia.com',
    // ---- 代码托管 Pages ----
    'github.io', 'gitlab.io', 'bitbucket.io', 'sourceforge.io', 'codeberg.page',
    // ---- PaaS / 静态站点托管 ----
    'netlify.app', 'vercel.app', 'herokuapp.com', 'pages.dev', 'surge.sh', 'glitch.me',
    'onrender.com', 'fly.dev', 'workers.dev', 'deno.dev',
    // ---- 博客与内容平台 ----
    'medium.com', 'wordpress.com', 'blogger.com', 'blogspot.com', 'tumblr.com', 'hatenablog.com',
    'fc2.com', 'livejournal.com', 'typepad.com', 'substack.com', 'ghost.io', 'hashnode.dev', 'dev.to',
    // ---- 文档与知识库 ----
    'readthedocs.io', 'notion.site', 'gitbook.io',
    // ---- 建站 / 个人页 ----
    'weebly.com', 'wixsite.com', 'jimdo.com', 'strikingly.com', 'carrd.co', 'about.me', 'linktr.ee',
    // ---- 本项目补充（原先误放在 OFFICIAL_DOMAINS 的用户内容托管域）----
    'replit.app', 'repl.co', 'firebaseapp.com', 'web.app', 'codesandbox.io', 'stackblitz.com'
  ];

  // ============ 可信文件分发平台（下载黑名单的「护栏」，禁止被自动拉黑）============
  // 合入自 VirusDetector 的 TRUSTED_DOWNLOAD_HOSTS。用途与 TRUSTED_PLATFORMS 不同：
  // 本表专供「下载黑名单」自动学习时做保护——用户在某个页面手动拦下一次下载后，
  // 系统会把下载来源域自动拉黑并跨站复用；若来源恰好是 GitHub Releases / PyPI / 微软 CDN
  // 这类共享分发平台，拉黑将连带误伤海量正常下载，因此这些域名一律禁止进入黑名单。
  // 注意：这不等于「豁免」——命中这些平台的页面仍照常参与全部评分。
  const TRUSTED_DOWNLOAD_HOSTS = [
    // 代码托管 Releases
    'github.com', 'gitlab.com', 'gitee.com', 'bitbucket.org', 'codeberg.org', 'githubusercontent.com',
    // 包管理器
    'npmjs.com', 'pypi.org', 'files.pythonhosted.org',
    // 开源托管
    'sourceforge.net', 'fosshub.com',
    // 大型厂商 CDN / 官方下载
    'microsoft.com', 'google.com', 'apple.com', 'mozilla.org', 'adobe.com', 'oracle.com', 'ibm.com', 'amazon.com',
    // 用户自定义可信域（2026-08-31 加，来自 B站网友反馈 / 同类 AI agent 误报）
    'LHW.pythonanywhere.com', // B站网友自建蓝奏云镜像站
    'lobsterai.youdao.com', // 有道 AI 龙虾（电脑 agent 工具，与 WorkBuddy 同类，误报豁免）
    // 操作系统官方源
    'ubuntu.com', 'debian.org', 'archlinux.org', 'fedoraproject.org', 'centos.org', 'opensuse.org',
    'docker.com', 'appimage.org',
    // 知名开源软件官方
    'videolan.org', 'libreoffice.org', 'gnu.org', 'apache.org', 'python.org', 'nodejs.org',
    'rust-lang.org', 'golang.org', 'nginx.org', 'mysql.com', 'postgresql.org'
  ];

  // ============ 已知银狐木马投递站黑名单（硬编码：命中即判 danger，永不豁免）============
  // 来源：用户上报 / CNCERT 通报。命中即强制拦截，不受灵敏度或维度开关影响。
  // KNOWN_BAD_DOMAINS 由上方 BLACKLIST_CATALOG 派生（见 _catalogFlatten）。


  // ============ 已知银狐「木马化投递物」文件名（硬编码：命中即强风险）============
  // 来源：用户提交的银狐样本「只读静态分析」（未执行，仅提取字符串级 IOC）。
  //   bzy.exe            → 内嵌 ProductName="A Great VPN" / CompanyName="NextVPN LLC"（假冒 A Great VPN 客户端木马）
  //   shanlian_VPN_64.exe → 内嵌 FileDescription="闪连VPN Setup" / CompanyName="闪连VPN"（假冒「闪连 VPN」木马）
  // 两者均为银狐（游蛇）典型的「木马化正版/诱导软件」投递：把流行工具（VPN/加速器/办公）重打包成带毒安装包，
  // 经仿冒下载站或群聊话术分发。MV3 扩展无法读取下载字节，故以「文件名」这一稳定可观测特征作为拦截锚点。
  // ⚠️ 仅比对小写规范化后的文件名；下载 URL 的查询串/片段已被剥离，避免误匹配路径。
  const KNOWN_BAD_FILENAMES = [
    'bzy.exe',
    'shanlian_vpn_64.exe',
    'shanlian-vpn-64.exe',
    'shanlianvpn_64.exe',
    '闪连vpn setup.exe',
    '闪连vpn_setup.exe',
    '闪连vpn.exe',
    'a great vpn.exe',
    'agreatvpn.exe',
    'nextvpn.exe'
  ];

  // 可疑下载文件名模式（仅作「中风险」提示，不直接强拦，避免误伤正常 VPN 官网）
  // 锚定银狐「随机/仿冒品牌 + VPN/加速器」安装包命名规律，阈值收紧（必须含 vpn + setup/install 且为 exe）。
  const SUSPICIOUS_DOWNLOAD_NAME_PATTERNS = [
    /_vpn_64\.exe$/i,
    /_vpn_32\.exe$/i,
    /vpn[_-]?setup\.exe$/i,
    /(setup|install).*vpn.*\.exe$/i,
    /vpn.*(setup|install).*\.exe$/i
  ];

  // ============ 品牌关键词（用于域名仿冒检测：段匹配 / 子串 / 堆叠 / 编辑距离；命中但非官方域 → 仿冒）============
  const BRAND_KEYWORDS = [
    'wechatpay','微信支付','alipay','支付宝','deepseek','chatglm','智谱清言','kimi','openai','chatgpt','doubao','豆包','tongyi','通义千问','xinghuo','讯飞星火','yiyan','文心一言',
    'bilibili','哔哩哔哩','iqiyi','爱奇艺','youku','优酷','mgtv','芒果tv','kugou','酷狗','kuwo','酷我','netease','网易云音乐','qqmusic','qq音乐','weiyun','腾讯微云','aliyundrive','阿里云盘',
    'quark','夸克网盘','baidupan','百度网盘','wps','金山办公','dingtalk','钉钉','feishu','飞书','weixin','微信','wechat','企业微信','todesk','向日葵',
    'sunlogin','teamviewer','anydesk','lenovo','联想','360安全卫士','huorong','火绒','qq','腾讯qq','sougou','搜狗','pinyin','输入法','baidu','百度','taobao','淘宝','tmall','天猫','jd','京东',
    'pinduoduo','拼多多','meituan','美团','aliyun','阿里云','tencent','腾讯云','huawei','华为云','csdn','gitee','github','juejin','掘金','zhihu','知乎','toutiao','今日头条','amap','高德','didiglobal','滴滴',
    'xunlei','迅雷','winrar','7-zip','bandizip','2345','好压','ludashi','鲁大师','drivergenius','驱动精灵','qqbrowser','qq浏览器','chrome','谷歌浏览器','firefox','火狐','edge','microsoft','mozilla',
    'moonshot','月之暗面','volcengine','火山引擎','xfyun','科大讯飞','bigmodel','wechat','android','chrome','clash','verge','potplayer','蓝奏云','lanzou','金蝶','kingdee','用友','ufida','航天信息','金税','税控','财务','erp',
    // 研究中高频被仿冒、原词库缺漏的对象
    'telegram','teams','微软teams','有道','有道翻译','youdao','比特浏览器','bitbrowser','快连','快连vpn','letsvpn','纸飞机','易翻译','货币换算','汇率转换','flash','搜狗浏览器','sogou浏览器',
    // 外国知名软件/模拟器（用户上报 rpcs3.io 仿冒 rpcs3 官方，需识别其为仿冒站）
    'rpcs3','ps3模拟器','pcsx2','ppsspp','xenia','cemu','yuzu','ryujinx','dolphin模拟器','cemu模拟器','retroarch','epsxe','citra','duckstation','rpcs3模拟器',
    // 海外主流软件品牌（仿冒站高频目标，扩充至 ~121 个品牌）
    'adobe','photoshop','premiere','aftereffects','illustrator','lightroom','acrobat','reader','pdf','vlc','potplayer','kmplayer','gomplayer','audacity','obs','ffmpeg',
    'office','word','excel','powerpoint','outlook','onenote','onenote','teams','skype','zoom','webex','slack','discord','telegram','thunderbird','foxmail','notepad','notepad++','sublime','vscode','visualstudiocode','jetbrains','pycharm','intellij',
    'chrome','chromium','brave','opera','vivaldi','safari','yandex','tor','centbrowser','maxthon','firefox','edge','internetexplorer','ie',
    'winrar','winzip','7zip','bandizip','peazip','360zip','haozip','2345好压','2345zip','2345看图王','2345浏览器','2345','ludashi','cpuz','hwmonitor','aida64','crystaldiskmark','crystaldiskinfo','prime95','furmark','memtest86','gpuz','msiafterburner','afterburner',
    'idm','internetdownloadmanager','fdm','freedownloadmanager','qbittorrent','utorrent','bittorrent','transmission','aria2','motrix','xdown',
    'avast','avg','kaspersky','bitdefender','eset','mcafee','norton','symantec','trendmicro','malwarebytes','avira','drweb','panda','gdata','f-secure','sophos','comodo','zonealarm','claymore',
    'asus','gigabyte','msi','asrock','corsair','kingston','samsung','westerndigital','seagate','toshiba','lg','dell','hp','acer','logitech','razer','steelseries','cherry','coolermaster','noctua','phanteks','lianli','nzxt','antecc','seasonic','corsair','gskill','teamgroup','adata','crucial','micron',    'intel','amd','nvidia',
    // 银狐木马化投递物品牌（来自用户提交样本静态分析：bzy.exe=A Great VPN/NextVPN LLC；shanlian_VPN_64.exe=闪连VPN）
    '闪连','shanlian','闪连vpn','nextvpn','agreatvpn','a great vpn','nextvpn llc',
    // 全球高危钓鱼品牌（非中国区官方域，但为银狐/钓鱼高发仿冒目标，显式补入）
    'paypal','facebook','whatsapp','instagram','netflix','linkedin','twitter','tiktok'
  ];

  // ============ 通用词 / 非品牌词（域名仿冒判定专用）============
  // ⚠️ 2026-10-29 实测误报（btsow.live 被判「域名仿冒官方品牌」，STRONG +60）：
  //   命中的"品牌词"并不是本表维护的品牌，而是**从 OFFICIAL_DOMAINS 自动派生**出来的：
  //     live  ← live.com  （Microsoft Live 服务）
  //     tool  ← tool.lu   （吾爱破解工具站）
  //     code  ← code.org
  //     book  ← book.com
  //     china ← china.com
  //   这些都是**普通英文名词 / 行业通用词**，任何人都能拿来做域名主干；
  //   一旦进入品牌词表，`xxx.live` / `tool.xxx` / `code.top` 这类正常域名
  //   就会命中「域名段精确匹配品牌词」而被判仿冒 —— 这就是"字段乱匹配"：
  //   把**通用词字段**（甚至**后缀字段**）当成了**品牌名字段**。
  //
  // 本表 = 品牌词的「专有性闸门」：凡在此表中的词，一律不得充当品牌名
  //        参与域名仿冒判定（analyzer.js 的 SPOOF_KEYWORDS / 派生词表均按此过滤）。
  // 注意：像 office / edge / teams 这类**产品名**不在表内 —— 它们确实是可被仿冒的品牌。
  const BRAND_GENERIC_WORDS = [
    // ---- 通用英文名词（最常被当作域名主干）----
    'live','tool','tools','code','book','books','china','chinese','english','world','free','news',
    'home','house','hotel','host','hosting','domain','domains','website','websites','web','page','pages',
    'site','sites','online','offline','shop','shops','store','stores','sale','sales','deal','deals',
    'discount','buy','sell','market','mall','cart','cloud','server','servers','data','file','files',
    'upload','download','downloads','media','image','images','photo','photos','video','videos','audio',
    'music','movie','movies','film','game','games','play','player','app','apps','software','hardware',
    'computer','tech','technology','digital','network','net','internet','mail','email','chat','forum',
    'bbs','blog','blogs','wiki','post','posts','article','articles','info','information','service',
    'services','support','help','center','centre','contact','about','account','user','users','member',
    'members','login','register','search','find','view','views','list','lists','index','main','default',
    'test','demo','preview','old','new','latest','first','last','next','top','best','good','great',
    'nice','cool','fun','hot','pro','plus','max','mini','mega','ultra','super','smart','quick','fast',
    'easy','simple','safe','security','secure','trust','credit','card','cards','bank','money','finance',
    'financial','pay','payment','payments','order','orders','gift','gifts','box','group','team',
    'company','business','work','works','job','jobs','career','careers','meeting','travel','tour',
    'tourism','food','drink','coffee','tea','health','doctor','medicine','care','love','life','earth',
    'sky','sun','moon','star','stars','night','day','week','month','year','time','clock','watch','run',
    'move','go','get','now','one','two','three','all','any','some','many','few','more','less','most',
    'open','public','private','global','local','national','international','city','town','state',
    'street','road','park','garden','studio','labs','lab','agency','inc','ltd','llc','corp','soft',
    'solution','solutions','system','systems','pdf','reader','afterburner','browser','tools',
    // ---- 常见中文通用词 ----
    '科技','网络','软件','下载','官网','商城','新闻','视频','音乐','游戏','工具','企业','服务','平台','中心','门户',
    // ---- 廉价 / 通用顶级域（注册局统一分配，永远不可能是"被仿冒的品牌"）----
    'top','xyz','shop','vip','cc','ren','wang','pw','click','link','online','fun','rest','icu','buzz',
    'work','date','trade','country','stream','gq','cf','ml','tk','ga','nic','cyou','red','ink','mobi',
    'pro','ltd','store','win','xin','racing','monster','loan','su','ru','live','club','site','tech',
    'space','press','host','design','dev','app','one','today','zone','works','expert','tips','guru',
    'ninja','rocks','fans','email','factory','digital','group','center','town','city','run','live'
  ];

  // 友情链接区块「指向无关大牌」检测专用品牌库：银狐伪官方下载站模板常在页脚「友情链接」里
  // 塞一堆百度/淘宝/QQ/微信等大牌外链来显得正规。命中这些大牌且非本站品牌才算「无关」。
  const FRIENDLY_LINK_BRANDS = [
    'baidu','百度','taobao','淘宝','tmall','天猫','jd','京东','pinduoduo','拼多多','meituan','美团','alipay','支付宝',
    'wechat','微信','qq','腾讯','tencent','sina','新浪','weibo','微博','netease','网易','163','youku','优酷','iqiyi','爱奇艺',
    'bilibili','哔哩哔哩','kugou','酷狗','douyin','抖音','toutiao','今日头条','didi','滴滴','ctrip','携程','360','lenovo','联想',
    'xiaomi','小米','huawei','华为','oppo','vivo','suning','苏宁','jumei','聚美','58','赶集','ganji','baixing','百姓','zhihu','知乎',
    'csdn','qqbrowser','qq浏览器','sogou','搜狗','uc','ucbrowser','uc浏览器','todesk','向日葵','teamviewer','anydesk','wps','金山','kingsoft',
    'kuaishou','快手','qqmusic','qq音乐','网易云音乐','baixing','百姓网','soso','sohu','搜狐','qqgame','wegame','steam'
  ];

  // 与"下载 / 安装"相关的上下文词
  const DOWNLOAD_KEYWORDS = [
    '下载', 'download', '安装', 'install', '官方版', '最新版', '正版', '免费版',
    '高速下载', '安全下载', '本地下载', '立即下载', '一键安装', '极速下载', '客户端', '安装包', '完整版'
  ];

  // 社会工程 / 钓鱼诱导话术（银狐投递文档、群聊话术）
  // 注：极常见的「工资/薪资/工资明细/发票/电子发票」已从本表移除（任何正常 HR/财务网页都会中招，
  // 造成大量误报）；财税类诱饵改由更精准、且以「存在下载入口」为门控的 LURE_THEMES 负责。
  // ⚠️ 2026-08-30 误报治理重构：社工话术拆分为「强诱导」与「一般可疑」两级。
  //
  // 原实现把所有词一视同仁按 n×6 计分（上限 24），但其中大量词汇在正规站遍地都是：
  //   '验证码' → 任何登录页都有
  //   '限时'/'福利'/'红包'/'返利'/'领取' → 电商与活动页标配
  //   '培训资料'/'学习资料'/'课程资料'/'成绩单' → 教育站标配
  //   '通知'/'通报'/'名单'/'人事'/'离职'/'劳动合同' → 企业与政务站常见
  //   '内部' → 过于泛化，误伤极重
  // 再叠加 useDownloadSocial 组合规则（有下载入口 + 命中社工话术 → danger），
  // 直接导致 znds.com 这类正规软件下载站被判死。
  //
  // 重构后：
  //   强诱导词（银狐/钓鱼专属话术）→ 高分，且参与组合升级
  //   一般可疑词（正规站常见）→ 仅低分，不参与组合升级
  //   '内部' 与 '验证码' 因误报率过高，直接移除
  // ⚠️ 2026-08-31 二次重构（实测根因驱动）：
  // 用真实页面 HTML 离线复现发现，STRONG 组里混入了两类「非钓鱼话术」，是正规站误报主因：
  //
  //   ① 软件资源站业态词：破解 / 注册机 / 激活工具 / 免费激活 / 内部版
  //      —— 吾爱破解、果核剥壳这类老牌技术社区的页面必然出现（这是它们的内容主题本身）。
  //         实测 www.ghxi.com 命中「破解 + 注册机 + 激活工具」三词直接推向 danger。
  //   ② 社群联系方式：qq群 / 加q群 / 加qq群 / 客服微信 / 扫码领取 / 远程协助
  //      —— 国内几乎所有社区站、工具站、开源项目页都挂 QQ 交流群。
  //         实测 tool.lu 仅因页面含「qq群」即命中强诱导。
  //
  // 这两类词的共同问题：它们描述「话题/联系方式」，而非「诱导受害者执行动作的诈骗剧本」。
  // 真正的银狐/钓鱼专属话术是「冒充公权力或财务场景施压」——公检法 / 涉案 / 通缉 / 安全账户 /
  // 转账 / 社保补贴 / 付款单据 / 内部通知 / 违纪 / 裁员 / 补偿 —— 正规站几乎不会成篇出现。
  //
  // 因此 STRONG 只保留诈骗剧本词；业态词与社群词下调至 WEAK（仍计低分参与堆叠，
  // 但不再单独触发「下载入口 + 强诱导 → 直接判 danger」的组合升级）。
  const SOCIAL_ENGINEERING_STRONG = [
    '安全账户', '涉案', '通缉', '公检法', '保密协议',
    '社保补贴', '付款单据', '内部通知', '违纪', '裁员'
  ];
  const SOCIAL_ENGINEERING_WEAK = [
    // ---- 原 STRONG 降级：软件资源站业态词（内容主题，非诈骗剧本）----
    '破解', '注册机', '激活工具', '免费激活', '内部版',
    // ---- 原 STRONG 降级：社群联系方式（国内社区站标配）----
    '加qq群', '加q群', 'qq群', '客服微信', '扫码领取', '远程协助',
    // ---- 原有弱词 ----
    '最新通知', '通报', '名单', '会议资料', '政策文件', '成绩单',
    '领取', '福利', '限时', '红包', '返利', '兼职', '中奖',
    '人事', '离职', '劳动合同', '培训资料', '学习资料', '课程资料',
    '转账', '补偿'
  ];
  // 向后兼容：合并视图，供旧调用方整体读取
  const SOCIAL_ENGINEERING = SOCIAL_ENGINEERING_STRONG.concat(SOCIAL_ENGINEERING_WEAK);

  // 假冒官方话术（仅保留「银狐用来安抚受害者」的强特征防御性话术；
  // 普通下载按钮文案「安全下载/高速下载/本地下载/电信下载/普通下载/绿色版/纯净版/无插件」过于常见，
  // 已从本表移除，避免任何带 exe 的正规下载站被误判为 danger）
  const FAKE_OFFICIAL = [
    '官方下载', '官网认证', '官网正版', '防病毒误报', '杀软误报', '杀毒软件误报',
    '加白名单', '官方授权', '这是安全的', '无毒', '官网下载', '正版下载', '官方正版'
  ];

  // ============ 银狐「签名诱饵」主题（高区分度，正常站点极少出现）============
  // 来源：2025–2026 多份银狐报告归纳的反复出现的投递主题。
  // 这些词单独出现在普通页面概率极低；若同时页内含下载/网盘入口，则高度可疑。
  // 已用 hasDownloadLink 门控（见 analyzer.js detLureTheme），避免政府/企业正常网页误伤。
  const LURE_THEMES = [
    '税务稽查', '所得税汇算', '企业所得税汇算', '个税退税', '个人所得税退税', '退税', '金税',
    '汇算清缴', '稽查通知', '税务抽查', '稽查局', '违规记录', '补贴申领', '社保补贴', '工资补贴',
    '薪资补贴', '行政处罚告知书', '处理决定书', '开票目录', '补贴发放', '补贴名单', '工资明细表',
    '录取名单', '采购名单', '名单公示', '清查通报', '整改通知', '专项检查', '稽查材料', '退费通知'
  ];

  // ============ 伪造「插件/浏览器/Flash 版本过低」更新提示 ============
  // 银狐常用「点击页面任意位置→弹窗 flash/浏览器版本过低→重定向下载页」诱导。
  // 门控：需页面含重定向/iframe 或下载入口，避免正常站点「请更新浏览器」横幅误伤。
  const FAKE_UPDATE_TERMS = [
    'flash版本过低', 'flash 版本过低', '版本过低', '插件版本过低', '浏览器版本过低', '您的浏览器版本过低',
    '浏览器版本过', '请更新插件', '需要安装插件', '插件已过期', '请安装最新插件', '缺少flash', '未安装flash',
    'flash播放器', '播放器版本过低', 'npapi', '请下载flash', 'adobe flash', 'flash player 版本'
  ];

  // 银狐黑产偏好的低成本 / 批量注册 TLD
  const SUSPICIOUS_TLDS = [
    'top', 'xyz', 'live', 'shop', 'vip', 'cc', 'ren', 'wang', 'pw', 'click', 'link',
    'online', 'fun', 'rest', 'icu', 'buzz', 'work', 'date', 'trade', 'country', 'stream',
    'gq', 'cf', 'ml', 'tk', 'ga', 'nic', 'cyou', 'red', 'ink', 'mobi', 'pro', 'ltd', 'store',
    'win', 'xin', 'buzz', 'racing', 'monster', 'download', 'loan', 'icu', 'su', 'ru'
  ];

  // 常见网盘 / 云盘分发域名（二级或主域关键词）
  const CLOUD_DISK_HOSTS = [
    'aliyundrive.com', 'alipan.com', 'pan.baidu.com', 'weiyun.com',
    'pan.quark.cn', 'lanzou', 'lanzoux', 'lanzous', '123pan.com', '123912.com',
    'ctfile.com', 'cowtransfer', 'airportal', 'firefoxchina.cn', 'mediafire.com',
    'drive.google.com', 'dropbox.com', 'mega.nz', 'pan.xunlei.com', 'cloud.189.cn'
  ];

  // 强可疑可执行文件扩展名（一旦下载基本就是木马载体）
  const EXEC_EXTENSIONS = ['exe', 'msi', 'scr', 'bat', 'cmd', 'com', 'pif', 'vbs', 'ps1', 'jar', 'lnk', 'cpl', 'wsf', 'hta', 'dll', 'sys'];
  // 中风险压缩包扩展名（需结合其它信号才判危）
  const ARCHIVE_EXTENSIONS = ['zip', 'rar', '7z', 'gz', 'tar', 'iso', 'img', 'tgz', 'bz2', 'xz', 'z', 'cab', 'arj', 'lzh', 'zst', 'apk'];

  // JS 混淆 / 打包特征（基于网页代码分析）
  // ⚠️ 通用规则（超长 hex 转义 / 大量 fromCharCode / 超长 atob base64）阈值已上调，
  // 避免误伤 Vercel/Netlify/Next.js 等现代化站点压缩后的生产 JS、内联字体/图片/sourcemap。
  // 保留 obfuscator.io 专属的 `_0x` 变量特征（terser/esbuild 等压缩器不会产出，是高置信混淆信号）。
  // ⚠️ 2026-08-30 误报治理重构（两条改动）：
  //   1) 删除 (unescape|decodeURIComponent) 规则：处理 % 编码是路由解析与参数解码的
  //      常规操作，正规站（尤其中文站、SPA、带跳转统计的站点）普遍使用，
  //      作为「混淆」特征误报率极高，予以删除。
  //   2) atob 长 base64 阈值 300 → 2000：内联 SVG / 图标字体 / 小图 / webpack 内联
  //      资源轻松超过 300 字符，原阈值几乎必中；抬到 2000 后命中的基本只剩真实加密载荷。
  // 保留项说明：packed 打包器、超长十六进制转义、大量 fromCharCode、_0x 变量数组
  // （obfuscator.io 专属）、document.write+unescape、javascript: 伪协议执行
  // —— 这些都是高置信的真实混淆特征，正规打包工具不会产出。
  const OBFUSCATION_PATTERNS = [
    /eval\s*\(\s*function\s*\([\s\S]{0,40}?\)\s*\{[\s\S]{0,80}?return[\s\S]{0,120}?\}\s*\(\s*\d+\s*,/i, // packed 打包器
    /\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){40,}/i, // 超长十六进制转义串（阈值 20→40）
    /(?:fromCharCode|String\.fromCharCode)\s*\((?:0x[0-9a-f]+|\d+)\s*(?:,[^)]{0,200}?){12,}/i, // 大量 fromCharCode（8→12）
    /atob\s*\(\s*['"][A-Za-z0-9+/=]{2000,}/i, // 超长 base64 字面量（120→300→2000，规避内联资源误判）
    /_0x[a-f0-9]{4,}\s*=[\s\S]{0,30}?\[['"][a-z0-9]+['"]\]/, // 典型十六进制变量混淆（obfuscator.io 专属）
    // 经典加密落地：document.write(unescape(...))
    // ⚠️ 2026-08-31 收紧：原规则只要出现 `document.write(unescape(` 即判混淆，
    // 但这正是 **CNZZ / 友盟+ 站长统计的官方标准埋点代码** 写法，国内数百万网站在用：
    //   document.write(unescape("%3Cspan id='cnzz_stat_icon_xxx'%3E%3C/span%3E%3Cscript src='"+p+"'%3E%3C/script%3E"))
    // 实测 www.lanzou.com 即因这段统计代码被判「JS 代码混淆 +30」。
    // 正规用法编码的只是一小段 HTML 标签（零星几个 %XX，且被字符串拼接打断）；
    // 真正的加密落地会把整段脚本全部编码 → 必然出现长串**连续** %XX。
    // 因此改为要求：unescape 调用后 200 字符内出现 ≥40 个连续 %XX 编码。
    /document\.write\s*\(\s*unescape\s*\([\s\S]{0,200}?(?:%[0-9a-f]{2}){40,}/i,
    /var\s+_0x[0-9a-f]+\s*=\s*\[/i, // 混淆变量数组（obfuscator.io 专属）
    /javascript\s*:\s*(?:eval|atob|decodeURIComponent)\s*\(/i
  ];

  // 虚拟机 / 沙箱环境检测（银狐 loader 强特征）
  // ⚠️ 只保留「原生系统调用 / 虚拟机厂商 / 反调试 / 显式 VM 探测函数名」这类强特征。
  // 已删除 navigator.hardwareConcurrency / navigator.plugins.length / navigator.maxTouchPoints /
  // screen.width / window.external / 泛化 debugger 关键字 / wmi|SELECT * FROM 等——这些是几乎所有
  // 现代网站（尤其 Vercel/Netlify/GitHub Pages 等海外托管站）都会用到的标准浏览器 API，
  // 命中即 +35 强特征直接判 danger，是海外托管/认证平台被误判为银狐的主因。
  // ⚠️ 2026-10-27 误报治理（Sangfor / 卡巴中国 / Dr.Web）：
  //   原实现把「VirtualBox|VMware|QEMU|Win32_Processor…」这类**产品名/系统类名**当作裸关键词，
  //   在整段内联脚本里做正则命中即判「沙箱探测」。
  //   但现代站点普遍把 CMS/SEO 数据以 JS 数据字面量内嵌进 <script>（Next.js 的 __NEXT_DATA__、
  //   导航树、文章正文），于是「深信服：VMware 替代方案」这类**正文**被当成探测代码，
  //   直接 +35 且 vmDetection 属 STRONG（命中即 danger，权重根本不参与判定）。
  //   产品名本身不是证据——真正的探测必然伴随「读取 UA / GPU / 硬件指纹」的代码结构。
  //   故拆成两组：
  //     ① VM_CODE_PATTERNS：自我表明意图的代码串，出现即可判定；
  //     ② VM_PROBE_TERMS：产品名/工具名，必须与 VM_PROBE_CONTEXT（探测语境）同处出现才算。
  const VM_CODE_PATTERNS = [
    /GetModuleHandle|IsDebuggerPresent|CreateToolhelp32Snapshot/i,
    /anti[_-]?debug|antiDebug|__debugger\b/i,
    /(?:detect[\s_]?vm|\bisVM\b|vmDetect|checkVM|sandboxCheck|antiSandbox)/i
  ];

  // 产品名 / 工具名 / WMI 类名：单独出现毫无判别力（软件下载站的软件清单、
  // 安全博客的正文、CMS 导航里都能有），仅在与探测语境同现时计分。
  const VM_PROBE_TERMS = /\b(?:virtualbox|vmware|qemu|parallels|hyper-?v|oracle vm|sandboxie|cpuz|speccy|wireshark)\b|win32_(?:processor|bios|computersystem)/gi;

  // 探测语境：从代码里读取运行环境指纹的结构（UA / WebGL / 硬件并发 / 屏幕 / 插件 / WMI 查询）。
  // 正文一句话里不会同时出现这些取属性/取参数的写法。
  const VM_PROBE_CONTEXT = /navigator\s*[.[]|useragent|hardwareconcurrency|devicememory|getparameter|unmasked|webgl|webdriver|screen\s*\.|activexobject|\bwmi\b|select\s+[\s\S]{0,20}from\s+win32_/i;

  // 向后兼容：旧调用点若只想知道「是否命中 VM 特征」，仍可用合并后的列表。
  const VM_DETECTION_PATTERNS = VM_CODE_PATTERNS;

  // 已知恶意脚本片段 / C2 行为特征（通用、低误报）
  const KNOWN_BAD_SNIPPETS = [
    /powershell\s+\-nop\s+\-w\s+hidden/i,
    /powershell\s+\-enc\b|powershell\s+\-e\s+[A-Za-z0-9+/=]{20,}|EncodedCommand/i, // PowerShell 编码执行（银狐 loader 常用）
    /iex\s*\(|Invoke-Expression|DownloadString|FromBase64String/i, // PowerShell 下载/解码载荷
    /certutil\s+\-urlcache\s+\-split\s+\-f/i,
    /bitsadmin\s+\/transfer/i,
    /rundll32\s*\(/i,
    /regsvr32\s+\/s\s+/i,
    /WScript\.Shell|wscript\.exe|cscript\.exe|mshta\b|mshta\.exe/i, // 脚本宿主/HTA 落地
    /ShellExecute\s*\(/i,
    /CreateObject\s*\(\s*['"]WScript/i,
    /\\AppData\\Roaming|%AppData%|%Temp%|%TEMP%/i,
    /taskkill\s+\/f\s+\/im/i,
    /netsh\s+firewall|netsh\s+advfirewall/i,
    /schtasks\s+\/create|reg\s+add.*CurrentVersion\\Run|sc\s+create\b|net\s+start\s+\w+/i, // 持久化
    /Set-MpPreference|Add-MpPreference|DisableAntiSpyware|-ExclusionPath|MpPreference/i, // 关闭/排除 Defender（银狐对抗）
    /VirtualAlloc|CreateThread|RtlMoveMemory|WriteProcessMemory/i, // 内存注入/Shellcode 加载（银狐 loader 强特征）
    /CurrentControlSet\\Services/i
  ];

  // 重定向 / 注入检测
  const REDIRECT_PATTERNS = [
    /<meta[^>]+http\-equiv\s*=\s*['"]?refresh/i, // meta refresh 跳转
    /location\.(href|replace|assign)\s*=\s*['"][^'"]+/i,
    /window\.open\s*\(\s*['"][^'"]+/i,
    /setTimeout\s*\(\s*function[\s\S]{0,40}?location/i,
    // ⚠️ 2026-10-27 误报治理：iframe 白名单改为「可带任意子域」的否定前瞻，
    // 避免 player.vimeo.com / www.youtube.com 等合法嵌入被误判为「重定向/注入(+25)」。
    // 白名单覆盖常见嵌入/统计/支付/社交/静态托管平台，这些站点被合法站点普遍内嵌，
    // 仅凭「跨域 iframe」一项不应加分；钓鱼站若内嵌其它未知域仍照常判定。
    // 边界判定放在零宽否定前瞻内部：要求被排除的 host 之后紧跟 "." 或字符串末尾，
    // 避免把 "myvimeo.com" 当成 vimeo 排除。
    /<iframe[^>]+src\s*=\s*['"](https?:)?\/\/(?!(?:[a-z0-9-]+\.)*(?:www\.)?(?:youtube|google|gstatic|googleapis|w3\.org|alicdn|bdimg|baidustatic|jsdelivr|unpkg|cdnjs|cloudflare|stripe|paypal|vimeo|wistia|twitch|disqus|github|githubusercontent|gitlab|vercel|netlify|pages\.dev|workers\.dev|firebaseapp|herokuapp|facebook|instagram|linkedin|twitter|imgur|bootstrapcdn)(?:\.|$))[^'"]+/i
  ];

  // ============ 链接分类（供拦截逻辑使用）============
  // ⚠️ 2026-08-31 修复一处通杀级误报：原实现对整条 href 做 `endsWith('.' + ext)` 判断，
  // 而 EXEC_EXTENSIONS 含 'com'、ARCHIVE_EXTENSIONS 含 'zip' / 'cab' / 'img' —— 这些同时
  // 是真实顶级域名。于是任何指向域名根、末尾不带斜杠的普通链接都会被判成「可执行文件直链」：
  //     <a href="http://www.woozooo.com">  →  endsWith('.com') → exec
  //     <a href="https://example.com">     →  exec
  // 页脚友链、合作方、备案查询链接普遍是这种写法，导致几乎所有中文站都凭空产出若干
  // 「.exe 直链」，直接触发 execDownload 维度加分（实测 www.lanzou.com 因此 +12）。
  //
  // 修复：扩展名只在【URL 路径的最后一段】上判断，host 不参与。
  //   http://www.woozooo.com        → path='/'          → 末段为空 → other  ✅
  //   https://x.com/setup.exe       → 末段='setup.exe'  → exec            ✅
  //   /dl/wechat.com                → 末段='wechat.com' → exec（真 DOS 可执行）✅
  function _lastPathSegment(href) {
    let s = String(href).split('#')[0].split('?')[0];
    // 剥离 scheme + host（含协议相对写法 //host/path）
    const m = s.match(/^[a-z][a-z0-9+.\-]*:\/\/[^/]*(\/.*)?$/i);
    if (m) s = m[1] || '/';
    else if (/^\/\/[^/]+/.test(s)) s = s.replace(/^\/\/[^/]+/, '') || '/';
    const seg = s.split('/').pop() || '';
    return seg.toLowerCase();
  }
  // 网盘域名是否出现在 URL 的 hostname（且位于标签边界）。
  // 含点的条目（pan.baidu.com / mediafire.com…）按 host 子串匹配；
  // 裸 token（lanzou / lanzoux / lanzous / cowtransfer / airportal）要求位于标签边界、
  // 且后接顶级域（避免命中博客路径 / 文章 slug 等无关 URL，如 …/post/lanzou-guide）。
  function _cloudHostInHref(href) {
    if (!href) return false;
    const m = String(href).match(/^[a-z][a-z0-9+.\-]*:\/\/([^\/]+)/i) || String(href).match(/^\/\/([^\/]+)/i);
    const host = (m ? m[1] : '').toLowerCase();
    if (!host) return false;
    for (const c of (CLOUD_DISK_HOSTS || [])) {
      if (c.indexOf('.') !== -1) {
        if (host.indexOf(c.toLowerCase()) !== -1) return true;
      } else {
        const tok = c.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        if (new RegExp('(?:^|\\.)' + tok + '[a-z0-9]*\\.').test(host)) return true;
      }
    }
    return false;
  }

  function classifyLink(href) {
    if (!href) return 'other';
    const h = href.toLowerCase();
    if (/^(javascript:|#|mailto:|tel:)/i.test(href)) return 'other';
    const seg = _lastPathSegment(href);
    if (seg && seg.indexOf('.') !== -1) {
      for (const e of EXEC_EXTENSIONS) if (seg.endsWith('.' + e)) return 'exec';
      for (const e of ARCHIVE_EXTENSIONS) if (seg.endsWith('.' + e)) return 'archive';
    }
    // ⚠️ 2026-10-27 误报治理：网盘判定改为只看 hostname 标签边界，不再对整条 href 裸子串匹配。
    // 否则博文路径 / 文章 slug 里出现 lanzou / 123pan 等字眼会被误判为「网盘分发」，
    // 连带触发 detCloudDisk(+30) 与 detLinkAnalysis(+10)。蓝奏云变体（lanzouw.com /
    // lanzoux.com）靠「标签边界 + 后接顶级域」仍可被正确识别。
    if (_cloudHostInHref(href)) return 'cloud';
    if (/download|\.exe|安装包|客户端|完整版|破解|激活|注册机|绿色版|免费版/i.test(href)) return 'download';
    return 'other';
  }

  const API = {
    OFFICIAL_DOMAINS,
    WHITELIST_CATALOG,
    // 2026-11-12：「访问正确的页面」官网映射（品牌词 → 官网域名）
    CORRECT_SITE_CATALOG,
    CORRECT_DOMAIN_MAP,
    CORRECT_BRANDS,
    // 2026-11-22：关联品牌词（品牌词 → 关联品牌词数组），analyzer 合并两级数据源后据此追加站点
    CORRECT_SITE_RELATIONS,
    // 2026-11-18：站点规格归一化（多官网 / 链接级官网）。analyzer 与设置页共用同一套校验，
    //   避免「内置表按一套规则收、云端补录按另一套规则收」导致同一个地址两边表现不一致。
    normalizeCorrectSites,
    BLACKLIST_CATALOG,
    categoryOfDomain,
    TRUSTED_PLATFORMS,
    TRUSTED_DOWNLOAD_HOSTS,
    KNOWN_BAD_DOMAINS,
    // 2026-11-23：内置「黑名单例外」（可推翻内置黑名单，不能推翻云端黑名单）
    EXCEPTION_DOMAINS,
    KNOWN_BAD_FILENAMES,
    SUSPICIOUS_DOWNLOAD_NAME_PATTERNS,
    BRAND_KEYWORDS,
    BRAND_GENERIC_WORDS,
    FRIENDLY_LINK_BRANDS,
    DOWNLOAD_KEYWORDS,
    SOCIAL_ENGINEERING,
    SOCIAL_ENGINEERING_STRONG,
    SOCIAL_ENGINEERING_WEAK,
    FAKE_OFFICIAL,
    SUSPICIOUS_TLDS,
    CLOUD_DISK_HOSTS,
    EXEC_EXTENSIONS,
    ARCHIVE_EXTENSIONS,
    OBFUSCATION_PATTERNS,
    VM_DETECTION_PATTERNS,
    VM_CODE_PATTERNS,
    VM_PROBE_TERMS,
    VM_PROBE_CONTEXT,
    KNOWN_BAD_SNIPPETS,
    REDIRECT_PATTERNS,
    LURE_THEMES,
    FAKE_UPDATE_TERMS,
    classifyLink
  };

  if (typeof window !== 'undefined') window.SF_IOCS = API;
  if (typeof self !== 'undefined') self.SF_IOCS = API;
  if (typeof module !== 'undefined' && module.exports) module.exports = API;
})();
