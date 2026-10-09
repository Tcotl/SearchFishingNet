"""词库：银狐高频搜索关键词、品牌官方域名映射、白名单、高危 TLD。

官方域名映射是全系统优先级最高的事实来源（对抗 GEO 投毒）：
  - 域名命中映射 → 直接放行，不送 AI；
  - 映射变更走人工维护，AI 无权修改本文件。

v2：覆盖主流钓鱼伪装软件全量词库（协同办公 / 远程控制 / 浏览器 / 文档办公 /
    财税开票 / 炒股行情 / 安全软件 / 系统工具 / 输入影音）。
"""

# 词库种子版本：平台首次启动或本版本号提升时，自动把缺失的默认词合并进平台词库
KEYWORDS_SEED_VERSION = 2

# ---------------- 银狐高频软件搜索关键词（按伪装类别组织） ----------------

KEYWORDS = [
    # 即时通讯 / 协同办公（银狐最常伪装）
    "钉钉下载",
    "钉钉官网下载",
    "企业微信下载",
    "微信电脑版下载",
    "QQ下载",
    "腾讯会议下载",
    "飞书下载",
    "飞书官网下载",
    # 远程控制（银狐渗透主力载体）
    "向日葵远程控制下载",
    "向日葵远程控制官网",
    "ToDesk下载",
    "ToDesk官网",
    "TeamViewer下载",
    "AnyDesk下载",
    "RustDesk下载",
    "远程控制软件下载",
    # 浏览器
    "Chrome浏览器下载",
    "谷歌浏览器下载",
    "Edge浏览器下载",
    "火狐浏览器下载",
    "360安全浏览器下载",
    "QQ浏览器下载",
    # 文档办公 / 设计
    "WPS下载",
    "WPS Office官网下载",
    "Office下载",
    "Photoshop下载",
    "福昕阅读器下载",
    "亿图图示下载",
    "PDF阅读器下载",
    "CAD软件下载",
    # 财税 / 开票（银狐重点攻击财务人群）
    "电子税务局下载",
    "金税盘驱动下载",
    "报税软件下载",
    "开票软件下载",
    "用友软件下载",
    "用友U8下载",
    "金蝶软件下载",
    "金蝶KIS下载",
    "百望开票软件下载",
    "航天信息开票软件下载",
    # 炒股 / 行情（银狐股票群诈骗载体）
    "同花顺下载",
    "东方财富下载",
    "通达信下载",
    "炒股软件下载",
    # 安全 / 系统工具
    "360安全卫士下载",
    "腾讯电脑管家下载",
    "火绒安全下载",
    "金山毒霸下载",
    "驱动精灵下载",
    "驱动人生下载",
    "7-Zip下载",
    "WinRAR下载",
    # 输入法 / 影音
    "搜狗输入法下载",
    "网易云音乐下载",
    "爱奇艺下载",
]

# ---------------- 品牌 → 官方域名（严格后缀匹配） ----------------

BRAND_OFFICIALS = {
    # 即时通讯 / 协同
    "钉钉": ["dingtalk.com"],
    "微信": ["weixin.qq.com", "weixin.com", "qq.com"],
    "企业微信": ["work.weixin.qq.com", "qq.com"],
    "QQ": ["qq.com", "im.qq.com"],
    "腾讯会议": ["meeting.tencent.com", "tencent.com"],
    "飞书": ["feishu.cn", "larksuite.com"],
    "字节跳动": ["bytedance.com", "feishu.cn"],
    # 远程控制
    "向日葵": ["sunlogin.oray.com", "oray.com"],
    "ToDesk": ["todesk.com"],
    "TeamViewer": ["teamviewer.com"],
    "AnyDesk": ["anydesk.com"],
    "RustDesk": ["rustdesk.com"],
    # 浏览器
    "Chrome": ["google.cn", "google.com"],
    "谷歌": ["google.cn", "google.com"],
    "Edge": ["microsoft.com", "microsoftedge.microsoft.com"],
    "Firefox": ["mozilla.org", "firefox.com.cn"],
    "火狐": ["mozilla.org", "firefox.com.cn"],
    "360": ["360.cn", "360.com", "browser.360.cn"],
    "QQ浏览器": ["browser.qq.com", "qq.com"],
    "搜狗": ["sogou.com"],
    # 文档办公 / 设计
    "WPS": ["wps.cn", "wps.com", "kingsoft.com", "wpspdf.cn"],
    "金山": ["kingsoft.com", "ijinshan.com"],
    "Microsoft": ["microsoft.com", "office.com"],
    "Office": ["microsoft.com", "office.com"],
    "Adobe": ["adobe.com"],
    "Photoshop": ["adobe.com"],
    "福昕": ["foxitsoftware.cn", "foxit.com"],
    "亿图": ["edrawsoft.cn", "edrawsoft.com"],
    "AutoCAD": ["autodesk.com", "autodesk.com.cn", "autocad.com"],
    "CAD": ["autodesk.com", "autodesk.com.cn", "autocad.com"],
    "中望CAD": ["zwsoft.cn", "zwcad.com"],
    "浩辰CAD": ["gstarcad.com", "gstarsoft.com"],
    # 财税 / 开票
    "用友": ["yonyou.com", "chanjet.com"],
    "金蝶": ["kingdee.com", "zhihuiji.cn"],
    "国家税务总局": ["chinatax.gov.cn"],
    "百望": ["baiwang.com"],
    "航天信息": ["aisino.com"],
    "航信": ["aisino.com"],
    # 炒股 / 行情
    "同花顺": ["10jqka.com.cn", "myhexin.com"],
    "东方财富": ["eastmoney.com"],
    "通达信": ["tdx.com.cn"],
    # 安全 / 系统工具
    "腾讯电脑管家": ["guanjia.qq.com", "qq.com"],
    "火绒": ["huorong.cn"],
    "驱动精灵": ["mydrivers.com"],
    "驱动人生": ["drivethelife.com", "updrv.com"],
    "7-Zip": ["7-zip.org"],
    "WinRAR": ["win-rar.com", "rarlab.com", "winrar.com.cn"],
    "华为": ["huawei.com"],
    # 输入法 / 影音
    "搜狗输入法": ["pinyin.sogou.com", "sogou.com"],
    "网易云音乐": ["music.163.com", "163.com"],
    "网易": ["163.com", "netease.com"],
    "爱奇艺": ["iqiyi.com"],
    # VPN（自定义关键词"VPN下载"命中品牌，官方直链均在注册域内）
    "SurfShark": ["surfshark.com"],
    "ExpressVPN": ["expressvpn.com", "expressrefer.com"],
    "NordVPN": ["nordvpn.com", "nordchecker.com"],
    "ProtonVPN": ["protonvpn.com", "proton.me"],
    "PureVPN": ["purevpn.com"],
    "Windscribe": ["windscribe.com"],
    "Mullvad": ["mullvad.net"],
}

# 常见多段后缀：注册域提取时按最长匹配剥除（com.cn 等不应算两级标签）
_MULTI_SUFFIXES = ("com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
                   "com.tw", "org.tw", "com.hk", "org.hk", "co.jp", "ne.jp",
                   "co.kr", "or.kr", "co.uk", "org.uk", "ac.uk", "gov.uk",
                   "com.au", "net.au", "com.br", "com.sg", "com.my")


def registrable_domain(host: str) -> str:
    """提取注册域（eTLD+1）：downloads.surfshark.com → surfshark.com；a.b.com.cn → b.com.cn。"""
    host = (host or "").lower().strip().removeprefix("www.")
    host = host.split("/")[0].split(":")[0]
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    tail2 = ".".join(labels[-2:])
    if tail2 in _MULTI_SUFFIXES:
        return ".".join(labels[-3:]) if len(labels) >= 3 else host
    return tail2

# 官方域名集合（扁平，便于 O(1) 查询）
OFFICIAL_DOMAINS = set()
for _domains in BRAND_OFFICIALS.values():
    OFFICIAL_DOMAINS.update(_domains)


def is_official(domain: str) -> tuple:
    """域名是否为某品牌官方域名（含子域，最长后缀优先以消解品牌间包含关系）。返回 (bool, 品牌)。"""
    d = (domain or "").lower().rstrip(".")
    best_len, best_brand = 0, ""
    for brand, officials in BRAND_OFFICIALS.items():
        for od in officials:
            if (d == od or d.endswith("." + od)) and len(od) > best_len:
                best_len, best_brand = len(od), brand
    return (True, best_brand) if best_len else (False, "")


# ---------------- 全局白名单（搜索结果常见正规站，直接放行） ----------------
# 注意：第三方软件下载站不在此列（见 DOWNLOAD_SITE_DOMAINS）——它们是银狐投毒链的
# 主要分发渠道，只降级为"待观察"，绝不进入可信区。

WHITELIST = {
    # 搜索/门户/云
    "baidu.com", "bing.com", "so.com", "sogou.com", "google.com",
    "zhihu.com", "csdn.net", "juejin.cn", "cnblogs.com", "blog.csdn.net",
    "bilibili.com", "douyin.com", "weibo.com", "tieba.baidu.com",
    "qq.com", "163.com", "126.com", "sohu.com", "sina.com.cn", "sina.com",
    "aliyun.com", "aliyuncs.com", "tencent.com", "huawei.com", "xiaomi.com",
    "jd.com", "taobao.com", "tmall.com", "pinduoduo.com",
    "github.com", "gitee.com", "gitcode.com", "npmjs.com",
    "microsoft.com", "apple.com", "adobe.com", "oracle.com", "mozilla.org",
    "wikipedia.org", "gov.cn", "12377.cn", "cnnic.cn",
    # 媒体/评测（非下载分发）
    "ithome.com", "pjtime.com",
    # 软件厂商官网（多品牌公共域）
    "yonyou.com", "kingdee.com", "aisino.com", "baiwang.com", "chinatax.gov.cn",
    "10jqka.com.cn", "eastmoney.com", "tdx.com.cn", "huorong.cn",
    "mydrivers.com", "drivethelife.com", "7-zip.org", "win-rar.com", "rarlab.com",
    "teamviewer.com", "anydesk.com", "rustdesk.com", "oray.com", "todesk.com",
    "feishu.cn", "larksuite.com", "ijinshan.com", "autodesk.com", "autodesk.com.cn",
    "foxitsoftware.cn", "edrawsoft.cn", "iqiyi.com",
}

# ---------------- 已知第三方软件下载站（非官方渠道：降为待观察，不放行） ----------------
# 站点规模大≠可信：历史上"高速下载器"捆绑即发源于此类站点，企业终端一律引导官网下载。

DOWNLOAD_SITE_DOMAINS = {
    "pc6.com", "downxia.com", "xpgod.com", "onlinedown.net", "mydown.com",
    "duote.com", "greenxf.com", "cr173.com", "downcc.com",
    "zol.com.cn", "pconline.com.cn", "yesky.com", "it168.com",
    # 国际捆绑安装器分发站（Softonic 系以捆绑推广著称，银狐亦借用其渠道）
    "softonic.com", "softpedia.com", "download.com", "cnet.com",
    "filehippo.com", "majorgeeks.com", "filehorse.com", "soft32.com",
    "techspot.com", "fosshub.com",
}

# 域名标签级下载渠道特征（soft1.zuitie.cn 这类靠模式识别兜底）
DOWNLOAD_LABEL_STARTS = ("soft", "down", "xiazai")
DOWNLOAD_LABELS_EXACT = {"download", "downloads", "xiazai", "xz", "soft", "down", "crx"}

# ---------------- 网盘/短链分发渠道（投毒站托管安装包的强特征） ----------------
# 匹配方式：host 含关键字即命中（覆盖 lanzou 系列换尾域名）

NETDISK_PATTERNS = (
    "lanzou", "ctfile", "pan.baidu.com", "cloud.189.cn", "feijipan", "123pan",
    "weiyun.com", "alipan", "aliyundrive", "wenshushu", "mega.nz", "mediafire",
    "ikhook", "n0pan", "sharefeier", "xiyezanyun", "zzpan", "xiaomiepan",
)


def in_whitelist(domain: str) -> bool:
    d = (domain or "").lower().lstrip("www.").rstrip(".")
    for w in WHITELIST:
        if d == w or d.endswith("." + w):
            return True
    return False


# ---------------- 高危 TLD ----------------

RISKY_TLDS = {
    "top", "xyz", "icu", "cyou", "cam", "bar", "rest", "zip", "mov",
    "work", "click", "link", "gq", "cf", "tk", "ml", "ga", "pw", "su",
    "ru", "cn.net", "buzz", "monster", "quest", "sbs", "cfd",
}

# ---------------- 关键词分组（供平台列表勾选展示） ----------------

KEYWORD_GROUPS: list[tuple[str, list[str]]] = [
    ("协同办公", ["钉钉下载", "钉钉官网下载", "企业微信下载", "微信电脑版下载", "QQ下载",
                "腾讯会议下载", "飞书下载", "飞书官网下载"]),
    ("远程控制", ["向日葵远程控制下载", "向日葵远程控制官网", "ToDesk下载", "ToDesk官网",
                "TeamViewer下载", "AnyDesk下载", "RustDesk下载", "远程控制软件下载"]),
    ("浏览器", ["Chrome浏览器下载", "谷歌浏览器下载", "Edge浏览器下载", "火狐浏览器下载",
              "360安全浏览器下载", "QQ浏览器下载"]),
    ("文档办公/设计", ["WPS下载", "WPS Office官网下载", "Office下载", "Photoshop下载",
                     "福昕阅读器下载", "亿图图示下载", "PDF阅读器下载", "CAD软件下载"]),
    ("财税/开票", ["电子税务局下载", "金税盘驱动下载", "报税软件下载", "开票软件下载",
                 "用友软件下载", "用友U8下载", "金蝶软件下载", "金蝶KIS下载",
                 "百望开票软件下载", "航天信息开票软件下载"]),
    ("炒股/行情", ["同花顺下载", "东方财富下载", "通达信下载", "炒股软件下载"]),
    ("安全/系统工具", ["360安全卫士下载", "腾讯电脑管家下载", "火绒安全下载", "金山毒霸下载",
                     "驱动精灵下载", "驱动人生下载", "7-Zip下载", "WinRAR下载"]),
    ("输入/影音", ["搜狗输入法下载", "网易云音乐下载", "爱奇艺下载"]),
]

# ---------------- 品牌别名（用于相似度检测的词根） ----------------

BRAND_TOKENS = {
    "钉钉": ["dingtalk", "dingding", "dd"],
    "微信": ["weixin", "wechat", "wx"],
    "企业微信": ["work.weixin", "qyweixin", "wework"],
    "QQ": ["qq", "tencent"],
    "腾讯会议": ["tencentmeeting", "wemeet"],
    "飞书": ["feishu", "lark"],
    "向日葵": ["sunlogin", "oray", "xiangrikui"],
    "ToDesk": ["todesk", "todesd", "t0desk"],
    "TeamViewer": ["teamviewer", "tv"],
    "AnyDesk": ["anydesk", "anydesd"],
    "RustDesk": ["rustdesk"],
    "WPS": ["wps", "kingsoft"],
    "Chrome": ["chrome", "googlechrome", "谷歌浏览器", "chrome浏览器"],
    "Edge": ["edge", "msedge"],
    "Firefox": ["firefox", "火狐"],
    "Photoshop": ["photoshop", "ps", "adobe"],
    "Office": ["office", "microsoft"],
    "福昕": ["foxit"],
    "亿图": ["edraw", "edrawmax"],
    "CAD": ["autocad", "autodesk", "cad", "中望", "zwcad", "zwsoft", "gstarcad", "浩辰"],
    "用友": ["yonyou", "chanjet", "用友", "u8"],
    "金蝶": ["kingdee", "金蝶", "kis", "k3"],
    "税务": ["chinatax", "金税", "报税", "税务", "shuiwu"],
    "开票": ["kaipiao", "开票", "fapiao", "发票"],
    "百望": ["baiwang", "百望"],
    "航信": ["aisino", "航信", "航天信息"],
    "同花顺": ["10jqka", "tonghuashun", "同花顺", "hexin"],
    "东方财富": ["eastmoney", "东方财富", "em"],
    "通达信": ["tdx", "通达信", "tongdaxin"],
    "360": ["360", "qihoo"],
    "火绒": ["huorong", "火绒"],
    "驱动精灵": ["mydrivers", "驱动精灵"],
    "驱动人生": ["drivethelife", "驱动人生"],
    "7-Zip": ["7zip", "7-zip", "7z"],
    "WinRAR": ["winrar"],
    "搜狗输入法": ["sogou", "pinyin"],
    "网易云音乐": ["netease", "163music", "cloudmusic"],
    "SurfShark": ["surfshark"],
    "ExpressVPN": ["expressvpn"],
    "NordVPN": ["nordvpn"],
    "ProtonVPN": ["protonvpn", "proton"],
    "PureVPN": ["purevpn"],
    "Windscribe": ["windscribe"],
    "Mullvad": ["mullvad"],
}
