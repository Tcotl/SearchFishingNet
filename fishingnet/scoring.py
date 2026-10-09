"""L1 规则评分引擎：域名置信度 0-100。

因子与分值对齐 docs/DESIGN.md §3.1：相似度 / RDAP 注册年龄 / SSL / TLD / URL 特征，
外加可选的威胁情报(VT)与 ICP 备案 API。所有因子带明细，供审计与 AI 输入。
"""

from __future__ import annotations

import json
import re
import socket
import ssl
import time
import urllib.request
from urllib.parse import urlparse

from . import config
from .keywords import (OFFICIAL_DOMAINS, BRAND_TOKENS, RISKY_TLDS, WHITELIST,
                       DOWNLOAD_SITE_DOMAINS, DOWNLOAD_LABEL_STARTS, DOWNLOAD_LABELS_EXACT,
                       in_whitelist, is_official, registrable_domain as _registrable)
from .models import RuleScore, tier_of, TRUSTED

# 同形字归一表：攻击者常用 0/o、1/l、3/e 混淆
_HOMOGLYPHS = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "|": "l", "!": "i", "$": "s",
})


def registrable_domain(domain: str) -> str:
    """兼容别名：注册域提取已统一到 keywords.registrable_domain。"""
    return _registrable(domain)


def normalize_domain(domain: str) -> str:
    d = (domain or "").lower().strip().lstrip(".").rstrip(".")
    if d.startswith("www."):
        d = d[4:]
    return d.translate(_HOMOGLYPHS)


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def similarity_findings(domain: str) -> list[str]:
    """返回相似度发现列表；空列表 = 无相似可疑。官方/白名单域名本身直接豁免。"""
    if is_official(domain)[0] or in_whitelist(domain):
        return []
    d = normalize_domain(domain)
    reg = normalize_domain(registrable_domain(domain))
    findings: list[str] = []
    base = reg.rsplit(".", 1)[0] if "." in reg else reg

    # 1) 品牌官方域名的近似变体（排除官方本身）
    for od in OFFICIAL_DOMAINS:
        obase = od.rsplit(".", 1)[0]
        if base == obase or base == normalize_domain(od):
            return []  # 官方域名本身
        dist = _levenshtein(base, obase)
        if 0 < dist <= 2 and len(obase) >= 5:
            findings.append(f"与官方域名 {od} 编辑距离 {dist}（{base} ≈ {obase}）")

    # 2) 品牌词出现在非官方域名的主体部分
    for brand, tokens in BRAND_TOKENS.items():
        for tok in tokens:
            if len(tok) < 3:
                continue
            if tok in base:
                findings.append(f"非官方域名主体包含品牌词「{brand}」({tok}): {base}")
                break

    # 3) punycode（中文域名混淆）
    raw = (domain or "").lower()
    if "xn--" in raw:
        findings.append("含 punycode 编码（xn--），存在同形字域名混淆风险")
    return findings


# ---------------- RDAP：域名注册年龄（免费、无 Key） ----------------

_RDAP_CACHE: dict[str, dict | None] = {}


def rdap_registration_date(domain: str) -> str | None:
    """通过 rdap.org 查询注册时间，返回 YYYY-MM-DD 或 None。"""
    reg = registrable_domain(domain)
    if reg in _RDAP_CACHE:
        cached = _RDAP_CACHE[reg]
        return cached.get("date") if cached else None
    entry: dict | None = None
    try:
        req = urllib.request.Request(
            f"https://rdap.org/domain/{reg}",
            headers={"Accept": "application/rdap+json", "User-Agent": "SearchFishingNet/0.1"},
        )
        with urllib.request.urlopen(req, timeout=config.RDAP_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8", "ignore"))
        for ev in data.get("events", []):
            if ev.get("eventAction") == "registration":
                entry = {"date": str(ev.get("eventDate", ""))[:10]}
                break
    except Exception:
        entry = None
    _RDAP_CACHE[reg] = entry
    return entry.get("date") if entry else None


def age_score(domain: str, today: float | None = None) -> tuple[int, str]:
    """注册年龄分值：>2年 +20；1-2年 +10；180d-1年 +5；90-180天 -5；<90天 -15。"""
    date_str = rdap_registration_date(domain)
    if not date_str:
        return 0, "RDAP 查询失败（新注册或查询不可用），不计分"
    try:
        reg_ts = time.mktime(time.strptime(date_str, "%Y-%m-%d"))
    except ValueError:
        return 0, f"注册时间解析失败: {date_str}"
    now = today or time.time()
    days = (now - reg_ts) / 86400
    if days > 730:
        return 20, f"注册于 {date_str}（{int(days // 365)} 年前），成熟域名"
    if days > 365:
        return 10, f"注册于 {date_str}（1-2 年）"
    if days > 180:
        return 5, f"注册于 {date_str}（半年-1 年）"
    if days > 90:
        return -5, f"注册于 {date_str}（90-180 天，偏新）"
    return -15, f"注册于 {date_str}（不足 90 天，强可疑）"


# ---------------- SSL 证书 ----------------

def ssl_check(domain: str) -> tuple[int, str]:
    """443 端口证书有效性：有效 +10，无 TLS -10，异常 0。"""
    host = domain.split(":")[0]
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return 10, "TLS 证书有效且与域名匹配"
    except ssl.SSLCertVerificationError as e:
        return -5, f"TLS 证书校验失败: {str(e)[:80]}"
    except (socket.timeout, ConnectionRefusedError, OSError):
        return -10, "443 端口无有效 TLS 服务"
    except Exception as e:
        return 0, f"TLS 检查异常: {str(e)[:80]}"


# ---------------- 可选：VirusTotal / ICP ----------------

def vt_score(domain: str) -> tuple[int, str, bool]:
    """VirusTotal 域名报告（可选）。返回 (delta, detail, hit)。"""
    if not config.VT_API_KEY:
        return 0, "未配置 VT API，跳过", False
    reg = registrable_domain(domain)
    try:
        req = urllib.request.Request(
            f"https://www.virustotal.com/api/v3/domains/{reg}",
            headers={"x-apikey": config.VT_API_KEY},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8", "ignore"))
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        if malicious >= 3:
            return -100, f"VT {malicious} 个引擎报恶意（{stats}）", True
        if malicious >= 1:
            return -30, f"VT {malicious} 个引擎报恶意（{stats}）", False
        return 10, f"VT 未检出恶意（{stats}）", False
    except Exception as e:
        return 0, f"VT 查询失败: {str(e)[:80]}", False


def icp_score(domain: str) -> tuple[int, str]:
    """ICP 备案（可选 API，POST domain=... 返回 JSON）。"""
    if not config.ICP_API_URL:
        return 0, "未配置 ICP 查询 API，跳过"
    try:
        body = urllib.parse.urlencode({"domain": registrable_domain(domain), "key": config.ICP_API_KEY}).encode()
        req = urllib.request.Request(config.ICP_API_URL, data=body,
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8", "ignore"))
        text = json.dumps(data, ensure_ascii=False)
        if '"code" : 200' in text or '"code":200' in text or data.get("success"):
            return 25, "ICP 备案存在（合规企业站强信号）"
        return 0, f"ICP 无备案或查询失败: {text[:80]}"
    except Exception as e:
        return 0, f"ICP 查询失败: {str(e)[:80]}"


# ---------------- URL / TLD 特征 ----------------

_URL_RISKY = re.compile(r"(download|setup|install|install|crack|破解|绿色版|免安装|去广告|激活|注册机)", re.I)


def url_features(hit_url: str, domain: str) -> list[tuple[str, int, str]]:
    out: list[tuple[str, int, str]] = []
    try:
        p = urlparse(hit_url or f"https://{domain}")
    except Exception:
        p = urlparse(f"https://{domain}")
    path_q = (p.path or "") + "?" + (p.query or "")
    hits = _URL_RISKY.findall(path_q)
    if hits:
        out.append(("url_feature", -5, f"URL 含敏感词: {sorted(set(h.lower() for h in hits))}"))
    if "@" in (hit_url or ""):
        out.append(("url_feature", -15, "URL 含 @（ userinfo 绕转手法）"))
    return out


def tld_score(domain: str) -> tuple[int, str]:
    tld = domain.rsplit(".", 1)[-1].lower() if "." in domain else ""
    if tld in RISKY_TLDS:
        return -10, f"高危 TLD: .{tld}"
    return 0, ""


# ---------------- 分发渠道风险（第三方下载站不放行） ----------------

def download_channel_check(domain: str) -> tuple[str, str]:
    """识别第三方下载/分发渠道。返回 (kind, detail)，kind ∈ {"known", "pattern", ""}。

    标签级匹配而非全文子串：避免 'microsoft' 含 'soft' 之类的误伤。
    """
    d = (domain or "").lower().rstrip(".")
    reg = registrable_domain(d)
    for site in DOWNLOAD_SITE_DOMAINS:
        if reg == site:
            return "known", f"已知第三方软件下载站（{site}）"
    for lab in d.split(".")[:-1]:  # 逐标签检查（跳过 TLD）
        # soft 只按前缀（microsoft 含 soft 不能误伤）；down 保留子串（bestdown/hxxdown 式命名）
        if lab in DOWNLOAD_LABELS_EXACT or lab.startswith(DOWNLOAD_LABEL_STARTS) \
                or "down" in lab:
            return "pattern", f"域名含下载/分发渠道特征标签「{lab}」"
    return "", ""


def apply_channel_factor(rs: RuleScore) -> None:
    """第三方下载/分发渠道风险。

    严格下载管控（默认）：已知下载站与模式命中一律封顶 39 分（可疑）——
    企业场景下只放行官方下载渠道，第三方下载渠道默认可能内置木马。
    宽松模式（设置关闭）：封顶 69 分（待观察）。
    """
    strict = bool(getattr(config, "STRICT_DOWNLOAD_POLICY", True))
    cap = 39 if strict else config.CHANNEL_SCORE_CAP
    strict_note = "严格下载管控：默认视为可能内置木马，已知站点将策略封堵" if strict \
        else "建议从品牌官网下载"
    kind, detail = download_channel_check(rs.domain)
    if kind == "known":
        rs.add("channel", 0, f"{detail}：非官方分发渠道（历史高速下载器捆绑重灾区）。{strict_note}")
        rs.score = min(rs.score, cap)
    elif kind == "pattern":
        rs.add("channel", -10, f"{detail}：非官方分发渠道，真实性存疑。{strict_note}")
        rs.score = min(rs.score, cap)


# ---------------- 汇总 ----------------

def score_domain(domain: str, hit_url: str = "") -> RuleScore:
    """对单个域名执行 L1 评分。官方/白名单直接置 100；VT 命中直接置 0。"""
    rs = RuleScore(domain=domain, score=100, tier=TRUSTED)

    # 优先级最高：官方域名映射（对抗 GEO 投毒）
    official, brand = is_official(domain)
    if official:
        rs.add("official", 0, f"品牌「{brand}」官方域名映射命中，直接放行")
        rs.tier = tier_of(rs.score)
        return rs
    if in_whitelist(domain):
        rs.add("whitelist", 0, "全局白名单命中，直接放行")
        rs.tier = tier_of(rs.score)
        return rs

    # 威胁情报
    vt_delta, vt_detail, vt_hit = vt_score(domain)
    if config.VT_API_KEY:
        rs.add("threat_intel", vt_delta, vt_detail)
        if vt_hit:
            rs.threat_intel_hit = True

    # ICP 备案
    icp_delta, icp_detail = icp_score(domain)
    if config.ICP_API_URL:
        rs.add("icp", icp_delta, icp_detail)

    # 相似度（核心信号）
    findings = similarity_findings(domain)
    if findings:
        rs.add("similarity", -40, "；".join(findings))
    else:
        rs.add("similarity", 0, "未发现与品牌官方域名相似/蹭名特征")

    # 注册年龄
    a_delta, a_detail = age_score(domain)
    rs.add("domain_age", a_delta, a_detail)

    # SSL
    s_delta, s_detail = ssl_check(domain)
    rs.add("ssl", s_delta, s_detail)

    # TLD
    t_delta, t_detail = tld_score(domain)
    if t_delta:
        rs.add("tld", t_delta, t_detail)

    # URL 特征
    for _, delta, detail in url_features(hit_url, domain):
        rs.add("url_feature", delta, detail)

    # 严格放行策略：非官方域名不自动放行（user 口径：只允许软件官方域名通行）
    if getattr(config, "STRICT_OFFICIAL_ONLY", True):
        rs.add("strict_pass", 0, "非官方域名：严格策略下不自动放行，强制进入取证与AI研判漏斗")
        rs.score = min(rs.score, config.NONOFFICIAL_SCORE_CAP)

    # 分发渠道（第三方下载站封顶待观察，绝不 trusted）
    apply_channel_factor(rs)

    rs.tier = tier_of(rs.score)
    return rs
