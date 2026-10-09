"""硬事实采集与复核优先级。

硬事实（对客观事实源的一手查询结果，独立于规则评分与 AI）：
- RDAP 注册年龄：免费无 Key，scoring 已带进程内缓存，结果持久化到记录 payload.facts；
- ICP 备案：配置 ICP_API_URL 后启用（国内站官方性最强证据之一）；
- VirusTotal：配置 VT_API_KEY 后启用（域名信誉兜底）。

事实入库后作为【硬事实核验】小节进入 AI 材料包，并参与复核优先级排序。
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from . import config
from .keywords import BRAND_TOKENS, RISKY_TLDS, registrable_domain


# ---------------- RDAP ----------------

def rdap_fact(domain: str) -> dict:
    """注册年龄事实：{registered, age_days}；查询失败返回 {"registered": None}。"""
    from .scoring import rdap_registration_date
    reg_date = rdap_registration_date(domain)
    if not reg_date:
        return {"registered": None, "age_days": None}
    age_days = age_since(reg_date)
    return {"registered": reg_date, "age_days": age_days}


def age_since(date_str: str) -> int | None:
    try:
        dt = datetime.fromisoformat(date_str).replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - dt).days)
    except Exception:
        return None


# ---------------- ICP / VT（配置 Key 后启用） ----------------

def icp_fact(domain: str) -> dict | None:
    """ICP 备案事实。未配置返回 None；查询失败返回 {"error": ...}。"""
    if not config.ICP_API_URL:
        return None
    try:
        body = urllib.parse.urlencode({"domain": registrable_domain(domain),
                                       "key": config.ICP_API_KEY or ""}).encode()
        req = urllib.request.Request(config.ICP_API_URL, data=body, headers={
            "Content-Type": "application/x-www-form-urlencoded"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8", "ignore"))
    except Exception as e:
        return {"error": str(e)[:100]}
    # 常见返回兼容：{code:200, data:{...}} / 直接 {...} / 列表
    payload = data.get("data") if isinstance(data, dict) and isinstance(data.get("data"), dict) else data
    if not isinstance(payload, dict):
        return {"error": "响应格式无法解析"}
    beian = str(payload.get("icp") or payload.get("beian") or payload.get("icpNo") or "").strip()
    owner = str(payload.get("unitName") or payload.get("owner") or payload.get("company") or "").strip()
    if not beian and not owner:
        return {"beian": "", "owner": "", "note": "无备案记录"}
    return {"beian": beian[:60], "owner": owner[:60]}


def vt_fact(domain: str) -> dict | None:
    """VirusTotal 域名事实。未配置返回 None。"""
    if not config.VT_API_KEY:
        return None
    reg = registrable_domain(domain)
    try:
        req = urllib.request.Request(
            f"https://www.virustotal.com/api/v3/domains/{reg}",
            headers={"x-apikey": config.VT_API_KEY})
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8", "ignore"))
        attrs = ((data.get("data") or {}).get("attributes") or {})
        stats = (attrs.get("last_analysis_stats") or {})
        return {"malicious": int(stats.get("malicious", 0)),
                "suspicious": int(stats.get("suspicious", 0)),
                "harmless": int(stats.get("harmless", 0)),
                "reputation": attrs.get("reputation")}
    except Exception as e:
        return {"error": str(e)[:100]}


def collect(domain: str, include_vt: bool = True, include_icp: bool = True) -> dict:
    """采集域名硬事实（尽力而为，任一失败不影响其他）。"""
    facts: dict = {"rdap": rdap_fact(domain), "collected_at": datetime.now().isoformat(timespec="seconds")}
    if include_icp:
        icp = icp_fact(domain)
        if icp is not None:
            facts["icp"] = icp
    if include_vt:
        vt = vt_fact(domain)
        if vt is not None:
            facts["vt"] = vt
    return facts


# ---------------- 复核优先级 ----------------

def review_priority(rec: dict) -> tuple[int, list[str]]:
    """待复核记录的处理优先级（0-100）与理由。分数越高越该先看。

    - AI 有恶意定性但置信度不足（spark 类保守模型的典型形态）→ 最高优先；
    - 域名含品牌词（仿冒基本面）→ 高；
    - 注册不足 90 天（坐床期站点）→ 高；
    - 下载渠道/网盘特征、高风险 TLD → 中。
    """
    score, reasons = 0, []
    domain = (rec.get("domain") or "").lower()
    body = registrable_domain(domain).split(".")[0] if registrable_domain(domain) else domain

    av = rec.get("ai_verdict") or {}
    verdict, conf = av.get("verdict") or "", int(av.get("confidence") or 0)
    if verdict in ("phishing", "malware_distribution"):
        score += 40
        reasons.append(f"AI 判恶意({verdict}/{conf})置信度不足待人工")
    elif verdict == "suspicious" and conf > 0:
        score += 12
        reasons.append(f"AI 存疑({conf})")

    hit_brand = next((b for b, toks in BRAND_TOKENS.items()
                      if any(t in body for t in toks if len(t) >= 3)), "")
    if hit_brand:
        score += 30
        reasons.append(f"域名含品牌词「{hit_brand}」")

    facts = rec.get("facts") or {}
    age = (facts.get("rdap") or {}).get("age_days")
    if age is not None:
        if age < 90:
            score += 30
            reasons.append(f"注册仅 {age} 天（坐床期）")
        elif age > 365 * 5:
            score -= 15
            reasons.append(f"注册 {age // 365} 年（老域名，仿冒概率低）")
    else:
        score += 5
        reasons.append("注册年龄未知")

    ev = rec.get("evidence") or {}
    links = ev.get("download_links") or []
    if any(d.get("netdisk") for d in links):
        score += 12
        reasons.append("下载入口指向网盘/短链")
    elif links:
        score += 6
        reasons.append("存在下载入口")

    tld = domain.rsplit(".", 1)[-1]
    if tld in RISKY_TLDS or domain.endswith(".top") or domain.endswith(".xyz"):
        score += 10
        reasons.append(f"高风险 TLD（.{tld}）")

    return max(0, min(100, score)), reasons


def priority_tier(score: int) -> str:
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"
