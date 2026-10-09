"""总览看板 API。"""

from __future__ import annotations

import time
from collections import Counter
from datetime import datetime

from fastapi import APIRouter

from fishingnet import config as core_config, intel

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/trends")
def trends(days: int = 30):
    """P4 趋势看板：按天发现/封堵/人工复核 + 人机一致率。"""
    return intel.trends(min(max(days, 7), 90))


@router.get("/overview")
def overview():
    """企业级 SaaS 面板聚合：KPI 环比 / 品牌仿冒 Top / 研判漏斗 / 系统健康。"""
    records = [r for r in intel.list_records() if r.get("status") == "active"]
    now = time.time()

    def _ts(rec):
        try:
            return datetime.fromisoformat((rec.get("created") or "").replace("Z", "")).timestamp()
        except Exception:
            return 0.0

    today0 = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
    yday0 = today0 - 86400
    new_today = sum(1 for r in records if _ts(r) >= today0)
    new_yesterday = sum(1 for r in records if yday0 <= _ts(r) < today0)
    blocked_today = sum(1 for r in records if r.get("disposition") in ("auto_blocked", "policy_blocked")
                        and (r.get("updated") or 0) >= today0 or False)

    # 品牌被仿冒 Top（AI 判恶意的 impersonated_brand 计数）
    brand_top = Counter()
    for r in records:
        av = r.get("ai_verdict") or {}
        if av.get("verdict") in ("phishing", "malware_distribution") and av.get("impersonated_brand"):
            brand_top[av["impersonated_brand"]] += 1
    brand_top = [{"brand": b, "count": n} for b, n in brand_top.most_common(10)]

    # 研判漏斗
    evidenced = sum(1 for r in records if r.get("evidence"))
    ai_judged = sum(1 for r in records if (r.get("ai_verdict") or {}).get("verdict"))
    blocked = sum(1 for r in records if r.get("disposition") in ("auto_blocked", "policy_blocked"))
    human = sum(1 for r in records if r.get("disposition") == "pending_review")
    funnel = [
        {"stage": "发现域名", "count": len(records)},
        {"stage": "动态取证", "count": evidenced},
        {"stage": "AI 裁决", "count": ai_judged},
        {"stage": "封堵处置", "count": blocked},
        {"stage": "人工复核", "count": human},
    ]

    # 系统健康
    samples = intel.list_samples()
    last_rec = max((_ts(r) for r in records), default=0)
    health = {
        "ai_configured": bool(core_config.AI_API_KEY),
        "ai_model": core_config.AI_MODEL,
        "ai_vision_model": core_config.AI_VISION_MODEL or None,
        "ai_jev_model": core_config.AI_JEV_MODEL or None,
        "samples": len(samples),
        "samples_analyzed": sum(1 for s in samples if s.get("status") == "analyzed"),
        "keywords_total": 0,
        "data_freshness": now - last_rec if last_rec else None,
    }
    try:
        from . import store
        health["keywords_total"] = len(store.get_keywords())
        wl = store.whitelist_domains()
        health["whitelist"] = len(wl)
    except Exception:
        pass

    return {
        "kpi": {"new_today": new_today, "new_yesterday": new_yesterday,
                "blocked_today": blocked_today,
                "blocked_total": blocked, "total": len(records)},
        "brand_top": brand_top,
        "funnel": funnel,
        "health": health,
    }


@router.get("/summary")
def summary():
    records = intel.list_records()
    by_status = Counter(r.get("status", "") for r in records)
    by_final = Counter(r.get("final", "") for r in records)
    by_disposition = Counter(r.get("disposition", "") for r in records)
    verdicts = Counter((r.get("ai_verdict") or {}).get("verdict", "未裁决") for r in records
                       if r.get("status") != "false_positive")

    # 近14天趋势（按记录创建日期）
    days = []
    base = time.strftime("%Y-%m-%d")
    trend_new = Counter()
    trend_blocked = Counter()
    for r in records:
        created = r.get("created", "")[:10]
        if created:
            trend_new[created] += 1
            if r.get("disposition") in ("auto_blocked",) or r.get("final") == "malicious":
                trend_blocked[created] += 1
    day_list = [time.strftime("%m-%d", time.localtime(time.time() - 86400 * i)) for i in range(13, -1, -1)]
    full_dates = [time.strftime("%Y-%m-%d", time.localtime(time.time() - 86400 * i)) for i in range(13, -1, -1)]
    for d, label in zip(full_dates, day_list):
        days.append({"date": label, "new": trend_new.get(d, 0), "blocked": trend_blocked.get(d, 0)})

    # 高频命中关键词
    kw_counter = Counter()
    for r in records:
        for h in r.get("hits", []):
            if h.get("keyword"):
                kw_counter[h["keyword"]] += 1

    blocked = intel.active_blocked()
    return {
        "total": len(records),
        "blocked_active": len(blocked),
        "pending_review": by_disposition.get("pending_review", 0),
        "false_positives": by_status.get("false_positive", 0),
        "malicious": by_final.get("malicious", 0),
        "monitored": by_disposition.get("monitored", 0),
        "allowed": by_disposition.get("allowed", 0),
        "by_status": dict(by_status),
        "by_final": dict(by_final),
        "verdicts": dict(verdicts),
        "trend": days,
        "top_keywords": kw_counter.most_common(8),
        "recent": [
            {"domain": r.get("domain"), "final": r.get("final"), "disposition": r.get("disposition"),
             "status": r.get("status"), "score": (r.get("score") or {}).get("score"),
             "ai_verdict": (r.get("ai_verdict") or {}).get("verdict"),
             "ai_confidence": (r.get("ai_verdict") or {}).get("confidence"),
             "created": r.get("created")}
            for r in records if r.get("status") != "false_positive"
        ][:10],
    }
