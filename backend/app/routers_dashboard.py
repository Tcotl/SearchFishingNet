"""总览看板 API。"""

from __future__ import annotations

import time
from collections import Counter

from fastapi import APIRouter

from fishingnet import intel

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/trends")
def trends(days: int = 30):
    """P4 趋势看板：按天发现/封堵/人工复核 + 人机一致率。"""
    return intel.trends(min(max(days, 7), 90))


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
            for r in records[:10]
        ],
    }
