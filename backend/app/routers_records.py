"""研判记录 API：列表/详情/截图/复核处置。"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, JSONResponse

from fishingnet import blocklist, intel

router = APIRouter(prefix="/api/records", tags=["records"])

VALID_STATUS = ("active", "false_positive", "allowed", "expired")
VALID_FEEDBACK = ("false_positive", "confirm", "allow", "confirm_block")


@router.get("")
def list_records(status: str | None = None, q: str | None = None,
                 disposition: str | None = None, final: str | None = None,
                 sort: str | None = None,
                 page: int = 1, page_size: int = 20):
    records = intel.list_records(status or None)
    if q:
        needle = q.lower()
        records = [r for r in records
                   if needle in (r.get("domain") or "").lower()
                   or any(needle in (h.get("keyword") or "").lower() or needle in (h.get("title") or "").lower()
                          for h in r.get("hits", []))]
    if disposition:
        records = [r for r in records if r.get("disposition") == disposition]
    if final:
        records = [r for r in records if r.get("final") == final]
    if sort == "priority":
        # 复核优先级：AI 有恶意定性但置信度不足/品牌词/坐床期新注册 置顶
        from fishingnet import facts as facts_mod
        decorated = []
        for r in records:
            score, reasons = facts_mod.review_priority(r)
            r = {**r, "priority": score, "priority_tier": facts_mod.priority_tier(score),
                 "priority_reasons": reasons}
            decorated.append(r)
        records = sorted(decorated, key=lambda x: (-x["priority"], x.get("domain") or ""))
    total = len(records)
    start = max(0, (page - 1) * page_size)
    return {"total": total, "page": page, "page_size": page_size,
            "items": records[start:start + page_size]}


@router.post("/batch-feedback")
def batch_feedback(body: dict):
    """批量复核处置：domains[] + kind（同单域接口），可随批量加入白名单。"""
    domains = [str(d).strip().lower() for d in (body.get("domains") or []) if str(d).strip()]
    kind = body.get("kind", "")
    if not domains:
        raise HTTPException(400, "domains 不能为空")
    if len(domains) > 200:
        raise HTTPException(400, "单次批量上限 200 条")
    if kind not in VALID_FEEDBACK:
        raise HTTPException(400, f"kind 须为 {VALID_FEEDBACK}")
    results = {"ok": [], "missing": []}
    for d in domains:
        (results["ok"] if intel.feedback(d, kind, body.get("note") or "")
         else results["missing"]).append(d)
    if kind in ("allow", "false_positive") and body.get("add_whitelist", True) and results["ok"]:
        from .store import add_whitelist
        add_whitelist(results["ok"], note=body.get("note") or "批量复核放行", source="feedback")
    blocked = blocklist.generate_all()
    return {"ok": True, "processed": len(results["ok"]), "missing": results["missing"],
            "blocked_count": blocked["count"]}


@router.get("/{domain}")
def get_record(domain: str):
    records = intel.list_records()
    for r in records:
        if r.get("domain") == domain:
            return r
    raise HTTPException(404, "记录不存在")


@router.get("/{domain}/screenshot")
def record_screenshot(domain: str):
    for r in intel.list_records():
        if r.get("domain") == domain:
            shot = (r.get("evidence") or {}).get("screenshot_path", "")
            if shot:
                from pathlib import Path
                p = Path(shot)
                if p.exists():
                    return FileResponse(p, media_type="image/png")
            break
    raise HTTPException(404, "无截图证据")


@router.post("/{domain}/feedback")
def record_feedback(domain: str, body: dict):
    kind = body.get("kind", "")
    if kind not in VALID_FEEDBACK:
        raise HTTPException(400, f"kind 须为 {VALID_FEEDBACK}")
    ok = intel.feedback(domain, kind, body.get("note") or "")
    if not ok:
        raise HTTPException(404, "记录不存在")
    # 放行时可选加入白名单增补，防止后续轮次重复告警
    if kind == "allow" and body.get("add_whitelist"):
        from .store import add_whitelist
        add_whitelist([domain], note=body.get("note") or "复核放行", source="feedback")
    blocked = blocklist.generate_all()
    return {"ok": True, "blocked_count": blocked["count"]}


@router.post("/{domain}/rejudge")
async def record_rejudge(domain: str):
    """对已有记录重新触发单域研判任务。"""
    from .jobs import manager
    from .tasks import TASK_REGISTRY, execute
    job = manager.create("judge", {"domain": domain,
                                   "mock_ai": False, "skip_evidence": False})
    import asyncio
    loop = asyncio.get_running_loop()
    loop.run_in_executor(routers_executor(), execute, job)
    return job.to_dict(tail=0)


def routers_executor():
    from .routers_jobs import EXECUTOR
    return EXECUTOR
