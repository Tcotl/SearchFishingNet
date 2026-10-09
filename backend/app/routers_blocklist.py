"""封堵产物 API。"""

from __future__ import annotations

import json
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse

from fishingnet import blocklist, intel

router = APIRouter(prefix="/api/blocklist", tags=["blocklist"])

ARTIFACTS = {
    "hosts": "hosts",
    "dnsmasq.conf": "dnsmasq.conf",
    "rpz.zone": "rpz.zone",
    "acl_domain.csv": "acl_domain.csv",
    "block_orders.json": "block_orders.json",
}


@router.get("")
def get_blocklist():
    blocked = intel.active_blocked()
    return {
        "count": len({r["domain"] for r in blocked}),
        "domains": sorted({r["domain"] for r in blocked}),
        "artifacts": sorted(ARTIFACTS.keys()),
        "dir": str(blocklist.config.BLOCKLIST_DIR),
    }


@router.get("/files/{name}", response_class=PlainTextResponse)
def get_artifact(name: str):
    if name not in ARTIFACTS:
        raise HTTPException(404, "未知产物")
    p = Path(blocklist.config.BLOCKLIST_DIR) / ARTIFACTS[name]
    if not p.exists():
        blocklist.generate_all()
    return p.read_text(encoding="utf-8")


@router.post("/regenerate")
def regenerate():
    result = blocklist.generate_all()
    return {"count": result["count"], "dir": result["dir"]}


# ---------------- 钓鱼站点列表导出 ----------------

def _phishing_rows(include_monitored: bool = False):
    """封堵域名：AI 确认恶意 + 严格策略封堵；include_monitored 时附带蹭品牌监控域名。"""
    dispositions = {"auto_blocked", "policy_blocked"}
    if include_monitored:
        dispositions.add("monitored")
    rows = []
    for r in intel.list_records():
        if r.get("status") == "active" and r.get("disposition") in dispositions:
            score = r.get("score") or {}
            ai = r.get("ai_verdict") or {}
            rows.append({
                "domain": r.get("domain"),
                "disposition": r.get("disposition"),
                "rule_score": score.get("score"),
                "ai_verdict": ai.get("verdict"),
                "ai_confidence": ai.get("confidence"),
                "impersonated_brand": ai.get("impersonated_brand") or "",
                "ai_evidence": "；".join((ai.get("evidence") or [])[:3]),
                "keywords": "、".join(sorted({h.get("keyword") for h in r.get("hits", []) if h.get("keyword")})),
                "engines": "、".join(sorted({h.get("engine") for h in r.get("hits", []) if h.get("engine")})),
                "final_url": (r.get("evidence") or {}).get("final_url") or "",
                "page_title": (r.get("evidence") or {}).get("page_title") or "",
                "first_seen": r.get("created"),
                "record_id": r.get("id"),
            })
    rows.sort(key=lambda x: (x["disposition"] != "auto_blocked", -(x["ai_confidence"] or 0)))
    return rows


@router.get("/export/phishing.csv")
def export_phishing_csv(include_monitored: bool = False):
    import csv
    import io

    rows = _phishing_rows(include_monitored)
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()) if rows else
                            ["domain", "disposition", "rule_score", "ai_verdict", "ai_confidence",
                             "impersonated_brand", "ai_evidence", "keywords", "engines",
                             "final_url", "page_title", "first_seen", "record_id"])
    writer.writeheader()
    writer.writerows(rows)
    from fastapi.responses import Response
    return Response(
        content="\ufeff" + buf.getvalue(),  # BOM 便于 Excel 识别 UTF-8
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=phishing_sites.csv"})


@router.get("/export/phishing.txt")
def export_phishing_txt():
    from fastapi.responses import Response
    domains = sorted({r["domain"] for r in _phishing_rows()
                      if r.get("disposition") in ("auto_blocked", "policy_blocked")})
    return Response(content="\n".join(domains), media_type="text/plain; charset=utf-8",
                    headers={"Content-Disposition": "attachment; filename=phishing_domains.txt"})


@router.get("/export/phishing.json")
def export_phishing_json():
    from fastapi.responses import Response
    return Response(
        content=json.dumps({"exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                            "count": len(_phishing_rows()),
                            "sites": _phishing_rows(include_monitored=True)},
                           ensure_ascii=False, indent=2),
        media_type="application/json; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename=phishing_sites.json"})
