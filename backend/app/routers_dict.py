"""词库管理 API：关键词、白名单增补、品牌官方映射（只读）。"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from fishingnet import blocklist, intel
from fishingnet.keywords import BRAND_OFFICIALS, KEYWORD_GROUPS

from . import store

router = APIRouter(prefix="/api/dict", tags=["dict"])


@router.get("/keywords")
def get_keywords():
    return {"keywords": store.get_keywords()}


@router.get("/keywords/groups")
def get_keyword_groups():
    """按类别分组的词库（用于任务发起时的列表勾选）；用户自定义词归入"其他"。"""
    kws = store.get_keywords()
    in_group = set()
    groups = []
    for cat, items in KEYWORD_GROUPS:
        valid = [k for k in items if k in kws]
        if valid:
            groups.append({"category": cat, "keywords": valid})
            in_group.update(valid)
    other = [k for k in kws if k not in in_group]
    if other:
        groups.append({"category": "其他", "keywords": other})
    return {"groups": groups, "total": len(kws)}


@router.post("/keywords")
def add_keyword(body: dict):
    kw = (body.get("keyword") or "").strip()
    if not kw:
        raise HTTPException(400, "关键词不能为空")
    if not store.add_keyword(kw):
        raise HTTPException(409, "关键词已存在")
    return {"ok": True, "keywords": store.get_keywords()}


@router.delete("/keywords/{keyword}")
def remove_keyword(keyword: str):
    if not store.remove_keyword(keyword):
        raise HTTPException(404, "关键词不存在")
    return {"ok": True, "keywords": store.get_keywords()}


@router.get("/whitelist")
def get_whitelist():
    return {"entries": store.get_whitelist_entries(),
            "enabled_count": len(store.whitelist_domains())}


@router.post("/whitelist")
def add_whitelist_items(body: dict):
    """批量添加白名单：domains 支持换行/逗号/分号分隔，可附备注。"""
    text = body.get("domains") or body.get("domain") or ""
    try:
        domains = store.parse_domain_input(text)
    except ValueError as e:
        raise HTTPException(400, str(e))
    if not domains:
        raise HTTPException(400, "请输入域名")
    added = store.add_whitelist(domains, note=(body.get("note") or "").strip(),
                                source="manual")
    return {"ok": True, "added": added, "duplicates": len(domains) - added,
            "entries": store.get_whitelist_entries()}


@router.put("/whitelist/{domain}")
def update_whitelist_item(domain: str, body: dict):
    enabled = body.get("enabled")
    note = body.get("note")
    if enabled is None and note is None:
        raise HTTPException(400, "无更新内容")
    if not store.update_whitelist(domain,
                                  enabled=None if enabled is None else bool(enabled),
                                  note=note):
        raise HTTPException(404, "不存在")
    return {"ok": True, "entries": store.get_whitelist_entries()}


@router.delete("/whitelist/{domain}")
def remove_whitelist_item(domain: str):
    if not store.remove_whitelist(domain):
        raise HTTPException(404, "不存在")
    return {"ok": True, "entries": store.get_whitelist_entries()}


@router.get("/brands")
def get_brands():
    custom = store.get_brand_officials()
    return {"brands": [{"brand": b, "officials": d, "custom": b in custom}
                       for b, d in sorted(BRAND_OFFICIALS.items())]}


# ---------------- 官方映射自增长：AI 候选 → 人工一键确认 ----------------

@router.get("/brand-candidates")
def brand_candidates():
    """从 AI 放行/待复核记录提取"页面宣称品牌 + 非官方域名"候选，供人工确认补映射。"""
    from fishingnet import facts as facts_mod
    from fishingnet.keywords import is_official, registrable_domain
    from fishingnet.scoring import download_channel_check

    mapped = {d for doms in store.get_brand_officials().values() for d in doms}
    MALICIOUS = ("phishing", "malware_distribution")
    seen, out = set(), []
    for rec in intel.list_records():
        if rec.get("status") not in ("active", "allowed"):
            continue
        if rec.get("disposition") not in ("pending_review", "allowed", "monitored"):
            continue
        domain = (rec.get("domain") or "").lower()
        if not domain:
            continue
        reg = registrable_domain(domain)
        if reg in seen or is_official(domain)[0] or reg in mapped:
            continue
        av = rec.get("ai_verdict") or {}
        # 恶意嫌疑（AI 判 phishing/malware_distribution）绝不作为映射候选——
        # 确认即放行，是把钓鱼站设为可信的相反操作
        if av.get("verdict") in MALICIOUS:
            continue
        ev = rec.get("evidence") or {}
        mentions = ev.get("brand_mentions") or []
        source = "ai_benign" if (av.get("verdict") in ("benign", "unrelated")
                                 or rec.get("disposition") in ("allowed", "monitored")) else "brand_mention"
        age_days = ((rec.get("facts") or {}).get("rdap") or {}).get("age_days")
        # 候选安全闸：坐床期新注册（<90 天）、带网盘/短链下载入口（分发站而非官网）、
        # 或带下载渠道标签的域名更可能是待确认的仿冒站，不进候选
        if age_days is not None and age_days < 90:
            continue
        if download_channel_check(reg)[0]:
            continue
        if any(d.get("netdisk") for d in (ev.get("download_links") or [])):
            continue
        # 品牌优先级：AI 标注的假冒品牌 > 页面标题命中的品牌词根（标题代表页面自我
        # 宣称；brand_mentions 是页面内检测到的软件名泛列表，对下载分发页不可靠）>
        # 标题中出现的品牌提及。锚不上的一律跳过（无依据不成候选）。
        title_l = (ev.get("page_title") or "").lower()
        brand = (av.get("impersonated_brand") or "").strip()
        if not brand:
            from fishingnet.keywords import BRAND_TOKENS
            hit = next((b for b, toks in BRAND_TOKENS.items()
                        if any(t in title_l for t in toks if len(t) >= 3)), "")
            brand = hit or next((m for m in sorted(mentions, key=len, reverse=True)
                                 if m.lower() in title_l), "")
        if not brand:
            continue
        seen.add(reg)
        out.append({
            "domain": reg,
            "brand": brand[:30],
            "source": source,
            "ai_verdict": av.get("verdict") or "",
            "page_title": (ev.get("page_title") or "")[:80],
            "age_days": age_days,
            "priority": facts_mod.review_priority(rec)[0],
        })
    out.sort(key=lambda x: -x["priority"])
    return {"items": out[:80], "total": len(out)}


@router.post("/brand-candidates/confirm")
def brand_candidates_confirm(body: dict):
    """确认候选映射：brand + domains（注册域）→ 并入官方映射 → 即时重评分放行。"""
    from fishingnet import scoring
    from fishingnet.models import D_ALLOWED

    brand = (body.get("brand") or "").strip()
    domains = [str(d).strip().lower() for d in (body.get("domains") or []) if str(d).strip()]
    if not brand or not domains:
        raise HTTPException(400, "需要 brand 与 domains")
    added = store.add_brand_official(brand, domains)
    applied = []
    for d in domains:
        rs = scoring.score_domain(d)
        intel.update_rule_score(d, rs.to_dict())
        if rs.tier == "trusted":
            intel.set_disposition(d, "benign", D_ALLOWED, note=f"官方映射确认：{brand}")
            applied.append(d)
    blocked = blocklist.generate_all()
    return {"ok": True, "added": added, "auto_allowed": applied, "blocked_count": blocked["count"]}


@router.delete("/brands/{brand}/{domain}")
def remove_brand_official(brand: str, domain: str):
    if not store.remove_brand_official(brand, domain):
        raise HTTPException(404, "映射不存在")
    return {"ok": True}


@router.post("/false-positive-cleanup")
def false_positive_cleanup(body: dict):
    """误报一键三连：回滚 + 加白 + 重新生成封堵产物。"""
    domain = (body.get("domain") or "").strip().lower()
    if not domain:
        raise HTTPException(400, "域名不能为空")
    if not intel.feedback(domain, "false_positive", body.get("note") or "平台误报处置"):
        raise HTTPException(404, "记录不存在")
    store.add_whitelist([domain], note=body.get("note") or "误报一键处置", source="feedback")
    blocked = blocklist.generate_all()
    return {"ok": True, "blocked_count": blocked["count"]}


# ---------------- P2 训练数据导出（专家模型微调语料） ----------------

@router.get("/training/export")
def training_export():
    """导出人工复核沉淀的判例（JSONL）：裁决材料摘要 + 人工终审，供小模型微调。"""
    import json as _json
    from fastapi.responses import Response
    lines = []
    for e in intel.list_exemplars(limit=100):
        lines.append(_json.dumps({
            "domain": e["domain"],
            "page_title": e["page_title"],
            "brand_claimed": e["brand"],
            "download_links": e["download_links"],
            "ai_verdict": e["ai_verdict"],
            "human_verdict": e["human_verdict"],
            "human_note": e["human_note"],
        }, ensure_ascii=False))
    body = "\n".join(lines)
    return Response(body, media_type="application/x-ndjson",
                    headers={"Content-Disposition": "attachment; filename=sfn_training_pairs.jsonl"})


@router.get("/training/stats")
def training_stats():
    """人机一致率 + 范例库规模（P2 调优效果度量）。"""
    from fishingnet.models import MALICIOUS_VERDICTS  # noqa: F401
    from fishingnet import intel as _intel
    ex = _intel.list_exemplars(limit=100)
    return {**_intel.agreement_stats(), "exemplars": len(ex)}
