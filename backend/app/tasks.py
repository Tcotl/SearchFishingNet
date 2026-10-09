"""任务执行体：把 fishingnet 核心能力包装为可在工作线程运行的任务函数。"""

from __future__ import annotations

import json
import random
import re
import time
import traceback
from pathlib import Path

from fishingnet import ai_judge, blocklist, config as core_config, intel, pipeline, scoring
from fishingnet import facts as facts_mod
from fishingnet.evidence import collect
from fishingnet.models import SearchHit, ThreatRecord

from .jobs import Job
from . import store
from .store import get_keywords


def _result_stats(result: dict) -> dict:
    return {
        "stats": result.get("stats"),
        "blocked_count": result.get("blocked", {}).get("count"),
        "blocked_domains": result.get("blocked", {}).get("domains"),
        "report": result.get("report"),
    }


# ---------------- 任务实现 ----------------


def run_crawl(job: Job) -> dict:
    keywords = job.params.get("keywords") or get_keywords()
    outputs = pipeline.crawl(
        keywords=keywords,
        max_pages=int(job.params.get("max_pages", 3)),
        max_results=int(job.params.get("max_results", 20)),
        progress=lambda m: manager_log(job, m),
    )
    return {"outputs": [str(p) for p in outputs], "keywords": keywords}


def run_ingest(job: Job) -> dict:
    path = job.params["file"]
    hits = pipeline.parse_input(path)
    if not hits:
        raise ValueError(f"未能从 {path} 解析到任何命中")
    result = pipeline.process(
        hits,
        mock_ai=bool(job.params.get("mock_ai", False)),
        skip_evidence=bool(job.params.get("skip_evidence", False)),
        quiet=True,
        progress=lambda m: manager_log(job, m),
    )
    return _result_stats(result)


def run_pipeline_job(job: Job) -> dict:
    """采集 + 研判 一体任务。resume 模式跳过 24 小时内已采集的关键词（断点续跑）。"""
    import re as _re
    import time as _time

    keywords = job.params.get("keywords") or get_keywords()
    resume = bool(job.params.get("resume", False))
    crawler_dir = core_config.PROJECT_ROOT / "Browser Web Crawler"
    now = _time.time()

    fresh_files: list[Path] = []
    todo: list[str] = []
    if resume:
        for kw in keywords:
            p = crawler_dir / f"unified_search_results_{_re.sub(r'[^\w\s-]', '_', kw)}.json"
            if p.exists() and now - p.stat().st_mtime < 86400:
                fresh_files.append(p)
            else:
                todo.append(kw)
        manager_log(job, f"[Pipeline] 续跑模式：{len(fresh_files)} 个关键词已有 24h 内结果（跳过采集），待采集 {len(todo)} 个")
    else:
        todo = list(keywords)

    manager_log(job, f"[Pipeline] 关键词: {keywords}")
    crawled = pipeline.crawl(
        keywords=todo,
        max_pages=int(job.params.get("max_pages", 3)),
        max_results=int(job.params.get("max_results", 20)),
        progress=lambda m: manager_log(job, m),
    )
    outputs = list(dict.fromkeys(fresh_files + crawled))  # 去重保序
    if not outputs:
        raise ValueError("采集未产出结果文件")

    all_hits: list[SearchHit] = []
    for p in outputs:
        manager_log(job, f"[Pipeline] 研判输入: {p.name}")
        all_hits.extend(pipeline.parse_input(p))
    result = pipeline.process(
        all_hits,
        mock_ai=bool(job.params.get("mock_ai", False)),
        skip_evidence=bool(job.params.get("skip_evidence", False)),
        quiet=True,
        progress=lambda m: manager_log(job, m),
    )
    return _result_stats(result)


def run_judge(job: Job) -> dict:
    domain = job.params["domain"].strip().lower()
    manager_log(job, f"[Judge] 单域研判: {domain}")
    hit = SearchHit(keyword="platform", engine="platform", rank=1,
                    url=f"https://{domain}", domain=domain)
    rs = scoring.score_domain(domain, hit.url)
    for b in rs.breakdown:
        manager_log(job, f"  L1 {b.factor}: {b.detail} ({b.delta:+d})")
    manager_log(job, f"  L1 总分: {rs.score} ({rs.tier})")

    if rs.tier == "trusted":
        rec = ThreatRecord(domain=domain, hits=[hit.to_dict()], rule_score=rs.to_dict(),
                           final="benign", disposition="allowed")
        intel.upsert_record(rec)
        blocklist.generate_all()
        return {"domain": domain, "score": rs.score, "tier": rs.tier,
                "final": "benign", "disposition": "allowed"}

    manager_log(job, "  L2 动态取证...")
    ev = collect(domain, hit.url)
    manager_log(job, f"  L2 完成: ok={ev.ok} title={ev.page_title[:50]!r}")

    # 硬事实采集（RDAP 免费；ICP/VT 配置 Key 后启用），持久化并进 AI 材料包
    try:
        facts = facts_mod.collect(domain)
        intel.update_facts(domain, facts)
        manager_log(job, f"  硬事实: 注册年龄={((facts.get('rdap') or {}).get('registered') or '未知')}"
                         f"{' ICP' if facts.get('icp') else ''}{' VT' if facts.get('vt') else ''}")
    except Exception as e:
        facts = {}
        manager_log(job, f"  硬事实采集失败(不影响研判): {str(e)[:80]}")

    verdict = ai_judge.judge(domain, rs, ev, [hit.to_dict()],
                             mock=bool(job.params.get("mock_ai", False)), facts=facts)
    rec = ThreatRecord(domain=domain, hits=[hit.to_dict()], rule_score=rs.to_dict(),
                       evidence=ev.to_dict(), ai_verdict=verdict.to_dict() if verdict else None)
    if verdict is None:
        rec.final, rec.disposition = "review", "pending_review"
        manager_log(job, "  L3 未配置 AI → pending_review")
    else:
        rec.ai_verdict = verdict.to_dict()
        manager_log(job, f"  L3 裁决: {verdict.verdict}/{verdict.confidence} [{verdict.channel}]")
        if verdict.is_malicious and verdict.confidence >= core_config.AI_BLOCK_CONFIDENCE:
            rec.final, rec.disposition = "malicious", "auto_blocked"
        elif verdict.verdict == "brand_abuse":
            rec.final, rec.disposition = "monitor", "monitored"
        elif verdict.verdict in ("benign", "unrelated"):
            rec.final, rec.disposition = "benign", "allowed"
        else:
            rec.final, rec.disposition = "review", "pending_review"
    intel.upsert_record(rec)
    blocklist.generate_all()
    return {
        "domain": domain, "score": rs.score, "tier": rs.tier,
        "final": rec.final, "disposition": rec.disposition,
        "ai": verdict.to_dict() if verdict else None,
        "evidence": ev.to_dict(),
    }


def run_rescore(job: Job) -> dict:
    manager_log(job, "[Rescore] 用当前评分模型重算存量记录")
    result = pipeline.rescore(progress=lambda m: manager_log(job, m))
    # 顺带补齐硬事实：给缺 RDAP 注册年龄的记录补采（免费、进程内缓存）
    patched = 0
    for rec in intel.list_records():
        if rec.get("status") != "active":
            continue
        facts = rec.get("facts") or {}
        if (facts.get("rdap") or {}).get("registered"):
            continue
        try:
            intel.update_facts(rec["domain"], facts_mod.collect(rec["domain"],
                                                                include_vt=False, include_icp=False))
            patched += 1
        except Exception:
            continue
    manager_log(job, f"[Rescore] 硬事实补采: {patched} 条")
    return result


def _ev_from_dict(d: dict | None):
    if not d:
        return None
    from fishingnet.models import Evidence
    ev = Evidence(domain=d.get("domain", ""))
    for f in ("ok", "final_url", "http_status", "page_title", "text_excerpt", "form_fields",
              "external_links", "download_links", "brand_mentions", "favicon_sha1",
              "screenshot_path", "error"):
        if f in d:
            setattr(ev, f, d[f])
    return ev


def _rs_from_dict(d: dict | None):
    from fishingnet.models import RuleScore, ScoreFactor
    d = d or {}
    rs = RuleScore(domain=d.get("domain", ""), score=int(d.get("score", 100)),
                   tier=d.get("tier", "watch"), threat_intel_hit=bool(d.get("threat_intel_hit")))
    for b in d.get("breakdown", []):
        rs.breakdown.append(ScoreFactor(factor=b.get("factor", ""), delta=int(b.get("delta", 0)),
                                        detail=b.get("detail", "")))
    return rs


def run_rejudge_pending(job: Job) -> dict:
    """重判待复核记录：复用已存取证证据（不重新访问），按当前 AI 配置重新裁决。

    用于"先跑采集、后配 AI Key"的场景：配置好后一键把 pending_review 记录全部重新定性。
    4 线程并行裁决（记录间无依赖）；主通道连续不可用时进入 60s 共享冷却窗，
    避免接口/网络异常期把全量记录烧成 Jev 兜底。
    """
    import threading
    from concurrent.futures import ThreadPoolExecutor

    from fishingnet import intel as _intel
    from fishingnet.models import (D_ALLOWED, D_AUTO_BLOCK, D_MONITOR, D_POLICY_BLOCK,
                                   D_REVIEW, MALICIOUS_VERDICTS, V_BRAND_ABUSE)

    records = [r for r in _intel.list_records() if r.get("disposition") == D_REVIEW
               and r.get("status") == "active"]
    manager_log(job, f"[Rejudge] 待复核记录 {len(records)} 条，复用已存证据重新裁决（4 线程）")
    stats = {"total": len(records), "trusted": 0, "blocked": 0, "monitor": 0,
             "review": 0, "allowed": 0, "no_ai": 0}
    lock = threading.Lock()
    net = {"fails": 0, "cooldown_until": 0.0}

    def process(rec: dict) -> None:
        domain = rec.get("domain", "")
        if not domain:
            return
        # 先按当前评分模型重算：词库更新后新命中的官方/白名单域名直接放行，无需 AI
        rs = scoring.score_domain(domain, ((rec.get("hits") or [{}])[0].get("url")) or "")
        if rs.tier == "trusted":
            with lock:
                stats["trusted"] += 1
            manager_log(job, f"  {domain}: 官方/白名单映射命中 → 放行")
            _intel.set_disposition(domain, "benign", D_ALLOWED, note="词库更新后官方映射命中")
            _intel.update_rule_score(domain, rs.to_dict())
            return
        # 冷却窗：网络异常期挂起，恢复后再继续消耗配额
        while time.time() < net["cooldown_until"]:
            time.sleep(5)
        # 硬事实：RDAP 注册年龄（免费、进程内缓存）缺失时补采并持久化
        facts = rec.get("facts") or {}
        if not (facts.get("rdap") or {}).get("registered"):
            try:
                facts = facts_mod.collect(domain, include_vt=False, include_icp=False)
                _intel.update_facts(domain, facts)
            except Exception:
                facts = facts or {}
        ev = _ev_from_dict(rec.get("evidence"))
        verdict = ai_judge.judge(domain, rs, ev, rec.get("hits", []),
                                 mock=bool(job.params.get("mock_ai", False)), facts=facts)
        if verdict is None:
            with lock:
                stats["no_ai"] += 1
            return
        with lock:
            if getattr(verdict, "channel", "") in ("final(接口错误)",
                                                   "final(Jev单通道·主通道不可用)"):
                net["fails"] += 1
                if net["fails"] >= 5:
                    net["cooldown_until"] = time.time() + 60
                    net["fails"] = 0
                    manager_log(job, "  ⚠ 连续 5 条主通道不可用（网络/接口异常），冷却 60s 后继续")
            else:
                net["fails"] = 0
        manager_log(job, f"  {domain}: {verdict.verdict}/{verdict.confidence} [{verdict.channel}]")
        if verdict.is_malicious and verdict.confidence >= core_config.AI_BLOCK_CONFIDENCE:
            with lock:
                stats["blocked"] += 1
            _intel.set_disposition(domain, "malicious", D_AUTO_BLOCK,
                                   note=f"AI 重判：{verdict.verdict}/{verdict.confidence}")
        elif verdict.verdict == V_BRAND_ABUSE:
            with lock:
                stats["monitor"] += 1
            _intel.set_disposition(domain, "monitor", D_MONITOR)
        elif verdict.verdict in ("benign", "unrelated"):
            with lock:
                stats["allowed"] += 1
            _intel.set_disposition(domain, "benign", D_ALLOWED)
        else:
            with lock:
                stats["review"] += 1
        # 裁决与依据写回 payload
        _intel.update_ai_verdict(domain, verdict.to_dict(),
                                 rs.to_dict() if rs else None)

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(process, records))
    blocklist.generate_all()
    # 样本补分析：已入库但未做 AI 行为分析的样本，一并补跑（复用静态报告，不重新下载）
    from fishingnet import ai_sample_analysis as _asa
    pending_samples = [s for s in _intel.list_samples() if s["status"] == "downloaded"]
    if pending_samples:
        manager_log(job, f"[Rejudge] 样本补分析: {len(pending_samples)} 个")
        c2 = 0
        for s in pending_samples:
            full = _intel.get_sample(s["sha256"])
            if not full or not full.get("static_report"):
                continue
            ai_report = _asa.analyze_sample(full, full["static_report"])
            if ai_report:
                _intel.update_sample_analysis(s["sha256"], ai_report)
                c2 += len(ai_report.get("c2_addresses") or [])
                manager_log(job, f"  样本 {s['file_name']}: 风险={ai_report.get('risk_level')} "
                                 f"C2候选={len(ai_report.get('c2_addresses') or [])}")
        stats["samples_analyzed"] = len(pending_samples)
        stats["sample_c2_total"] = c2
    manager_log(job, f"[Rejudge] 完成: {stats}")
    return stats


def run_agent_discover(job: Job) -> dict:
    """P1 联网 Agent 扩展采集：AI 关键词变体 + DuckDuckGo 免费引擎 → 既有研判漏斗。

    params.keywords 缺省时从启用词库随机抽取 5 个；params.max_new_domains 控制
    送入漏斗的新域名上限（默认 30，防止一次跑批过重）。
    """
    from fishingnet import agent_expand

    kws = [k.strip() for k in (job.params.get("keywords") or []) if str(k).strip()]
    if not kws:
        all_kws = store.get_keywords()
        kws = random.sample(all_kws, min(5, len(all_kws)))
    max_new = int(job.params.get("max_new_domains") or 30)
    manager_log(job, f"[Agent] 种子词 {len(kws)} 个: {kws}")

    result = agent_expand.discover(kws,
                                   variants_per_kw=int(job.params.get("variants_per_kw") or 4),
                                   max_results_per_query=int(job.params.get("max_results_per_query") or 10),
                                   progress=lambda m: manager_log(job, m))
    hits = result.pop("hits")
    manager_log(job, f"[Agent] 采集完成: {result}")

    # 只送新域名进漏斗（已入库的直接跳过）
    known = {r.get("domain") for r in intel.list_records()}
    fresh = [h for h in hits if h.domain not in known][:max_new]
    skipped = len(hits) - len(fresh)
    manager_log(job, f"[Agent] 新域名 {len(fresh)} 个入库研判（库内重复跳过 {skipped}）")
    if not fresh:
        return {**result, "new_domains": 0, "skipped_known": skipped, "stats": {}}
    stats = pipeline.process(fresh, skip_evidence=bool(job.params.get("skip_evidence", False)),
                             progress=lambda m: manager_log(job, m))["stats"]
    return {**result, "new_domains": len(fresh), "skipped_known": skipped, "stats": stats}


def run_dispatch_block(job: Job) -> dict:
    """P3 设备接管：把当前封堵列表下发到已配置渠道（webhook / AdGuard Home）。

    params.domains 缺省 = 全部 active 封堵（auto_blocked + policy_blocked）。
    """
    from fishingnet import blocklist as _blocklist, dispatch as _dispatch

    domains = [str(d).strip().lower() for d in (job.params.get("domains") or []) if str(d).strip()]
    if not domains:
        domains = sorted({r["domain"] for r in intel.active_blocked()})
    manager_log(job, f"[Dispatch] 封堵工单 {len(domains)} 个域名，下发渠道下发中...")
    results = _dispatch.dispatch(domains)
    for ch, r in results.items():
        manager_log(job, f"  {ch}: {'✓' if r.get('ok') else '✗'} {str(r.get('detail'))[:120]}")
    ok = all(r.get("ok") for r in results.values())
    return {"domains": len(domains), "channels": results, "ok": ok}


def run_sample_analyze(job: Job) -> dict:
    """AI 行为分析指定样本（params.sha256）；缺省分析全部 downloaded 状态样本。

    供人工上传样本后即时触发，也可独立补跑未分析样本（与 rejudge 的样本补分析同源）。
    """
    from fishingnet import ai_sample_analysis as _asa

    sha = (job.params.get("sha256") or "").strip().lower()
    if sha:
        if not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise ValueError("非法 sha256")
        if not intel.get_sample(sha):
            raise ValueError(f"样本不存在: {sha[:16]}…")
        targets = [sha]
    else:
        targets = [s["sha256"] for s in intel.list_samples() if s["status"] == "downloaded"]
    manager_log(job, f"[SampleAnalyze] 待分析样本 {len(targets)} 个")
    stats = {"analyzed": 0, "skipped": 0, "c2_total": 0}
    for s_sha in targets:
        full = intel.get_sample(s_sha)
        if not full or not full.get("static_report"):
            stats["skipped"] += 1
            continue
        ai_report = _asa.analyze_sample(full, full["static_report"])
        if ai_report:
            intel.update_sample_analysis(s_sha, ai_report)
            c2 = len(ai_report.get("c2_addresses") or [])
            stats["analyzed"] += 1
            stats["c2_total"] += c2
            manager_log(job, f"  ✓ {full['file_name']}: 风险={ai_report.get('risk_level')} "
                             f"C2候选={c2} 家族={ai_report.get('family_guess', '')[:30]}")
        else:
            stats["skipped"] += 1
            manager_log(job, f"  ✗ {full['file_name']}: AI 分析未返回（未配 Key/调用失败），保持待分析")
    manager_log(job, f"[SampleAnalyze] 完成: {stats}")
    return stats


def run_sample_hunt(job: Job) -> dict:
    """样本猎取：从已确认封堵站点下载载荷 → 静态分析 → AI 行为/C2 分析。

    params.domain 缺省时遍历全部 auto_blocked（AI 确认恶意）记录。
    """
    from fishingnet import ai_sample_analysis, intel as _intel, sample_hunter

    domain = (job.params.get("domain") or "").strip().lower()
    if domain:
        rec = next((r for r in _intel.list_records() if r.get("domain") == domain), None)
        if not rec:
            raise ValueError(f"未找到 {domain} 的情报记录")
        if rec.get("disposition") not in ("auto_blocked", "policy_blocked"):
            raise ValueError(f"{domain} 不是已封堵站点（当前处置: {rec.get('disposition')}），拒绝下载")
        targets = [domain]
    else:
        targets = sorted({r["domain"] for r in _intel.active_blocked()
                          if r.get("disposition") == "auto_blocked"})
        if not targets:
            raise ValueError("当前没有 AI 确认恶意（auto_blocked）的站点；可指定单域名（限已封堵）")

    manager_log(job, f"[SampleHunt] 猎取范围: {targets}")
    stats = {"domains": len(targets), "samples": 0, "analyzed": 0, "skipped": 0, "failed": 0, "c2_total": 0}
    for dom in targets:
        rec = next((r for r in _intel.list_records() if r.get("domain") == dom), None)
        urls = sample_hunter.gather_targets(dom)
        if not urls and rec is not None:
            # 存证里没有直链（旧取证或页面无锚点下载）→ 重访站点刷新下载入口
            manager_log(job, f"  {dom}: 存证无直链，重新取证抓取下载入口...")
            from fishingnet.evidence import collect
            ev = collect(dom, ((rec.get("hits") or [{}])[0].get("url")) or f"https://{dom}")
            if ev.ok:
                _intel.update_evidence(dom, ev.to_dict())
                urls = sample_hunter.gather_targets(dom)
        if not urls:
            manager_log(job, f"  {dom}: 无可用下载直链，跳过")
            stats["skipped"] += 1
            continue
        manager_log(job, f"  {dom}: {len(urls)} 个下载入口")
        for u in urls:
            try:
                sample = sample_hunter.download(u, dom)
            except Exception as e:
                stats["failed"] += 1
                manager_log(job, f"    ✗ {u[:80]} → {str(e)[:80]}")
                continue
            static_report = sample.pop("static_report")
            ai_report = ai_sample_analysis.analyze_sample(sample, static_report)
            if ai_report:
                sample["status"] = "analyzed"
            _intel.upsert_sample(sample, static_report, ai_report)
            stats["samples"] += 1
            if ai_report:
                stats["analyzed"] += 1
                stats["c2_total"] += len(ai_report.get("c2_addresses") or [])
                manager_log(job, f"    ✓ {sample['file_name']} sha256={sample['sha256'][:16]}… "
                                 f"风险={ai_report.get('risk_level')} "
                                 f"C2候选={len(ai_report.get('c2_addresses') or [])}")
            else:
                manager_log(job, f"    ✓ {sample['file_name']} 已静态分析入库（AI 未接入，待重分析）")
            break  # 每域名取首个成功载荷即可
    manager_log(job, f"[SampleHunt] 完成: {stats}")
    return stats


def manager_log(job: Job, msg: str) -> None:
    from .jobs import manager
    manager.log(job, msg)


TASK_REGISTRY = {
    "crawl": run_crawl,
    "ingest": run_ingest,
    "pipeline": run_pipeline_job,
    "judge": run_judge,
    "rescore": run_rescore,
    "rejudge_pending": run_rejudge_pending,
    "sample_hunt": run_sample_hunt,
    "sample_analyze": run_sample_analyze,
    "agent_discover": run_agent_discover,
    "dispatch_block": run_dispatch_block,
}


def execute(job: Job) -> None:
    """在工作线程中同步执行任务（供线程池调用）。"""
    from .jobs import manager
    job.status = "running"
    job.started_at = time.time()
    try:
        fn = TASK_REGISTRY.get(job.type)
        if fn is None:
            raise ValueError(f"未知任务类型: {job.type}")
        job.result = fn(job)
        job.status = "success"
    except Exception as e:
        job.status = "failed"
        job.error = f"{e}"
        manager.log(job, f"[异常] {e}")
        manager.log(job, traceback.format_exc()[-1500:])
    finally:
        job.finished_at = time.time()


def resolve_upload(name: str) -> Path:
    """校验并解析上传文件名（防路径穿越）。"""
    p = (core_config.DATA_DIR / "uploads" / Path(name).name).resolve()
    if not p.exists() or core_config.DATA_DIR not in p.parents:
        raise ValueError(f"上传文件不存在: {name}")
    return p


def latest_crawl_output() -> str | None:
    crawler_dir = core_config.PROJECT_ROOT / "Browser Web Crawler"
    files = sorted(crawler_dir.glob("unified_search_results_*.json"), key=lambda p: p.stat().st_mtime)
    return str(files[-1]) if files else None
