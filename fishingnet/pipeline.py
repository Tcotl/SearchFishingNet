"""流水线编排：采集(JSON/关键词) → L1 评分 → L2 取证 → L3 AI 严判 → 情报落库 → 封堵产物。"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

from . import ai_judge, blocklist, config, intel, scoring
from .evidence import collect
from .keywords import KEYWORDS
from .models import (D_ALLOWED, D_AUTO_BLOCK, D_MONITOR, D_POLICY_BLOCK, D_REVIEW,
                     MALICIOUS_VERDICTS, SearchHit, ThreatRecord, V_BRAND_ABUSE)

# ---------------- 采集：解析现有爬虫输出 ----------------


def parse_crawler_json(path: str | Path) -> list[SearchHit]:
    """解析 Browser Web Crawler 的 unified_search_results_*.json（防御式解析）。"""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    keyword = (data.get("metadata") or {}).get("keyword", Path(path).stem)
    results = data.get("results") or {}
    hits: list[SearchHit] = []
    for engine, items in results.items():
        if not isinstance(items, list):
            continue
        for i, item in enumerate(items):
            if not isinstance(item, dict):
                continue
            url = item.get("url") or ""
            domain = (item.get("domain") or "").strip()
            if not domain and url:
                try:
                    domain = urlparse(url).netloc.replace("www.", "", 1)
                except Exception:
                    domain = ""
            if not domain:
                continue
            hits.append(SearchHit(
                keyword=keyword, engine=engine, rank=int(item.get("rank") or i + 1),
                title=(item.get("title") or "").strip(),
                url=url, domain=domain,
                description=(item.get("description") or "").strip(),
                display_url=(item.get("display_url") or "").strip()))
    return hits


def parse_domains_txt(path: str | Path, keyword: str = "unknown") -> list[SearchHit]:
    hits = []
    for i, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines()):
        d = line.strip()
        if d and not d.startswith("#"):
            hits.append(SearchHit(keyword=keyword, engine="txt", rank=i + 1, domain=d))
    return hits


def parse_input(path: str | Path) -> list[SearchHit]:
    p = Path(path)
    if p.suffix == ".txt":
        return parse_domains_txt(p)
    return parse_crawler_json(p)


# ---------------- 研判主流程 ----------------


def process(hits: list[SearchHit], mock_ai: bool = False,
            skip_evidence: bool = False, quiet: bool = False,
            progress: Callable[[str], None] | None = None) -> dict:

    def log(msg: str) -> None:
        if progress is not None:
            progress(msg)
        if not quiet:
            print(msg)

    # 合并去重：同域名保留全部命中语境
    by_domain: dict[str, list[SearchHit]] = {}
    for h in hits:
        by_domain.setdefault(h.domain, []).append(h)
    log(f"输入: {len(hits)} 条命中, 去重后 {len(by_domain)} 个域名")

    stats = {"total": len(by_domain), "trusted": 0, "policy": 0, "judged": 0, "blocked": 0,
             "monitor": 0, "review": 0, "allowed": 0, "no_ai": 0}
    records: list[ThreatRecord] = []

    for domain, dhits in sorted(by_domain.items()):
        rs = scoring.score_domain(domain, dhits[0].url)
        log(f"\n[{domain}] L1 评分: {rs.score} ({rs.tier})")
        for b in rs.breakdown:
            log(f"    - {b.factor}: {b.detail} ({b.delta:+d})")

        if rs.tier == "trusted":
            stats["trusted"] += 1
            rec = ThreatRecord(domain=domain, hits=[h.to_dict() for h in dhits],
                               rule_score=rs.to_dict(), final="benign", disposition=D_ALLOWED)
            records.append(rec)
            intel.upsert_record(rec)
            continue

        # 严格下载管控：已知第三方下载站不做研判，直接策略封堵（企业场景默认只放行官方下载渠道）
        if config.STRICT_DOWNLOAD_POLICY and scoring.download_channel_check(domain)[0] == "known":
            stats["policy"] += 1
            log("    → 策略封堵（严格下载管控：非官方下载渠道，默认可能内置木马）")
            rec = ThreatRecord(domain=domain, hits=[h.to_dict() for h in dhits],
                               rule_score=rs.to_dict(), final="policy", disposition=D_POLICY_BLOCK)
            records.append(rec)
            intel.upsert_record(rec)
            continue

        # L2 动态取证（高危/可疑才取证）
        stats["judged"] += 1
        if skip_evidence:
            ev = None
        else:
            log(f"    L2 取证中({dhits[0].url or 'https://' + domain})...")
            ev = collect(domain, dhits[0].url)
            if ev.ok:
                log(f"    取证成功: {ev.page_title[:50] or '(无标题)'}")
            else:
                log(f"    取证失败: {ev.error}")

        # L3 AI 严判
        verdict = ai_judge.judge(domain, rs, ev, [h.to_dict() for h in dhits], mock=mock_ai)
        rec = ThreatRecord(domain=domain, hits=[h.to_dict() for h in dhits],
                           rule_score=rs.to_dict(),
                           evidence=ev.to_dict() if ev else None)
        if verdict is None:
            # 未接入 AI：降级 pending_review，绝不自动封堵
            stats["no_ai"] += 1
            stats["review"] += 1
            rec.final = "review"
            rec.disposition = D_REVIEW
            log("    L3 未接入 AI → pending_review")
        else:
            rec.ai_verdict = verdict.to_dict()
            log(f"    L3 裁决: {verdict.verdict} 置信度 {verdict.confidence} [{verdict.channel}]")
            for e in verdict.evidence[:3]:
                log(f"      · {e[:80]}")
            if verdict.verdict in MALICIOUS_VERDICTS and verdict.confidence >= config.AI_BLOCK_CONFIDENCE:
                stats["blocked"] += 1
                rec.final = "malicious"
                rec.disposition = D_AUTO_BLOCK
                log("    → 自动封堵候选")
            elif verdict.verdict == V_BRAND_ABUSE:
                stats["monitor"] += 1
                rec.final = "monitor"
                rec.disposition = D_MONITOR
            elif verdict.verdict in ("benign", "unrelated"):
                stats["allowed"] += 1
                rec.final = "benign"
                rec.disposition = D_ALLOWED
            else:
                stats["review"] += 1
                rec.final = "review"
                rec.disposition = D_REVIEW
        records.append(rec)
        intel.upsert_record(rec)

    intel.log_run("pipeline", stats)
    blocked = blocklist.generate_all()
    report_path = blocklist.write_report(stats, blocked)
    return {"stats": stats, "blocked": blocked, "records": records, "report": report_path}


# ---------------- 存量重评分 ----------------


def rescore(progress: Callable[[str], None] | None = None) -> dict:
    """用当前评分模型重算所有存量记录的 L1 分数，并执行严格下载管控策略。

    - 只刷新 rule_score 展示，不改变 AI 裁决结论；
    - 严格模式下对已知第三方下载站执行策略封堵（仅限 active 状态，人工误报回滚的不再动）。
    """
    def log(msg: str) -> None:
        if progress is not None:
            progress(msg)
        print(msg)

    records = intel.list_records()
    log(f"[Rescore] 开始重评分，共 {len(records)} 条记录")
    changed = {"trusted→watch": 0, "other": 0}
    policy_applied = 0
    for rec in records:
        domain = rec.get("domain") or ""
        if not domain:
            continue
        url = ((rec.get("hits") or [{}])[0].get("url")) or ""
        rs = scoring.score_domain(domain, url)
        old = (rec.get("score") or {}).get("score")
        intel.update_rule_score(domain, rs.to_dict())
        if old is not None and old >= 70 and rs.score < 70:
            changed["trusted→watch"] += 1
            log(f"  {domain}: {old} → {rs.score} ({rs.tier}) ↓")
        else:
            changed["other"] += 1
            log(f"  {domain}: {old if old is not None else '-'} → {rs.score} ({rs.tier})")

        # 严格下载管控：策略封堵已知第三方下载站（不覆盖已有 AI 裁决处置与人工误报回滚）
        if config.STRICT_DOWNLOAD_POLICY and rec.get("status") == "active" \
                and rec.get("disposition") not in (D_AUTO_BLOCK, D_POLICY_BLOCK) \
                and scoring.download_channel_check(domain)[0] == "known":
            intel.set_disposition(domain, "policy", D_POLICY_BLOCK,
                                  "严格下载管控：非官方下载渠道策略封堵")
            policy_applied += 1
            log(f"  {domain}: → 策略封堵（非官方下载渠道）")
    blocklist.generate_all()
    return {"total": len(records), **changed, "policy_blocked": policy_applied}


# ---------------- 关键词采集（调用现有爬虫） ----------------


def crawl(keywords: list[str] | None = None,
          max_pages: int = 3, max_results: int = 20,
          progress: Callable[[str], None] | None = None) -> list[Path]:
    """调用现有 Browser Web Crawler 采集（四引擎顺序执行）。返回生成的 JSON 文件列表。

    子进程优先使用爬虫自带 venv（其 playwright 浏览器已就绪），实时回传 stdout 进度。
    """
    import subprocess
    import sys

    def log(msg: str) -> None:
        if progress is not None:
            progress(msg)
        print(msg)

    crawler_dir = config.PROJECT_ROOT / "Browser Web Crawler"
    script = crawler_dir / "Search_Crawler.py"
    venv_python = crawler_dir / ".venv" / "bin" / "python"
    python = str(venv_python) if venv_python.exists() else sys.executable
    kws = keywords or KEYWORDS
    outputs: list[Path] = []
    for kw in kws:
        cmd = [python, str(script), kw, "--max-pages", str(max_pages),
               "--max-results", str(max_results)]
        log(f"采集: {kw} ...")
        try:
            proc = subprocess.Popen(cmd, cwd=str(crawler_dir),
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, errors="ignore", bufsize=1)
            assert proc.stdout is not None
            for line in proc.stdout:
                log(line.rstrip())
            proc.wait(timeout=None)
        except subprocess.TimeoutExpired:
            log(f"  {kw} 采集超时，继续下一个")
        except Exception as e:
            log(f"  {kw} 采集异常: {e}")
        out = crawler_dir / f"unified_search_results_{re.sub(r'[^\w\s-]', '_', kw)}.json"
        if out.exists():
            outputs.append(out)
    return outputs
