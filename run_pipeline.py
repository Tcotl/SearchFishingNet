#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SearchFishingNet CLI —— 基于搜索引擎的钓鱼网络威胁情报系统。

用法:
  python run_pipeline.py ingest <爬虫JSON或域名txt> [--mock-ai] [--skip-evidence]
  python run_pipeline.py crawl [关键词...] [--max-pages 3] [--max-results 20]
  python run_pipeline.py crawl-then-judge <关键词> [--mock-ai]
  python run_pipeline.py judge <domain> [--mock-ai]
  python run_pipeline.py report
  python run_pipeline.py feedback <domain> false_positive [--note "..."]
  python run_pipeline.py list [--status pending_review]
"""

from __future__ import annotations

import argparse
import sys

from fishingnet import blocklist, config, intel, pipeline, scoring
from fishingnet.evidence import collect
from fishingnet.keywords import KEYWORDS


def cmd_ingest(args) -> int:
    hits = pipeline.parse_input(args.input)
    if not hits:
        print(f"未能从 {args.input} 解析到任何命中")
        return 1
    result = pipeline.process(hits, mock_ai=args.mock_ai, skip_evidence=args.skip_evidence)
    _print_result(result)
    return 0


def cmd_crawl(args) -> int:
    kws = args.keywords or KEYWORDS
    outputs = pipeline.crawl(kws, max_pages=args.max_pages, max_results=args.max_results)
    if not outputs:
        print("采集未产出任何结果文件")
        return 1
    print(f"\n采集完成，产出 {len(outputs)} 个文件:")
    for p in outputs:
        print(f"  {p}")
    print("\n下一步: python run_pipeline.py ingest <上述JSON路径>")
    return 0


def cmd_crawl_then_judge(args) -> int:
    outputs = pipeline.crawl([args.keyword], max_pages=args.max_pages, max_results=args.max_results)
    if not outputs:
        print("采集未产出结果")
        return 1
    hits = pipeline.parse_input(outputs[0])
    result = pipeline.process(hits, mock_ai=args.mock_ai, skip_evidence=args.skip_evidence)
    _print_result(result)
    return 0


def cmd_judge(args) -> int:
    """单域名研判：评分 → 取证 → AI 严判。"""
    from fishingnet import ai_judge
    from fishingnet.models import SearchHit, ThreatRecord

    domain = args.domain
    hit = SearchHit(keyword="manual", engine="manual", rank=1, url=f"https://{domain}", domain=domain)
    rs = scoring.score_domain(domain, hit.url)
    print(f"L1 评分: {rs.score} ({rs.tier})")
    for b in rs.breakdown:
        print(f"  - {b.factor}: {b.detail} ({b.delta:+d})")
    if rs.tier == "trusted":
        print("→ 官方/白名单域名，放行")
        return 0
    print("L2 取证中...")
    ev = collect(domain, hit.url)
    print(f"  ok={ev.ok} title={ev.page_title[:60]!r} error={ev.error[:80]}")
    verdict = ai_judge.judge(domain, rs, ev, [hit.to_dict()], mock=args.mock_ai)
    if verdict is None:
        print("L3 未配置 SFN_AI_API_KEY，无法 AI 严判")
        return 1
    print(f"L3 裁决: {verdict.verdict} 置信度 {verdict.confidence} [{verdict.channel}]")
    for e in verdict.evidence:
        print(f"  · {e}")
    rec = ThreatRecord(domain=domain, hits=[hit.to_dict()], rule_score=rs.to_dict(),
                       evidence=ev.to_dict(), ai_verdict=verdict.to_dict())
    intel.upsert_record(rec)
    blocklist.generate_all()
    print(f"已落库: data/fishingnet.db ({rec.id})")
    return 0


def cmd_rescore(args) -> int:
    result = pipeline.rescore()
    print(f"\n重评分完成: 共 {result['total']} 条（其中 trusted→watch {result['trusted→watch']} 条）")
    return 0


def cmd_report(args) -> int:
    blocked = blocklist.generate_all()
    stats = {"total": 0, "trusted": 0, "judged": 0, "blocked": blocked["count"],
             "monitor": 0, "review": 0, "allowed": 0, "no_ai": 0}
    path = blocklist.write_report(stats, blocked)
    print(f"封堵域名 {blocked['count']} 个，产物目录: {blocked['dir']}")
    print(f"报告: {path}")
    return 0


def cmd_feedback(args) -> int:
    ok = intel.feedback(args.domain, args.kind, args.note or "")
    if ok:
        blocklist.generate_all()
        print(f"已处理反馈: {args.domain} → {args.kind}，封堵产物已重新生成")
        return 0
    print(f"未找到 {args.domain} 的情报记录")
    return 1


def cmd_list(args) -> int:
    records = intel.list_records(args.status or None)
    if not records:
        print("（无记录）")
        return 0
    print(f"{'域名':<40} {'状态':<15} {'最终':<10} {'规则分':<6} AI裁决")
    print("-" * 100)
    for r in records:
        score = r.get("score") or {}
        ai = r.get("ai_verdict") or {}
        print(f"{r.get('domain', ''):<40} {r.get('status', ''):<15} "
              f"{r.get('final', ''):<10} {score.get('score', ''):<6} "
              f"{ai.get('verdict', '')}/{ai.get('confidence', '')}")
    return 0


def _print_result(result: dict) -> None:
    stats = result["stats"]
    blocked = result["blocked"]
    print("\n" + "=" * 60)
    print("研判完成")
    print("=" * 60)
    print(f"  输入域名:          {stats['total']}")
    print(f"  白名单/官方放行:   {stats['trusted']}")
    print(f"  进入取证+AI严判:   {stats['judged']}")
    print(f"  确认恶意(封堵):    {stats['blocked']}")
    print(f"  蹭品牌(监控):      {stats['monitor']}")
    print(f"  人工复核:          {stats['review']} (其中 AI 未接入 {stats['no_ai']})")
    print(f"  放行:              {stats['allowed']}")
    print(f"  当前封堵域名总数:  {blocked['count']}")
    print(f"  封堵产物:          {blocked['dir']}")
    print(f"  运营报告:          {result['report']}")


def main() -> int:
    parser = argparse.ArgumentParser(prog="run_pipeline",
                                     description="SearchFishingNet 钓鱼网络威胁情报系统")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("ingest", help="消费爬虫JSON/域名txt → 研判流水线")
    p.add_argument("input")
    p.add_argument("--mock-ai", action="store_true", help="离线 mock AI（测试用）")
    p.add_argument("--skip-evidence", action="store_true", help="跳过动态取证（快速跑通）")
    p.set_defaults(func=cmd_ingest)

    p = sub.add_parser("crawl", help="调用现有四引擎爬虫采集关键词")
    p.add_argument("keywords", nargs="*")
    p.add_argument("--max-pages", type=int, default=3)
    p.add_argument("--max-results", type=int, default=20)
    p.set_defaults(func=cmd_crawl)

    p = sub.add_parser("crawl-then-judge", help="采集单个关键词并直接研判")
    p.add_argument("keyword")
    p.add_argument("--max-pages", type=int, default=3)
    p.add_argument("--max-results", type=int, default=20)
    p.add_argument("--mock-ai", action="store_true")
    p.add_argument("--skip-evidence", action="store_true")
    p.set_defaults(func=cmd_crawl_then_judge)

    p = sub.add_parser("judge", help="单域名完整研判")
    p.add_argument("domain")
    p.add_argument("--mock-ai", action="store_true")
    p.set_defaults(func=cmd_judge)

    p = sub.add_parser("rescore", help="评分模型升级后，对存量记录重新计算 L1 分数")
    p.set_defaults(func=cmd_rescore)

    p = sub.add_parser("report", help="重新生成封堵产物与报告")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("feedback", help="运营反馈: false_positive / confirm / allow / confirm_block")
    p.add_argument("domain")
    p.add_argument("kind", choices=["false_positive", "confirm", "allow", "confirm_block"])
    p.add_argument("--note", default="")
    p.set_defaults(func=cmd_feedback)

    p = sub.add_parser("list", help="查看情报记录")
    p.add_argument("--status", default=None)
    p.set_defaults(func=cmd_list)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
