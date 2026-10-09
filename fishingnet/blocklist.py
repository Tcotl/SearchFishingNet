"""处置层：根据情报库生成各格式封堵产物 + 运营报告。"""

from __future__ import annotations

import json
from datetime import datetime

from . import config, intel


def generate_all() -> dict:
    """从情报库拉取生效封堵域名，生成 hosts / dnsmasq / RPZ / ACL CSV / 工单 JSON / 报告。"""
    records = intel.active_blocked()
    domains = sorted({r["domain"] for r in records if r.get("domain")})
    by_domain = {r["domain"]: r for r in records}
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    bl = config.BLOCKLIST_DIR
    bl.mkdir(parents=True, exist_ok=True)

    hosts = bl / "hosts"
    hosts.write_text(
        "# SearchFishingNet DNS 封堵 - hosts 格式\n"
        f"# 生成时间: {ts} | 域名数: {len(domains)}\n"
        "# 回滚: python run_pipeline.py feedback <domain> false_positive\n\n" +
        "".join(f"0.0.0.0 {d}\n" for d in domains),
        encoding="utf-8")

    dnsmasq = bl / "dnsmasq.conf"
    dnsmasq.write_text(
        f"# SearchFishingNet DNS 封堵 - dnsmasq ({ts})\n" +
        "".join(f"address=/{d}/\n" for d in domains),
        encoding="utf-8")

    rpz = bl / "rpz.zone"
    serial = datetime.now().strftime("%Y%m%d%H")
    rpz.write_text(
        f"$TTL 300\n@ IN SOA localhost. root.localhost. ({serial} 3600 600 86400 300)\n"
        "  NS localhost.\n" +
        "".join(f"{d} CNAME .\n*.{d} CNAME .\n" for d in domains),
        encoding="utf-8")

    acl = bl / "acl_domain.csv"
    acl.write_text("domain,disposition,rule_score,ai_verdict,ai_confidence\n" +
                   "".join(
                       f"{d},auto_blocked,"
                       f"{(by_domain[d].get('score') or {}).get('score', '')},"
                       f"{(by_domain[d].get('ai_verdict') or {}).get('verdict', '')},"
                       f"{(by_domain[d].get('ai_verdict') or {}).get('confidence', '')}\n"
                       for d in domains),
                   encoding="utf-8")

    orders = bl / "block_orders.json"
    orders.write_text(json.dumps({
        "generated_at": ts,
        "count": len(domains),
        "orders": [{"domain": d,
                    "evidence": {"screenshot": (by_domain[d].get("evidence") or {}).get("screenshot_path", ""),
                                 "page_title": (by_domain[d].get("evidence") or {}).get("page_title", "")},
                    "ai_evidence": (by_domain[d].get("ai_verdict") or {}).get("evidence", []),
                    "record_id": by_domain[d].get("id")}
                   for d in domains]},
        ensure_ascii=False, indent=2), encoding="utf-8")

    return {"domains": domains, "dir": str(bl), "count": len(domains)}


def write_report(stats: dict, blocked: dict) -> str:
    """本轮运营报告 data/report.md。"""
    lines = [
        "# SearchFishingNet 运营报告",
        f"\n生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n",
        "## 本轮统计\n",
        f"- 输入域名: {stats.get('total', 0)}",
        f"- 白名单/官方放行: {stats.get('trusted', 0)}",
        f"- 规则评分后进入取证+AI严判: {stats.get('judged', 0)}",
        f"- 确认恶意(自动封堵): {stats.get('blocked', 0)}",
        f"- 蹭品牌(监控): {stats.get('monitor', 0)}",
        f"- 证据不足(人工复核): {stats.get('review', 0)}",
        f"- 判定正常/无关(放行): {stats.get('allowed', 0)}",
        f"- AI 未接入而待复核: {stats.get('no_ai', 0)}",
        "\n## 当前封堵列表\n",
    ]
    if blocked.get("domains"):
        lines += [f"- `{d}`" for d in blocked["domains"]]
    else:
        lines.append("（空）")
    lines.append(f"\n封堵产物目录: {blocked.get('dir', '')}\n")
    path = config.DATA_DIR / "report.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return str(path)
