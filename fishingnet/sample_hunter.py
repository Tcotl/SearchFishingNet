"""样本猎取与隔离存放。

安全护栏：
- 仅允许对「已确认封堵」的域名取证下载（auto_blocked / 显式指定的封堵记录）；
- 大小上限 / 超时熔断；HTML 响应（网页而非载荷）自动拒绝；
- 样本按 sha256 隔离存放 data/samples/<sha256>/，全流程只做静态分析，绝不在本机执行。
"""

from __future__ import annotations

import json
import re
import urllib.request
from pathlib import Path

from . import config, intel
from .static_analysis import MAX_SAMPLE_SIZE, analyze_bytes

QUARANTINE_DIR = config.DATA_DIR / "samples"


def _safe_filename(url: str) -> str:
    name = url.rstrip("/").split("/")[-1].split("?")[0]
    name = re.sub(r"[^\w.\-()]", "_", name)[:80]
    return name or "sample.bin"


def gather_targets(domain: str) -> list[str]:
    """从域名情报记录的取证数据里收集下载链接（L2 已抓取的下载入口优先）。"""
    rec = next((r for r in intel.list_records() if r.get("domain") == domain), None)
    if not rec:
        return []
    urls: list[str] = []
    ev = rec.get("evidence") or {}
    for d in ev.get("download_links") or []:
        u = d.get("url") or ""
        if d.get("netdisk"):
            continue  # 网盘链接需要登录/验证码，无法直连下载
        if u.startswith("http"):
            urls.append(u)
    if not urls:
        # 兜底：落地页与外链里找安装包后缀
        candidates = [ev.get("final_url") or ""] + (ev.get("external_links") or [])
        urls = [u for u in candidates
                if u and re.search(r"\.(exe|msi|zip|rar|7z|apk)([?#].*)?$", u, re.I)]
    # 本站直链优先
    urls.sort(key=lambda u: domain not in u)
    return list(dict.fromkeys(urls))[:5]


def download(url: str, domain: str) -> dict:
    """下载单个样本到隔离区并完成静态分析。返回样本记录 dict。"""
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SearchFishingNet-SampleHunter/1.0",
    })
    with urllib.request.urlopen(req, timeout=90) as resp:
        ctype = (resp.headers.get("Content-Type") or "").lower()
        first = resp.read(4096)
        if "text/html" in ctype or first.lstrip()[:1] == b"<":
            raise ValueError("响应是网页而非文件载荷")
        data = first + resp.read(MAX_SAMPLE_SIZE - len(first) + 1)
        if len(data) > MAX_SAMPLE_SIZE:
            raise ValueError(f"样本超过大小上限 {MAX_SAMPLE_SIZE // 1024 // 1024}MB")
    if len(data) < 512:
        raise ValueError("文件过小，非有效载荷")

    name = _safe_filename(url)
    report = analyze_bytes(name, data)
    sha = report["file"]["sha256"]
    sample_dir = QUARANTINE_DIR / sha
    sample_dir.mkdir(parents=True, exist_ok=True)
    (sample_dir / name).write_bytes(data)
    (sample_dir / "static_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    return {
        "sha256": sha,
        "md5": report["file"]["md5"],
        "sha1": report["file"]["sha1"],
        "source_domain": domain,
        "source_url": url,
        "file_name": name,
        "size": len(data),
        "ftype": report["file"]["type"],
        "static_report": report,
        "status": "downloaded",
    }
