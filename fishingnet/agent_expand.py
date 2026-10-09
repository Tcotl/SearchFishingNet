"""P1 联网 Agent 扩展采集：SEO 头部结果之外的第二采集曲线。

- AI 关键词变体扩展：把"钉钉下载"扩成真实用户会搜的长尾（含英文/安装包名/
  破解词等 GEO 投毒常见定向）；主判模型即可胜任（免费小模型亦可）。
- DuckDuckGo HTML 免费引擎：无需 Key、无需浏览器，四引擎爬虫（易风控）之外的
  低成本补充；适度频率（每次请求间隔 ≥1.5s）。
- 产出统一 SearchHit，直接喂 pipeline.process 走既有研判漏斗（评分→取证→严判）。
"""

from __future__ import annotations

import random
import re
import time
import urllib.parse
import urllib.request

from . import ai_client, config
from .models import SearchHit

_DDG_URL = "https://html.duckduckgo.com/html/"
_BING_URL = "https://cn.bing.com/search?"
_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")
_last_hit = 0.0


def _throttle():
    global _last_hit
    wait = 1.5 - (time.time() - _last_hit)
    if wait > 0:
        time.sleep(wait)
    _last_hit = time.time()


def _fetch_html(url: str, data: bytes | None = None) -> str:
    req = urllib.request.Request(url, data=data, headers={
        "User-Agent": _UA, "Accept": "text/html",
        "Accept-Language": "zh-CN,zh;q=0.9"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.read().decode("utf-8", "ignore")


def _strip_tags(s: str) -> str:
    return re.sub(r"<[^>]+>", "", s)


def _decode_bing_redirect(href: str) -> str:
    """Bing /ck/a 跳转链接的 u=a1<base64url> 参数还原为真实 URL。"""
    m = re.search(r'[?&]u=a1([^&]+)', href)
    if not m:
        return href
    try:
        b64 = m.group(1).replace("-", "+").replace("_", "/")
        b64 += "=" * (-len(b64) % 4)
        import base64
        return base64.b64decode(b64).decode("utf-8", "ignore")
    except Exception:
        return ""


def bing_cn_search(query: str, max_results: int = 12) -> list[SearchHit]:
    """必应中国 HTML 检索（免 Key 免浏览器）。失败返回空表。"""
    _throttle()
    try:
        html = _fetch_html(_BING_URL + urllib.parse.urlencode(
            {"q": query, "count": str(min(max_results, 20)), "setlang": "zh-hans"}))
    except Exception:
        return []
    hits: list[SearchHit] = []
    seen: set[str] = set()
    for m in re.finditer(r'<h2[^>]*><a[^>]+href="([^"]+)"[^>]*>(.*?)</a></h2>', html, re.S):
        href, title = m.group(1), _strip_tags(m.group(2)).strip()
        url = href if href.startswith("http") else _decode_bing_redirect(href)
        if not url.startswith("http") or "bing.com" in url:
            continue
        host = urllib.parse.urlparse(url).netloc.lower().removeprefix("www.")
        if not host or host in seen:
            continue
        seen.add(host)
        hits.append(SearchHit(keyword=query, engine="bing", rank=len(hits) + 1,
                              title=title[:120], url=url, domain=host))
        if len(hits) >= max_results:
            break
    return hits


def ddg_search(query: str, max_results: int = 12) -> list[SearchHit]:
    """DuckDuckGo HTML 检索（备选，风控较严）。失败返回空表。"""
    _throttle()
    try:
        html = _fetch_html(_DDG_URL, data=urllib.parse.urlencode(
            {"q": query, "kl": "cn-zh"}).encode())
    except Exception:
        return []
    hits: list[SearchHit] = []
    seen_domains: set[str] = set()
    for m in re.finditer(r'uddg=([^"&]+)', html):
        url = urllib.parse.unquote(m.group(1))
        if not url.startswith("http"):
            continue
        host = urllib.parse.urlparse(url).netloc.lower().removeprefix("www.")
        if not host or host in seen_domains or "duckduckgo" in host:
            continue
        seen_domains.add(host)
        hits.append(SearchHit(keyword=query, engine="ddg", rank=len(hits) + 1,
                              url=url, domain=host))
        if len(hits) >= max_results:
            break
    return hits


def free_search(query: str, max_results: int = 12) -> list[SearchHit]:
    """免费引擎检索：必应中国优先，DDG 兜底。"""
    hits = bing_cn_search(query, max_results)
    return hits or ddg_search(query, max_results)


_VARIANT_PROMPT = """你是搜索查询扩展器。针对给定的"软件+下载"类中文搜索词，生成 {n} 个中国用户真实会搜的变体查询，覆盖：官方下载、直接安装包名（如 xxxsetup.exe）、英文站、"破解/激活"（黑产常用来投毒的词）、版本号词（如 2026 最新版）、绿色版/离线安装包。

要求：每行一个查询，不要编号、不要解释、不要重复原词本身。"""


def expand_keywords(seed: str, n: int = 8) -> list[str]:
    """AI 生成搜索变体；失败时退化为规则后缀变体。"""
    variants: list[str] = []
    if config.AI_API_KEY:
        try:
            raw = ai_client.ask(f"搜索词：{seed}", _VARIANT_PROMPT.format(n=n))
            for line in raw.splitlines():
                v = line.strip().lstrip("0123456789.-、) ").strip()
                if v and 4 <= len(v) <= 40 and v != seed and v not in variants:
                    variants.append(v)
        except Exception:
            pass
    if not variants:  # 无 AI 时规则兜底
        variants = [f"{seed} 官网", f"{seed} exe", f"{seed} 绿色版",
                    f"{seed} 离线安装包", f"{seed} 最新版下载"]
    return variants[:n]


def discover(seed_keywords: list[str], variants_per_kw: int = 4,
             max_results_per_query: int = 10,
             progress=None) -> dict:
    """扩展采集主流程：变体扩展 → DDG 检索 → 去重后的 SearchHit 列表。"""
    def log(msg: str):
        if progress:
            progress(msg)

    queries: list[str] = []
    for kw in seed_keywords:
        vs = expand_keywords(kw, variants_per_kw)
        queries.append(kw)
        queries.extend(vs)
        log(f"[Agent] {kw} → +{len(vs)} 变体")
    queries = list(dict.fromkeys(queries))

    hits: list[SearchHit] = []
    seen_domains: set[str] = set()
    ok_q = fail_q = 0
    for i, q in enumerate(queries):
        log(f"[Agent] ({i + 1}/{len(queries)}) 免费引擎: {q}")
        found = free_search(q, max_results_per_query)
        if not found:
            fail_q += 1
            continue
        ok_q += 1
        new = 0
        for h in found:
            if h.domain in seen_domains:
                continue
            seen_domains.add(h.domain)
            hits.append(h)
            new += 1
        log(f"[Agent]   → {len(found)} 结果，新增域名 {new}")
    return {"queries": len(queries), "ok_queries": ok_q, "failed_queries": fail_q,
            "domains": len(seen_domains), "hits": hits}
