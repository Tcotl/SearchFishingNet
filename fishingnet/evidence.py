"""L2 动态取证：Playwright 无害化访问候选站点，采集裁决材料。

护栏：禁下载、仅 http/https、单页超时熔断、截图与正文落盘 data/evidence/。
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from datetime import datetime
from urllib.parse import urlparse

from . import config
from .browser import launch_kwargs
from .keywords import registrable_domain
from .models import Evidence


def _safe_url(url: str) -> str | None:
    try:
        p = urlparse(url)
    except Exception:
        return None
    if p.scheme not in ("http", "https") or not p.netloc:
        return None
    return url


async def _collect(domain: str, url: str, screenshot_path: str) -> Evidence:
    ev = Evidence(domain=domain)
    from playwright.async_api import async_playwright

    pw = await async_playwright().start()
    try:
        browser = await pw.chromium.launch(**launch_kwargs())
        ctx = await browser.new_context(
            viewport={"width": config.SCREENSHOT_W, "height": config.SCREENSHOT_H},
            user_agent=("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
            locale="zh-CN",
            timezone_id="Asia/Shanghai",
            ignore_https_errors=True,
        )
        # 护栏：拒绝下载
        ctx.set_default_navigation_timeout(config.EVIDENCE_TIMEOUT * 1000)
        page = await ctx.new_page()

        def _deny_download(dl):
            asyncio.ensure_future(dl.cancel())

        page.on("download", _deny_download)

        try:
            resp = await page.goto(url, wait_until="domcontentloaded", timeout=config.EVIDENCE_TIMEOUT * 1000)
            ev.http_status = resp.status if resp else None
        except Exception as e:
            ev.error = f"goto: {str(e)[:150]}"
            return ev

        # 渲染等待（自适应，非 networkidle 避免长挂）
        try:
            await page.wait_for_load_state("networkidle", timeout=6000)
        except Exception:
            pass
        await asyncio.sleep(1.5)

        ev.final_url = page.url
        ev.page_title = (await page.title() or "").strip()[:300]

        # 正文
        try:
            text = await page.inner_text("body")
            text = re.sub(r"\s+", " ", text).strip()
            ev.text_excerpt = text[: config.EVIDENCE_TEXT_MAX]
        except Exception:
            pass

        # 品牌宣称：页面 title/正文中出现的品牌词（供 AI 核对"宣称品牌 vs 域名归属"）
        try:
            from .keywords import BRAND_TOKENS
            hay = (ev.page_title + " " + ev.text_excerpt[:2000]).lower()
            for brand, tokens in BRAND_TOKENS.items():
                for tok in tokens:
                    if len(tok) >= 2 and tok.lower() in hay:
                        if brand not in ev.brand_mentions:
                            ev.brand_mentions.append(brand)
                        break
            ev.brand_mentions = ev.brand_mentions[:8]
        except Exception:
            pass

        # 下载链路分析：下载按钮/安装包链接指向哪里（投毒站强特征）
        try:
            from .keywords import NETDISK_PATTERNS
            anchors = await page.eval_on_selector_all(
                "a[href]",
                "els => els.map(e => ({href: e.href, text: (e.innerText||'').trim().slice(0,60)}))")
            dl_pat = re.compile(r"\.(exe|msi|zip|rar|7z|dmg|apk|gz|bat|scr)([?#].*)?$", re.I)
            base_host = urlparse(ev.final_url or url).netloc.lower().removeprefix("www.")
            seen: set[str] = set()
            for a in anchors or []:
                href = a.get("href") or ""
                label = a.get("text") or ""
                if not href.startswith("http"):
                    continue
                is_file = bool(dl_pat.search(href.split("#")[0]))
                is_dl_text = ("下载" in label) or (label.lower() in ("download", "local download", "high-speed download"))
                if not (is_file or is_dl_text):
                    continue
                host = urlparse(href).netloc.lower().removeprefix("www.")
                if not host:
                    continue
                key = href.split("#")[0]
                if key in seen:
                    continue
                seen.add(key)
                # 站外判定按注册域对比：downloads.surfshark.com 与 surfshark.com
                # 是同站的官方 CDN 子域，不应误标"站外主机"误导 AI 严判
                ev.download_links.append({
                    "url": href[:300],
                    "text": label[:60],
                    "host": host,
                    "netdisk": any(p in host for p in NETDISK_PATTERNS),
                    "offsite": registrable_domain(host) != registrable_domain(base_host),
                })
                if len(ev.download_links) >= 12:
                    break
        except Exception:
            pass

        # 表单字段（钓鱼登录框信号）
        try:
            fields = await page.eval_on_selector_all(
                "input", "els => els.map(e => ({type: e.type, name: e.name, placeholder: e.placeholder}))")
            ev.form_fields = [
                {"type": f.get("type"), "name": (f.get("name") or "")[:40],
                 "placeholder": (f.get("placeholder") or "")[:60]}
                for f in (fields or []) if f.get("type") in ("text", "password", "tel", "email")
            ][:20]
        except Exception:
            pass

        # 外链
        try:
            links = await page.eval_on_selector_all(
                "a[href]", "els => els.map(e => e.href).filter(h => h.startsWith('http'))")
            ev.external_links = list(dict.fromkeys(links))[:30]
        except Exception:
            pass

        # favicon hash（同类站聚类用）
        try:
            fav_resp = await ctx.request.get(urlparse(ev.final_url or url)._replace(path="/favicon.ico").geturl(),
                                             timeout=8000, fail_on_status_code=False)
            if fav_resp.ok:
                ev.favicon_sha1 = hashlib.sha1(await fav_resp.body()).hexdigest()
        except Exception:
            pass

        # 截图
        try:
            await page.screenshot(path=screenshot_path, full_page=False)
            ev.screenshot_path = screenshot_path
        except Exception:
            pass

        ev.ok = True
        return ev
    finally:
        try:
            await pw.stop()
        except Exception:
            pass


def collect(domain: str, url: str = "") -> Evidence:
    """同步入口：取证一个域名。url 缺省时尝试 https://domain。"""
    target = _safe_url(url) or _safe_url(f"https://{domain}")
    if not target:
        return Evidence(domain=domain, error="invalid url")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    shot_dir = config.EVIDENCE_DIR / domain
    shot_dir.mkdir(parents=True, exist_ok=True)
    shot = str(shot_dir / f"{ts}.png")
    try:
        return asyncio.run(_collect(domain, target, shot))
    except Exception as e:
        return Evidence(domain=domain, error=f"collect failed: {str(e)[:150]}")
