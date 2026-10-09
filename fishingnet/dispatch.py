"""P3 设备接管：AI 研判结果 → 封堵工单 → 直接下发防火墙/DNS。

- 通用 webhook：POST {action:"block", domains:[...]}，适配任意能收 JSON 的
  防火墙/SOAR/DNS 网关；
- AdGuard Home 适配器：登录控制 API 后添加对平台封堵列表 TXT 的订阅
  （||domain^ 规则由 AdGuard 按订阅自动维护）。

二者均为尽力而为：任一失败不影响另一个，错误信息带回调用方展示。
"""

from __future__ import annotations

import http.cookiejar
import json
import time
import urllib.request

from . import config


def _post_json(url: str, payload: dict, headers: dict | None = None,
               opener: urllib.request.OpenerDirector | None = None,
               timeout: int = 20) -> tuple[bool, str]:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with (opener or urllib.request.build_opener()).open(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "ignore")[:200]
            return 200 <= resp.status < 300, body or "ok"
    except Exception as e:
        return False, str(e)[:150]


def dispatch_webhook(domains: list[str]) -> dict | None:
    """通用封堵 webhook。未配置返回 None。"""
    if not config.BLOCK_WEBHOOK_URL:
        return None
    payload = {"action": "block", "source": "SearchFishingNet",
               "generated_at": int(time.time()), "count": len(domains), "domains": domains}
    ok, msg = _post_json(config.BLOCK_WEBHOOK_URL, payload)
    return {"ok": ok, "detail": msg}


def dispatch_adguard() -> dict | None:
    """AdGuard Home：登录控制 API 并订阅平台封堵列表。未配置返回 None。"""
    if not (config.ADGUARD_URL and config.ADGUARD_BLOCKLIST_URL):
        return None
    base = config.ADGUARD_URL.rstrip("/")
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    ok, msg = _post_json(f"{base}/control/login",
                         {"name": config.ADGUARD_USER, "password": config.ADGUARD_PASS},
                         opener=opener)
    if not ok:
        return {"ok": False, "detail": f"AdGuard 登录失败: {msg}"}
    ok, msg = _post_json(f"{base}/control/filtering/add_url",
                         {"name": "SearchFishingNet 封堵列表",
                          "url": config.ADGUARD_BLOCKLIST_URL, "whitelist": False},
                         opener=opener)
    # 已存在同 URL 订阅时 AdGuard 返回 400，视为成功（幂等）
    if not ok and "already" in msg.lower():
        ok, msg = True, "订阅已存在"
    return {"ok": ok, "detail": msg or "ok"}


def dispatch(domains: list[str]) -> dict:
    """下发到所有已配置渠道。返回 {渠道: {ok, detail}}。"""
    out: dict = {}
    if config.BLOCK_WEBHOOK_URL:
        out["webhook"] = dispatch_webhook(domains) or {}
    if config.ADGUARD_URL:
        out["adguard"] = dispatch_adguard() or {}
    if not out:
        out["none"] = {"ok": False, "detail": "未配置任何下发渠道（设置页 → 设备接管）"}
    return out
