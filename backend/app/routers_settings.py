"""设置 API：AI 接入、阈值、可选情报源、连通性测试。"""

from __future__ import annotations

import json
import urllib.request

from fastapi import APIRouter

from fishingnet import config as core_config

from . import store

router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("")
def get_settings():
    return {
        **store.get_settings(),
        "ai_api_key_set": store.get_settings()["ai_api_key_set"],
        "data_dir": str(core_config.DATA_DIR),
        "project_root": str(core_config.PROJECT_ROOT),
    }


@router.put("")
def put_settings(body: dict):
    store.update_settings(body)
    return store.get_settings()


@router.post("/test-ai")
def test_ai():
    """分别探测主判模型（文本推理）与视觉模型（若配置）的连通性。"""
    if not core_config.AI_API_KEY:
        return {"ok": False, "message": "未配置 AI API Key"}

    def ping(model: str) -> tuple[bool, str]:
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": "回复两个字：连通"}],
        }
        req = urllib.request.Request(
            core_config.AI_BASE_URL.rstrip("/") + "/chat/completions",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {core_config.AI_API_KEY}"})
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read().decode("utf-8", "ignore"))
            msg = (data.get("choices") or [{}])[0].get("message") or {}
            content = msg.get("content") or msg.get("reasoning_content") or ""
            if isinstance(content, list):
                content = "".join(p.get("text", "") for p in content if isinstance(p, dict))
            return True, f"{model} 连通正常，返回: {str(content)[:40]}"
        except Exception as e:
            return False, f"{model} 调用失败: {str(e)[:150]}"

    def ping_jev(model: str) -> tuple[bool, str]:
        try:
            from fishingnet import ai_client
            data = ai_client.jev_eval(
                "连通性测试。", {"ok": {"type": "noul", "instructions": "1+1 是否等于 2？"}}, model)
            conf = (data.get("answers") or {}).get("ok", {}).get("noul")
            return True, f"{model}（Jev结构化）连通正常，noul={conf:.2f}"
        except Exception as e:
            return False, f"{model}（Jev结构化）调用失败: {str(e)[:150]}"

    results = []
    ok_main, msg_main = ping(core_config.AI_MODEL)
    results.append(msg_main)
    ok = ok_main
    vision = (core_config.AI_VISION_MODEL or "").strip()
    if vision and vision != core_config.AI_MODEL:
        ok_v, msg_v = ping(vision)
        results.append(msg_v)
        ok = ok and ok_v
    jev = (core_config.AI_JEV_MODEL or "").strip()
    if jev:
        ok_j, msg_j = ping_jev(jev)
        results.append(msg_j)
        if not ok:  # 主通道不可用但 Jev 可用 → 研判仍可运行（自动降级 Jev 单通道）
            ok = ok_j
    return {"ok": ok, "message": "；".join(results)}


@router.post("/test-dispatch")
def test_dispatch():
    """P3 下发渠道连通性测试：webhook / AdGuard Home（用单域名 test.example.com）。"""
    from fishingnet import config as cfg, dispatch as _dispatch
    results = {}
    if cfg.BLOCK_WEBHOOK_URL:
        results["webhook"] = _dispatch.dispatch_webhook(["test.example.com"])
    if cfg.ADGUARD_URL:
        results["adguard"] = _dispatch.dispatch_adguard()
    if not results:
        return {"ok": False, "message": "未配置任何下发渠道（webhook / AdGuard Home）"}
    ok = all(r.get("ok") for r in results.values() if r is not None)
    msg = "；".join(f"{k}: {'✓' if v.get('ok') else '✗'} {str(v.get('detail'))[:80]}"
                    for k, v in results.items() if v is not None)
    return {"ok": ok, "message": msg}
