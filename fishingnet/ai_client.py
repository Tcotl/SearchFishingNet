"""共享 AI 客户端：OpenAI 兼容 chat 调用 + Jev 结构化评估协议。

供 AI 站点研判（ai_judge）与 AI 样本分析（ai_sample_analysis）共用：
- 推理模型思考输出兼容：content 优先，回退 reasoning_content，剥离 <think> 块；
- temperature 被拒自动去参重试；
- 视觉能力进程内学习缓存（不支持图片的模型记为 text-only）；
- jev_eval：TypeSafe SystemOne 结构化评估（noul/choice/score），Jev 模型专用。
"""

from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request

from . import config


class ApiError(Exception):
    def __init__(self, message: str, status: int = 0):
        super().__init__(message)
        self.status = status
        self.body = message


# 模型能力缓存（进程内学习）：model -> "vision" | "text-only"
_MODEL_CAPS: dict[str, str] = {}


def extract_answer(message: dict) -> str:
    content = message.get("content") or ""
    if isinstance(content, list):  # 部分厂商返回分段数组
        content = "".join(p.get("text", "") for p in content if isinstance(p, dict))
    text = (content or "").strip()
    if not text:
        text = (message.get("reasoning_content") or message.get("reasoning") or "").strip()
    return re.sub(r"<think>.*?</think>", "", text, flags=re.S).strip()


def chat(model: str, messages: list, temperature) -> str:
    payload: dict = {"model": model, "messages": messages}
    if temperature is not None:
        payload["temperature"] = temperature
    req = urllib.request.Request(
        config.AI_BASE_URL.rstrip("/") + "/chat/completions",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {config.AI_API_KEY}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=config.AI_TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8", "ignore"))
    except urllib.error.HTTPError as e:
        raise ApiError(e.read().decode("utf-8", "ignore")[:400], e.code) from None
    except Exception as e:
        raise ApiError(str(e)[:200]) from None
    return extract_answer((data.get("choices") or [{}])[0].get("message") or {})


def ask(message_content, system_prompt: str, model: str | None = None) -> str:
    """带能力自适应的单轮调用，返回助手文本；错误抛 ApiError。

    重试策略：temperature 被拒去参重试；网络层错误（DNS/超时/连接重置，
    status=0）指数退避重试——本机代理 fake-IP DNS 抖动时接口会批量瞬断。
    """
    model = model or config.AI_MODEL
    temperature = 0
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": message_content},
    ]
    for attempt in range(4):
        try:
            return chat(model, messages, temperature)
        except ApiError as e:
            low = e.body.lower()
            if temperature is not None and "temperature" in low and e.status in (400, 422):
                temperature = None  # 推理模型常拒绝采样参数
                continue
            if any(k in low for k in ("image", "multimodal", "vision", "图片", "图像", "visual")):
                _MODEL_CAPS[model] = "text-only"
                raise
            if e.status == 0:
                time.sleep(min(2 ** attempt, 8))
                continue
            raise
    raise ApiError("重试次数耗尽")


def vision_supported(model: str) -> bool:
    return _MODEL_CAPS.get(model) != "text-only"


def vision_model() -> str:
    return (getattr(config, "AI_VISION_MODEL", "") or "").strip() or config.AI_MODEL


# ---------------- Jev 结构化评估（TypeSafe SystemOne 协议） ----------------

def jev_endpoint() -> str:
    """评估端点：显式配置优先，否则按 chat 网关地址推导。

    TokenDance 形如 https://host/gateway/v1 → https://host/gateway/typesafe/v1/systemone
    """
    url = (getattr(config, "AI_JEV_URL", "") or "").strip()
    if url:
        return url
    base = config.AI_BASE_URL.rstrip("/")
    if base.endswith("/v1"):
        base = base[: -len("/v1")]
    return base + "/typesafe/v1/systemone"


def jev_eval(state: str, questions: dict, model: str | None = None) -> dict:
    """TypeSafe SystemOne 结构化评估（Jev 模型专用协议，非 chat）。

    state 为任务上下文；questions 形如
      {"名称": {"type": "noul", "instructions": ...}}                         真假判断概率
      {"名称": {"type": "choice", "instructions": ..., "criteria": {选项: 说明}}}  候选选择
      {"名称": {"type": "score", "instructions": ..., "criteria": [评分依据...]}}  等级评分
    返回网关原始响应（含 answers/usage）；错误抛 ApiError。
    """
    model = model or config.AI_JEV_MODEL
    payload = json.dumps({"model": model, "state": state, "questions": questions}).encode()
    headers = {"Content-Type": "application/json",
               "Authorization": f"Bearer {config.AI_API_KEY}"}
    data = None
    for attempt in range(4):  # 网络层错误退避重试（同 ask）
        req = urllib.request.Request(jev_endpoint(), data=payload, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=config.AI_TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8", "ignore"))
            break
        except urllib.error.HTTPError as e:
            raise ApiError(e.read().decode("utf-8", "ignore")[:400], e.code) from None
        except Exception as e:
            if attempt == 3:
                raise ApiError(str(e)[:200]) from None
            time.sleep(min(2 ** attempt, 8))
    if not isinstance(data.get("answers"), dict):
        raise ApiError(f"Jev 响应缺少 answers: {json.dumps(data, ensure_ascii=False)[:200]}")
    return data
