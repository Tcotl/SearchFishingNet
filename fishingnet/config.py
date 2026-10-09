"""运行配置：路径、阈值、AI 接入、可选外部情报 API。环境变量可覆盖。"""

from __future__ import annotations

import os
from pathlib import Path

# ---------------- 路径 ----------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("SFN_DATA_DIR", PROJECT_ROOT / "data"))
EVIDENCE_DIR = DATA_DIR / "evidence"
BLOCKLIST_DIR = DATA_DIR / "blocklist"
DB_PATH = DATA_DIR / "fishingnet.db"

for _d in (DATA_DIR, EVIDENCE_DIR, BLOCKLIST_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# ---------------- 研判阈值（对应 DESIGN.md §3.1） ----------------

SCORE_TRUSTED = 70      # >= 放行
SCORE_WATCH = 40        # >= 待观察
SCORE_SUSPICIOUS = 15   # >= 可疑

# AI 裁决采纳门槛：双通道均为恶意、置信度均不低于此值 → 自动封堵
AI_BLOCK_CONFIDENCE = 75
# 双通道结论不一致时允许的置信度差；超出差值且同为恶意也降级人工
AI_CONSISTENCY_GAP = 25

# 第三方下载/分发渠道评分封顶：≥70 即 trusted，故封顶 69 强制落入待观察
CHANNEL_SCORE_CAP = 69

# 严格下载管控：只放行品牌官方域名，第三方下载站策略封堵、模式命中降为可疑。
# 企业场景默认开启；平台设置页/环境变量 SFN_STRICT_DOWNLOAD 可关闭。
STRICT_DOWNLOAD_POLICY = os.environ.get("SFN_STRICT_DOWNLOAD", "1").lower() not in ("0", "false", "no")

# 严格放行策略：只有品牌官方域名（及人工审定的白名单）自动放行，
# 其余域名一律封顶 69 分进入取证与 AI 研判漏斗。平台设置页/环境变量 SFN_STRICT_OFFICIAL_ONLY 可关闭。
STRICT_OFFICIAL_ONLY = os.environ.get("SFN_STRICT_OFFICIAL_ONLY", "1").lower() not in ("0", "false", "no")
NONOFFICIAL_SCORE_CAP = 69

# ---------------- AI 接入（OpenAI 兼容协议） ----------------

AI_API_KEY = os.environ.get("SFN_AI_API_KEY", "")
AI_BASE_URL = os.environ.get("SFN_AI_BASE_URL", "https://open.bigmodel.cn/api/paas/v4")
AI_MODEL = os.environ.get("SFN_AI_MODEL", "glm-4.5v")
# 视觉多模态模型（通道B，截图裁决）；留空则主模型兼任。主模型可配纯文本推理模型
# （GLM-4.6 / DeepSeek-R1 等），能力自动探测降级。
AI_VISION_MODEL = os.environ.get("SFN_AI_VISION_MODEL", "")
# Jev 结构化评估模型（通道C，TypeSafe SystemOne 协议）：输出真假概率/定性概率
# 分布/置信度，不生成自然语言（如博查 bocha-jev-v1）。留空不启用。
AI_JEV_MODEL = os.environ.get("SFN_AI_JEV_MODEL", "")
# Jev 评估端点；留空按 AI_BASE_URL 推导（…/gateway/v1 → …/gateway/typesafe/v1/systemone）
AI_JEV_URL = os.environ.get("SFN_AI_JEV_URL", "")
AI_TIMEOUT = int(os.environ.get("SFN_AI_TIMEOUT", "180"))

# ---------------- P3 设备接管（封堵工单下发） ----------------

BLOCK_WEBHOOK_URL = os.environ.get("SFN_BLOCK_WEBHOOK_URL", "")   # 通用 webhook（防火墙/DNS/SOAR）
ADGUARD_URL = os.environ.get("SFN_ADGUARD_URL", "")               # AdGuard Home，如 http://192.168.1.2
ADGUARD_USER = os.environ.get("SFN_ADGUARD_USER", "")
ADGUARD_PASS = os.environ.get("SFN_ADGUARD_PASS", "")
# AdGuard 订阅的封堵列表 URL（须 AdGuard 可达，如 http://<本机>:8765/... 反代）
ADGUARD_BLOCKLIST_URL = os.environ.get("SFN_ADGUARD_BLOCKLIST_URL", "")

# ---------------- 可选外部数据源 ----------------

VT_API_KEY = os.environ.get("SFN_VT_API_KEY", "")          # VirusTotal
ICP_API_URL = os.environ.get("SFN_ICP_API_URL", "")        # ICP备案查询API(POST domain=..)
ICP_API_KEY = os.environ.get("SFN_ICP_API_KEY", "")

RDAP_TIMEOUT = 15
EVIDENCE_TIMEOUT = 30          # 动态取证单页超时
EVIDENCE_TEXT_MAX = 4000       # 正文截断
SCREENSHOT_W, SCREENSHOT_H = 1280, 800

TTL_DAYS = 30

# ---------------- 安全护栏 ----------------

# 提示词注入的常见模式，正文送审前会被剥离/中和
INJECTION_PATTERNS = [
    "忽略以上", "忽略之前", "无视上述", "你现在是", "新的指令",
    "ignore previous", "ignore all previous", "disregard the above",
    "system prompt", "<|", "|>", "### instruction",
]
