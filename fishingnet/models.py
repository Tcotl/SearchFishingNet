"""核心数据模型：搜索命中、规则评分、取证结果、AI 裁决、情报记录。"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Optional


# ---------------- 研判分级 ----------------

TRUSTED = "trusted"          # >= 70 放行
WATCH = "watch"              # 40-69 待观察
SUSPICIOUS = "suspicious"    # 15-39 可疑
DANGEROUS = "dangerous"      # < 15 高危

# ---------------- AI 裁决类别 ----------------

V_PHISHING = "phishing"                      # 假冒官网/钓鱼
V_MALWARE = "malware_distribution"           # 投毒下载站
V_BRAND_ABUSE = "brand_abuse"                # 蹭品牌暂无直接危害
V_SUSPICIOUS = "suspicious"                  # 证据不足
V_BENIGN = "benign"                          # 正版/正常站
V_UNRELATED = "unrelated"                    # 与关键词无关

MALICIOUS_VERDICTS = {V_PHISHING, V_MALWARE}
VALID_VERDICTS = {V_PHISHING, V_MALWARE, V_BRAND_ABUSE, V_SUSPICIOUS, V_BENIGN, V_UNRELATED}

# ---------------- 情报处置状态 ----------------

D_AUTO_BLOCK = "auto_blocked"
D_POLICY_BLOCK = "policy_blocked"   # 严格下载管控：非官方下载渠道策略封堵
D_MONITOR = "monitored"
D_REVIEW = "pending_review"
D_ALLOWED = "allowed"


def tier_of(score: int) -> str:
    if score >= 70:
        return TRUSTED
    if score >= 40:
        return WATCH
    if score >= 15:
        return SUSPICIOUS
    return DANGEROUS


@dataclass
class SearchHit:
    """一条搜索结果（来自现有爬虫 JSON 或 domains txt）。"""
    keyword: str
    engine: str
    rank: int
    title: str = ""
    url: str = ""
    domain: str = ""
    description: str = ""
    display_url: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScoreFactor:
    factor: str
    delta: int
    detail: str


@dataclass
class RuleScore:
    """L1 规则评分结果。"""
    domain: str
    score: int
    tier: str
    breakdown: list = field(default_factory=list)   # list[ScoreFactor]
    threat_intel_hit: bool = False

    def add(self, factor: str, delta: int, detail: str) -> None:
        self.breakdown.append(ScoreFactor(factor, delta, detail))
        self.score = max(0, min(100, self.score + delta))

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "score": self.score,
            "tier": self.tier,
            "threat_intel_hit": self.threat_intel_hit,
            "breakdown": [asdict(b) for b in self.breakdown],
        }


@dataclass
class Evidence:
    """L2 动态取证结果。"""
    domain: str
    ok: bool = False
    final_url: str = ""
    http_status: Optional[int] = None
    page_title: str = ""
    text_excerpt: str = ""
    form_fields: list = field(default_factory=list)
    external_links: list = field(default_factory=list)
    download_links: list = field(default_factory=list)   # [{url,text,host,netdisk,offsite}]
    brand_mentions: list = field(default_factory=list)   # 页面 title/正文宣称的品牌词
    favicon_sha1: str = ""
    screenshot_path: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AiVerdict:
    """L3 AI 严判结果（单通道）。"""
    verdict: str
    confidence: int                      # 0-100
    impersonated_brand: str = ""
    evidence: list = field(default_factory=list)
    risk_points: list = field(default_factory=list)
    recommendation: str = ""             # block / monitor / allow / review
    raw: str = ""
    channel: str = ""                    # text / vision / final

    @property
    def is_malicious(self) -> bool:
        return self.verdict in MALICIOUS_VERDICTS

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ThreatRecord:
    """情报记录：一个域名一条，含完整证据链与裁决链。"""
    domain: str
    hits: list = field(default_factory=list)             # list[SearchHit.to_dict]
    rule_score: Optional[dict] = None                    # RuleScore.to_dict
    evidence: Optional[dict] = None                      # Evidence.to_dict
    ai_verdict: Optional[dict] = None                    # 最终(A/B合并后)裁决
    final: str = ""                                      # malicious / benign / review / monitor
    disposition: str = ""
    created_at: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: "sfn--" + str(uuid.uuid4()))
    ttl_days: int = 30

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "created": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(self.created_at)),
            "type": "phishing-site",
            "domain": self.domain,
            "hits": self.hits,
            "score": self.rule_score,
            "evidence": self.evidence,
            "ai_verdict": self.ai_verdict,
            "final": self.final,
            "disposition": self.disposition,
            "ttl_days": self.ttl_days,
        }
