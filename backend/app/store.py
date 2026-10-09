"""平台运行时配置存储：关键词、白名单增补、设置项，落盘 data/config/*.json。"""

from __future__ import annotations

import json
import re
import threading
import time
from pathlib import Path

from fishingnet import config as core_config
from fishingnet.keywords import KEYWORDS as DEFAULT_KEYWORDS, WHITELIST as DEFAULT_WHITELIST, KEYWORDS_SEED_VERSION

CONF_DIR = core_config.DATA_DIR / "config"
CONF_DIR.mkdir(parents=True, exist_ok=True)

_LOCK = threading.RLock()  # 可重入：add_xxx 持锁后仍会调用同锁的 getter

DEFAULT_SETTINGS = {
    "ai_base_url": core_config.AI_BASE_URL,
    "ai_model": core_config.AI_MODEL,
    "ai_vision_model": core_config.AI_VISION_MODEL,
    "ai_jev_model": core_config.AI_JEV_MODEL,
    "ai_jev_url": core_config.AI_JEV_URL,
    "ai_api_key": core_config.AI_API_KEY,
    "vt_api_key": core_config.VT_API_KEY,
    "icp_api_url": core_config.ICP_API_URL,
    "icp_api_key": core_config.ICP_API_KEY,
    "ai_block_confidence": core_config.AI_BLOCK_CONFIDENCE,
    "ai_consistency_gap": core_config.AI_CONSISTENCY_GAP,
    "strict_download_policy": True,
    "strict_official_only": True,
    "skip_evidence_default": False,
    "block_webhook_url": "",
    "adguard_url": "",
    "adguard_user": "",
    "adguard_pass": "",
    "adguard_blocklist_url": "",
}


def _path(name: str) -> Path:
    return CONF_DIR / f"{name}.json"


def _read(name: str, default):
    p = _path(name)
    if not p.exists():
        return default
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return default


def _write(name: str, data) -> None:
    _path(name).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


# ---------------- 关键词 ----------------

def get_keywords() -> list[str]:
    with _LOCK:
        stored = _read("keywords", None)
        if stored is None:  # 首次：以默认词库初始化落盘
            _write("keywords", DEFAULT_KEYWORDS)
            _write("keywords_seed_version", KEYWORDS_SEED_VERSION)
            return list(DEFAULT_KEYWORDS)
        stored = list(stored)
        # 词库升级：种子版本提升时，把新增的默认词合并进平台词库（用户删除的自定义词不复活）
        seeded = _read("keywords_seed_version", 1)
        if seeded < KEYWORDS_SEED_VERSION:
            merged = stored + [k for k in DEFAULT_KEYWORDS if k not in stored]
            _write("keywords", merged)
            _write("keywords_seed_version", KEYWORDS_SEED_VERSION)
            return merged
        return stored


def add_keyword(kw: str) -> bool:
    kw = kw.strip()
    if not kw:
        return False
    with _LOCK:
        kws = get_keywords()
        if kw in kws:
            return False
        kws.insert(0, kw)
        _write("keywords", kws)
    return True


def remove_keyword(kw: str) -> bool:
    with _LOCK:
        kws = get_keywords()
        if kw not in kws:
            return False
        kws.remove(kw)
        _write("keywords", kws)
    return True


# ---------------- 官方域名映射增补（映射自增长：人工确认 AI 候选后入库） ----------------
# 结构：{brand: [official_domain, ...]}；确认即并入 keywords.BRAND_OFFICIALS（最长后缀
# 匹配含子域），成为全系统最高优先级事实源，对应域名随 rescore 自动放行。

def get_brand_officials() -> dict:
    with _LOCK:
        data = _read("brand_officials", {})
        return {str(b): [str(d) for d in (doms or [])] for b, doms in data.items()}


def add_brand_official(brand: str, domains: list[str]) -> int:
    brand = (brand or "").strip()[:40]
    clean = sorted({d.strip().lower().lstrip(".") for d in domains if d.strip()})
    if not brand or not clean:
        return 0
    with _LOCK:
        data = get_brand_officials()
        merged = sorted(set(data.get(brand, [])) | set(clean))
        data[brand] = merged
        _write("brand_officials", data)
    apply_settings()
    return len(clean)


def remove_brand_official(brand: str, domain: str) -> bool:
    with _LOCK:
        data = get_brand_officials()
        doms = data.get(brand) or []
        if domain not in doms:
            return False
        doms.remove(domain)
        if doms:
            data[brand] = doms
        else:
            data.pop(brand, None)
        _write("brand_officials", data)
    apply_settings()
    return True


# ---------------- 白名单增补（误报回流 + 人工添加） ----------------
# 条目结构：{domain, note, source(manual|feedback), enabled, added_at}
# 兼容旧版纯字符串列表，读取时自动迁移。

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")


def _normalize_entries(raw) -> list[dict]:
    entries = []
    for item in raw or []:
        if isinstance(item, str):
            entries.append({"domain": item.lower(), "note": "", "source": "manual",
                            "enabled": True, "added_at": 0})
        elif isinstance(item, dict) and item.get("domain"):
            entries.append({
                "domain": str(item["domain"]).lower(),
                "note": item.get("note", ""),
                "source": item.get("source", "manual"),
                "enabled": bool(item.get("enabled", True)),
                "added_at": item.get("added_at", 0),
            })
    return entries


def parse_domain_input(text: str) -> list[str]:
    """批量输入解析域名：逗号/分号/空白/换行分隔；去掉协议与 www；校验格式。"""
    out: list[str] = []
    seen: set[str] = set()
    for part in re.split(r"[\s,;，；]+", (text or "").strip()):
        d = part.strip().lower()
        for prefix in ("https://", "http://"):
            if d.startswith(prefix):
                d = d[len(prefix):]
        d = d.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]  # 去路径/参数/锚点
        d = d.removeprefix("www.")
        if not d:
            continue
        if not _DOMAIN_RE.match(d):
            raise ValueError(f"无效域名: {part!r}")
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def get_whitelist_entries() -> list[dict]:
    with _LOCK:
        return _normalize_entries(_read("whitelist_extra", []))


def whitelist_domains() -> set[str]:
    """生效中的白名单域名集合（enabled 才参与放行判定）。"""
    return {e["domain"] for e in get_whitelist_entries() if e["enabled"]}


def add_whitelist(domains: list[str], note: str = "", source: str = "manual") -> int:
    """批量加入白名单，返回实际新增数（已存在的跳过）。"""
    with _LOCK:
        entries = get_whitelist_entries()
        existing = {e["domain"] for e in entries}
        added = 0
        for d in domains:
            if d in existing:
                continue
            entries.insert(0, {"domain": d, "note": note, "source": source,
                               "enabled": True, "added_at": time.time()})
            existing.add(d)
            added += 1
        _write("whitelist_extra", entries)
    _refresh_checker()
    return added


def remove_whitelist(domain: str) -> bool:
    with _LOCK:
        entries = get_whitelist_entries()
        kept = [e for e in entries if e["domain"] != domain.lower()]
        if len(kept) == len(entries):
            return False
        _write("whitelist_extra", kept)
    _refresh_checker()
    return True


def update_whitelist(domain: str, enabled: bool | None = None, note: str | None = None) -> bool:
    with _LOCK:
        entries = get_whitelist_entries()
        hit = False
        for e in entries:
            if e["domain"] == domain.lower():
                hit = True
                if enabled is not None:
                    e["enabled"] = enabled
                if note is not None:
                    e["note"] = note
        if not hit:
            return False
        _write("whitelist_extra", entries)
    _refresh_checker()
    return True


def _refresh_checker() -> None:
    from fishingnet import scoring
    scoring.in_whitelist = _make_whitelist_checker()


def _make_whitelist_checker():
    """组合默认白名单与平台增补（仅 enabled），替换 scoring.in_whitelist 运行时实现。"""
    extra = whitelist_domains()

    def checker(domain: str) -> bool:
        d = (domain or "").lower().lstrip("www.").rstrip(".")
        if any(d == w or d.endswith("." + w) for w in extra):
            return True
        return any(d == w or d.endswith("." + w) for w in DEFAULT_WHITELIST)

    return checker


# ---------------- 设置 ----------------

def get_settings(mask_secrets: bool = True) -> dict:
    with _LOCK:
        s = dict(DEFAULT_SETTINGS)
        s.update(_read("settings", {}))
    if mask_secrets:
        for k in ("ai_api_key", "vt_api_key", "icp_api_key", "adguard_pass"):
            s[f"{k}_set"] = bool(s.pop(k, ""))
            s[k] = ""  # 前端可提交空字符串表示不修改
    return s


_SECRET_KEYS = {"ai_api_key", "vt_api_key", "icp_api_key", "adguard_pass"}


def update_settings(patch: dict) -> None:
    with _LOCK:
        current = _read("settings", {})
        for k, v in patch.items():
            if k not in DEFAULT_SETTINGS or v is None:
                continue
            if k in _SECRET_KEYS and v == "":
                continue  # 密钥传空 = 保持现状，避免前端回传脱敏值覆盖
            current[k] = v  # 其余字段空值 = 清除（如清空视觉/Jev 模型）
        _write("settings", current)
    apply_settings()


def apply_settings() -> None:
    """把 settings.json 应用到 fishingnet.config 运行时属性（env 优先级低于平台设置）。"""
    with _LOCK:
        s = dict(DEFAULT_SETTINGS)
        s.update(_read("settings", {}))
    core_config.AI_BASE_URL = s["ai_base_url"] or core_config.AI_BASE_URL
    core_config.AI_MODEL = s["ai_model"] or core_config.AI_MODEL
    core_config.AI_VISION_MODEL = s.get("ai_vision_model", "") or ""
    core_config.AI_JEV_MODEL = (s.get("ai_jev_model", "") or "").strip()
    core_config.AI_JEV_URL = (s.get("ai_jev_url", "") or "").strip()
    core_config.AI_API_KEY = s["ai_api_key"] or core_config.AI_API_KEY
    core_config.VT_API_KEY = s["vt_api_key"] or core_config.VT_API_KEY
    core_config.ICP_API_URL = s["icp_api_url"] or core_config.ICP_API_URL
    core_config.ICP_API_KEY = s["icp_api_key"] or core_config.ICP_API_KEY
    core_config.AI_BLOCK_CONFIDENCE = int(s["ai_block_confidence"])
    core_config.AI_CONSISTENCY_GAP = int(s["ai_consistency_gap"])
    core_config.STRICT_DOWNLOAD_POLICY = bool(s.get("strict_download_policy", True))
    core_config.STRICT_OFFICIAL_ONLY = bool(s.get("strict_official_only", True))
    core_config.BLOCK_WEBHOOK_URL = (s.get("block_webhook_url", "") or "").strip()
    core_config.ADGUARD_URL = (s.get("adguard_url", "") or "").strip()
    core_config.ADGUARD_USER = (s.get("adguard_user", "") or "").strip()
    core_config.ADGUARD_PASS = (s.get("adguard_pass", "") or "").strip()
    core_config.ADGUARD_BLOCKLIST_URL = (s.get("adguard_blocklist_url", "") or "").strip()
    from fishingnet import scoring
    scoring.in_whitelist = _make_whitelist_checker()
    _apply_brand_officials()


def _apply_brand_officials() -> None:
    """平台确认的自定义官方映射并入 keywords.BRAND_OFFICIALS / OFFICIAL_DOMAINS。"""
    from fishingnet import keywords as kw_mod
    for brand, domains in get_brand_officials().items():
        kw_mod.BRAND_OFFICIALS.setdefault(brand, [])
        for d in domains:
            if d not in kw_mod.BRAND_OFFICIALS[brand]:
                kw_mod.BRAND_OFFICIALS[brand].append(d)
                kw_mod.OFFICIAL_DOMAINS.add(d)
