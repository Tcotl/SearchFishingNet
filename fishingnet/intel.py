"""情报库：SQLite 落盘。表结构宽松（JSON 快照），支持运营反馈闭环。"""

from __future__ import annotations

import json
import re
import sqlite3
import time
from pathlib import Path

from . import config
from .models import ThreatRecord

_SCHEMA = """
CREATE TABLE IF NOT EXISTS records (
    id TEXT PRIMARY KEY,
    domain TEXT UNIQUE,
    final TEXT,
    disposition TEXT,
    status TEXT DEFAULT 'active',
    rule_score INTEGER,
    ai_verdict TEXT,
    ai_confidence INTEGER,
    created_at REAL,
    updated_at REAL,
    ttl_expire_at REAL,
    note TEXT DEFAULT '',
    payload TEXT
);
CREATE TABLE IF NOT EXISTS samples (
    sha256 TEXT PRIMARY KEY,
    source_domain TEXT,
    source_url TEXT,
    file_name TEXT,
    size INTEGER,
    md5 TEXT,
    sha1 TEXT,
    ftype TEXT,
    status TEXT,
    risk_level TEXT DEFAULT '',
    c2_count INTEGER DEFAULT 0,
    static_report TEXT,
    ai_report TEXT,
    created_at REAL,
    analyzed_at REAL
);
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL,
    keyword_file TEXT,
    stats TEXT
);
"""


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    return conn


def upsert_record(rec: ThreatRecord) -> None:
    conn = _conn()
    try:
        existing = conn.execute("SELECT id, status FROM records WHERE domain=?", (rec.domain,)).fetchone()
        now = time.time()
        payload = json.dumps(rec.to_dict(), ensure_ascii=False)
        if existing:
            # 运营安全：人工标记的误报不因重新采集被洗回封堵状态
            status = existing["status"]
            if status in ("false_positive", "allowed"):
                conn.execute(
                    """UPDATE records SET final=?, disposition='', rule_score=?,
                       ai_verdict=?, ai_confidence=?, updated_at=?, ttl_expire_at=?, payload=?
                       WHERE domain=?""",
                    (rec.final, _rule_score(rec), _ai_verdict(rec), _ai_confidence(rec),
                     now, rec.created_at + rec.ttl_days * 86400, payload, rec.domain))
            else:
                conn.execute(
                    """UPDATE records SET final=?, disposition=?, status='active', rule_score=?,
                       ai_verdict=?, ai_confidence=?, updated_at=?, ttl_expire_at=?, payload=?
                       WHERE domain=?""",
                    (rec.final, rec.disposition, _rule_score(rec), _ai_verdict(rec), _ai_confidence(rec),
                     now, rec.created_at + rec.ttl_days * 86400, payload, rec.domain))
        else:
            conn.execute(
                """INSERT INTO records (id, domain, final, disposition, status, rule_score,
                   ai_verdict, ai_confidence, created_at, updated_at, ttl_expire_at, payload)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (rec.id, rec.domain, rec.final, rec.disposition, "active", _rule_score(rec),
                 _ai_verdict(rec), _ai_confidence(rec), rec.created_at, now,
                 rec.created_at + rec.ttl_days * 86400, payload))
        conn.commit()
    finally:
        conn.close()


def _rule_score(rec: ThreatRecord) -> int:
    return (rec.rule_score or {}).get("score", 0) if rec.rule_score else 0


def _ai_verdict(rec: ThreatRecord) -> str:
    return (rec.ai_verdict or {}).get("verdict", "") if rec.ai_verdict else ""


def _ai_confidence(rec: ThreatRecord) -> int:
    return (rec.ai_verdict or {}).get("confidence", 0) if rec.ai_verdict else ""


def feedback(domain: str, kind: str, note: str = "") -> bool:
    """运营反馈/人工复核处置。

    false_positive: 误报 → 移出封堵，状态持久（重跑不复活）
    allow:          放行
    confirm_block:  人工确认恶意 → 进入封堵
    confirm:        确认记录有效（不改变处置）
    """
    assert kind in ("false_positive", "confirm", "allow", "confirm_block")
    conn = _conn()
    try:
        row = conn.execute("SELECT id FROM records WHERE domain=?", (domain,)).fetchone()
        if not row:
            return False
        now = time.time()
        # 人工结论入 payload（P2 专家范例库/人机一致率的事实源）
        human_map = {"false_positive": "benign", "allow": "benign", "confirm_block": "malicious"}
        if kind in human_map:
            try:
                payload = json.loads(conn.execute(
                    "SELECT payload FROM records WHERE domain=?", (domain,)).fetchone()["payload"])
                payload["human_verdict"] = {
                    "verdict": human_map[kind], "at": now, "source": "manual_review"}
                conn.execute("UPDATE records SET payload=? WHERE domain=?",
                             (json.dumps(payload, ensure_ascii=False), domain))
            except Exception:
                pass
        if kind == "false_positive":
            conn.execute("UPDATE records SET status='false_positive', disposition='', final='', note=?, updated_at=? WHERE domain=?",
                         (note or "误报回滚", now, domain))
        elif kind == "allow":
            conn.execute("UPDATE records SET status='allowed', disposition='allowed', final='benign', note=?, updated_at=? WHERE domain=?",
                         (note, now, domain))
        elif kind == "confirm_block":
            conn.execute("UPDATE records SET status='active', disposition='auto_blocked', final='malicious', note=?, updated_at=? WHERE domain=?",
                         (note or "人工复核确认恶意", now, domain))
        else:  # confirm
            conn.execute("UPDATE records SET status='active', note=?, updated_at=? WHERE domain=?",
                         (note, now, domain))
        conn.commit()
        return True
    finally:
        conn.close()


def update_rule_score(domain: str, score_dict: dict) -> bool:
    """只刷新规则评分（保留 AI 裁决/证据/处置），用于评分模型升级后的存量重算。"""
    conn = _conn()
    try:
        row = conn.execute("SELECT payload FROM records WHERE domain=?", (domain,)).fetchone()
        if not row:
            return False
        payload = json.loads(row["payload"])
        payload["score"] = score_dict
        conn.execute("UPDATE records SET rule_score=?, payload=?, updated_at=? WHERE domain=?",
                     (score_dict.get("score", 0), json.dumps(payload, ensure_ascii=False),
                      time.time(), domain))
        conn.commit()
        return True
    finally:
        conn.close()


def update_evidence(domain: str, evidence: dict) -> bool:
    """更新记录的取证数据（保留处置与裁决），供样本猎取前刷新下载入口。"""
    conn = _conn()
    try:
        row = conn.execute("SELECT payload FROM records WHERE domain=?", (domain,)).fetchone()
        if not row:
            return False
        payload = json.loads(row["payload"])
        payload["evidence"] = evidence
        conn.execute("UPDATE records SET payload=?, updated_at=? WHERE domain=?",
                     (json.dumps(payload, ensure_ascii=False), time.time(), domain))
        conn.commit()
        return True
    finally:
        conn.close()


def update_facts(domain: str, facts: dict) -> bool:
    """写入/合并硬事实（RDAP/ICP/VT）到 payload.facts，保留其余数据。"""
    conn = _conn()
    try:
        row = conn.execute("SELECT payload FROM records WHERE domain=?", (domain,)).fetchone()
        if not row:
            return False
        payload = json.loads(row["payload"])
        merged = dict(payload.get("facts") or {})
        merged.update(facts or {})
        payload["facts"] = merged
        conn.execute("UPDATE records SET payload=?, updated_at=? WHERE domain=?",
                     (json.dumps(payload, ensure_ascii=False), time.time(), domain))
        conn.commit()
        return True
    finally:
        conn.close()


# ---------------- P2 专家范例库 / 人机一致率 ----------------

def _derive_human_verdict(payload: dict, status: str) -> str:
    """从记录状态推导人工结论（含历史数据回填：feedback 前无 human_verdict 列）。"""
    # mock 时代的演示性回滚不是真实复核结论（note 带标记），不进范例/一致率统计
    note = payload.get("note") or ""
    if "mock" in note.lower() or "演示" in note:
        return ""
    hv = (payload.get("human_verdict") or {}).get("verdict")
    if hv:
        return hv
    if status == "false_positive":
        return "benign"
    if status == "allowed" and "放行" in note:
        return "benign"
    if payload.get("disposition") == "auto_blocked" and "人工" in note:
        return "malicious"
    return ""


def list_exemplars(limit: int = 12) -> list[dict]:
    """专家范例：有人工结论 + AI 裁决 + 证据的记录，供 few-shot 注入与微调导出。"""
    out = []
    for r in list_records():
        hv = _derive_human_verdict(r, r.get("status") or "")
        av = r.get("ai_verdict") or {}
        if not hv or not av.get("verdict") or r.get("ai_verdict", {}).get("channel", "").startswith("mock"):
            continue
        ev = r.get("evidence") or {}
        out.append({
            "domain": r.get("domain"),
            "human_verdict": hv,
            "human_note": (r.get("note") or "")[:120],
            "ai_verdict": av.get("verdict"),
            "ai_confidence": av.get("confidence"),
            "page_title": (ev.get("page_title") or "")[:80],
            "brand": (av.get("impersonated_brand") or "")[:30],
            "download_links": [d.get("host") for d in (ev.get("download_links") or [])[:3]],
            "updated": r.get("status") and (r.get("created") or ""),
        })
        if len(out) >= limit * 3:
            break
    # 误报范例优先（更稀缺、更防幻觉），恶意次之
    out.sort(key=lambda x: (x["human_verdict"] != "benign",))
    return out[:limit]


def agreement_stats() -> dict:
    """人机一致率：有人工结论且有 AI 裁决的记录中，恶意组别/良性组别一致占比。"""
    total = agree = 0
    fp_blocked = 0   # AI 判恶意但人工判误报（AI 过严）
    missed = 0       # AI 判良性但人工确认恶意（AI 过宽，最危险）
    for r in list_records():
        hv = _derive_human_verdict(r, r.get("status") or "")
        av = (r.get("ai_verdict") or {}).get("verdict")
        if not hv or not av or av == "suspicious":
            continue
        total += 1
        h_mal, a_mal = hv == "malicious", av in ("phishing", "malware_distribution")
        if h_mal == a_mal:
            agree += 1
        elif h_mal and not a_mal:
            missed += 1
        elif not h_mal and a_mal:
            fp_blocked += 1
    return {"total": total, "agree": agree,
            "rate": round(agree / total * 100, 1) if total else None,
            "ai_too_strict": fp_blocked, "ai_too_lenient": missed}


def trends(days: int = 30) -> dict:
    """P4 趋势看板：按天发现量 + 封堵动作 + 人工复核（按 created_at/updated_at 归桶）。"""
    from datetime import datetime

    now = time.time()
    start = now - days * 86400
    day_fmt = "%m-%d"
    discovered: dict[str, int] = {}
    blocked_ev: dict[str, int] = {}
    human_ev: dict[str, int] = {}
    conn = _conn()
    try:
        rows = conn.execute(
            "SELECT created_at, updated_at, status, disposition, payload FROM records").fetchall()
    finally:
        conn.close()
    for r in rows:
        try:
            payload = json.loads(r["payload"])
        except Exception:
            continue
        d0 = datetime.fromtimestamp(r["created_at"]).strftime(day_fmt)
        if r["created_at"] >= start:
            discovered[d0] = discovered.get(d0, 0) + 1
        if r["updated_at"] >= start:
            du = datetime.fromtimestamp(r["updated_at"]).strftime(day_fmt)
            if r["disposition"] in ("auto_blocked", "policy_blocked") and r["status"] == "active":
                blocked_ev[du] = blocked_ev.get(du, 0) + 1
            if _derive_human_verdict(payload, r["status"]):
                human_ev[du] = human_ev.get(du, 0) + 1
    series = []
    for i in range(days - 1, -1, -1):
        d = datetime.fromtimestamp(now - i * 86400).strftime(day_fmt)
        series.append({"date": d,
                       "discovered": discovered.get(d, 0),
                       "blocked": blocked_ev.get(d, 0),
                       "human_review": human_ev.get(d, 0)})
    return {"series": series, "agreement": agreement_stats()}


def update_ai_verdict(domain: str, ai_verdict: dict, rule_score: dict | None = None) -> bool:
    """写回 AI 裁决（与可选的新评分）到 payload 与列，保留处置状态。"""
    conn = _conn()
    try:
        row = conn.execute("SELECT payload FROM records WHERE domain=?", (domain,)).fetchone()
        if not row:
            return False
        payload = json.loads(row["payload"])
        payload["ai_verdict"] = ai_verdict
        if rule_score:
            payload["score"] = rule_score
        conn.execute(
            "UPDATE records SET ai_verdict=?, ai_confidence=?, rule_score=?, payload=?, updated_at=? WHERE domain=?",
            (ai_verdict.get("verdict", ""), ai_verdict.get("confidence", 0),
             (rule_score or payload.get("score") or {}).get("score", 0),
             json.dumps(payload, ensure_ascii=False), time.time(), domain))
        conn.commit()
        return True
    finally:
        conn.close()


def set_disposition(domain: str, final: str, disposition: str, note: str = "") -> bool:
    """设置处置（保持 active 状态），同步 payload 快照。供策略执行使用。"""
    conn = _conn()
    try:
        row = conn.execute("SELECT payload FROM records WHERE domain=?", (domain,)).fetchone()
        if not row:
            return False
        payload = json.loads(row["payload"])
        payload["final"] = final
        payload["disposition"] = disposition
        payload["note"] = note
        conn.execute("UPDATE records SET final=?, disposition=?, note=?, updated_at=?, payload=? WHERE domain=?",
                     (final, disposition, note, time.time(), json.dumps(payload, ensure_ascii=False), domain))
        conn.commit()
        return True
    finally:
        conn.close()


def active_blocked() -> list[dict]:
    """当前生效的封堵域名：AI 确认恶意 + 严格策略封堵（排除误报/过期/放行）。"""
    conn = _conn()
    try:
        rows = conn.execute(
            "SELECT domain, payload FROM records WHERE disposition IN ('auto_blocked','policy_blocked') "
            "AND status='active' AND ttl_expire_at > ?", (time.time(),)).fetchall()
        return [json.loads(r["payload"]) for r in rows]
    finally:
        conn.close()


def list_records(status: str | None = None) -> list[dict]:
    conn = _conn()
    try:
        if status:
            rows = conn.execute(
                "SELECT status, disposition, final, note, payload FROM records "
                "WHERE status=? ORDER BY updated_at DESC", (status,)).fetchall()
        else:
            rows = conn.execute(
                "SELECT status, disposition, final, note, payload FROM records "
                "ORDER BY updated_at DESC").fetchall()
        out = []
        for r in rows:
            payload = json.loads(r["payload"])
            # 以数据库列为生效状态（payload 是生成时快照，反馈后可能过期）
            payload["status"] = r["status"]
            payload["disposition"] = r["disposition"]
            payload["final"] = r["final"]
            payload["note"] = r["note"]
            out.append(payload)
        return out
    finally:
        conn.close()


# ---------------- 样本库 ----------------

def upsert_sample(sample: dict, static_report: dict, ai_report: dict | None = None) -> None:
    conn = _conn()
    try:
        # 重复入库（如人工重复上传）不带新分析结果时，保留已有分析状态，不把
        # analyzed 打回 downloaded（同误报状态保护的防回退原则）
        conn.execute(
            """INSERT INTO samples (sha256, source_domain, source_url, file_name, size, md5, sha1,
               ftype, status, risk_level, c2_count, static_report, ai_report, created_at, analyzed_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(sha256) DO UPDATE SET
               source_domain=excluded.source_domain,
               source_url=excluded.source_url, file_name=excluded.file_name,
               size=excluded.size, ftype=excluded.ftype,
               static_report=excluded.static_report,
               status=CASE WHEN excluded.ai_report IS NOT NULL THEN 'analyzed'
                           ELSE samples.status END,
               risk_level=CASE WHEN excluded.ai_report IS NOT NULL THEN excluded.risk_level
                               ELSE samples.risk_level END,
               c2_count=CASE WHEN excluded.ai_report IS NOT NULL THEN excluded.c2_count
                             ELSE samples.c2_count END,
               ai_report=COALESCE(excluded.ai_report, samples.ai_report),
               analyzed_at=COALESCE(excluded.analyzed_at, samples.analyzed_at)""",
            (sample["sha256"], sample["source_domain"], sample["source_url"], sample["file_name"],
             sample["size"], sample.get("md5", ""), sample.get("sha1", ""), sample.get("ftype", ""),
             sample.get("status", "downloaded"),
             (ai_report or {}).get("risk_level", ""),
             len((ai_report or {}).get("c2_addresses") or []),
             json.dumps(static_report, ensure_ascii=False),
             json.dumps(ai_report, ensure_ascii=False) if ai_report else None,
             time.time(), time.time() if ai_report else None))
        conn.commit()
    finally:
        conn.close()


def update_sample_analysis(sha256: str, ai_report: dict) -> None:
    conn = _conn()
    try:
        conn.execute("UPDATE samples SET ai_report=?, risk_level=?, c2_count=?, status='analyzed', analyzed_at=? WHERE sha256=?",
                     (json.dumps(ai_report, ensure_ascii=False),
                      ai_report.get("risk_level", ""),
                      len(ai_report.get("c2_addresses") or []),
                      time.time(), sha256))
        conn.commit()
    finally:
        conn.close()


def list_samples() -> list[dict]:
    conn = _conn()
    try:
        rows = conn.execute("SELECT * FROM samples ORDER BY created_at DESC").fetchall()
        keys = ("sha256", "source_domain", "source_url", "file_name", "size", "md5", "sha1",
                "ftype", "status", "risk_level", "c2_count", "created_at", "analyzed_at")
        return [{k: r[k] for k in keys} for r in rows]
    finally:
        conn.close()


def get_sample(sha256: str) -> dict | None:
    conn = _conn()
    try:
        r = conn.execute("SELECT * FROM samples WHERE sha256=?", (sha256,)).fetchone()
        if not r:
            return None
        d = {k: r[k] for k in r.keys()}
        d["static_report"] = json.loads(r["static_report"]) if r["static_report"] else None
        d["ai_report"] = json.loads(r["ai_report"]) if r["ai_report"] else None
        return d
    finally:
        conn.close()


def sample_path(sha256: str) -> Path | None:
    """隔离区样本文件路径（校验 sha 格式防路径穿越）。"""
    if not re.fullmatch(r"[0-9a-f]{64}", sha256 or ""):
        return None
    base = config.DATA_DIR / "samples" / sha256
    if not base.is_dir():
        return None
    for f in base.iterdir():
        if f.suffix != ".json":
            return f
    return None


def log_run(keyword_file: str, stats: dict) -> None:
    conn = _conn()
    try:
        conn.execute("INSERT INTO runs (ts, keyword_file, stats) VALUES (?,?,?)",
                     (time.time(), keyword_file, json.dumps(stats, ensure_ascii=False)))
        conn.commit()
    finally:
        conn.close()
