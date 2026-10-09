"""AI 样本行为分析：基于静态分析报告推断行为链、能力与恶意外连地址（C2）。

复用共享 AI 客户端（支持常规推理模型/视觉模型）。样本绝不在本机执行，
AI 仅基于静态证据做行为推断，并要求对每个 C2 判断给出字符串级证据与置信度。
"""

from __future__ import annotations

import json
import re

from . import ai_client
from .ai_client import ApiError

SYSTEM_PROMPT = """你是企业安全团队的恶意样本分析师（静态分析角色，样本未执行）。根据材料中的静态分析报告（文件类型、熵、PE导入表能力信号、字符串、IOC、下载来源）推断样本的行为与恶意外连地址。

只输出一个 JSON 对象（不要 markdown 代码块）：
{
 "family_guess": "家族/类型推测（如：银狐远控投放器 / Gamaredon dropper / 捆绑安装器 / 正常软件安装包）",
 "risk_level": "high|medium|low",
 "behavior_chain": ["步骤1（用户视角触发）", "步骤2（释放/持久化）", "步骤3（外连/窃取）"],
 "capabilities": ["远程控制", "键盘记录", "信息窃取", "持久化", "下载器", "反调试", "勒索加密"],
 "c2_addresses": [{"indicator": "1.2.3.4:8443 或 c2.example.top", "type": "ip|domain|url", "confidence": 0-100, "evidence": "样本字符串中的原始引用"}],
 "dropped_files": ["释放路径，来自字符串证据"],
 "persistence": "持久化方式（注册表Run/计划任务/服务/无）",
 "summary": "两三句中文结论"
}

严判规则：
1. 每个 c2_addresses 条目必须给出样本字符串中的原始证据，无证据的不要列入；推测性的 confidence ≤ 40。
2. 行为链必须可由静态证据支撑（导入API/字符串/释放路径），标注不确定处。
3. 安装器（Inno/NSIS）与正常软件安装包（签名厂商、正规下载链路）不要误判为恶意；结合来源域名是否为已封堵钓鱼站综合判断。
4. 硬编码 IP 直连、动态域名、非常见端口、powershell -enc、schtasks 持久化是强恶意外连信号。
5. 证据不足时 risk_level 给 low/medium，不要夸大。"""


def _material(sample: dict, static_report: dict) -> str:
    f = static_report.get("file", {})
    parts = [
        f"【样本来源】域名 {sample.get('source_domain')}（已被平台确认为钓鱼/投毒站点并封堵），下载自 {sample.get('source_url')}",
        f"【文件】{f.get('name')} / {f.get('type')} / {f.get('size')} bytes / 熵 {f.get('entropy')}",
        f"【哈希】MD5 {f.get('md5')} / SHA1 {f.get('sha1')} / SHA256 {f.get('sha256')}",
    ]
    if static_report.get("installer"):
        parts.append(f"【安装器】{static_report['installer']}")
    if static_report.get("packed"):
        parts.append("【加壳】存在高熵节，疑似加壳/加密载荷")
    pe = static_report.get("pe")
    if pe:
        parts.append(f"【PE】{pe.get('machine')} / {pe.get('subsystem')} / 编译时间 {pe.get('compiled')}")
        if pe.get("import_signals"):
            parts.append("【导入表能力信号】")
            for cap, apis in pe["import_signals"].items():
                parts.append(f"  - {cap}: {', '.join(apis[:10])}")
    iocs = static_report.get("iocs", {})
    if iocs.get("urls"):
        parts.append("【URL 字符串】" + "；".join(iocs["urls"][:15]))
    if iocs.get("ips"):
        parts.append("【IP 字符串】" + "；".join(iocs["ips"][:15]))
    if iocs.get("domains"):
        parts.append("【域名字符串】" + "；".join(iocs["domains"][:20]))
    if iocs.get("registry"):
        parts.append("【注册表引用】" + "；".join(iocs["registry"][:10]))
    if iocs.get("commands"):
        parts.append("【命令行】" + " | ".join(iocs["commands"][:10]))
    if iocs.get("suspicious_strings"):
        parts.append("【可疑字符串】" + " | ".join(iocs["suspicious_strings"][:15]))
    return "\n".join(parts)


def _parse(raw: str) -> dict:
    m = re.search(r"\{.*\}", raw, re.S)
    if not m:
        return {"error": "AI 输出无法解析", "raw": raw[:500]}
    try:
        obj = json.loads(m.group(0))
    except json.JSONDecodeError:
        return {"error": "AI 输出 JSON 解析失败", "raw": raw[:500]}
    obj["c2_addresses"] = [
        {**c, "indicator": str(c.get("indicator", ""))[:120],
         "confidence": max(0, min(100, int(c.get("confidence") or 0))),
         "evidence": str(c.get("evidence", ""))[:200]}
        for c in (obj.get("c2_addresses") or []) if c.get("indicator")
    ][:20]
    for k in ("behavior_chain", "capabilities", "dropped_files"):
        obj[k] = [str(x)[:200] for x in (obj.get(k) or [])][:15]
    obj["summary"] = str(obj.get("summary") or "")[:800]
    return obj


def analyze_sample(sample: dict, static_report: dict) -> dict | None:
    """AI 行为分析。未配置 API Key 返回 None。"""
    if not ai_client.config.AI_API_KEY:
        return None
    try:
        raw = ai_client.ask(_material(sample, static_report), SYSTEM_PROMPT)
        return _parse(raw)
    except ApiError as e:
        return {"error": f"AI 接口调用失败: {e.body[:150]}"}
