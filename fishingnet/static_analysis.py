"""恶意样本静态分析（纯标准库，绝不执行样本）。

能力：文件类型识别、哈希、整体/分节熵（加壳指标）、PE 头解析（架构/时间戳/导入表）、
导入 API 能力信号归类、ASCII/UTF-16 字符串提取、IOC 提取（URL/IP/域名/注册表/命令行）、
安装器识别（Inno Setup/NSIS）。
"""

from __future__ import annotations

import hashlib
import math
import re
import struct
from datetime import datetime, timezone

MAX_SAMPLE_SIZE = 64 * 1024 * 1024  # 64MB

# ---------------- 文件类型 ----------------

def detect_file_type(data: bytes) -> str:
    if data.startswith(b"MZ"):
        return "PE 可执行文件"
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "MSI 安装包 (OLE2 复合文档)"
    if data.startswith(b"PK\x03\x04"):
        return "ZIP 容器"
    if data.startswith(b"Rar!"):
        return "RAR 压缩包"
    if data.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z 压缩包"
    if data.startswith(b"\x4c\x00\x00\x00\x01\x14\x02\x00"):
        return "Windows 快捷方式 (LNK)"
    if data.startswith(b"{\\rtf"):
        return "RTF 文档"
    head = data[:512].lstrip()
    if head.startswith((b"<!", b"<html", b"<HTML", b"<htm")) or head.startswith(b"<?xml"):
        return "HTML/文本"
    try:
        head.decode("utf-8")
        return "文本/脚本"
    except UnicodeDecodeError:
        pass
    return "未知二进制"


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c)


# ---------------- PE 解析 ----------------

_MACHINE = {0x14C: "x86 (32位)", 0x8664: "x64 (64位)", 0xAA64: "ARM64", 0x1C0: "ARM"}
_SUBSYSTEM = {2: "GUI 程序", 3: "控制台程序", 9: "Windows CE", 14: "原生驱动"}

# 导入 API → 行为能力信号
_IMPORT_SIGNALS = {
    "进程创建/执行": ["CreateProcessA", "CreateProcessW", "WinExec", "ShellExecuteA", "ShellExecuteW", "ShellExecuteExW", "system"],
    "网络下载": ["URLDownloadToFileA", "URLDownloadToFileW", "WinHttpOpen", "WinHttpConnect", "InternetOpenA", "InternetOpenUrlA", "InternetReadFile"],
    "网络通信": ["socket", "connect", "WSAStartup", "send", "recv", "WSASocketA", "getaddrinfo"],
    "注册表持久化": ["RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW"],
    "键盘监听": ["SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState"],
    "屏幕捕获": ["GetDC", "BitBlt", "GetDesktopWindow"],
    "密码/凭据": ["CryptUnprotectData", "CredEnumerateA", " CryptGetUserKey"],
    "文件操作": ["CopyFileA", "CopyFileW", "MoveFileExA", "DeleteFileA", "WriteFile", "CreateFileA", "CreateFileW"],
    "反调试/虚拟机检测": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugStringA", "GetTickCount"],
    "服务/计划任务": ["OpenSCManagerA", "OpenSCManagerW", "CreateServiceA", "CreateServiceW", "StartServiceA"],
    "内存注入": ["WriteProcessMemory", "VirtualAllocEx", "CreateRemoteThread", "CreateRemoteThreadEx", "NtUnmapViewOfSection"],
    "加密/勒索": ["CryptEncrypt", "CryptAcquireContextA"],
}


def parse_pe(data: bytes) -> dict | None:
    """解析 PE 头：架构/时间戳/子系统/节表/导入表。失败返回 None。"""
    if not data.startswith(b"MZ") or len(data) < 0x100:
        return None
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return None
        coff = e_lfanew + 4
        machine, num_sections, _, _, _, opt_size, chars = struct.unpack_from("<HHIIIHH", data, coff)
        opt = coff + 20
        magic = struct.unpack_from("<H", data, opt)[0]
        pe32plus = magic == 0x20B
        entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
        image_base = struct.unpack_from("<Q" if pe32plus else "<I", data, opt + 24)[0]
        subsystem = struct.unpack_from("<H", data, opt + 68)[0]
        ts = struct.unpack_from("<I", data, coff + 4)[0]
        try:
            compiled = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            compiled = str(ts)

        # 节表
        sec_off = opt + opt_size
        sections = []
        for i in range(min(num_sections, 16)):
            base = sec_off + i * 40
            name = data[base:base + 8].rstrip(b"\x00").decode("ascii", "ignore")
            vsize, va, rsize, rptr = struct.unpack_from("<IIII", data, base + 8)
            sdata = data[rptr:rptr + min(rsize, 2 * 1024 * 1024)]
            ent = shannon_entropy(sdata)
            sections.append({"name": name, "va": hex(image_base + va), "size": rsize,
                             "entropy": round(ent, 2), "packed": ent > 7.2})

        # 导入表（数据目录[1]）
        imports: dict[str, list[str]] = {}
        dir_rva = struct.unpack_from("<I", data, opt + (112 if pe32plus else 96) + 8)[0]
        if dir_rva:
            sec_raw = []
            for i in range(min(num_sections, 16)):
                base = sec_off + i * 40
                vsize, va, rsize, rptr = struct.unpack_from("<IIII", data, base + 8)
                sec_raw.append((va, max(vsize, rsize), rptr))

            def rva_to_off(rva: int) -> int | None:
                for va, size, rptr in sec_raw:
                    if va <= rva < va + size:
                        return rptr + (rva - va)
                return None

            off = rva_to_off(dir_rva)
            step = 0
            while off and step < 64:
                oft, _, _, name_rva, ft = struct.unpack_from("<IIIII", data, off)
                if name_rva == 0 and ft == 0:
                    break
                dll_off = rva_to_off(name_rva)
                dll = "unknown"
                if dll_off:
                    raw = data[dll_off:dll_off + 64]
                    dll = raw.split(b"\x00")[0].decode("ascii", "ignore")
                funcs: list[str] = []
                thunk_rva = oft or ft
                t_off = rva_to_off(thunk_rva)
                tsize = 8 if pe32plus else 4
                ord_mask = 0x8000000000000000 if pe32plus else 0x80000000
                while t_off and len(funcs) < 64:
                    val = struct.unpack_from("<Q" if pe32plus else "<I", data, t_off)[0]
                    if val == 0:
                        break
                    if not (val & ord_mask):
                        fo = rva_to_off(val)
                        if fo:
                            fn = data[fo + 2:fo + 2 + 64].split(b"\x00")[0].decode("ascii", "ignore")
                            if fn:
                                funcs.append(fn)
                    t_off += tsize
                if dll:
                    imports[dll] = funcs
                off += 20
                step += 1

        # 能力信号归类
        signals: dict[str, list[str]] = {}
        all_funcs = {f: dll for dll, fs in imports.items() for f in fs}
        for capability, apis in _IMPORT_SIGNALS.items():
            hits = sorted({f for f in all_funcs if f.strip() in [a.strip() for a in apis]})
            if hits:
                signals[capability] = hits

        return {
            "machine": _MACHINE.get(machine, hex(machine)),
            "compiled": compiled,
            "subsystem": _SUBSYSTEM.get(subsystem, str(subsystem)),
            "sections": sections,
            "imports": imports,
            "import_signals": signals,
        }
    except Exception:
        return None


# ---------------- 字符串与 IOC ----------------

_ASCII_RE = re.compile(rb"[\x20-\x7e]{6,}")
_UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")
_URL_RE = re.compile(r"(?:https?|ftp)://[^\s\"'<>|\\]{4,200}", re.I)
# 前后向断言排除 OID/版本长点分串的任意窗口（1.3.6.1.4.1… 不再产出 1.3.6.1 / 1.311.21.20 之类碎片）
_IP_RE = re.compile(r"(?<!\d)(?<!\d\.)(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?!\.\d)")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+"
    r"(?:top|xyz|icu|cyou|com|net|cn|org|info|cc|vip|shop|site|online|club|ru|su|me|io|biz|pw|tk|ml|ga|cf|gq|fit|bar|buzz|monster|quest|sbs|cfd)\b",
    re.I)
_REG_RE = re.compile(r"(?:HKEY_[A-Z_]+|HKCU|HKLM)\\[^\s\"'<>]{2,120}")
_PRIVATE_IP = re.compile(r"^(10\.|127\.|169\.254|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|0\.0\.0\.0|255\.)")
_SUSPICIOUS_KEYWORDS = [
    "cmd.exe", "powershell", "-enc", "schtasks /create", "regsvr32", "rundll32",
    "certutil", "bitsadmin", "vssadmin delete", "taskkill", "appidid",
    "360tray", "360safe", "qqpcrtp", "kxetray", "hipsdaemon", "usysdiag",
    "wechat", "wechatwin", "%appdata%", "%temp%", "startup", "currentversion\\run",
    "minidump", "keylog", "inno setup", "nullsoft",
]


def extract_strings(data: bytes, limit: int = 4000) -> list[str]:
    out: list[str] = []
    for m in _ASCII_RE.finditer(data):
        out.append(m.group().decode("ascii", "ignore"))
    for m in _UTF16_RE.finditer(data):
        out.append(m.group().decode("utf-16-le", "ignore"))
    seen: set[str] = set()
    uniq = []
    for s in out:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
        if len(uniq) >= limit:
            break
    return uniq


def extract_iocs(strings: list[str]) -> dict:
    urls = list(dict.fromkeys(u.rstrip(".,);") for s in strings for u in _URL_RE.findall(s)))[:60]
    url_text = " ".join(urls)
    ips = [ip for s in strings for ip in _IP_RE.findall(s)
           if all(int(o) <= 255 for o in ip.split(":")[0].split("."))]
    ips = [ip for ip in dict.fromkeys(ips) if not _PRIVATE_IP.match(ip)][:40]
    domains = [d.lower() for s in strings for d in _DOMAIN_RE.findall(s)
               if d.lower() not in url_text.lower()]
    domains = list(dict.fromkeys(domains))[:60]
    registry = list(dict.fromkeys(r for s in strings for r in _REG_RE.findall(s)))[:30]
    commands = [s.strip() for s in strings
                if any(k in s.lower() for k in ("cmd.exe", "powershell", "schtasks", "regsvr32",
                                                "rundll32", "certutil", "bitsadmin", "msiexec"))
                and len(s) < 300][:30]
    suspicious = [s.strip()[:160] for s in strings
                  if any(k in s.lower() for k in _SUSPICIOUS_KEYWORDS)][:40]
    return {"urls": urls, "ips": ips, "domains": domains,
            "registry": registry, "commands": commands, "suspicious_strings": suspicious}


def detect_installer(strings: list[str]) -> str | None:
    joined = " ".join(strings[:1500]).lower()
    if "inno setup" in joined:
        return "Inno Setup 安装器"
    if "nullsoft" in joined or "nsis" in joined:
        return "Nullsoft (NSIS) 安装器"
    return None


def analyze_bytes(file_name: str, data: bytes) -> dict:
    """完整静态分析，返回报告 dict（纯只读，不执行）。"""
    ftype = detect_file_type(data)
    pe = parse_pe(data) if ftype.startswith("PE") else None
    strings = extract_strings(data)
    report = {
        "file": {
            "name": file_name,
            "size": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "entropy": round(shannon_entropy(data), 2),
            "type": ftype,
        },
        "pe": pe,
        "installer": detect_installer(strings),
        "iocs": extract_iocs(strings),
        "string_count": len(strings),
    }
    if pe and any(s.get("packed") for s in pe.get("sections", [])):
        report["packed"] = True
    return report
