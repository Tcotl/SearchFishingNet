"""Playwright 浏览器自动发现：venv 里 playwright 期望的 build 可能没装，
但 ms-playwright 缓存里常有其他版本，自动挑一个可用的可执行文件。"""

from __future__ import annotations

import glob
import os
import sys
from pathlib import Path

_CACHE_GLOBS = [
    # macOS (arm64/x64 新版目录布局)
    "~/Library/Caches/ms-playwright/chromium-*/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
    "~/Library/Caches/ms-playwright/chromium-*/chrome-mac/Chromium.app/Contents/MacOS/Chromium",
    "~/Library/Caches/ms-playwright/chromium-*/chrome-mac-arm64/Chromium.app/Contents/MacOS/Chromium",
    "~/Library/Caches/ms-playwright/chromium_headless_shell-*/chrome-headless-shell-mac-arm64/chrome-headless-shell",
    # Linux
    "~/.cache/ms-playwright/chromium-*/chrome-linux/chrome",
    "~/.cache/ms-playwright/chromium_headless_shell-*/chrome-linux/headless_shell",
    # Windows
    "~/AppData/Local/ms-playwright/chromium-*/chrome-win/chrome.exe",
    "~/AppData/Local/ms-playwright/chromium_headless_shell-*/chrome-win/headless_shell.exe",
]


def find_chromium() -> str | None:
    """返回本机可用的 Chromium 可执行文件路径；找不到返回 None。"""
    env_path = os.environ.get("SFN_CHROMIUM_PATH", "")
    if env_path and Path(env_path).exists():
        return env_path

    candidates: list[str] = []
    for pattern in _CACHE_GLOBS:
        candidates.extend(glob.glob(os.path.expanduser(pattern)))

    if not candidates:
        return None

    # 优先选版本号较大的 chromium（完整版优先于 headless shell）
    def sort_key(p: str):
        headless = "headless" in p
        ver = 0
        for part in Path(p).parts:
            if part.startswith("chromium"):
                digits = "".join(ch for ch in part if ch.isdigit())
                ver = int(digits) if digits else 0
        return (not headless, ver)

    candidates.sort(key=sort_key, reverse=True)
    return candidates[0]


def launch_kwargs() -> dict:
    """带护栏的无头浏览器启动参数。"""
    args = [
        "--no-sandbox",
        "--disable-dev-shm-usage",
        "--disable-infobars",
        "--disable-background-networking",
        "--disable-sync",
        "--no-first-run",
        "--disable-default-apps",
        # 取证模式不需要自动化伪装，保持默认即可；禁自动下载等风险行为
        "--disable-download-notification",
    ]
    kw: dict = {"headless": True, "args": args}
    exe = find_chromium()
    if exe:
        kw["executable_path"] = exe
    return kw
