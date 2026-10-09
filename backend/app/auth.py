"""平台后台认证：用户名/口令登录 + 会话管理。

- 凭据存于 data/config/auth.json（加盐 SHA256，默认 admin/admin，首次访问自动初始化）；
- 会话令牌存于 data/config/sessions.json（跨重启有效，7 天过期）；
- 浏览器侧通过 HttpOnly Cookie（sfn_session）携带，EventSource/静态资源同源自动带上；
- 机器间调用可用环境变量 SFN_API_TOKEN 走 Bearer 旁路（导出/下载类消费方）。
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time

from . import store

COOKIE_NAME = "sfn_session"
SESSION_TTL = 7 * 24 * 3600
DEFAULT_USER, DEFAULT_PASSWORD = "admin", "admin"

_lock = threading.RLock()


def _hash(password: str, salt: str) -> str:
    return hashlib.sha256((salt + ":" + password).encode()).hexdigest()


# ---------------- 凭据 ----------------

def _load_credentials() -> dict:
    """读取凭据文件；不存在则以默认 admin/admin 初始化。"""
    with _lock:
        path = store.CONF_DIR / "auth.json"
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                pass
        salt = secrets.token_hex(8)
        cred = {"username": DEFAULT_USER, "salt": salt,
                "password_hash": _hash(DEFAULT_PASSWORD, salt)}
        path.write_text(json.dumps(cred, ensure_ascii=False), encoding="utf-8")
        return cred


def verify_credentials(username: str, password: str) -> bool:
    cred = _load_credentials()
    ok_user = hmac.compare_digest(str(username), cred.get("username", ""))
    ok_pass = hmac.compare_digest(_hash(password or "", cred.get("salt", "")),
                                  cred.get("password_hash", ""))
    return ok_user and ok_pass


def change_password(old_password: str, new_password: str) -> bool:
    if not verify_credentials(_load_credentials().get("username", ""), old_password):
        return False
    if len(new_password or "") < 5:
        raise ValueError("新口令至少 5 位")
    with _lock:
        cred = _load_credentials()
        cred["salt"] = secrets.token_hex(8)
        cred["password_hash"] = _hash(new_password, cred["salt"])
        (store.CONF_DIR / "auth.json").write_text(
            json.dumps(cred, ensure_ascii=False), encoding="utf-8")
    return True


# ---------------- 会话 ----------------

def _load_sessions() -> dict:
    with _lock:
        path = store.CONF_DIR / "sessions.json"
        if not path.exists():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}
    now = time.time()
    return {t: s for t, s in data.items() if isinstance(s, dict) and s.get("expires", 0) > now}


def _save_sessions(sessions: dict) -> None:
    with _lock:
        (store.CONF_DIR / "sessions.json").write_text(
            json.dumps(sessions, ensure_ascii=False), encoding="utf-8")


def create_session(username: str) -> str:
    token = secrets.token_urlsafe(32)
    with _lock:
        sessions = _load_sessions()
        sessions[token] = {"user": username, "expires": time.time() + SESSION_TTL}
        _save_sessions(sessions)
    return token


def validate_session(token: str) -> str | None:
    """令牌有效返回用户名，否则 None。"""
    if not token:
        return None
    sessions = _load_sessions()
    s = sessions.get(token)
    if not s or s.get("expires", 0) < time.time():
        return None
    return str(s.get("user") or "")


def revoke_session(token: str) -> None:
    with _lock:
        sessions = _load_sessions()
        if token in sessions:
            sessions.pop(token)
            _save_sessions(sessions)
