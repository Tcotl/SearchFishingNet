"""SearchFishingNet 平台后端：FastAPI 应用。

开发模式: uvicorn backend.app.main:app --reload --port 8765
生产模式: python backend/run.py  （同端口托管前端构建产物）
"""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from . import auth, store
from .routers_auth import router as auth_router
from .routers_jobs import router as jobs_router, set_executor
from .routers_records import router as records_router
from .routers_dashboard import router as dashboard_router
from .routers_blocklist import router as blocklist_router
from .routers_dict import router as dict_router
from .routers_settings import router as settings_router
from .routers_samples import router as samples_router

app = FastAPI(title="SearchFishingNet", version="1.0.0",
              description="基于搜索引擎的钓鱼网络威胁情报平台")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],  # Vite dev
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)

API_TOKEN = os.environ.get("SFN_API_TOKEN", "")

# 免鉴权路径：登录接口与独立登录口（含其背景图）
AUTH_EXEMPT = ("/api/auth/login", "/login", "/login-bg")
LOGIN_HTML = Path(__file__).resolve().parent / "login.html"
LOGIN_BG = Path(__file__).resolve().parent / "login_bg.svg"


def _redirect_login(request: Request):
    target = request.url.path
    if request.url.query:
        target += f"?{request.url.query}"
    from urllib.parse import quote
    return RedirectResponse(f"/login?redirect={quote(target, safe='')}", status_code=302)


@app.middleware("http")
async def auth_guard(request: Request, call_next):
    """统一鉴权：/api 走 401 JSON；后台页面未登录 302 到独立登录口 /login。

    - 浏览器：会话 Cookie（sfn_session）；
    - 机器调用：Bearer 静态令牌（SFN_API_TOKEN）；
    - 管理后台 SPA 的任何字节都不会在未登录时下发。
    """
    path = request.url.path
    if path in AUTH_EXEMPT:
        return await call_next(request)
    if path.startswith("/api"):
        user = auth.validate_session(request.cookies.get(auth.COOKIE_NAME, ""))
        if not user and API_TOKEN and request.headers.get("authorization", "") == f"Bearer {API_TOKEN}":
            user = "api-token"
        if not user:
            # 中间件内 raise HTTPException 不会被异常处理器转换，需直接返回响应
            return JSONResponse({"detail": "未登录或会话已过期"}, status_code=401)
    elif not auth.validate_session(request.cookies.get(auth.COOKIE_NAME, "")):
        # 非 API（后台 SPA 页面/静态资源）：未登录一律重定向独立登录口
        return _redirect_login(request)
    return await call_next(request)


@app.get("/login", include_in_schema=False)
def login_entry():
    """独立登录口：自包含页面，不依赖管理后台 SPA。"""
    return FileResponse(LOGIN_HTML, media_type="text/html")


@app.get("/login-bg", include_in_schema=False)
def login_bg():
    """登录页背景图（免鉴权，随登录口一起访问）。"""
    return FileResponse(LOGIN_BG, media_type="image/svg+xml")


app.include_router(auth_router)
app.include_router(jobs_router)
app.include_router(records_router)
app.include_router(dashboard_router)
app.include_router(blocklist_router)
app.include_router(dict_router)
app.include_router(settings_router)
app.include_router(samples_router)

_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="sfn-job")
set_executor(_EXECUTOR)


@app.on_event("startup")
def startup():
    store.apply_settings()


# ---------------- 前端静态托管（生产模式） ----------------

FRONTEND_DIST = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"
if FRONTEND_DIST.exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa_fallback(full_path: str):
        candidate = FRONTEND_DIST / full_path
        if full_path and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(FRONTEND_DIST / "index.html")
