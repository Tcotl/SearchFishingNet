"""认证 API：登录/登出/会话查询/修改口令。"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, Response

from . import auth

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _session_token(request: Request) -> str:
    return request.cookies.get(auth.COOKIE_NAME, "")


@router.post("/login")
def login(body: dict, response: Response):
    username = str(body.get("username") or "").strip()
    password = str(body.get("password") or "")
    if not auth.verify_credentials(username, password):
        raise HTTPException(401, "用户名或口令错误")
    token = auth.create_session(username)
    response.set_cookie(auth.COOKIE_NAME, token, max_age=auth.SESSION_TTL,
                        httponly=True, samesite="lax", path="/")
    return {"ok": True, "username": username}


@router.get("/me")
def me(request: Request):
    user = auth.validate_session(_session_token(request))
    if not user:
        raise HTTPException(401, "未登录")
    return {"username": user}


@router.post("/logout")
def logout(request: Request, response: Response):
    token = _session_token(request)
    if token:
        auth.revoke_session(token)
    response.delete_cookie(auth.COOKIE_NAME, path="/")
    return {"ok": True}


@router.post("/change-password")
def change_password(body: dict, request: Request):
    user = auth.validate_session(_session_token(request))
    if not user:
        raise HTTPException(401, "未登录")
    old = str(body.get("old_password") or "")
    new = str(body.get("new_password") or "")
    if new != str(body.get("confirm_password") or new):
        raise HTTPException(400, "两次输入的新口令不一致")
    try:
        ok = auth.change_password(old, new)
    except ValueError as e:
        raise HTTPException(400, str(e)) from None
    if not ok:
        raise HTTPException(401, "原口令错误")
    return {"ok": True}
