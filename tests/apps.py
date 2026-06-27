"""In-process FastAPI applications used as scan targets in tests.

Two apps are provided: a deliberately *vulnerable* login app and a *secure*
one. They are served in-process through ``httpx.ASGITransport`` so integration
tests never touch the network. The vulnerable app is intentionally insecure for
testing AuthRadar; it must never be deployed.
"""

from __future__ import annotations

import uuid
from collections import Counter
from typing import Annotated

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response

VALID_USER = "alice"
VALID_PASSWORD = "correct-horse-battery-staple"

_INDEX_HTML = """<!doctype html><html><body>
<a href="/login">Login</a> <a href="/dashboard">Dashboard</a> <a href="/logout">Logout</a>
</body></html>"""

_VULN_LOGIN_HTML = """<!doctype html><html><body>
<form method="post" action="/login">
  <input type="text" name="username">
  <input type="password" name="password">
  <button type="submit">Sign in</button>
</form></body></html>"""

_SECURE_LOGIN_HTML = """<!doctype html><html><body>
<form method="post" action="/login">
  <input type="hidden" name="csrf_token" value="tok-123">
  <input type="text" name="username">
  <input type="password" name="password">
  <button type="submit">Sign in</button>
</form></body></html>"""


def build_vulnerable_app() -> FastAPI:
    """A login app exhibiting many authentication weaknesses."""
    app = FastAPI()
    sessions: dict[str, bool] = {}

    @app.get("/", response_class=HTMLResponse)
    async def index() -> str:
        return _INDEX_HTML

    @app.get("/login", response_class=HTMLResponse)
    async def login_form(request: Request) -> Response:
        sid = request.cookies.get("SID") or uuid.uuid4().hex
        response = HTMLResponse(_VULN_LOGIN_HTML)
        response.set_cookie("SID", sid, samesite=None)  # no Secure/HttpOnly/SameSite
        return response

    @app.post("/login")
    async def login(
        request: Request,
        username: Annotated[str, Form()],
        password: Annotated[str, Form()],
    ) -> Response:
        sid = request.cookies.get("SID") or uuid.uuid4().hex
        if username == VALID_USER and password == VALID_PASSWORD:
            sessions[sid] = True  # session NOT rotated -> fixation
            return RedirectResponse("/dashboard", status_code=302)
        if username == VALID_USER:
            return PlainTextResponse("incorrect password", status_code=200)
        return PlainTextResponse("user not found", status_code=200)  # enumeration

    @app.get("/dashboard")
    async def dashboard(request: Request) -> Response:
        sid = request.cookies.get("SID", "")
        if sessions.get(sid):
            return PlainTextResponse("welcome to your dashboard")
        return PlainTextResponse("unauthorized", status_code=401)

    @app.get("/logout")
    async def logout() -> Response:
        return PlainTextResponse("bye")  # does NOT invalidate the session

    return app


def build_secure_app() -> FastAPI:
    """A login app following authentication best practices."""
    app = FastAPI()
    sessions: dict[str, bool] = {}
    failures: Counter[str] = Counter()

    @app.get("/", response_class=HTMLResponse)
    async def index() -> str:
        return _INDEX_HTML

    @app.get("/login", response_class=HTMLResponse)
    async def login_form(request: Request) -> Response:
        sid = request.cookies.get("SID") or uuid.uuid4().hex
        response = HTMLResponse(_SECURE_LOGIN_HTML)
        response.set_cookie("SID", sid, secure=True, httponly=True, samesite="lax")
        return response

    @app.post("/login")
    async def login(
        request: Request,
        username: Annotated[str, Form()],
        password: Annotated[str, Form()],
    ) -> Response:
        if failures[username] >= 5:
            return PlainTextResponse("too many attempts, try again later", status_code=429)
        if username == VALID_USER and password == VALID_PASSWORD:
            failures[username] = 0
            new_sid = uuid.uuid4().hex
            sessions[new_sid] = True  # rotate session on login
            response = RedirectResponse("/dashboard", status_code=302)
            response.set_cookie("SID", new_sid, secure=True, httponly=True, samesite="lax")
            return response
        failures[username] += 1
        return PlainTextResponse("invalid credentials", status_code=401)  # generic

    @app.get("/dashboard")
    async def dashboard(request: Request) -> Response:
        sid = request.cookies.get("SID", "")
        if sessions.get(sid):
            return PlainTextResponse("welcome to your dashboard")
        return PlainTextResponse("unauthorized", status_code=401)

    @app.get("/logout")
    async def logout(request: Request) -> Response:
        sid = request.cookies.get("SID", "")
        sessions.pop(sid, None)  # invalidate server-side
        return PlainTextResponse("bye")

    return app
