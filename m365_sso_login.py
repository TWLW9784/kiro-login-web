# -*- coding: utf-8 -*-
"""m365_sso_login.py — Kiro 企业版 / 外部 IdP（Microsoft 365 / Entra ID）SSO 登录编排。

基于 zsecducna/kiro-login-helper 的已验证流程重构为可复用、可配置端口的类，
以支持 kiro-login-web 的并发批量登录（每个任务独占一个回环端口）。

流程（auth-code + PKCE + 本地回环）：
    1. 生成 PKCE verifier/challenge + 反 CSRF state
    2. 构造 https://app.kiro.dev/signin?...（redirect_uri=http://localhost:<port>）
    3. 绑定回环监听 127.0.0.1:<port>（+ [::1]:<port> best-effort）
    4. 浏览器在门户选 "Your organization" → 填邮箱 → 门户做 home realm discovery
       → 302 跳到 /signin/callback 带 external IdP 描述符（issuer_url/client_id/scopes）
       → 本模块 OIDC discover + 跑第二条 auth-code+PKCE，302 到 IdP（M365）
    5. 浏览器在 M365 登录（密码 [+ MFA]）→ code 回到 /oauth/callback
    6. 在 IdP token_endpoint 换 access/refresh
    7. ListAvailableProfiles（带 TokenType: EXTERNAL_IDP）取 profile_arn
    8. 产出 external_idp 凭据 dict

仅用标准库（urllib/http.server/...），不引入第三方依赖。
"""
from __future__ import annotations

import base64
import hashlib
import http.server
import json
import queue
import secrets
import socket
import socketserver
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

# --- 常量（镜像 Kiro IDE / helper） ---
SOCIAL_SIGNIN_BASE_URL = "https://app.kiro.dev/signin"
SOCIAL_REDIRECT_FROM = "KiroIDE"
OAUTH_CALLBACK_PATH = "/oauth/callback"
SOCIAL_AUTH_BASE = "https://prod.us-east-1.auth.desktop.kiro.dev"
SOCIAL_TOKEN_URL = SOCIAL_AUTH_BASE + "/oauth/token"
DEFAULT_REGION = "us-east-1"
KIRO_IDE_VERSION = "0.10.32"
LIST_PROFILES_TARGET = "AmazonCodeWhispererService.ListAvailableProfiles"

# 外部 IdP issuer/endpoint 主机后缀白名单（防 SSRF / 开放重定向）。
ALLOWED_EXTERNAL_IDP_SUFFIXES = (
    ".microsoftonline.com",
    ".microsoftonline.us",
    ".microsoftonline.cn",
)


# --- PKCE ---
def random_url_safe(n: int) -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(n)).rstrip(b"=").decode("ascii")


def pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


# --- IdP 端点校验（SSRF / 开放重定向防护） ---
def validate_external_idp_endpoint(raw_url: str) -> None:
    parsed = urllib.parse.urlparse((raw_url or "").strip())
    if parsed.scheme.lower() != "https":
        raise ValueError("external IdP URL must be https: %r" % raw_url)
    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError("external IdP URL has no host: %r" % raw_url)
    is_ip = False
    for fam in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(fam, host)
            is_ip = True
            break
        except OSError:
            continue
    if is_ip:
        raise ValueError("external IdP host must not be an IP literal: %r" % host)
    for suffix in ALLOWED_EXTERNAL_IDP_SUFFIXES:
        if host.endswith(suffix):
            return
    raise ValueError("external IdP host %r is not allow-listed" % host)


# --- HTTP ---
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect not allowed", headers, fp)


def _opener(proxy_url: Optional[str], follow_redirects: bool = True):
    handlers = []
    if proxy_url:
        handlers.append(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
    else:
        handlers.append(urllib.request.ProxyHandler())
    if not follow_redirects:
        handlers.append(_NoRedirect())
    return urllib.request.build_opener(*handlers)


def http_get_json(url, proxy_url, follow_redirects=True, timeout=30):
    req = urllib.request.Request(url, method="GET", headers={"Accept": "application/json"})
    with _opener(proxy_url, follow_redirects).open(req, timeout=timeout) as resp:
        body = resp.read(1 << 20)
    return json.loads(body.decode("utf-8"))


def http_post_form(url, form, proxy_url, timeout=30):
    data = urllib.parse.urlencode(form).encode("ascii")
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
    )
    return _do_request(req, proxy_url, timeout)


def http_post_json(url, payload, headers, proxy_url, timeout=30):
    data = json.dumps(payload).encode("utf-8")
    base_headers = {"Content-Type": "application/json", "Accept": "application/json"}
    base_headers.update(headers or {})
    req = urllib.request.Request(url, data=data, method="POST", headers=base_headers)
    return _do_request(req, proxy_url, timeout)


def _do_request(req, proxy_url, timeout):
    try:
        with _opener(proxy_url).open(req, timeout=timeout) as resp:
            raw = resp.read()
            status = resp.status
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        status = exc.code
    text = raw.decode("utf-8", "replace")
    parsed = None
    if text.strip():
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None
    return status, parsed, text


# --- OIDC 发现 + token 交换（外部 IdP leg） ---
def oidc_discover(issuer_url, proxy_url):
    validate_external_idp_endpoint(issuer_url)
    doc_url = issuer_url.strip().rstrip("/") + "/.well-known/openid-configuration"
    doc = http_get_json(doc_url, proxy_url, follow_redirects=False)
    auth_endpoint = (doc.get("authorization_endpoint") or "").strip()
    token_endpoint = (doc.get("token_endpoint") or "").strip()
    if not auth_endpoint or not token_endpoint:
        raise ValueError("OIDC discovery missing authorization_endpoint or token_endpoint")
    validate_external_idp_endpoint(auth_endpoint)
    validate_external_idp_endpoint(token_endpoint)
    return auth_endpoint, token_endpoint


def external_idp_authorize_url(auth_endpoint, client_id, redirect_uri, scopes, challenge, state, login_hint):
    q = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": scopes,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "response_mode": "query",
        "state": state,
    }
    if (login_hint or "").strip():
        q["login_hint"] = login_hint
    return auth_endpoint + "?" + urllib.parse.urlencode(q)


def exchange_external_idp_code(token_endpoint, client_id, code, verifier, redirect_uri, scopes, proxy_url):
    form = {
        "client_id": client_id,
        "grant_type": "authorization_code",
        "code": code.strip(),
        "redirect_uri": redirect_uri,
        "code_verifier": verifier,
    }
    if (scopes or "").strip():
        form["scope"] = scopes
    status, parsed, text = http_post_form(token_endpoint, form, proxy_url)
    parsed = parsed or {}
    access = parsed.get("access_token", "")
    if not (200 <= status < 300) or not access:
        err = parsed.get("error", "")
        desc = parsed.get("error_description", "")
        if err:
            raise RuntimeError("external IdP token exchange failed (status %d): %s: %s" % (status, err, desc))
        raise RuntimeError("external IdP token exchange failed (status %d): %s" % (status, text[:200]))
    return access, parsed.get("refresh_token", ""), int(parsed.get("expires_in", 0) or 0), ""


def exchange_social_code(code, verifier, redirect_uri, proxy_url):
    payload = {"code": code.strip(), "code_verifier": verifier, "redirect_uri": redirect_uri}
    status, parsed, text = http_post_json(SOCIAL_TOKEN_URL, payload, None, proxy_url)
    parsed = parsed or {}
    access = parsed.get("accessToken", "")
    if not (200 <= status < 300) or not access:
        raise RuntimeError("social token exchange failed (status %d): %s" % (status, text[:200]))
    return (access, parsed.get("refreshToken", ""), int(parsed.get("expiresIn", 0) or 0),
            parsed.get("profileArn", "") or "")


# --- profile ARN 解析 ---
def build_machine_id(*parts):
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def build_user_agent(machine_id):
    return ("aws-sdk-js/1.0.0 ua/2.1 os/windows#10.0.26200 lang/js md/nodejs#22.21.1 "
            "api/codewhispererruntime#1.0.0 m/N,E KiroIDE-%s-%s" % (KIRO_IDE_VERSION, machine_id))


def build_x_amz_user_agent(machine_id):
    return "aws-sdk-js/1.0.0 KiroIDE-%s-%s" % (KIRO_IDE_VERSION, machine_id)


def codewhisperer_host(region):
    return "q.%s.amazonaws.com" % region


def list_available_profiles(access_token, region, external_idp, proxy_url):
    if not access_token.strip():
        raise ValueError("access token is empty")
    machine_id = build_machine_id(access_token)
    url = "https://%s/" % codewhisperer_host(region)
    headers = {
        "Content-Type": "application/x-amz-json-1.0",
        "Accept": "application/x-amz-json-1.0",
        "Authorization": "Bearer " + access_token,
        "X-Amz-Target": LIST_PROFILES_TARGET,
        "amz-sdk-invocation-id": build_machine_id(access_token, region, "list-profiles"),
        "amz-sdk-request": "attempt=1; max=1",
        "x-amzn-kiro-agent-mode": "vibe",
        "x-amzn-codewhisperer-optout": "true",
        "User-Agent": build_user_agent(machine_id),
        "x-amz-user-agent": build_x_amz_user_agent(machine_id),
    }
    if external_idp:
        headers["TokenType"] = "EXTERNAL_IDP"
    req = urllib.request.Request(url, data=b"{}", method="POST", headers=headers)
    status, parsed, text = _do_request(req, proxy_url, timeout=30)
    if not (200 <= status < 300):
        raise RuntimeError("list-profiles failed (status %d): %s" % (status, text[:200]))
    profiles = []
    for prof in (parsed or {}).get("profiles", []) or []:
        arn = (prof.get("arn") or "").strip()
        if arn:
            profiles.append({"arn": arn, "name": prof.get("profileName") or prof.get("name") or ""})
    return profiles


def region_from_profile_arn(profile_arn):
    parts = (profile_arn or "").strip().split(":")
    if len(parts) >= 4:
        return parts[3].strip()
    return ""


# --- JWT / username ---
def decode_jwt_claims(token):
    parts = (token or "").strip().split(".")
    if len(parts) < 2:
        return {}
    seg = parts[1]
    padded = seg + "=" * (-len(seg) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded)
        return json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return {}


def derive_username(access_token):
    claims = decode_jwt_claims(access_token)
    for key in ("preferred_username", "email", "upn", "unique_name", "name", "oid", "sub"):
        val = (claims.get(key) or "").strip()
        if val:
            return val
    return ""


# --- 回环监听 ---
class FlowState:
    def __init__(self, portal_state, proxy_url, redirect_base):
        self.portal_state = portal_state
        self.proxy_url = proxy_url
        self.redirect_base = redirect_base  # http://localhost:<port>
        self.lock = threading.Lock()
        self.leg2 = None
        self.result_queue = queue.Queue(maxsize=1)
        self._delivered = False

    def deliver(self, result):
        with self.lock:
            if self._delivered:
                return
            self._delivered = True
        self.result_queue.put(result)


class CallbackHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _html(self, ok):
        msg = ("Kiro sign-in complete. You can close this tab and return to the terminal."
               if ok else "Kiro sign-in failed. Return to the terminal and try again.")
        body = ('<!doctype html><html><head><meta charset="utf-8"><title>Kiro Sign-In</title></head>'
                '<body style="font-family:sans-serif;padding:2rem"><p>%s</p></body></html>' % msg).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _empty(self, code=204):
        self.send_response(code)
        self.end_headers()

    def do_GET(self):
        state = self.server.flow_state
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        q = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}

        is_descriptor = (q.get("login_option", "").strip().lower() == "external_idp") or bool(q.get("issuer_url", "").strip())
        if path != OAUTH_CALLBACK_PATH and is_descriptor:
            with state.lock:
                already = state.leg2 is not None
            if already:
                return self._empty()
            issuer_url = q.get("issuer_url", "").strip()
            client_id = q.get("client_id", "").strip()
            scopes = q.get("scopes", "").strip()
            login_hint = q.get("login_hint", "").strip()
            if not client_id:
                self._html(False)
                state.deliver(RuntimeError("invalid external IdP descriptor (missing client_id)"))
                return
            try:
                auth_endpoint, token_endpoint = oidc_discover(issuer_url, state.proxy_url)
            except Exception as exc:
                self._html(False)
                state.deliver(exc)
                return
            verifier = random_url_safe(96)
            state2 = random_url_safe(32)
            redirect_uri = state.redirect_base + OAUTH_CALLBACK_PATH
            with state.lock:
                if state.leg2 is not None:
                    return self._empty()
                state.leg2 = {
                    "state": state2, "verifier": verifier, "token_endpoint": token_endpoint,
                    "issuer_url": issuer_url, "client_id": client_id, "scopes": scopes,
                    "redirect_uri": redirect_uri,
                }
            auth_url = external_idp_authorize_url(
                auth_endpoint, client_id, redirect_uri, scopes, pkce_challenge(verifier), state2, login_hint)
            self.send_response(302)
            self.send_header("Location", auth_url)
            self.end_headers()
            return

        if path == OAUTH_CALLBACK_PATH:
            with state.lock:
                ctx2 = state.leg2
            code = q.get("code", "").strip()
            cb_state = q.get("state", "").strip()
            err = q.get("error", "").strip()
            if ctx2 is None or not cb_state or cb_state != ctx2["state"]:
                return self._empty()
            if err:
                desc = q.get("error_description", "").strip()
                self._html(False)
                state.deliver(RuntimeError("external IdP authorization error: %s %s" % (err, desc)))
                return
            if not code:
                return self._empty()
            self._html(True)
            state.deliver({"kind": "external_idp", "code": code, **ctx2})
            return

        # social leg
        code = q.get("code", "").strip()
        err = q.get("error", "").strip()
        cb_state = q.get("state", "").strip()
        if not code and not err:
            return self._empty()
        if not state.portal_state or cb_state != state.portal_state:
            return self._empty()
        if err:
            desc = q.get("error_description", "").strip()
            self._html(False)
            state.deliver(RuntimeError("SSO authorization error: %s %s" % (err, desc)))
            return
        self._html(True)
        state.deliver({"kind": "social", "code": code})


class _V4Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class _V6Server(_V4Server):
    address_family = socket.AF_INET6


# --- 会话编排类 ---
@dataclass
class M365LoginResult:
    ok: bool
    error: str = ""
    auth_method: str = ""
    access_token: str = ""
    refresh_token: str = ""
    expires_in: int = 0
    client_id: str = ""
    issuer_url: str = ""
    token_endpoint: str = ""
    scopes: str = ""
    profile_arn: str = ""
    region: str = DEFAULT_REGION
    username: str = ""
    profiles: list = field(default_factory=list)


class M365LoginSession:
    """单账号 M365/外部 IdP SSO 登录会话；端口可配置以支持并发。

    用法：
        sess = M365LoginSession(port=3130, proxy_url=None, region="us-east-1")
        signin_url = sess.start()            # 绑监听 + 返回 signin URL
        # 用浏览器驱动 signin_url 完成 M365 登录
        result = sess.wait_and_exchange(timeout=300)
        sess.close()
    """

    def __init__(self, port: int, proxy_url: Optional[str] = None, region: str = DEFAULT_REGION,
                 log: Optional[Callable[[str], None]] = None):
        self.port = port
        self.proxy_url = proxy_url or None
        self.region = region or DEFAULT_REGION
        self.log = log or (lambda m: None)
        self.redirect_base = "http://localhost:%d" % port
        self.verifier = random_url_safe(96)
        self.state = random_url_safe(32)
        self.servers: list = []
        self.flow_state: Optional[FlowState] = None
        self.signin_url = ""

    def start(self) -> str:
        challenge = pkce_challenge(self.verifier)
        self.signin_url = SOCIAL_SIGNIN_BASE_URL + "?" + urllib.parse.urlencode({
            "state": self.state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "redirect_uri": self.redirect_base,
            "redirect_from": SOCIAL_REDIRECT_FROM,
        })
        self.flow_state = FlowState(self.state, self.proxy_url, self.redirect_base)
        try:
            v4 = _V4Server(("127.0.0.1", self.port), CallbackHandler)
        except OSError as exc:
            raise RuntimeError("无法绑定回环 127.0.0.1:%d（端口被占用？）：%s" % (self.port, exc))
        v4.flow_state = self.flow_state
        self.servers.append(v4)
        try:
            v6 = _V6Server(("::1", self.port), CallbackHandler)
            v6.flow_state = self.flow_state
            self.servers.append(v6)
        except OSError:
            pass
        for srv in self.servers:
            threading.Thread(target=srv.serve_forever, daemon=True).start()
        return self.signin_url

    def wait_and_exchange(self, timeout: int = 300, stop_event: "threading.Event | None" = None) -> M365LoginResult:
        assert self.flow_state is not None, "call start() first"
        deadline = time.time() + timeout
        result = None
        while time.time() < deadline:
            if stop_event is not None and stop_event.is_set():
                return M365LoginResult(False, error="已中断")
            try:
                result = self.flow_state.result_queue.get(timeout=1.0)
                break
            except queue.Empty:
                continue
        if result is None:
            return M365LoginResult(False, error="SSO 登录超时（%ds 内未完成）" % timeout)
        if isinstance(result, Exception):
            return M365LoginResult(False, error=str(result))

        region = self.region or DEFAULT_REGION
        try:
            if result["kind"] == "external_idp":
                access, refresh, expires_in, _ = exchange_external_idp_code(
                    result["token_endpoint"], result["client_id"], result["code"],
                    result["verifier"], result["redirect_uri"], result["scopes"], self.proxy_url)
                out = M365LoginResult(
                    True, auth_method="external_idp", access_token=access, refresh_token=refresh,
                    expires_in=expires_in, client_id=result["client_id"],
                    issuer_url=result["issuer_url"], token_endpoint=result["token_endpoint"],
                    scopes=result["scopes"], region=region)
                external_idp = True
            else:
                access, refresh, expires_in, profile_arn = exchange_social_code(
                    result["code"], self.verifier, self.redirect_base, self.proxy_url)
                out = M365LoginResult(
                    True, auth_method="social", access_token=access, refresh_token=refresh,
                    expires_in=expires_in, profile_arn=profile_arn, region=region)
                external_idp = False
        except Exception as exc:
            return M365LoginResult(False, error="token 交换失败：%s" % exc)

        # 解析 profile ARN
        if not out.profile_arn:
            try:
                profs = list_available_profiles(out.access_token, region, external_idp, self.proxy_url)
                out.profiles = profs
                if profs:
                    out.profile_arn = profs[0]["arn"]
            except Exception as exc:
                return M365LoginResult(False, error="解析 profile ARN 失败：%s" % exc)
        if not out.profile_arn:
            return M365LoginResult(False, error="登录成功但未获取到 profile ARN（账号可能未开通 Kiro/CodeWhisperer）")
        arn_region = region_from_profile_arn(out.profile_arn)
        if arn_region:
            out.region = arn_region
        out.username = derive_username(out.access_token)
        return out

    def close(self) -> None:
        for srv in self.servers:
            try:
                srv.shutdown()
            except Exception:
                pass
        self.servers = []


def build_auth_json(result: M365LoginResult) -> dict:
    """产出 CLIProxyAPI 兼容的 Kiro 凭据 dict（external_idp 无 client_secret）。"""
    obj = {
        "access_token": result.access_token,
        "auth_method": result.auth_method,
        "disabled": False,
        "refresh_token": result.refresh_token,
        "region": result.region,
        "timestamp": int(time.time() * 1000),
        "type": "kiro",
    }
    if result.expires_in > 0:
        expires_at = int(time.time()) + result.expires_in
        obj["expired"] = datetime.fromtimestamp(expires_at, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if result.profile_arn:
        obj["profile_arn"] = result.profile_arn
    if result.client_id:
        obj["client_id"] = result.client_id
    if result.token_endpoint:
        obj["token_endpoint"] = result.token_endpoint
    if result.issuer_url:
        obj["issuer_url"] = result.issuer_url
    if result.scopes:
        obj["scopes"] = result.scopes
    return obj
