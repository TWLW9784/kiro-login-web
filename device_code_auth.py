# -*- coding: utf-8 -*-
"""
device_code_auth.py — Login Kiro qua AWS SSO OIDC device-code flow,
xuat ra JSON DURABLE day du (refresh_token + client_id + client_secret + profile_arn).

Clone dung luong 9router /api/oauth/kiro/device-code:
    1. RegisterClient        -> client_id + client_secret  (DURABLE)
    2. StartDeviceAuthorization -> user_code + verification_uri (login browser)
    3. CreateToken (poll)    -> access_token + refresh_token + expiresIn (DURABLE)
    4. ListAvailableProfiles -> profile_arn  (de KHONG bi 403)

Khac voi web-refresh (cookie ~7 ngay): token o day co refresh_token that ->
9router tu refresh HANG THANG.

Config OIDC (trich tu source 9router chunks/5339.js):
    register:    https://oidc.{region}.amazonaws.com/client/register
    deviceauth:  https://oidc.{region}.amazonaws.com/device_authorization
    token:       https://oidc.{region}.amazonaws.com/token
    clientName:  kiro-oauth-client   (public)
    scopes:      codewhisperer:completions/analysis/conversations
    grantTypes:  device_code, refresh_token
    issuerUrl:   https://identitycenter.amazonaws.com/ssoins-722374e8c3c8e6c6
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import ssl
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Callable, Optional
from urllib.parse import urlparse

# --- Config (clone tu 9router) ---
KIRO_CLIENT_NAME = "kiro-oauth-client"
KIRO_CLIENT_TYPE = "public"
KIRO_SCOPES = [
    "codewhisperer:completions",
    "codewhisperer:analysis",
    "codewhisperer:conversations",
]
KIRO_GRANT_TYPES = [
    "urn:ietf:params:oauth:grant-type:device_code",
    "refresh_token",
]
KIRO_ISSUER_URL = "https://identitycenter.amazonaws.com/ssoins-722374e8c3c8e6c6"
BUILDER_ID_START_URL = "https://view.awsapps.com/start"

# HAI region KHAC NHAU:
# - OIDC (login IAM device-code): phai trung region IAM Identity Center cua ban
#   (IDC d-9066713dd7 thuong la us-east-1). Dung eu-central-1 o day -> HTTP 400 invalid_request.
# - Kiro Q API (quota 9router / ListAvailableProfiles): eu-central-1 cho workspace EU.
DEFAULT_OIDC_REGION = "us-east-1"
DEFAULT_KIRO_REGION = "us-east-1"
REGION_OPTIONS = (
    "us-east-1",
    "us-east-2",
    "us-west-2",
    "eu-central-1",
    "eu-west-1",
    "eu-west-2",
    "eu-north-1",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-south-1",
    "ca-central-1",
    "sa-east-1",
)
KIRO_REGION_OPTIONS = REGION_OPTIONS  # alias

# ListAvailableProfiles (de lay profileArn) — CodeWhisperer/Q endpoint
CW_ENDPOINT_TMPL = "https://q.{region}.amazonaws.com/"
CW_LIST_PROFILES_TARGET = "AmazonCodeWhispererService.ListAvailableProfiles"
KIRO_PROFILE_API_VERSION = "0.12.333"
Q_GENERATE_TARGET = "generateAssistantResponse"
KIRO_MGMT_BASE_TMPL = "https://management.{region}.kiro.dev/"
KIRO_MGMT_SERVICE = "KiroControlPlaneBearerService"
KIRO_MGMT_TARGET_GET_PROFILE = f"{KIRO_MGMT_SERVICE}.GetProfile"
KIRO_MGMT_TARGET_LIST_KEYS = f"{KIRO_MGMT_SERVICE}.ListApiKeys"
KIRO_MGMT_TARGET_CREATE_KEY = f"{KIRO_MGMT_SERVICE}.CreateApiKey"


def normalize_region(region: str, default: str) -> str:
    r = (region or default).strip()
    return r if r in REGION_OPTIONS else default


def normalize_oidc_region(region: str) -> str:
    return normalize_region(region, DEFAULT_OIDC_REGION)


def normalize_kiro_region(region: str) -> str:
    return normalize_region(region, DEFAULT_KIRO_REGION)


def region_from_profile_arn(arn: str) -> str:
    """Trich region tu arn:aws:codewhisperer:REGION:... (neu co)."""
    parts = (arn or "").split(":")
    if len(parts) >= 4 and parts[2] == "codewhisperer" and parts[3]:
        return parts[3]
    return ""


def kiro_q_url(region: str, path: str = "") -> str:
    r = normalize_kiro_region(region)
    base = CW_ENDPOINT_TMPL.format(region=r)
    return base + path.lstrip("/") if path else base


def kiro_mgmt_url(region: str) -> str:
    return KIRO_MGMT_BASE_TMPL.format(region=normalize_kiro_region(region))


def _oidc_base(region: str) -> str:
    r = (region or "").strip().lower()
    # 信任任何合法 region 格式（如 us-east-1 / ap-south-1）；否则走白名单回退
    if not re.match(r"^[a-z]{2}-[a-z]+-\d+$", r):
        r = normalize_oidc_region(region)
    return f"https://oidc.{r}.amazonaws.com"


def derive_from_start_url(start_url: str) -> tuple[str, str]:
    """从 start_url 提取 (region, issuer_url)。

    支持新版 SSO Portal URL：https://ssoins-XXXX.portal.<region>.app.aws[/...]
      -> region = <region>；issuer_url = https://identitycenter.amazonaws.com/ssoins-XXXX
    老版 d-xxx.awsapps.com/start 无法从 URL 直接拿到实例 ID，返回空值（由调用方回退默认）。
    返回 (region, issuer_url)，拿不到的部分为 ""。
    """
    url = (start_url or "").strip()
    if not url:
        return "", ""
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        return "", ""
    host = host.lower()
    # 新版：ssoins-XXXX.portal.<region>.app.aws
    m = re.match(r"^(ssoins-[0-9a-f]+)\.portal\.([a-z0-9-]+)\.app\.aws$", host)
    if m:
        instance_id = m.group(1)
        region = m.group(2)
        issuer_url = f"https://identitycenter.amazonaws.com/{instance_id}"
        return region, issuer_url
    return "", ""


def _post_json(url: str, body: dict, headers: Optional[dict] = None,
               timeout: float = 30.0) -> tuple[int, dict]:
    raw = json.dumps(body).encode("utf-8")
    h = {"Content-Type": "application/json", "Accept": "application/json"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=raw, method="POST", headers=h)
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            txt = r.read().decode("utf-8", "replace")
            try:
                return r.status, json.loads(txt)
            except Exception:
                return r.status, {"_raw": txt}
    except urllib.error.HTTPError as e:
        txt = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(txt)
        except Exception:
            return e.code, {"_raw": txt}


@dataclass
class DeviceAuthStart:
    """Ket qua buoc StartDeviceAuthorization — hien cho user de login."""
    ok: bool
    client_id: str = ""
    client_secret: str = ""
    device_code: str = ""
    user_code: str = ""
    verification_uri: str = ""
    verification_uri_complete: str = ""
    expires_in: int = 0
    interval: int = 5
    oidc_region: str = DEFAULT_OIDC_REGION
    kiro_region: str = DEFAULT_KIRO_REGION
    auth_method: str = "idc"
    start_url: str = ""
    error: str = ""

    @property
    def region(self) -> str:
        """Backward compat: OIDC region dung cho poll token."""
        return self.oidc_region


@dataclass
class DurableExport:
    """JSON durable day du sau khi login xong."""
    access_token: str = ""
    refresh_token: str = ""
    expires_in: int = 0
    expires_at: str = ""
    profile_arn: str = ""
    client_id: str = ""
    client_secret: str = ""
    region: str = DEFAULT_KIRO_REGION
    oidc_region: str = DEFAULT_OIDC_REGION
    auth_method: str = "idc"
    start_url: str = ""
    email: str = ""
    error: str = ""

    def is_durable(self) -> bool:
        return bool(self.refresh_token and self.client_id and self.client_secret)

    def to_full_json(self) -> dict:
        """Dinh dang snake_case full — parse_kiro_export doc duoc + durable."""
        return {
            "type": "kiro",
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "expires_in": self.expires_in,
            "expires_at": self.expires_at,
            "profile_arn": self.profile_arn,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "region": self.region,
            "oidc_region": self.oidc_region,
            "auth_method": self.auth_method,
            "start_url": self.start_url,
            "email": self.email,
        }


def register_and_start(
    oidc_region: str = DEFAULT_OIDC_REGION,
    kiro_region: str = DEFAULT_KIRO_REGION,
    auth_method: str = "idc",
    start_url: str = "",
    log: Callable[[str], None] = print,
    *,
    region: str = "",  # deprecated alias -> oidc_region
) -> DeviceAuthStart:
    """Buoc 1+2: RegisterClient + StartDeviceAuthorization.

    Tra ve DeviceAuthStart co user_code + verification_uri_complete de login browser.
    """
    if region:
        oidc_region = region
    start_url = (start_url or "").strip() or BUILDER_ID_START_URL
    # 新版 SSO Portal URL：从 URL 自动提取 region 与实例 ID（issuerUrl），
    # 避免 UI 选错 region 或写死的 issuerUrl 与实际实例不匹配。
    derived_region, derived_issuer = derive_from_start_url(start_url)
    issuer_url = derived_issuer or KIRO_ISSUER_URL
    if derived_region:
        # 从真实 Portal URL 提取的 region 是权威值，直接用，不走白名单回退
        oidc_region = derived_region
    else:
        oidc_region = normalize_oidc_region(oidc_region)
    kiro_region = normalize_kiro_region(kiro_region)
    log(f"device-code: OIDC={oidc_region} (login IAM) · Kiro Q={kiro_region} (9router quota)")
    auth_method = "idc" if auth_method == "idc" else "builder-id"
    if derived_issuer:
        log(f"device-code: 从 Portal URL 提取实例 issuer={derived_issuer} region={derived_region}")

    # 1. RegisterClient
    log("device-code: RegisterClient ...")
    reg_status, reg = _post_json(
        _oidc_base(oidc_region) + "/client/register",
        {
            "clientName": KIRO_CLIENT_NAME,
            "clientType": KIRO_CLIENT_TYPE,
            "scopes": KIRO_SCOPES,
            "grantTypes": KIRO_GRANT_TYPES,
            "issuerUrl": issuer_url,
        },
    )
    client_id = reg.get("clientId")
    client_secret = reg.get("clientSecret")
    if reg_status >= 400 or not client_id or not client_secret:
        return DeviceAuthStart(
            ok=False,
            error=f"RegisterClient that bai (HTTP {reg_status}): "
                  f"{reg.get('_raw') or reg}",
        )
    log(f"  client_id: {client_id[:20]}...  (secret len={len(client_secret)})")

    # 2. StartDeviceAuthorization
    log("device-code: StartDeviceAuthorization ...")
    da_status, da = _post_json(
        _oidc_base(oidc_region) + "/device_authorization",
        {
            "clientId": client_id,
            "clientSecret": client_secret,
            "startUrl": start_url,
        },
    )
    device_code = da.get("deviceCode")
    user_code = da.get("userCode")
    if da_status >= 400 or not device_code:
        hint = ""
        if da_status == 400 and oidc_region != DEFAULT_OIDC_REGION:
            hint = (f" (Go y: OIDC region phai trung IAM Identity Center — "
                    f"thu {DEFAULT_OIDC_REGION} o muc 'OIDC region (login IAM)')")
        elif da_status == 400:
            hint = " (Kiem tra IDC start URL co dung d-xxx.awsapps.com/start khong)"
        return DeviceAuthStart(
            ok=False,
            error=f"DeviceAuthorization that bai (HTTP {da_status}): "
                  f"{da.get('_raw') or da}{hint}",
        )
    log(f"  user_code: {user_code}")
    log(f"  verify: {da.get('verificationUriComplete')}")

    return DeviceAuthStart(
        ok=True,
        client_id=client_id,
        client_secret=client_secret,
        device_code=device_code,
        user_code=user_code or "",
        verification_uri=da.get("verificationUri", ""),
        verification_uri_complete=da.get("verificationUriComplete", ""),
        expires_in=int(da.get("expiresIn") or 600),
        interval=int(da.get("interval") or 5),
        oidc_region=oidc_region,
        kiro_region=kiro_region,
        auth_method=auth_method,
        start_url=start_url,
    )


def poll_for_token(
    start: DeviceAuthStart,
    fetch_profile: bool = True,
    stop_event=None,
    log: Callable[[str], None] = print,
) -> DurableExport:
    """Buoc 3+4: poll CreateToken den khi user login xong, roi lay profileArn.

    Block den khi: co token / het han / stop_event set.
    """
    oidc_region = start.oidc_region
    kiro_region = start.kiro_region
    token_url = _oidc_base(oidc_region) + "/token"
    deadline = time.time() + start.expires_in
    interval = max(2, start.interval)

    log("device-code: cho ban login browser & dang poll token ...")
    access_token = refresh_token = ""
    expires_in = 0
    last_pending_log = 0.0
    while time.time() < deadline:
        if stop_event is not None and stop_event.is_set():
            return DurableExport(error="Da huy (stop).")
        status, tok = _post_json(token_url, {
            "clientId": start.client_id,
            "clientSecret": start.client_secret,
            "deviceCode": start.device_code,
            "grantType": "urn:ietf:params:oauth:grant-type:device_code",
        })
        access_token = tok.get("accessToken", "")
        if access_token:
            refresh_token = tok.get("refreshToken", "")
            expires_in = int(tok.get("expiresIn") or 3600)
            log("  -> nhan duoc token!")
            break
        err = tok.get("error", "")
        if err in ("authorization_pending", "slow_down", ""):
            if err == "slow_down":
                interval += 2
            now = time.time()
            if now - last_pending_log >= 15:
                remain = max(0, int(deadline - now))
                log(f"device-code: token 还未授权，继续等待（剩余约 {remain} 秒）")
                last_pending_log = now
            time.sleep(interval)
            continue
        # loi that su
        return DurableExport(
            error=f"CreateToken loi: {err} - {tok.get('error_description') or tok}")
    if not access_token:
        return DurableExport(error="Het han cho login (khong nhan duoc token).")

    now = dt.datetime.now(dt.timezone.utc)
    expires_at = (now + dt.timedelta(seconds=expires_in)).strftime(
        "%Y-%m-%dT%H:%M:%S.000Z")

    exp = DurableExport(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=expires_in,
        expires_at=expires_at,
        client_id=start.client_id,
        client_secret=start.client_secret,
        region=kiro_region,
        oidc_region=oidc_region,
        auth_method="idc" if start.auth_method == "idc" else "builder-id",
        start_url=start.start_url,
    )

    # 4. ListAvailableProfiles -> profileArn (de khong bi 403)
    if fetch_profile:
        log(f"device-code: ListAvailableProfiles (q.{kiro_region}) de lay profileArn ...")
        arn, email = list_profile_arn(access_token, kiro_region, log=log)
        if arn:
            exp.profile_arn = arn
            log(f"  profile_arn: {arn}")
        else:
            log("  WARN: chua lay duoc profileArn (co the can fix tay sau).")
        if email:
            exp.email = email

    return exp


def list_profile_arn(
    access_token: str,
    region: str = DEFAULT_KIRO_REGION,
    log: Callable[[str], None] = print,
) -> tuple[str, str]:
    """Goi ListAvailableProfiles -> (profile_arn, ''). '' neu khong lay duoc."""
    region = normalize_kiro_region(region)
    url = kiro_q_url(region)
    host = f"q.{region}.amazonaws.com"
    machine_id = hashlib.sha256(access_token.encode("utf-8")).hexdigest()
    user_agent = (
        "aws-sdk-js/1.0.0 ua/2.1 os/Linux lang/js md/nodejs#24 "
        f"api/codewhispererruntime#1.0.0 m/N,E KiroIDE-{KIRO_PROFILE_API_VERSION}-{machine_id}"
    )
    amz_user_agent = f"aws-sdk-js/1.0.0 KiroIDE-{KIRO_PROFILE_API_VERSION}-{machine_id}"
    raw = json.dumps({"maxResults": 10}).encode("utf-8")
    req = urllib.request.Request(url, data=raw, method="POST", headers={
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/x-amz-json-1.0",
        "x-amz-target": CW_LIST_PROFILES_TARGET,
        "x-amz-user-agent": amz_user_agent,
        "User-Agent": user_agent,
        "Host": host,
        "amz-sdk-invocation-id": str(uuid.uuid4()),
        "amz-sdk-request": "attempt=1; max=1",
        "Connection": "close",
    })
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        log(f"  ListAvailableProfiles HTTP {e.code}: {body[:120]}")
        return "", ""
    except Exception as e:
        log(f"  ListAvailableProfiles loi: {e}")
        return "", ""

    profiles = data.get("profiles") or []
    if not profiles:
        return "", ""
    # uu tien profile co arn
    for p in profiles:
        arn = p.get("arn") or p.get("profileArn")
        if arn:
            return arn, ""
    return "", ""


def probe_generate_assistant(
    access_token: str,
    profile_arn: str,
    region: str,
    timeout: float = 10.0,
) -> tuple[int, dict]:
    """Lightweight call-plane probe for the same endpoint used by kiro-rs IDE mode."""
    region = normalize_kiro_region(region)
    machine_id = hashlib.sha256(f"{access_token}|probe".encode("utf-8")).hexdigest()
    body = {
        "conversationState": {
            "currentMessage": {
                "userInputMessage": {
                    "content": "ping",
                    "origin": "AI_EDITOR",
                    "modelId": "claude-sonnet-4.5",
                }
            }
        },
        "profileArn": profile_arn,
    }
    raw = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        f"https://q.{region}.amazonaws.com/generateAssistantResponse",
        data=raw,
        method="POST",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "x-amzn-codewhisperer-optout": "true",
            "x-amzn-kiro-agent-mode": "vibe",
            "x-amzn-kiro-profile-arn": profile_arn,
            "x-amz-user-agent": f"aws-sdk-js/1.0.34 KiroIDE-{KIRO_PROFILE_API_VERSION}-{machine_id}",
            "User-Agent": f"aws-sdk-js/1.0.34 ua/2.1 os/Linux lang/js md/nodejs#24 api/codewhispererstreaming#1.0.34 m/E KiroIDE-{KIRO_PROFILE_API_VERSION}-{machine_id}",
            "Host": f"q.{region}.amazonaws.com",
            "amz-sdk-invocation-id": str(uuid.uuid4()),
            "amz-sdk-request": "attempt=1; max=1",
            "Connection": "close",
        },
    )
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            txt = r.read(2048).decode("utf-8", "replace")
            try:
                return r.status, json.loads(txt) if txt else {}
            except Exception:
                return r.status, {"_raw": txt}
    except urllib.error.HTTPError as e:
        txt = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(txt)
        except Exception:
            return e.code, {"_raw": txt}
    except Exception as e:
        return 0, {"_raw": str(e)}


def kiro_mgmt_call(
    access_token: str,
    profile_arn: str,
    region: str,
    target: str,
    extra: Optional[dict] = None,
    timeout: float = 30.0,
    token_type: Optional[str] = None,
) -> tuple[int, dict]:
    body = {"profileArn": profile_arn}
    if extra:
        body.update(extra)
    raw = json.dumps(body).encode("utf-8")
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/x-amz-json-1.0",
        "X-Amz-Target": target,
        "Accept": "application/json",
    }
    # 外部 IdP（M365/Entra）token 必须携 EXTERNAL_IDP，否则管理面返回
    # 400 AccessDeniedException "Invalid token"。
    if token_type:
        headers["tokentype"] = token_type
    req = urllib.request.Request(
        kiro_mgmt_url(region),
        data=raw,
        method="POST",
        headers=headers,
    )
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            txt = r.read().decode("utf-8", "replace")
            return r.status, json.loads(txt) if txt else {}
    except urllib.error.HTTPError as e:
        txt = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(txt)
        except Exception:
            return e.code, {"_raw": txt}


def get_profile(access_token: str, profile_arn: str, region: str, token_type: Optional[str] = None) -> tuple[int, dict]:
    return kiro_mgmt_call(access_token, profile_arn, region, KIRO_MGMT_TARGET_GET_PROFILE, token_type=token_type)


def api_keys_enabled(profile_response: dict) -> bool:
    return (
        profile_response.get("profile", {})
        .get("optInFeatures", {})
        .get("apiKeys", {})
        .get("toggle") == "ON"
    )


def list_api_keys(access_token: str, profile_arn: str, region: str, token_type: Optional[str] = None) -> tuple[int, dict]:
    return kiro_mgmt_call(access_token, profile_arn, region, KIRO_MGMT_TARGET_LIST_KEYS, token_type=token_type)


def create_api_key(access_token: str, profile_arn: str, region: str, label: str, token_type: Optional[str] = None) -> tuple[int, dict]:
    return kiro_mgmt_call(access_token, profile_arn, region, KIRO_MGMT_TARGET_CREATE_KEY, {"label": label}, token_type=token_type)


def refresh_access_token(
    refresh_token: str,
    client_id: str,
    client_secret: str,
    oidc_region: str = DEFAULT_OIDC_REGION,
    timeout: float = 30.0,
) -> tuple[int, dict]:
    raw = json.dumps({
        "clientId": client_id,
        "clientSecret": client_secret,
        "refreshToken": refresh_token,
        "grantType": "refresh_token",
    }).encode("utf-8")
    req = urllib.request.Request(
        _oidc_base(oidc_region) + "/token",
        data=raw,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
            txt = r.read().decode("utf-8", "replace")
            return r.status, json.loads(txt) if txt else {}
    except urllib.error.HTTPError as e:
        txt = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(txt)
        except Exception:
            return e.code, {"_raw": txt}


__all__ = [
    "DeviceAuthStart", "DurableExport",
    "register_and_start", "poll_for_token", "list_profile_arn",
    "KIRO_CLIENT_NAME", "BUILDER_ID_START_URL",
    "DEFAULT_OIDC_REGION", "DEFAULT_KIRO_REGION",
    "REGION_OPTIONS", "KIRO_REGION_OPTIONS",
    "normalize_oidc_region", "normalize_kiro_region", "normalize_region",
    "region_from_profile_arn", "kiro_q_url", "kiro_mgmt_url",
    "get_profile", "api_keys_enabled", "list_api_keys", "create_api_key", "refresh_access_token", "probe_generate_assistant",
]
