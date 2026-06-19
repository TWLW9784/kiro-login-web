"""mfa_totp.py — 本地计算 TOTP（RFC 6238）验证码，并从 AWS MFA 注册页面抓取密钥。

为什么本地算而不用 2fa.run：
  - 2fa.run 有滑块人机验证 + IP 风控，服务端直接 GET 撞 403，不可靠。
  - TOTP 是标准算法，给定密钥本地毫秒级算出，离线、稳定、零外部依赖。

主要能力：
  1. normalize_secret(): 清洗用户/页面拿到的 base32 密钥（去空格、补齐）。
  2. totp_now(): 用密钥算当前 6 位验证码。
  3. extract_secret_from_page(): 从 AWS「身份验证程序」MFA 注册页面把 secret key 抠出来。
"""

from __future__ import annotations

import re
from typing import Callable, Optional

import pyotp


def normalize_secret(secret: str) -> str:
    """清洗 base32 TOTP 密钥：去空格/连字符、转大写。AWS 显示的密钥常带空格分组。"""
    if not secret:
        return ""
    cleaned = re.sub(r"[\s\-]", "", secret).upper()
    # 只保留 base32 合法字符
    cleaned = re.sub(r"[^A-Z2-7]", "", cleaned)
    return cleaned


def is_valid_secret(secret: str) -> bool:
    s = normalize_secret(secret)
    if len(s) < 16:
        return False
    try:
        pyotp.TOTP(s).now()
        return True
    except Exception:
        return False


def totp_now(secret: str) -> str:
    """根据 base32 密钥算当前 6 位 TOTP 验证码。失败抛异常。"""
    s = normalize_secret(secret)
    return pyotp.TOTP(s).now()


# AWS 显示密钥的典型形态：大写字母+数字、常以空格分组，例如
#   "ABCD EFGH IJKL MNOP QRST UVWX YZ23 4567"
# 这里用宽松正则匹配「连续 base32 块（含空格分隔）」，再 normalize。
_SECRET_BLOCK_RE = re.compile(r"\b(?:[A-Z2-7]{4}\s*){4,}[A-Z2-7]{2,}\b")


def extract_secret_from_page(page, log: Callable[[str], None] = print) -> Optional[str]:
    """从当前 AWS MFA 注册页面尝试抓取 authenticator secret key。

    AWS「Set up authenticator app」页面通常有一个「Show secret key」链接，
    点开后显示一串 base32 密钥。这里依次尝试：
      1. 点击 Show secret key / 显示密钥 之类的展开链接
      2. 从常见容器（code/带 secret 关键字的元素）读取
      3. 兜底：在整页文本里用正则匹配 base32 块
    成功返回 normalize 后的密钥，失败返回 None。
    """
    # 1) 尝试展开「显示密钥」
    for label in (
        "Show secret key", "show secret key", "Show secret", "Reveal secret",
        "显示密钥", "显示秘钥", "Can't scan", "Can't scan the QR code",
        "Cannot scan", "manually", "Enter key manually",
    ):
        try:
            loc = page.get_by_text(label, exact=False)
            if loc.count() > 0:
                loc.first.click(timeout=1500)
                log(f"    MFA: 点击展开「{label}」")
                page.wait_for_timeout(400)
                break
        except Exception:
            pass

    # 2) 从可能承载密钥的元素读取
    candidate_selectors = [
        "code",
        "[data-testid*=secret]",
        "[class*=secret]",
        "[id*=secret]",
        "input[readonly]",
    ]
    for sel in candidate_selectors:
        try:
            locs = page.locator(sel)
            n = locs.count()
            for i in range(min(n, 8)):
                el = locs.nth(i)
                txt = ""
                try:
                    txt = el.inner_text(timeout=800)
                except Exception:
                    pass
                if not txt:
                    try:
                        txt = el.input_value(timeout=800)
                    except Exception:
                        pass
                cand = normalize_secret(txt or "")
                if is_valid_secret(cand):
                    log(f"    MFA: 从 {sel} 读到密钥（{len(cand)} 位）")
                    return cand
        except Exception:
            pass

    # 3) 兜底：整页文本正则匹配 base32 块
    try:
        body = page.inner_text("body", timeout=1500)
    except Exception:
        body = ""
    if body:
        for m in _SECRET_BLOCK_RE.finditer(body):
            cand = normalize_secret(m.group(0))
            if is_valid_secret(cand):
                log(f"    MFA: 从页面文本正则匹配到密钥（{len(cand)} 位）")
                return cand

    log("    MFA: 未能从页面抓取到 secret key")
    return None
