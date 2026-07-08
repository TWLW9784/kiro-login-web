# -*- coding: utf-8 -*-
"""m365_browser_login.py — 用 Playwright 驱动 Kiro 门户 → M365 SSO 登录页。

配合 m365_sso_login.M365LoginSession：本模块只负责"在浏览器里把人做的事做完"——
选 Your organization、填邮箱、跟随跳转到 M365、填密码、处理 MFA / Stay signed in，
直到浏览器最终落到本地回环（sign-in complete）。OAuth 编排与 token 交换由 session 负责。
"""
from __future__ import annotations

import time
from typing import Callable, Optional

from playwright.sync_api import sync_playwright

import mfa_totp


def _tile_args(window_index: int, window_count: int):
    """与 idc_browser_login 一致的错峰窗口布局参数（headless 下无实际意义，保留接口一致）。"""
    return []


def drive_m365_login(
    signin_url: str,
    email: str,
    password: str,
    *,
    mfa_secret: str = "",
    log: Callable[[str], None] = lambda m: None,
    headless: bool = True,
    proxy: str = "",
    timeout_s: int = 300,
    stop_event=None,
    debug_dir: str = "",
    on_secret: Optional[Callable[[str], None]] = None,
) -> tuple[bool, str]:
    """驱动浏览器完成 M365 SSO 登录。返回 (reached_loopback, error)。

    成功条件：浏览器最终被重定向到 http://localhost:<port>（回环），
    此时 M365LoginSession 的监听已捕获 code，调用方随后 wait_and_exchange。
    """
    safe = "".join(c if c.isalnum() else "_" for c in (email or "acc"))[:20]
    shot_i = {"n": 0}

    def shot(tag: str):
        if not debug_dir:
            return
        try:
            from pathlib import Path
            Path(debug_dir).mkdir(parents=True, exist_ok=True)
            page.screenshot(path=str(Path(debug_dir) / f"{safe}_{shot_i['n']:02d}_{tag}.png"))
        except Exception:
            pass
        shot_i["n"] += 1

    def stopped() -> bool:
        return stop_event is not None and stop_event.is_set()

    launch_args = ["--no-sandbox", "--disable-dev-shm-usage"]
    # 关键：OAuth 回调重定向到 http://localhost:<port>，必须让回环地址绕过代理，
    # 否则 Chromium（新版默认不 bypass localhost）会把回调请求也送进出口代理，
    # 请求到不了本机监听端口 → result_queue 收不到 code → wait_and_exchange 超时。
    proxy_cfg = {"server": proxy, "bypass": "localhost, 127.0.0.1, ::1, [::1]"} if proxy else None

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless, args=launch_args, proxy=proxy_cfg)
        ctx = browser.new_context(ignore_https_errors=True, locale="en-US")
        page = ctx.new_page()
        try:
            page.goto(signin_url, wait_until="domcontentloaded", timeout=30000)
        except Exception as exc:
            browser.close()
            return False, f"打开登录页失败：{exc}"
        time.sleep(2.0)
        shot("01_landing")

        # 1) 点 "Your organization" 的 Sign in
        org_clicked = False
        try:
            loc = page.locator(
                "xpath=//*[contains(normalize-space(.),'Your organization')]"
                "/ancestor-or-self::*[self::button][1]"
            )
            if loc.count():
                loc.first.click()
                org_clicked = True
        except Exception:
            pass
        if not org_clicked:
            # 退化策略：最后一个 "Sign in" 通常是 organization
            try:
                signs = page.get_by_text("Sign in", exact=True)
                n = signs.count()
                if n:
                    signs.nth(n - 1).click()
                    org_clicked = True
            except Exception:
                pass
        if not org_clicked:
            browser.close()
            return False, "未找到 'Your organization' 登录入口"
        time.sleep(2.5)
        shot("02_org")

        # 2) 填工作邮箱 → Continue
        filled = False
        for sel in ("input[type=email]", "input[name=email]", "input[type=text]"):
            try:
                el = page.locator(sel).first
                if el.count() and el.is_visible():
                    el.fill(email)
                    filled = True
                    break
            except Exception:
                continue
        if not filled:
            browser.close()
            return False, "未找到组织邮箱输入框"
        _click_any(page, ['button:has-text("Continue")', 'button:has-text("Next")',
                          'button[type=submit]', 'input[type=submit]'])
        time.sleep(5.0)
        shot("03_after_email")

        # 3) 主循环：处理 M365 密码 / MFA / Stay signed in，直到落到回环
        deadline = time.time() + timeout_s
        last_url = ""
        idle = 0
        mfa_secret_norm = mfa_totp.normalize_secret(mfa_secret) if mfa_secret else ""
        mfa_attempts = 0
        pwd_done = False
        while time.time() < deadline:
            if stopped():
                browser.close()
                return False, "已中断"
            url = page.url
            if "localhost:%d" % _port_from(signin_url) in url or _reached_complete(page):
                shot("99_loopback")
                browser.close()
                return True, ""
            try:
                body = page.inner_text("body", timeout=3000).lower()
            except Exception:
                body = ""

            # M365 密码页
            if not pwd_done and ("enter password" in body or "输入密码" in body
                                 or page.locator("input[type=password]").count()):
                pw = page.locator("input[type=password], input[name=passwd]").first
                if pw.count() and pw.is_visible():
                    try:
                        pw.fill(password)
                        log("已填入 M365 密码")
                        _click_any(page, ['#idSIButton9', 'input[type=submit]',
                                          'button[type=submit]', 'button:has-text("Sign in")'])
                        pwd_done = True
                        time.sleep(4.0)
                        shot("04_after_pwd")
                        continue
                    except Exception:
                        pass

            # 密码错误 / 账号问题
            if any(k in body for k in ["your account or password is incorrect",
                                       "incorrect password", "密码不正确", "couldn't find your account",
                                       "didn't recognize"]):
                browser.close()
                return False, "M365 账号或密码错误"

            # Stay signed in?
            if "stay signed in" in body or "保持登录" in body or "reduce the number of times" in body:
                _click_any(page, ['#idSIButton9', 'button:has-text("Yes")',
                                  'input[type=submit][value="Yes"]'])
                time.sleep(3.0)
                shot("05_stay")
                continue

            # MFA：已有密钥则算 TOTP 填入
            if any(k in body for k in ["verification code", "enter code", "authenticator",
                                       "verify your identity", "输入验证码", "one-time"]):
                mfa_attempts += 1
                if mfa_attempts > 4:
                    browser.close()
                    return False, "MFA 验证多次失败"
                if mfa_secret_norm:
                    code = mfa_totp.totp_now(mfa_secret_norm)
                    code_box = page.locator("input[type=tel], input[name=otc], input[autocomplete='one-time-code'], input[type=text]").first
                    if code_box.count() and code_box.is_visible():
                        try:
                            code_box.fill(code)
                            _click_any(page, ['#idSubmit_SAOTCC_Continue', '#idSIButton9',
                                              'input[type=submit]', 'button:has-text("Verify")',
                                              'button:has-text("Next")'])
                            log("已填入 MFA 验证码")
                            time.sleep(4.0)
                            shot(f"06_mfa_{mfa_attempts}")
                            continue
                        except Exception:
                            pass
                else:
                    # 无预设密钥且要求 MFA：需要绑定新 authenticator（暂不支持自动绑定）
                    browser.close()
                    return False, "该账号要求 MFA 但未提供 TOTP 密钥（暂不支持自动绑定 M365 authenticator）"

            # "More information required" / 跳过类提示：尽量点 Next 往前
            if "more information" in body or "需要更多信息" in body:
                # 尝试 Skip setup（若允许）
                if not _click_any(page, ['#idBtn_Back', 'a:has-text("Skip")',
                                         'button:has-text("Skip")', 'input[value="Skip setup"]']):
                    _click_any(page, ['#idSIButton9', 'input[type=submit]'])
                time.sleep(3.0)
                continue

            # 通用前进按钮
            if url == last_url:
                idle += 1
            else:
                idle = 0
            last_url = url
            if idle >= 1:
                if not _click_any(page, ['#idSIButton9', 'button[type=submit]', 'input[type=submit]',
                                         'button:has-text("Next")', 'button:has-text("Continue")']):
                    # 无可点元素，再等等
                    pass
            time.sleep(2.0)

        browser.close()
        return False, "登录流程超时（未到达回环回调）"


def _click_any(page, selectors) -> bool:
    for sel in selectors:
        try:
            el = page.locator(sel).first
            if el.count() and el.is_visible():
                el.click()
                return True
        except Exception:
            continue
    return False


def _reached_complete(page) -> bool:
    try:
        txt = page.inner_text("body", timeout=1500).lower()
        return "sign-in complete" in txt
    except Exception:
        return False


def _port_from(signin_url: str) -> int:
    import re
    m = re.search(r"redirect_uri=http%3A%2F%2Flocalhost%3A(\d+)", signin_url)
    if m:
        return int(m.group(1))
    m = re.search(r"localhost:(\d+)", signin_url)
    return int(m.group(1)) if m else 3128
