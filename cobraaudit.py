#!/usr/bin/env python3
"""
CobraAudit — Bug Bounty Audit Framework
Modules: apikeys · oauth · pwreset

Usage:
  cobraaudit apikeys --key sk_live_xxx
  cobraaudit apikeys --file nextrecon_output.md
  cobraaudit apikeys --target https://target.com
  cobraaudit oauth --target https://target.com
  cobraaudit pwreset --target https://target.com --email test@target.com
  cobraaudit all --target https://target.com
"""

import re
import sys
import json
import time
import math
import argparse
import requests
from urllib.parse import urlencode
from collections import Counter

import shutil

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich.text import Text
from rich.columns import Columns
from rich.padding import Padding
from rich.align import Align
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

# Cap at 100 cols so panels don't stretch on wide terminals
_WIDTH = min(shutil.get_terminal_size((100, 24)).columns, 100)
console = Console(highlight=False, width=_WIDTH)

# ── Palette ──────────────────────────────────────────────────────────────────
C = {
    "red":      "bold red",
    "mag":      "bold magenta",
    "cyan":     "bold cyan",
    "green":    "bold green",
    "yellow":   "bold yellow",
    "dim":      "dim white",
    "white":    "white",
    "strike_r": "red",
    "strike_m": "magenta",
}

SEV_STYLE = {
    "CRITICAL": ("bold white on red",     "⬛ CRITICAL"),
    "HIGH":     ("bold black on yellow",  "🔴 HIGH    "),
    "MEDIUM":   ("bold black on cyan",    "🟡 MEDIUM  "),
    "LOW":      ("bold white on blue",    "🔵 LOW     "),
    "INFO":     ("dim white",             "   INFO    "),
}

SEV_PANEL_BORDER = {
    "CRITICAL": "red",
    "HIGH":     "yellow",
    "MEDIUM":   "cyan",
    "LOW":      "blue",
    "INFO":     "dim",
}

TIMEOUT = 15

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
    "Accept": "application/json, text/html,*/*",
}

# ── Banner ────────────────────────────────────────────────────────────────────

# ── Helpers ───────────────────────────────────────────────────────────────────

def print_banner():
    console.print()
    console.print("[bold red]    ╔═╗╔═╗╔╗ ╦═╗╔═╗  ╔═╗╦ ╦╔╦╗╦╔╦╗[/bold red]")
    console.print("[bold red]    ║  ║ ║╠╩╗╠╦╝╠═╣  ╠═╣║ ║ ║║║ ║ [/bold red]")
    console.print("[bold red]    ╚═╝╚═╝╚═╝╩╚═╩ ╩  ╩ ╩╚═╝═╩╝╩ ╩ [/bold red]")
    console.print()
    subtitle = (
        "[bold cyan]◈[/bold cyan] [bold white]API KEY VALIDATOR[/bold white]  "
        "[bold cyan]◈[/bold cyan] [bold white]OAUTH AUDITOR[/bold white]  "
        "[bold cyan]◈[/bold cyan] [bold white]PWRESET TESTER[/bold white]"
    )
    console.print(Align(
        Panel(subtitle, border_style="bold magenta", expand=False, padding=(0, 3)),
        align="center",
    ))
    console.print(Align("[dim]CobraSEC  ·  v1.0.0[/dim]", align="center"))
    console.print()

def sev_badge(level: str) -> str:
    style, label = SEV_STYLE.get(level, ("white", level))
    return f"[{style}]{label}[/{style}]"

def section(title: str, color: str = "magenta"):
    console.print()
    console.print(Rule(f"[bold {color}]  {title}  [/bold {color}]", style=color))
    console.print()

def ok(msg: str):
    console.print(f"  [bold green]✔[/bold green]  {msg}")

def warn(msg: str):
    console.print(f"  [bold yellow]⚠[/bold yellow]  [yellow]{msg}[/yellow]")

def info(msg: str):
    console.print(f"  [bold cyan]◆[/bold cyan]  {msg}")

def err(msg: str):
    console.print(f"  [bold red]✘[/bold red]  [red]{msg}[/red]")

def emit_finding(title: str, severity: str, detail: str, fix: str = ""):
    border = SEV_PANEL_BORDER.get(severity, "white")
    badge = sev_badge(severity)
    body = Text()
    body.append(f"  {detail}\n", style="white")
    if fix:
        body.append(f"\n  Fix:  ", style="dim")
        body.append(fix, style="dim cyan")
    console.print(
        Panel(
            body,
            title=f"[bold {border}] ⚡ {title} [/bold {border}]",
            subtitle=badge,
            border_style=border,
            padding=(0, 1),
        )
    )
    console.print()

def probe_spinner(label: str):
    """Return a Progress context that shows a spinner."""
    return Progress(
        SpinnerColumn("dots", style="bold magenta"),
        TextColumn(f"[cyan]{label}[/cyan]"),
        transient=True,
        console=console,
    )


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 1 — API KEY VALIDATOR
# ══════════════════════════════════════════════════════════════════════════════

API_TESTS = {
    "stripe_secret": {
        "pattern": r"sk_live_[0-9a-zA-Z]{24,}",
        "test": lambda k: requests.get("https://api.stripe.com/v1/balance", auth=(k, ""), timeout=TIMEOUT),
        "valid_code": 200,
        "name": "Stripe Secret Key (LIVE)",
        "severity": "CRITICAL",
        "impact": "Full Stripe account access — read balances, create charges, issue refunds, access customer data",
    },
    "stripe_secret_test": {
        "pattern": r"sk_test_[0-9a-zA-Z]{24,}",
        "test": lambda k: requests.get("https://api.stripe.com/v1/balance", auth=(k, ""), timeout=TIMEOUT),
        "valid_code": 200,
        "name": "Stripe Secret Key (TEST)",
        "severity": "MEDIUM",
        "impact": "Access to Stripe test environment — confirms key exposure pattern",
    },
    "sendgrid": {
        "pattern": r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",
        "test": lambda k: requests.get("https://api.sendgrid.com/v3/user/profile",
                                        headers={"Authorization": f"Bearer {k}"}, timeout=TIMEOUT),
        "valid_code": 200,
        "name": "SendGrid API Key",
        "severity": "HIGH",
        "impact": "Send emails as the organisation, access contact lists, read email activity",
    },
    "github_token": {
        "pattern": r"gh[pousr]_[A-Za-z0-9]{36,}",
        "test": lambda k: requests.get("https://api.github.com/user",
                                        headers={"Authorization": f"token {k}"}, timeout=TIMEOUT),
        "valid_code": 200,
        "name": "GitHub Personal Access Token",
        "severity": "HIGH",
        "impact": "Access to private repos, org membership, potentially write code or read secrets",
    },
    "slack_token": {
        "pattern": r"xox[baprs]\-[0-9A-Za-z\-]{10,}",
        "test": lambda k: requests.post("https://slack.com/api/auth.test",
                                         headers={"Authorization": f"Bearer {k}"}, timeout=TIMEOUT),
        "valid_code": 200,
        "valid_check": lambda r: r.json().get("ok") is True,
        "name": "Slack Token",
        "severity": "HIGH",
        "impact": "Read/send messages, access workspace data, enumerate users and channels",
    },
    "mailgun": {
        "pattern": r"key-[0-9a-zA-Z]{32}",
        "test": lambda k: requests.get("https://api.mailgun.net/v3/domains",
                                        auth=("api", k), timeout=TIMEOUT),
        "valid_code": 200,
        "name": "Mailgun API Key",
        "severity": "HIGH",
        "impact": "Send emails as the organisation, access mailing lists and logs",
    },
    "twilio": {
        "pattern": r"SK[0-9a-f]{32}",
        "test": lambda k: None,
        "valid_code": 200,
        "name": "Twilio API Key",
        "severity": "HIGH",
        "impact": "Send SMS/calls, access account data (requires SID pairing)",
    },
    "firebase_server": {
        "pattern": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
        "test": lambda k: requests.get("https://fcm.googleapis.com/fcm/send",
                                        headers={"Authorization": f"key={k}"}, timeout=TIMEOUT),
        "valid_code": 400,
        "name": "Firebase Server Key",
        "severity": "HIGH",
        "impact": "Send push notifications to all app users",
    },
    "shopify_private": {
        "pattern": r"shppa_[a-fA-F0-9]{32}",
        "test": lambda k: None,
        "valid_code": 200,
        "name": "Shopify Private App Key",
        "severity": "CRITICAL",
        "impact": "Full store access — orders, customers, products, payments",
    },
    "npm_token": {
        "pattern": r"npm_[A-Za-z0-9]{36}",
        "test": lambda k: requests.get("https://registry.npmjs.org/-/whoami",
                                        headers={"Authorization": f"Bearer {k}"}, timeout=TIMEOUT),
        "valid_code": 200,
        "name": "NPM Token",
        "severity": "HIGH",
        "impact": "Publish malicious packages as the organisation",
    },
    "aws_key": {
        "pattern": r"AKIA[0-9A-Z]{16}",
        "test": lambda k: None,
        "valid_code": 200,
        "name": "AWS Access Key ID",
        "severity": "CRITICAL",
        "impact": "AWS account access (requires secret key to test — report key ID exposure immediately)",
    },
}


def extract_keys_from_text(text: str):
    found = []
    for key_type, cfg in API_TESTS.items():
        for m in re.findall(cfg["pattern"], text):
            found.append((key_type, m))
    return found


def test_key(key_type: str, key_value: str) -> dict:
    cfg = API_TESTS.get(key_type)
    if not cfg:
        return {}
    if cfg["test"](key_value) is None:
        return {"type": key_type, "key": key_value, "valid": None,
                "name": cfg["name"], "severity": cfg["severity"], "impact": cfg["impact"]}
    try:
        r = cfg["test"](key_value)
        valid_check = cfg.get("valid_check")
        if valid_check:
            valid = r.status_code == cfg["valid_code"] and valid_check(r)
        else:
            valid = r.status_code == cfg["valid_code"]
        return {"type": key_type, "key": key_value, "valid": valid, "status": r.status_code,
                "name": cfg["name"], "severity": cfg["severity"], "impact": cfg["impact"]}
    except Exception as e:
        return {"type": key_type, "key": key_value, "valid": None, "error": str(e),
                "name": cfg["name"], "severity": cfg["severity"], "impact": cfg["impact"]}


def run_apikeys(args):
    section("MODULE 1  ·  API KEY VALIDATOR", "red")
    keys_to_test = []

    if getattr(args, "key", None):
        for key_type, cfg in API_TESTS.items():
            if re.match(cfg["pattern"], args.key):
                keys_to_test.append((key_type, args.key))
        if not keys_to_test:
            warn(f"Could not identify key type for: {args.key[:20]}...")
            return

    elif getattr(args, "file", None):
        try:
            text = open(args.file).read()
            keys_to_test = extract_keys_from_text(text)
            info(f"Scanning file: [bold]{args.file}[/bold]")
            info(f"Potential keys found: [bold cyan]{len(keys_to_test)}[/bold cyan]")
        except FileNotFoundError:
            err(f"File not found: {args.file}")
            return

    elif getattr(args, "target", None):
        with probe_spinner(f"Fetching {args.target}"):
            try:
                r = requests.get(args.target, headers=HEADERS, timeout=TIMEOUT)
                keys_to_test = extract_keys_from_text(r.text)
            except Exception as e:
                err(f"Failed to fetch target: {e}")
                return
        info(f"Keys found in page source: [bold cyan]{len(keys_to_test)}[/bold cyan]")

    if not keys_to_test:
        console.print("  [dim]No API keys found to test.[/dim]")
        return

    console.print()
    results = []
    for key_type, key_value in keys_to_test:
        name = API_TESTS[key_type]["name"]
        with probe_spinner(f"Testing {name}  ({key_value[:18]}…)"):
            result = test_key(key_type, key_value)
            results.append(result)
            time.sleep(0.4)

    # Results table
    table = Table(
        box=box.ROUNDED,
        border_style="magenta",
        header_style="bold magenta",
        show_lines=False,
    )
    table.add_column("Key Type",    style="white",      min_width=28)
    table.add_column("Key Preview", style="dim cyan",   min_width=22)
    table.add_column("Valid?",      justify="center",   min_width=12)
    table.add_column("Severity",    justify="center",   min_width=18)

    for r in results:
        if r.get("valid") is True:
            valid_str = "[bold green]✔  VALID[/bold green]"
        elif r.get("valid") is False:
            valid_str = "[dim]✘  invalid[/dim]"
        else:
            valid_str = "[yellow]?  unverified[/yellow]"
        table.add_row(
            r["name"],
            r["key"][:22] + "…",
            valid_str,
            sev_badge(r["severity"]),
        )

    console.print(Padding(table, (0, 2)))
    console.print()

    # Emit findings for valid or unverified keys
    for r in results:
        if r.get("valid") or r.get("valid") is None:
            emit_finding(
                f"API Key Exposed: {r['name']}",
                r["severity"],
                f"Key: {r['key'][:32]}…\nImpact: {r['impact']}",
                "Rotate key immediately. Remove from source code. Use server-side env vars.",
            )

    return results


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 2 — OAUTH AUDITOR
# ══════════════════════════════════════════════════════════════════════════════

OAUTH_PATHS = [
    "/oauth/authorize", "/oauth2/authorize", "/oauth/token", "/oauth2/token",
    "/auth/authorize", "/auth/oauth/authorize", "/connect/authorize",
    "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server",
    "/api/oauth/authorize", "/v1/oauth/authorize", "/v2/oauth/authorize",
    "/login/oauth/authorize",
]


def discover_oauth(target: str) -> dict:
    base = target.rstrip("/")
    found = {}
    for path in ["/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"]:
        try:
            r = requests.get(base + path, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
            if r.status_code == 200 and ("authorization_endpoint" in r.text or "token_endpoint" in r.text):
                data = r.json()
                found["auth_endpoint"]   = data.get("authorization_endpoint")
                found["token_endpoint"]  = data.get("token_endpoint")
                found["issuer"]          = data.get("issuer")
                found["scopes"]          = data.get("scopes_supported", [])
                found["response_types"]  = data.get("response_types_supported", [])
                found["grant_types"]     = data.get("grant_types_supported", [])
                found["pkce_methods"]    = data.get("code_challenge_methods_supported", [])
                found["well_known"]      = base + path
                return found
        except Exception:
            pass

    for path in OAUTH_PATHS:
        try:
            r = requests.get(base + path, headers=HEADERS, timeout=TIMEOUT, allow_redirects=False)
            if r.status_code in [200, 302, 400, 401]:
                if "authorize" in path:
                    found["auth_endpoint"] = base + path
                elif "token" in path:
                    found["token_endpoint"] = base + path
        except Exception:
            pass
    return found


def check_implicit_flow(auth_endpoint: str, client_id: str = "test"):
    if not auth_endpoint:
        return None
    try:
        params = {
            "response_type": "token",
            "client_id": client_id,
            "redirect_uri": "https://example.com/callback",
            "scope": "openid profile email",
        }
        r = requests.get(auth_endpoint + "?" + urlencode(params),
                         headers=HEADERS, timeout=TIMEOUT, allow_redirects=False)
        if r.status_code in [200, 302]:
            body = r.text.lower()
            if "unsupported_response_type" in body or "response_type_not_supported" in body:
                return False
            return True
        return False
    except Exception:
        return None


def check_pkce_enforcement(auth_endpoint: str, client_id: str = "test"):
    if not auth_endpoint:
        return None
    try:
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "https://example.com/callback",
            "scope": "openid profile email",
        }
        r = requests.get(auth_endpoint + "?" + urlencode(params),
                         headers=HEADERS, timeout=TIMEOUT, allow_redirects=False)
        body = r.text.lower()
        if "code_challenge" in body and "required" in body:
            return False
        if r.status_code in [200, 302] and "error" not in body:
            return True
        return False
    except Exception:
        return None


def check_state_param(auth_endpoint: str, client_id: str = "test"):
    if not auth_endpoint:
        return None
    try:
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "https://example.com/callback",
            "scope": "openid profile email",
        }
        r = requests.get(auth_endpoint + "?" + urlencode(params),
                         headers=HEADERS, timeout=TIMEOUT, allow_redirects=False)
        body = r.text.lower()
        if "state" in body and "required" in body:
            return False
        if r.status_code in [200, 302]:
            return True
        return False
    except Exception:
        return None


def check_redirect_uri_bypass(auth_endpoint: str, client_id: str = "test") -> list:
    if not auth_endpoint:
        return []
    bypasses = []
    payloads = [
        ("Path traversal",       "https://legitimate.com/callback/../../../evil.com"),
        ("Extra path segment",   "https://legitimate.com/callback/extra"),
        ("Query param append",   "https://legitimate.com/callback?evil=https://attacker.com"),
        ("Subdomain wildcard",   "https://evil.legitimate.com/callback"),
        ("URL-encoded dot",      "https://legitimate.com%2fcallback"),
        ("Open redirect chain",  "https://legitimate.com/redirect?to=https://attacker.com"),
    ]
    for name, uri in payloads:
        try:
            params = {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": uri,
                "state": "test123",
            }
            r = requests.get(auth_endpoint + "?" + urlencode(params),
                             headers=HEADERS, timeout=TIMEOUT, allow_redirects=False)
            if r.status_code == 302 and "error" not in r.headers.get("Location", "").lower():
                bypasses.append((name, uri))
        except Exception:
            pass
    return bypasses


def run_oauth(args):
    section("MODULE 2  ·  OAUTH / OIDC AUDITOR", "cyan")
    target    = args.target
    client_id = getattr(args, "client_id", None) or "test"

    info(f"Target: [bold]{target}[/bold]")

    with probe_spinner("Discovering OAuth/OIDC endpoints…"):
        endpoints = discover_oauth(target)

    if not endpoints:
        warn("No OAuth endpoints found. Try --auth-endpoint to specify manually.")
        return

    # Endpoint summary table
    ep_table = Table(box=box.SIMPLE_HEAD, border_style="dim", header_style="bold cyan", show_header=False)
    ep_table.add_column("Key",   style="dim",      min_width=18)
    ep_table.add_column("Value", style="cyan")
    for k, v in endpoints.items():
        if v:
            val = ", ".join(v) if isinstance(v, list) else str(v)
            ep_table.add_row(k, val[:90])
    console.print(Padding(ep_table, (0, 2)))

    auth_ep  = endpoints.get("auth_endpoint", "")
    findings = []

    # ── Test 1: Implicit flow
    with probe_spinner("Checking implicit flow (response_type=token)…"):
        implicit = check_implicit_flow(auth_ep, client_id)
    if implicit is True:
        findings.append(("IMPLICIT_FLOW", "HIGH"))
        emit_finding(
            "Implicit Flow Enabled",
            "HIGH",
            f"response_type=token accepted at:\n  {auth_ep}",
            "Disable implicit flow. Use authorization code + PKCE instead. (RFC 9700)",
        )
    elif implicit is False:
        ok("Implicit flow disabled")
    else:
        warn("Implicit flow — could not determine (requires a valid client_id)")

    # ── Test 2: PKCE enforcement
    with probe_spinner("Checking PKCE enforcement…"):
        pkce = check_pkce_enforcement(auth_ep, client_id)
    if pkce is True:
        findings.append(("PKCE_NOT_ENFORCED", "MEDIUM"))
        emit_finding(
            "PKCE Not Enforced",
            "MEDIUM",
            "Authorization code flow accepted without code_challenge parameter.",
            "Require PKCE for all public clients. Set code_challenge_method=S256.",
        )
    elif pkce is False:
        ok("PKCE enforced")
    else:
        warn("PKCE — could not determine")

    # ── Test 3: State parameter
    with probe_spinner("Checking state parameter enforcement…"):
        state = check_state_param(auth_ep, client_id)
    if state is True:
        findings.append(("STATE_NOT_REQUIRED", "MEDIUM"))
        emit_finding(
            "State Parameter Not Required",
            "MEDIUM",
            "OAuth flow accepted without state parameter — CSRF on OAuth flow possible.",
            "Require and validate state parameter on all OAuth requests.",
        )
    elif state is False:
        ok("State parameter enforced")

    # ── Test 4: Redirect URI bypass
    with probe_spinner("Testing redirect_uri bypass patterns…"):
        bypasses = check_redirect_uri_bypass(auth_ep, client_id)
    if bypasses:
        findings.append(("REDIRECT_URI_BYPASS", "HIGH"))
        for name, uri in bypasses:
            emit_finding(
                f"Redirect URI Bypass: {name}",
                "HIGH",
                f"Accepted URI: {uri}",
                "Implement strict exact-match validation on redirect_uri.",
            )
    else:
        ok("Redirect URI validation appears strict")

    # ── Test 5: Dangerous advertised response types
    if endpoints.get("response_types"):
        dangerous = [rt for rt in endpoints["response_types"] if "token" in rt]
        if dangerous:
            findings.append(("DANGEROUS_RESPONSE_TYPES", "MEDIUM"))
            emit_finding(
                "Dangerous Response Types Advertised",
                "MEDIUM",
                f"Supports: {', '.join(dangerous)}",
                "Remove token response types from supported list if not required.",
            )

    # Summary
    _print_summary("OAuth Audit", findings)
    return findings


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 3 — PASSWORD RESET AUDITOR
# ══════════════════════════════════════════════════════════════════════════════

RESET_PATHS = [
    "/forgot-password", "/reset-password", "/password-reset", "/auth/reset",
    "/account/forgot-password", "/user/forgot-password", "/api/password/reset",
    "/api/auth/forgot-password", "/api/reset-password", "/users/password",
    "/api/v1/auth/forgot-password", "/api/v2/auth/forgot-password",
]


def discover_reset_endpoint(target: str):
    base = target.rstrip("/")
    for path in RESET_PATHS:
        try:
            r = requests.get(base + path, headers=HEADERS, timeout=TIMEOUT)
            if r.status_code in [200, 405]:
                return base + path
        except Exception:
            pass
    return None


def check_host_header_injection(reset_endpoint: str, email: str) -> list:
    if not reset_endpoint:
        return []
    results = []
    payloads = [
        ("Host header",       {"Host": "attacker.com"}),
        ("X-Forwarded-Host",  {"X-Forwarded-Host": "attacker.com"}),
        ("X-Forwarded-For",   {"X-Forwarded-For": "attacker.com"}),
        ("X-Host",            {"X-Host": "attacker.com"}),
        ("X-Original-URL",    {"X-Original-URL": "https://attacker.com/reset"}),
    ]
    for name, extra_headers in payloads:
        try:
            h = {**HEADERS, **extra_headers}
            r = requests.post(reset_endpoint, headers=h, json={"email": email}, timeout=TIMEOUT)
            if r.status_code == 200:
                results.append((name, r.status_code))
        except Exception:
            pass
    return results


def check_username_enumeration(reset_endpoint: str, email: str):
    if not reset_endpoint:
        return None
    try:
        r_valid = requests.post(reset_endpoint, headers=HEADERS,
                                json={"email": email}, timeout=TIMEOUT)
        r_fake  = requests.post(reset_endpoint, headers=HEADERS,
                                json={"email": "definitelynotreal_xyz_12345@fakefakedomain.xyz"},
                                timeout=TIMEOUT)
        if r_valid.status_code != r_fake.status_code:
            return {"type": "status_code", "valid": r_valid.status_code, "invalid": r_fake.status_code}
        diff = abs(len(r_valid.text) - len(r_fake.text))
        if diff > 20:
            return {"type": "response_length", "valid_len": len(r_valid.text), "invalid_len": len(r_fake.text)}
        return None
    except Exception:
        return None


def check_rate_limiting(reset_endpoint: str, email: str):
    if not reset_endpoint:
        return None
    try:
        codes = []
        for _ in range(8):
            r = requests.post(reset_endpoint, headers=HEADERS,
                              json={"email": email}, timeout=TIMEOUT)
            codes.append(r.status_code)
            time.sleep(0.3)
        if not any(c in [429, 403, 503] for c in codes):
            return {"requests": len(codes), "codes": codes}
        return None
    except Exception:
        return None


def run_pwreset(args):
    section("MODULE 3  ·  PASSWORD RESET AUDITOR", "yellow")
    target = args.target
    email  = getattr(args, "email", None) or "test@example.com"

    info(f"Target:     [bold]{target}[/bold]")
    info(f"Test email: [bold cyan]{email}[/bold cyan]")

    reset_ep = getattr(args, "reset_endpoint", None)
    if not reset_ep:
        with probe_spinner("Discovering password reset endpoint…"):
            reset_ep = discover_reset_endpoint(target)

    if not reset_ep:
        warn("No reset endpoint found automatically.")
        console.print("  [dim]Try: cobraaudit pwreset --target URL --reset-endpoint /forgot-password --email you@target.com[/dim]")
        return

    ok(f"Reset endpoint: [cyan]{reset_ep}[/cyan]")
    console.print()

    findings = []

    # ── Test 1: Host header injection
    with probe_spinner("Testing host header injection…"):
        host_results = check_host_header_injection(reset_ep, email)
    if host_results:
        findings.append("HOST_HEADER_INJECTION")
        emit_finding(
            "Potential Host Header Injection",
            "HIGH",
            f"Reset endpoint accepted requests with poisoned headers:\n  {[r[0] for r in host_results]}\n\nUse Burp Collaborator / interactsh to confirm email callback.",
            "Build reset URLs from server config, never from Host header. Whitelist allowed hosts.",
        )
    else:
        console.print("  [dim]◆  Host header injection — cannot confirm without email inbox access[/dim]")

    # ── Test 2: Username enumeration
    with probe_spinner("Testing username enumeration…"):
        enum_result = check_username_enumeration(reset_ep, email)
    if enum_result:
        findings.append("USERNAME_ENUMERATION")
        if enum_result["type"] == "status_code":
            emit_finding(
                "Username Enumeration via Status Code",
                "MEDIUM",
                f"Valid email → HTTP {enum_result['valid']}\nInvalid email → HTTP {enum_result['invalid']}",
                "Return identical responses for valid and invalid emails.",
            )
        else:
            emit_finding(
                "Username Enumeration via Response Length",
                "MEDIUM",
                f"Valid email response:   {enum_result['valid_len']} bytes\nInvalid email response: {enum_result['invalid_len']} bytes",
                "Normalise response body length for all outcomes.",
            )
    else:
        ok("No username enumeration detected")

    # ── Test 3: Rate limiting
    with probe_spinner("Testing rate limiting (8 rapid requests)…"):
        rate_result = check_rate_limiting(reset_ep, email)
    if rate_result:
        findings.append("NO_RATE_LIMIT")
        emit_finding(
            "No Rate Limiting on Password Reset",
            "MEDIUM",
            f"Sent {rate_result['requests']} requests — all returned status codes: {set(rate_result['codes'])}\nNo 429 / 403 throttling observed.",
            "Implement rate limiting: max 3–5 requests per hour per email/IP.",
        )
    else:
        ok("Rate limiting appears to be in place")

    _print_summary("Password Reset Audit", [(f, "MEDIUM") for f in findings])
    return findings


# ══════════════════════════════════════════════════════════════════════════════
# SHARED SUMMARY
# ══════════════════════════════════════════════════════════════════════════════

def _print_summary(title: str, findings: list):
    console.print()
    console.print(Rule(f"[bold white]  {title} Summary  [/bold white]", style="white"))
    if findings:
        console.print(f"\n  [bold red]  {len(findings)} issue(s) found[/bold red]\n")
        for code, sev_level in findings:
            console.print(f"  {sev_badge(sev_level)}  [white]{code}[/white]")
    else:
        console.print("\n  [bold green]  ✔  No issues detected[/bold green]")
    console.print()


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="CobraAudit — Bug Bounty Audit Framework",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    sub = parser.add_subparsers(dest="module")

    # apikeys
    p_keys = sub.add_parser("apikeys", help="Test API keys for validity and permissions")
    p_keys.add_argument("--key",    metavar="KEY",  help="Single API key to test")
    p_keys.add_argument("--file",   metavar="FILE", help="File to scan for API keys")
    p_keys.add_argument("--target", metavar="URL",  help="URL to fetch and scan for API keys")

    # oauth
    p_oauth = sub.add_parser("oauth", help="Test OAuth/OIDC for misconfigurations")
    p_oauth.add_argument("--target",        metavar="URL", required=True)
    p_oauth.add_argument("--client-id",     metavar="ID",  help="Known client ID (optional)")
    p_oauth.add_argument("--auth-endpoint", metavar="URL", help="Known authorization endpoint (optional)")

    # pwreset
    p_reset = sub.add_parser("pwreset", help="Audit password reset functionality")
    p_reset.add_argument("--target",         metavar="URL",   required=True)
    p_reset.add_argument("--email",          metavar="EMAIL", help="Test email address")
    p_reset.add_argument("--reset-endpoint", metavar="URL",   help="Known reset endpoint (optional)")

    # all
    p_all = sub.add_parser("all", help="Run all modules against a target")
    p_all.add_argument("--target",    metavar="URL",   required=True)
    p_all.add_argument("--email",     metavar="EMAIL", help="Email for pwreset module")
    p_all.add_argument("--client-id", metavar="ID",    help="OAuth client ID")

    args = parser.parse_args()

    if not args.module:
        parser.print_help()
        return

    if args.module == "apikeys":
        run_apikeys(args)

    elif args.module == "oauth":
        run_oauth(args)

    elif args.module == "pwreset":
        run_pwreset(args)

    elif args.module == "all":
        args.key            = None
        args.file           = None
        args.reset_endpoint = None
        run_apikeys(args)
        run_oauth(args)
        run_pwreset(args)


if __name__ == "__main__":
    main()
