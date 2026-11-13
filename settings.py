"""Startup settings checks and redirect validation, kept free of Flask state."""

from __future__ import annotations

import re
from collections.abc import Mapping
from urllib.parse import urlsplit

OIDC_VARS = ("OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET")


class ConfigError(RuntimeError):
    """A required setting is missing or invalid."""


def resolve_auth_mode(env: Mapping[str, str]) -> str:
    """Return "oidc" or "none".

    The app only runs without sign-in when AUTH_MODE=none is set explicitly.
    Otherwise every OIDC setting and FLASK_SECRET_KEY must be present.
    """
    mode = env.get("AUTH_MODE", "oidc").strip().lower() or "oidc"
    if mode == "none":
        return "none"
    if mode != "oidc":
        raise ConfigError(f"AUTH_MODE must be 'oidc' or 'none', got {mode!r}")
    missing = [
        n for n in (*OIDC_VARS, "FLASK_SECRET_KEY") if not env.get(n, "").strip()
    ]
    if missing:
        raise ConfigError(
            "Missing required setting(s): "
            + ", ".join(missing)
            + ". Set them, or set AUTH_MODE=none to run without sign-in."
        )
    return "oidc"


def parse_okta_environments(env: Mapping[str, str]) -> dict[str, dict[str, str]]:
    """Read OKTA_ENVIRONMENTS ("name=https://org,name2=https://org2", any length).

    Each entry gets the token variable OKTA_<NAME>_API_TOKEN.
    """
    raw = env.get("OKTA_ENVIRONMENTS", "").strip()
    if not raw:
        raise ConfigError(
            "Missing required setting: OKTA_ENVIRONMENTS "
            "(for example name=https://your-org.example.com,other=https://...)"
        )
    result: dict[str, dict[str, str]] = {}
    for item in raw.split(","):
        name, sep, url = item.strip().partition("=")
        name, url = name.strip().lower(), url.strip().rstrip("/")
        if not sep or not name or not url.startswith(("https://", "http://")):
            raise ConfigError(
                f"OKTA_ENVIRONMENTS entry {item.strip()!r} must be name=URL"
            )
        token_var = "OKTA_" + re.sub(r"[^A-Z0-9]", "_", name.upper()) + "_API_TOKEN"
        result[name] = {"url": url, "token_var": token_var}
    return result


def split_list(value: str | None) -> list[str]:
    """Split a comma-separated setting into lowercase, non-empty items."""
    return [i.strip().lower() for i in (value or "").split(",") if i.strip()]


def is_user_allowed(
    email: str, groups: list[str], allowed_users: list[str], allowed_groups: list[str]
) -> bool:
    """True when no allow-list is set, or the user matches one of them."""
    if not allowed_users and not allowed_groups:
        return True
    if email.strip().lower() in allowed_users:
        return True
    return any(g.strip().lower() in allowed_groups for g in groups)


def same_origin(headers: Mapping[str, str], host_url: str) -> bool:
    """CSRF check for state-changing requests: Origin (or Referer) must match."""
    source = headers.get("Origin") or headers.get("Referer")
    if not source:
        return False
    a, b = urlsplit(source), urlsplit(host_url)
    return (a.scheme, a.netloc) == (b.scheme, b.netloc)


def safe_next(target: str | None) -> str | None:
    """Return target only if it is a same-site relative path, else None."""
    if not target or not target.startswith("/"):
        return None
    if target.startswith(("//", "/\\")) or "\\" in target:
        return None
    parts = urlsplit(target)
    if parts.scheme or parts.netloc:
        return None
    if any(ord(c) < 32 for c in target):
        return None
    return target
