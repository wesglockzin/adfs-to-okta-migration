"""Startup settings checks and redirect validation, kept free of Flask state."""

from __future__ import annotations

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
