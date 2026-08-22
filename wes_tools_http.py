"""
wes_tools_http — shared HTTP identity layer for the wes-tools fleet.

One function: make_session(tool_name, tool_version). Every tool that talks
to an external service (Okta, IdPs, etc.) builds its `requests.Session`
through this helper so the fleet shows up consistently and identifiably
in upstream audit logs.

Auth headers stay tool-local — this module owns identity, not auth.

This file is the canonical source. Each tool directory holds a vendored
copy at the same filename, propagated by `scripts/sync_shared.sh`. Edit
the workspace-root copy and run the sync script — never edit a vendored
copy directly.
"""
from __future__ import annotations

import requests


def make_session(tool_name: str, tool_version: str) -> requests.Session:
    """Return a requests.Session pre-configured for the wes-tools fleet.

    Sets:
      - User-Agent: {tool_name}/{tool_version} (wes-tools)
      - Accept:     application/json

    Both are sane defaults; callers can mutate `session.headers` after
    construction to override (e.g. for non-JSON endpoints) or to add
    the tool's Authorization header.
    """
    session = requests.Session()
    session.headers.update({
        "User-Agent": f"{tool_name}/{tool_version} (wes-tools)",
        "Accept": "application/json",
    })
    return session
