"""
wes_tools_http — HTTP session helper.

One function: make_session(tool_name, tool_version). Every call that talks
to an external service (Okta, IdPs, etc.) builds its `requests.Session`
through this helper so requests are identifiable in upstream audit logs.

Auth headers stay caller-local — this module owns identity, not auth.
"""
from __future__ import annotations

import requests


def make_session(tool_name: str, tool_version: str) -> requests.Session:
    """Return a requests.Session pre-configured with a User-Agent and Accept header.

    Sets:
      - User-Agent: {tool_name}/{tool_version}
      - Accept:     application/json

    Both are sane defaults; callers can mutate `session.headers` after
    construction to override (e.g. for non-JSON endpoints) or to add
    the tool's Authorization header.
    """
    session = requests.Session()
    session.headers.update({
        "User-Agent": f"{tool_name}/{tool_version}",
        "Accept": "application/json",
    })
    return session
