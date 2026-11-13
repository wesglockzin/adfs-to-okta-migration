"""
setup_tokens.py — Store Okta API tokens in the OS credential store (optional).

Run once per machine (or whenever a token changes):
    adfs-to-okta-setup-tokens

One token is asked for per name in OKTA_ENVIRONMENTS. Tokens are saved to:
  macOS  → Keychain
  Windows → Credential Manager
  Linux  → Secret Service (GNOME Keyring / KWallet)

The migration tool reads them automatically — no plaintext tokens in .env.
Environment variables work without a keyring.
"""
from __future__ import annotations

import getpass
import logging
import os
import sys

from dotenv import load_dotenv

from settings import ConfigError, parse_okta_environments

try:
    import keyring
except ImportError:
    keyring = None

KEYRING_SERVICE = "adfs-okta-migration"

log = logging.getLogger("setup_tokens")


def say(message: str = "") -> None:
    """Interactive prompt output for the person running the setup."""
    print(message)  # noqa: T201 - interactive prompt text, not diagnostics


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s", stream=sys.stdout)
    if keyring is None:
        log.error("'keyring' package not installed. Run: pip install keyring")
        sys.exit(1)
    load_dotenv()
    try:
        environments = parse_okta_environments(os.environ)
    except ConfigError as e:
        log.error("%s", e)
        sys.exit(1)

    say("\nADFS → Okta Migration Tool — Token Setup")
    say("=" * 45)
    say("Tokens will be stored in your OS credential store.")
    say("Press Enter to keep an existing token unchanged.\n")

    changed = 0
    for name, cfg in environments.items():
        var = cfg["token_var"]
        label = f"{name.upper()} ({cfg['url']})"
        existing = keyring.get_password(KEYRING_SERVICE, var)
        hint = " [already set]" if existing else " [not set]"
        value = getpass.getpass(f"{label}{hint}\n  Enter token (Enter to skip): ")
        if value.strip():
            keyring.set_password(KEYRING_SERVICE, var, value.strip())
            say(f"  ✓ {var} saved.\n")
            changed += 1
        else:
            say(f"  – {var} unchanged.\n")

    say(f"Done. {changed} token(s) updated.")
    if changed:
        say("Restart the migration tool to pick up the new tokens.\n")


if __name__ == "__main__":
    main()
