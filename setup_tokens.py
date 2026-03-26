"""
setup_tokens.py — Store Okta API tokens in the OS credential store.

Run once per machine (or whenever a token changes):
    python setup_tokens.py

Tokens are saved to:
  macOS  → Keychain
  Windows → Credential Manager
  Linux  → Secret Service (GNOME Keyring / KWallet)

The migration tool reads them automatically — no plaintext tokens in .env.
"""
from __future__ import annotations

import getpass
import sys

try:
    import keyring
except ImportError:
    print("ERROR: 'keyring' package not installed.")
    print("Run:  pip install keyring")
    sys.exit(1)

KEYRING_SERVICE = "adfs-okta-migration"

TOKENS = [
    ("OKTA_DEV_API_TOKEN",  "DEV  (https://YOUR_DEV_OKTA_DOMAIN.okta-gov.com)"),
    ("OKTA_STG_API_TOKEN",  "STG  (https://YOUR_STG_OKTA_DOMAIN.okta-gov.com)"),
    ("OKTA_PROD_API_TOKEN", "PROD (https://YOUR_PROD_OKTA_DOMAIN.okta-gov.com)"),
]


def main() -> None:
    print("\nADFS → Okta Migration Tool — Token Setup")
    print("=" * 45)
    print("Tokens will be stored in your OS credential store.")
    print("Press Enter to keep an existing token unchanged.\n")

    changed = 0
    for var, label in TOKENS:
        existing = keyring.get_password(KEYRING_SERVICE, var)
        hint = " [already set]" if existing else " [not set]"
        value = getpass.getpass(f"{label}{hint}\n  Enter token (Enter to skip): ")
        if value.strip():
            keyring.set_password(KEYRING_SERVICE, var, value.strip())
            print(f"  ✓ {var} saved.\n")
            changed += 1
        else:
            print(f"  – {var} unchanged.\n")

    print(f"Done. {changed} token(s) updated.")
    if changed:
        print("Restart the migration tool to pick up the new tokens.\n")


if __name__ == "__main__":
    main()
