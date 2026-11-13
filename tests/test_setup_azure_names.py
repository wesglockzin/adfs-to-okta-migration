"""setup-azure.sh must name tokens the way settings.py does."""

import subprocess
from pathlib import Path

from settings import parse_okta_environments

SCRIPT = Path(__file__).resolve().parent.parent / "setup-azure.sh"


def test_script_trims_only_the_ends_of_environment_names():
    line = next(ln for ln in SCRIPT.read_text().splitlines() if "env_name=$(echo" in ln)
    assert "tr -d '[:space:]'" not in line


def test_script_token_variable_matches_settings():
    script = SCRIPT.read_text().splitlines()
    name_line = next(ln for ln in script if "env_name=$(echo" in ln)
    var_line = next(ln for ln in script if ln.strip().startswith("token_var="))
    entry = " Okta Prod =https://x.okta.com"
    code = f'entry="{entry}"\n{name_line}\n{var_line}\nprintf %s "$token_var"'
    out = subprocess.run(
        ["bash", "-c", code], capture_output=True, text=True, check=True
    ).stdout
    envs = parse_okta_environments({"OKTA_ENVIRONMENTS": entry.strip()})
    assert [v["token_var"] for v in envs.values()] == [out]
