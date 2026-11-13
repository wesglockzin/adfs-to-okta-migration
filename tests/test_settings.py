import pytest

from settings import ConfigError, resolve_auth_mode, safe_next

FULL = {
    "OIDC_ISSUER": "https://issuer.example.test",
    "OIDC_CLIENT_ID": "test-id-not-real",
    "OIDC_CLIENT_SECRET": "test-secret-not-real",
    "FLASK_SECRET_KEY": "test-key-not-real",
}


def test_unset_auth_refuses_to_start():
    with pytest.raises(ConfigError) as exc:
        resolve_auth_mode({})
    assert "OIDC_ISSUER" in str(exc.value)
    assert "FLASK_SECRET_KEY" in str(exc.value)


def test_missing_secret_key_is_named():
    env = {k: v for k, v in FULL.items() if k != "FLASK_SECRET_KEY"}
    with pytest.raises(ConfigError, match="FLASK_SECRET_KEY"):
        resolve_auth_mode(env)


def test_full_oidc_settings_accepted():
    assert resolve_auth_mode(FULL) == "oidc"


def test_explicit_none_allowed():
    assert resolve_auth_mode({"AUTH_MODE": "none"}) == "none"


def test_unknown_mode_rejected():
    with pytest.raises(ConfigError, match="AUTH_MODE"):
        resolve_auth_mode({"AUTH_MODE": "off"})


@pytest.mark.parametrize("target", ["/", "/logs", "/api/scan?env=dev"])
def test_safe_next_accepts_relative_paths(target):
    assert safe_next(target) == target


@pytest.mark.parametrize(
    "target",
    [
        None,
        "",
        "//evil.example",
        "/\\evil.example",
        "https://evil.example/",
        "javascript:alert(1)",
        "logs",
        "/ok\r\nSet-Cookie: x=1",
    ],
)
def test_safe_next_rejects_everything_else(target):
    assert safe_next(target) is None
