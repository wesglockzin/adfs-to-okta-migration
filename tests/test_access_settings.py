import pytest

from settings import (
    ConfigError,
    is_user_allowed,
    parse_okta_environments,
    same_origin,
    split_list,
)


def test_okta_environments_any_length_with_derived_token_names():
    envs = parse_okta_environments(
        {"OKTA_ENVIRONMENTS": "dev=https://a.example.test/, qa-2=https://b.example.test"}
    )
    assert list(envs) == ["dev", "qa-2"]
    assert envs["dev"] == {"url": "https://a.example.test", "token_var": "OKTA_DEV_API_TOKEN"}
    assert envs["qa-2"]["token_var"] == "OKTA_QA_2_API_TOKEN"


def test_okta_environments_missing_names_the_setting():
    with pytest.raises(ConfigError, match="OKTA_ENVIRONMENTS"):
        parse_okta_environments({})


@pytest.mark.parametrize("value", ["dev", "dev=", "=https://a.example.test", "dev=ftp://x"])
def test_okta_environments_rejects_malformed_entries(value):
    with pytest.raises(ConfigError):
        parse_okta_environments({"OKTA_ENVIRONMENTS": value})


def test_split_list_ignores_blanks_and_case():
    assert split_list(" A@x.test, ,b@x.test ") == ["a@x.test", "b@x.test"]
    assert split_list(None) == []


def test_allow_list_rules():
    assert is_user_allowed("anyone@x.test", [], [], [])
    assert is_user_allowed("a@x.test", [], ["a@x.test"], [])
    assert is_user_allowed("z@x.test", ["Ops"], [], ["ops"])
    assert not is_user_allowed("z@x.test", ["other"], ["a@x.test"], ["ops"])


def test_same_origin_checks_origin_then_referer():
    host = "https://tool.example.test/"
    assert same_origin({"Origin": "https://tool.example.test"}, host)
    assert same_origin({"Referer": "https://tool.example.test/page"}, host)
    assert not same_origin({"Origin": "https://evil.example"}, host)
    assert not same_origin({"Origin": "http://tool.example.test"}, host)
    assert not same_origin({}, host)
