import pytest
import requests

from okta_saml_import import OktaClient


def make_response(status, body=b"[]", headers=None):
    resp = requests.Response()
    resp.status_code = status
    resp._content = body
    resp.url = "https://okta.example.test/api"
    resp.headers.update(headers or {})
    return resp


class FakeSession:
    """Stands in for requests.Session; replays queued responses."""

    def __init__(self, responses):
        self.headers = {}
        self.responses = list(responses)
        self.urls = []

    def get(self, url, **kwargs):
        self.urls.append(url)
        return self.responses.pop(0)


@pytest.fixture
def client():
    return OktaClient("https://okta.example.test/", "token")


def test_http_error_keeps_status_and_body(client):
    body = b'{"errorSummary": "boom"}'
    client.session = FakeSession([make_response(500, body)])
    with pytest.raises(requests.HTTPError) as exc:
        client._get("/api/v1/apps")
    assert exc.value.response.status_code == 500
    assert "boom" in exc.value.response.text


def test_rate_limit_is_retried(client, monkeypatch):
    sleeps = []
    monkeypatch.setattr("time.sleep", sleeps.append)
    client.session = FakeSession(
        [make_response(429), make_response(200, b'[{"label": "A"}]')]
    )
    assert client._get("/api/v1/apps") == [{"label": "A"}]
    assert len(sleeps) == 1


def test_rate_limit_gives_up_with_http_error(client, monkeypatch):
    monkeypatch.setattr("time.sleep", lambda _s: None)
    client.session = FakeSession([make_response(429) for _ in range(4)])
    with pytest.raises(requests.HTTPError):
        client._get("/api/v1/apps")


def test_get_all_apps_follows_next_link(client):
    first = make_response(
        200,
        b'[{"label": "A"}]',
        {"Link": '<https://okta.example.test/page2>; rel="next"'},
    )
    second = make_response(200, b'[{"label": "B"}]')
    client.session = FakeSession([first, second])
    apps = client.get_all_apps()
    assert sorted(apps) == ["A", "B"]
    assert client.session.urls[1] == "https://okta.example.test/page2"


def test_dry_run_makes_no_calls():
    client = OktaClient("https://okta.example.test", "token", dry_run=True)
    client.session = FakeSession([])
    assert client._post("/api/v1/apps", {})["_dryrun"] is True


def test_user_agent_has_no_org_text():
    client = OktaClient("https://okta.example.test", "token")
    assert "internal" not in client.session.headers["User-Agent"]
