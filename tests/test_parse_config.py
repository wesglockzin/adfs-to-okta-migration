from okta_saml_import import parse_config

SAMPLE = r"""App Name: Example App
SSO URL: https://sp.example.test/sso
Entity ID: urn:example:app
Name ID Format: emailAddress
RequiresReview: TRUE
Signing Certificate: example_signing.pem
Encryption Certificate: None
Access Control Policy: Permit specific group

ACS Endpoints:
  [0] https://sp.example.test/acs
  [2] https://sp.example.test/acs-two

Attribute Statements:
  mail -> email
  sn -> lastName

Okta Translation Notes:
  - Create assignment rule for group: "EXAMPLECORP\Staff"
  - Create assignment rule for group: "Staff"
  - MFA group documented: "Admins"
"""


def write(tmp_path, text):
    path = tmp_path / "app_config.txt"
    path.write_text(text, encoding="utf-8-sig")
    return path


def test_parses_scalar_fields(tmp_path):
    data = parse_config(write(tmp_path, SAMPLE))
    assert data["app_name"] == "Example App"
    assert data["sso_url"] == "https://sp.example.test/sso"
    assert data["entity_id"] == "urn:example:app"
    assert data["name_id_format"] == "emailAddress"
    assert data["requires_review"] is True
    assert data["signing_cert_file"] == "example_signing.pem"
    assert data["encryption_cert_file"] is None


def test_acs_endpoints_skip_gaps(tmp_path):
    data = parse_config(write(tmp_path, SAMPLE))
    assert data["acs_endpoints"] == [
        "https://sp.example.test/acs",
        "https://sp.example.test/acs-two",
    ]


def test_attribute_statements(tmp_path):
    data = parse_config(write(tmp_path, SAMPLE))
    assert data["attribute_statements"] == ["mail -> email", "sn -> lastName"]


def test_groups_strip_domain_and_deduplicate(tmp_path):
    data = parse_config(write(tmp_path, SAMPLE))
    assert data["assign_groups"] == ["Staff"]
    assert data["assign_everyone"] is False


def test_defaults_to_everyone_when_nothing_parsed(tmp_path):
    data = parse_config(write(tmp_path, "App Name: Bare\n"))
    assert data["assign_everyone"] is True
    assert data["assign_groups"] == []
    assert data["requires_review"] is False


def test_all_users_rule(tmp_path):
    text = "Okta Translation Notes:\n  - Create assignment rule for all users\n"
    data = parse_config(write(tmp_path, text))
    assert data["assign_everyone"] is True
