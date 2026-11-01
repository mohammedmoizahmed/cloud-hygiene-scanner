import base64
import re

import pytest

from app import create_app
from app.checks import Finding
from app.scanner import ScanResult


def stub_scan():
    findings = [
        Finding("security_groups_open", "Security", "critical", "sg-1 (open)", "All traffic is open",
                "x", "Restrict it.", "us-east-1", "Network security"),
        Finding("ebs_unattached", "Cost", "low", "vol-1", "Unattached volume (8 GiB)", "x", "Delete it.",
                "us-east-1", "Cost optimisation"),
        Finding("tags", "Governance", "low", "i-1", "<script>alert(1)</script>", "<b>bold</b>", "Tag it.",
                "us-east-1", ""),
    ]
    errors = [{"check": "s3_public_access", "title": "S3 Block Public Access", "region": "us-east-1",
               "message": "ClientError: AccessDenied"}]
    return ScanResult("2026-11-01T08:00:00+00:00", "2026-11-01T08:00:09+00:00", ["us-east-1"], 6, findings, errors)


@pytest.fixture
def app():
    return create_app(scan_fn=stub_scan)


def basic(user="admin", password="test-password"):
    return {"Authorization": "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()}


def token(client):
    html = client.get("/", headers=basic()).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def run_scan_now(client):
    return client.post("/scan", data={"csrf_token": token(client)}, headers=basic())


def test_the_app_refuses_to_start_without_a_secret_key(monkeypatch):
    monkeypatch.delenv("SECRET_KEY")
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        create_app()


def test_the_app_refuses_to_start_without_a_password(monkeypatch):
    monkeypatch.delenv("SCANNER_PASSWORD")
    with pytest.raises(RuntimeError, match="SCANNER_PASSWORD"):
        create_app()


def test_auth_can_be_switched_off_for_a_local_demo(monkeypatch):
    monkeypatch.delenv("SCANNER_PASSWORD")
    monkeypatch.setenv("SCANNER_AUTH", "off")
    assert create_app(scan_fn=stub_scan).test_client().get("/").status_code == 200


def test_health_and_version_are_public(app):
    client = app.test_client()
    assert client.get("/health").get_data(as_text=True) == "OK"
    assert set(client.get("/version").get_json()) == {"commit", "built"}


def test_the_dashboard_needs_a_login(app):
    response = app.test_client().get("/")
    assert response.status_code == 401 and "Basic" in response.headers["WWW-Authenticate"]


@pytest.mark.parametrize("user, password", [("admin", "wrong"), ("someone", "test-password"), ("", "")])
def test_wrong_credentials_are_refused(app, user, password):
    assert app.test_client().get("/", headers=basic(user, password)).status_code == 401


def test_the_api_and_the_scan_button_are_protected_too(app):
    client = app.test_client()
    assert client.get("/api/findings").status_code == 401
    assert client.post("/scan").status_code == 401


def test_before_any_scan_the_page_says_so(app):
    assert "No scan yet" in app.test_client().get("/", headers=basic()).get_data(as_text=True)


def test_scanning_shows_the_findings_and_the_counts(app):
    client = app.test_client()
    assert run_scan_now(client).status_code == 302
    html = client.get("/", headers=basic()).get_data(as_text=True)
    assert "3 findings" in html and "All traffic is open" in html and "Unattached volume" in html


def test_a_scan_without_the_form_token_is_refused(app):
    response = app.test_client().post("/scan", data={}, headers=basic())
    assert response.status_code == 400


def test_checks_that_could_not_run_are_shown(app):
    client = app.test_client()
    run_scan_now(client)
    html = client.get("/", headers=basic()).get_data(as_text=True)
    assert "could not run" in html and "AccessDenied" in html


def test_text_from_aws_is_escaped(app):
    client = app.test_client()
    run_scan_now(client)
    html = client.get("/", headers=basic()).get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html


def test_filter_by_severity_and_category(app):
    client = app.test_client()
    run_scan_now(client)
    critical = client.get("/?severity=critical", headers=basic()).get_data(as_text=True)
    assert "All traffic is open" in critical and "Unattached volume" not in critical
    cost = client.get("/?category=Cost", headers=basic()).get_data(as_text=True)
    assert "Unattached volume" in cost and "All traffic is open" not in cost


def test_unknown_filters_are_ignored(app):
    client = app.test_client()
    run_scan_now(client)
    html = client.get("/?severity=nonsense&category=<b>", headers=basic()).get_data(as_text=True)
    assert "3 findings" in html and "All traffic is open" in html


def test_empty_filter_result_has_a_message(app):
    client = app.test_client()
    run_scan_now(client)
    assert "Nothing to report" in client.get("/?severity=info", headers=basic()).get_data(as_text=True)


def test_api_returns_the_latest_scan_as_json(app):
    client = app.test_client()
    assert client.get("/api/findings", headers=basic()).get_json() == {"scan": None, "findings": []}
    run_scan_now(client)
    data = client.get("/api/findings", headers=basic()).get_json()
    assert len(data["findings"]) == 3 and data["errors"][0]["check"] == "s3_public_access"


def test_times_are_shown_in_saudi_time_by_default(app):
    client = app.test_client()
    run_scan_now(client)
    assert "01 Nov 2026 11:00" in client.get("/", headers=basic()).get_data(as_text=True)


def test_version_shows_the_build_the_pipeline_stamped():
    app = create_app(scan_fn=stub_scan, config={"APP_COMMIT": "abc1234567", "APP_BUILD_TIME": "2026-11-01T08:00Z"})
    client = app.test_client()
    assert client.get("/version").get_json() == {"commit": "abc1234567", "built": "2026-11-01T08:00Z"}
    assert "abc12345" in client.get("/", headers=basic()).get_data(as_text=True)


def test_security_headers_and_no_caching(app):
    response = app.test_client().get("/", headers=basic())
    assert response.headers["X-Frame-Options"] == "DENY" and response.headers["Cache-Control"] == "no-store"
