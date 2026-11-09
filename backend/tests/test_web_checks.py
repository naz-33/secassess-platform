from pathlib import Path
from app.modules.findings import FindingSeverity
from app.modules.web_assessment.types import CapturedResponse
from app.modules.web_assessment.runners.curl_runner import parse_raw_curl_response
from app.modules.web_assessment.checks.security_headers import (
    check_security_headers,
    check_cors_configuration,
    check_plain_http_target,
    check_http_to_https_redirect,
    check_tls_configuration,
)
from app.modules.web_assessment.checks.exposed_files import (
    check_exposed_file,
    is_soft_404,
    parse_robots_txt,
)
from app.modules.web_assessment.checks.information_disclosure import (
    check_banner_headers,
    check_verbose_error_pages,
    check_sensitive_content,
)
from app.modules.web_assessment.checks.session_management import (
    check_cookie_attributes,
    mask_cookie_value,
    parse_set_cookie,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_security_headers_missing_all():
    """Crafted response with no security headers should produce findings for all headers."""
    resp = CapturedResponse(
        url="https://example.com/",
        method="GET",
        status=200,
        headers=[("Content-Type", "text/html")],
        body="<html><body>Hello</body></html>",
    )
    findings = check_security_headers(resp)
    titles = [f.title for f in findings]

    assert any("Content-Security-Policy" in t for t in titles)
    assert any("X-Frame-Options" in t for t in titles)
    assert any("X-Content-Type-Options" in t for t in titles)
    assert any("Referrer-Policy" in t for t in titles)
    assert any("Permissions-Policy" in t for t in titles)
    assert any("Strict-Transport-Security" in t for t in titles)
    assert all(f.category == "security_headers" for f in findings)
    assert all(f.wstg_id.startswith("WSTG-") for f in findings)


def test_security_headers_hardened_sample():
    """Hardened response fixture with all security headers must produce zero findings."""
    raw = (FIXTURES_DIR / "hardened_response.txt").read_text(encoding="utf-8")
    resp = parse_raw_curl_response(raw, url="https://secure.local/", method="GET", elapsed_ms=10.0)

    findings = check_security_headers(resp)
    assert len(findings) == 0, f"Expected 0 findings on hardened response, got: {[f.title for f in findings]}"


def test_weak_csp_and_weak_hsts():
    """Verify detection of unsafe-inline/eval in CSP and low max-age in HSTS."""
    resp = CapturedResponse(
        url="https://example.com/",
        method="GET",
        status=200,
        headers=[
            ("Content-Security-Policy", "default-src 'self' 'unsafe-inline' 'unsafe-eval'"),
            ("Strict-Transport-Security", "max-age=3600"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("Referrer-Policy", "strict-origin"),
            ("Permissions-Policy", "camera=()"),
        ],
    )
    findings = check_security_headers(resp)
    titles = [f.title for f in findings]
    assert any("Weak Content-Security-Policy" in t for t in titles)
    assert any("Weak Strict-Transport-Security Max-Age" in t for t in titles)


def test_hsts_ignored_on_plain_http():
    """HSTS should NOT be flagged as missing if the response is served over plain HTTP."""
    resp = CapturedResponse(
        url="http://example.com/",
        method="GET",
        status=200,
        headers=[("X-Content-Type-Options", "nosniff")],
    )
    findings = check_security_headers(resp)
    assert not any("Strict-Transport-Security" in f.title for f in findings)


def test_cors_wildcard_credentials_and_reflection():
    """Test wildcard CORS with credentials and reflected origin."""
    resp1 = CapturedResponse(
        url="http://example.com/api",
        method="GET",
        status=200,
        headers=[
            ("Access-Control-Allow-Origin", "*"),
            ("Access-Control-Allow-Credentials", "true"),
        ],
    )
    f1 = check_cors_configuration(resp1)
    assert len(f1) == 1
    assert "Insecure Permissive CORS" in f1[0].title
    assert f1[0].severity == FindingSeverity.HIGH

    resp2 = CapturedResponse(
        url="http://example.com/api",
        method="GET",
        status=200,
        headers=[
            ("Access-Control-Allow-Origin", "http://attacker.com"),
            ("Access-Control-Allow-Credentials", "true"),
        ],
    )
    f2 = check_cors_configuration(resp2, origin_tested="http://attacker.com")
    assert len(f2) == 1
    assert "Arbitrary CORS Origin Reflection" in f2[0].title


def test_plain_http_target_and_redirect():
    """Test findings generated when target is plain HTTP and when redirect is missing."""
    f_plain = check_plain_http_target("http://insecure.local", https_available=False)
    assert len(f_plain) == 1
    assert "Plain HTTP" in f_plain[0].title

    # Missing redirect when HTTPS is available
    http_resp = CapturedResponse(
        url="http://insecure.local/",
        method="GET",
        status=200,
        headers=[("Location", "")],
    )
    f_redir = check_http_to_https_redirect(http_resp, https_available=True)
    assert len(f_redir) == 1
    assert "Missing HTTP to HTTPS Redirect" in f_redir[0].title


def test_tls_configuration_checks():
    """Test pure TLS configuration checks (expired, self-signed, mismatch, deprecated)."""
    tls_data = {
        "accepted_protocols": ["TLSv1.0", "TLSv1.2"],
        "is_expired": True,
        "is_self_signed": True,
        "hostname_mismatch": True,
        "not_after": "Jan 01 2020",
        "san": ["other.com"],
        "common_name": "other.com",
    }
    findings = check_tls_configuration(tls_data, target_host="target.local")
    titles = [f.title for f in findings]
    assert any("Deprecated TLS Protocols" in t for t in titles)
    assert any("Expired TLS Certificate" in t for t in titles)
    assert any("Self-Signed" in t for t in titles)
    assert any("Hostname Mismatch" in t for t in titles)


def test_cookie_attributes_variants():
    """Verify parsing and security checking of multiple Set-Cookie variants."""
    resp = CapturedResponse(
        url="https://example.com/",
        method="GET",
        status=200,
        headers=[
            ("Set-Cookie", "session=12345; Path=/"),  # Missing HttpOnly, Secure, SameSite; short numeric
            ("Set-Cookie", "tracker=abc; Secure; SameSite=None"),  # SameSite=None without Secure? No, has Secure
            ("Set-Cookie", "bad_none=xyz; SameSite=None"),  # SameSite=None WITHOUT Secure
            ("Set-Cookie", "persistent=token_long_123456789; HttpOnly; Secure; SameSite=Lax; Max-Age=40000000"),  # > 1 yr
        ],
    )
    findings = check_cookie_attributes(resp)
    titles = [f.title for f in findings]

    assert any("Missing HttpOnly" in t for t in titles)
    assert any("Missing Secure" in t for t in titles)
    assert any("Missing SameSite" in t for t in titles)
    assert any("Insecure SameSite=None" in t for t in titles)
    assert any("Excessive Expiration" in t for t in titles)
    assert any("Weak or Predictable Session Identifier" in t for t in titles)


def test_cookie_masking_helper():
    """Verify session cookie values are masked in display summaries."""
    assert mask_cookie_value("123") == "***"
    assert mask_cookie_value("0123456789abcdef") == "012...def"
    assert mask_cookie_value("") == ""


def test_exposed_files_soft_404_baseline():
    """SPA catch-all returning 200 with identical HTML must NOT produce false positives."""
    baseline_html = "<html><head><title>Juice Shop SPA</title></head><body><app-root></app-root></body></html>"
    baseline_res = CapturedResponse(
        url="http://localhost:3000/notfound_baseline_abc",
        method="GET",
        status=200,
        body=baseline_html,
    )

    probe_git = CapturedResponse(
        url="http://localhost:3000/.git/HEAD",
        method="GET",
        status=200,
        body=baseline_html,  # Returns SPA catch-all!
    )
    assert is_soft_404(probe_git, baseline_res) is True
    findings_git = check_exposed_file(probe_git, baseline_res)
    assert len(findings_git) == 0  # Guarded against soft-404!

    # Real .git/HEAD
    real_git = CapturedResponse(
        url="http://localhost:3000/.git/HEAD",
        method="GET",
        status=200,
        body="ref: refs/heads/master\n",
    )
    assert is_soft_404(real_git, baseline_res) is False
    findings_real_git = check_exposed_file(real_git, baseline_res)
    assert len(findings_real_git) == 1
    assert "Exposed Git Repository Metadata" in findings_real_git[0].title
    assert findings_real_git[0].severity == FindingSeverity.HIGH


def test_exposed_env_and_directory_listing():
    """Verify genuine .env and directory listing signatures."""
    env_resp = CapturedResponse(
        url="http://localhost:3000/.env",
        method="GET",
        status=200,
        body="DATABASE_URL=postgres://user:pass@localhost:5432/db\nSECRET_KEY=supersecret\n",
    )
    f_env = check_exposed_file(env_resp, baseline=None)
    assert len(f_env) == 1
    assert "Exposed Environment Configuration File" in f_env[0].title
    assert f_env[0].severity == FindingSeverity.CRITICAL

    dir_resp = CapturedResponse(
        url="http://localhost:3000/backup/",
        method="GET",
        status=200,
        body="<html><head><title>Index of /backup</title></head><body><h1>Index of /backup</h1><pre><a href=...>file.zip</a></pre></body></html>",
    )
    f_dir = check_exposed_file(dir_resp, baseline=None)
    assert len(f_dir) == 1
    assert "Directory Listing Enabled" in f_dir[0].title


def test_robots_txt_parsing():
    """Verify parsing Disallow entries in robots.txt."""
    robots_content = "User-agent: *\nDisallow: /admin\nDisallow: /api/private\nDisallow: /\n# Comment\n"
    disallowed = parse_robots_txt(robots_content)
    assert "/admin" in disallowed
    assert "/api/private" in disallowed
    assert "/" not in disallowed
    assert "# Comment" not in disallowed


def test_information_disclosure_signatures():
    """Verify banner headers, stack traces, and sensitive HTML comments."""
    # Banner header
    banner_resp = CapturedResponse(
        url="http://localhost:3000/",
        method="GET",
        status=200,
        headers=[("Server", "Apache/2.4.41 (Ubuntu)"), ("X-Powered-By", "PHP/7.4.3")],
    )
    f_banners = check_banner_headers(banner_resp)
    assert len(f_banners) == 2

    # Stack trace
    stack_resp = CapturedResponse(
        url="http://localhost:3000/err",
        method="GET",
        status=500,
        body="Traceback (most recent call last):\n  File 'app.py', line 42, in index\nZeroDivisionError: division by zero",
    )
    f_stack = check_verbose_error_pages(stack_resp)
    assert len(f_stack) == 1
    assert "Verbose Error Page / Stack Trace" in f_stack[0].title

    # Sensitive HTML comment
    comment_resp = CapturedResponse(
        url="http://localhost:3000/",
        method="GET",
        status=200,
        body="<html><!-- TODO: remove admin password admin123 --><body>App</body></html>",
    )
    f_comm = check_sensitive_content(comment_resp)
    assert len(f_comm) == 1
    assert "Sensitive Developer Comments" in f_comm[0].title

