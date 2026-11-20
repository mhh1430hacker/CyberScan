"""Tools 071-080 (privacy & data protection). Fixture secrets are fake but correctly formatted; every test that
handles them asserts that no value leaks into the result."""
import io
import json
import zipfile

import pytest
from PIL import Image

from conftest import b64, ids, no_secret_leak

# fake, format-valid test values (not real credentials)
GITHUB = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
HF = "hf_" + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dE3f"
AWS = "AKIA" + "Z7Q2X9K4M1P8L3N6"
PEM = "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n-----END RSA PRIVATE KEY-----"
CARD = "4111 1111 1111 1111"   # Visa test number (Luhn-valid)


def _jpeg(*, gps=True, serial=True, artist=True):
    image = Image.new("RGB", (32, 32), (120, 30, 60))
    exif = Image.Exif()
    exif[0x010F] = "ExampleCam"
    exif[0x0110] = "Model X"
    if artist:
        exif[0x013B] = "Jane Doe"
    if serial:
        exif.get_ifd(0x8769)[0xA431] = "SN-0001234"
    if gps:
        exif.get_ifd(0x8825).update({1: "N", 2: (24.0, 42.0, 50.0), 3: "E", 4: (46.0, 40.0, 30.0)})
    out = io.BytesIO()
    image.save(out, "JPEG", exif=exif.tobytes() if (gps or serial or artist) else b"")
    return out.getvalue()


def _docx(*, author="Jane Doe", company="Example Corp", comments=True, tracked=True, hidden=True):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        z.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>')
        core = '<cp:coreProperties xmlns:cp="x" xmlns:dc="y">'
        if author:
            core += f"<dc:creator>{author}</dc:creator><cp:lastModifiedBy>{author}</cp:lastModifiedBy>"
        z.writestr("docProps/core.xml", core + "</cp:coreProperties>")
        z.writestr("docProps/app.xml", f"<Properties>{f'<Company>{company}</Company>' if company else ''}<Application>Word</Application></Properties>")
        body = "<w:document><w:body><w:p><w:r><w:t>Quarterly plan</w:t></w:r>"
        if tracked:
            body += '<w:del w:author="Jane Doe"><w:r><w:delText>layoffs in March</w:delText></w:r></w:del>'
        if hidden:
            body += "<w:r><w:rPr><w:vanish/></w:rPr><w:t>internal note</w:t></w:r>"
        z.writestr("word/document.xml", body + "</w:p></w:body></w:document>")
        if comments:
            z.writestr("word/comments.xml", '<w:comments><w:comment w:author="Bob Smith"><w:p><w:r><w:t>check numbers</w:t></w:r></w:p></w:comment></w:comments>')
    return out.getvalue()


def _pdf(*, author="Jane Doe", revisions=2):
    body = b"%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\n2 0 obj << /Author (" + author.encode() + b") /Producer (Writer) >> endobj\ntrailer << /Root 1 0 R /Info 2 0 R >>\n%%EOF\n"
    for _ in range(revisions - 1):
        body += b"3 0 obj << /Type /Page >> endobj\ntrailer << /Root 1 0 R /Prev 0 >>\n%%EOF\n"
    return body


# ---- 071 EXIF --------------------------------------------------------------------------------
EX = "cyberscan.privacy.exif-metadata"


def test_071_gps_serial_and_artist(run):
    result = run(EX, {"data_base64": b64(_jpeg()), "file_name": "holiday.jpg"})
    assert {"exif.gps", "exif.camera-serial", "exif.artist"} <= ids(result)
    gps = result["artifacts"]["gps_rounded"]  # 24°42'50"N 46°40'30"E, rounded to 2 decimals (~1 km)
    assert gps["latitude"] == pytest.approx(24.71, abs=0.011) and gps["longitude"] == pytest.approx(46.675, abs=0.011)
    assert "SN-0001234" not in json.dumps(result["findings"])  # values are described, not dumped


def test_071_clean_image_and_unsupported(run):
    clean = run(EX, {"data_base64": b64(_jpeg(gps=False, serial=False, artist=False))})
    assert clean["classification"] == "clean"
    assert run(EX, {"data_base64": b64(b"%PDF-1.4 not an image")})["status"] == "unsupported"


# ---- 072 PII ---------------------------------------------------------------------------------
PI = "cyberscan.privacy.pii-detector"
PII_TEXT = """name,email,card,iban,note
Jane,jane.doe@corp-mail.net,4111 1111 1111 1111,SA0380000000608010167519,SSN 123-45-6789
Omar,omar@corp-mail.net,,,national id: 1000000008 mobile 0551234567
Bob,bob@example.com,4111 1111 1111 1112,GB00WEST12345698765432,DOB: 1990-04-12 passport no A1234567
"""


def test_072_detects_and_validates(run):
    result = run(PI, {"content": PII_TEXT})
    counts = result["artifacts"]["counts"]
    assert counts["email"] == 2                    # example.com is a documentation domain
    assert counts["payment_card"] == 1             # ...1112 fails Luhn
    assert counts["iban"] == 1                     # the GB00 one fails mod-97
    assert counts["us_ssn"] == 1 and counts["saudi_id"] == 1 and counts["phone"] == 1
    assert counts["date_of_birth"] == 1 and counts["passport"] == 1
    no_secret_leak(result, "4111 1111 1111 1111", "4111111111111111", "SA0380000000608010167519", "123-45-6789", "jane.doe@")


def test_072_clean_text_and_filter(run):
    assert run(PI, {"content": "Meeting notes: ship v2 on Friday. Build 1234-56."})["classification"] == "clean"
    only = run(PI, {"content": PII_TEXT, "kinds": ["email"]})
    assert set(only["artifacts"]["counts"]) == {"email"}


# ---- 073 sensitive data ----------------------------------------------------------------------
SD = "cyberscan.privacy.sensitive-data"


def test_073_classification_levels(run):
    public = run(SD, {"content": "Product brochure. Our new app helps teams plan sprints."})
    assert public["artifacts"]["sensitivity"] == "public" and public["classification"] == "clean"
    hr = run(SD, {"content": "INTERNAL USE ONLY\nSalary bands and bonus targets for the performance review cycle."})
    assert hr["artifacts"]["sensitivity"] == "confidential" and "category.hr" in ids(hr)
    medical = run(SD, {"content": "STRICTLY CONFIDENTIAL\nPatient diagnosis: ICD-10 E11.9, prescription renewed."})
    assert medical["artifacts"]["sensitivity"] == "restricted" and "category.health" in ids(medical)
    arabic = run(SD, {"content": "سري للغاية\nكشف حساب ورقم الحساب للعميل"})
    assert arabic["artifacts"]["sensitivity"] == "restricted"


# ---- 074 / 075 keys and credentials ----------------------------------------------------------
AK = "cyberscan.privacy.api-key-exposure"
CR = "cyberscan.privacy.credential-exposure"
CONFIG = f"""
github_token = "{GITHUB}"
HF_TOKEN={HF}
aws_access_key_id = {AWS}
api_key = "your-api-key-here"
DATABASE_URL=postgres://app:S3cr3tPassw0rd!@db.internal:5432/app
smtp: https://mailer:Qx7pLm2zR9@smtp.example.test/send
{PEM}
"""


def test_074_api_keys(run):
    result = run(AK, {"content": CONFIG, "path": "settings.env"})
    found = ids(result)
    assert {"key.github_token", "key.huggingface_token", "key.aws_access_key_id"} <= found
    assert not any("postgres" in f or "private" in f for f in found)  # credentials belong to tool 075
    no_secret_leak(result, GITHUB, HF, AWS)
    assert result["artifacts"]["keys"] == 3


def test_075_credentials(run):
    result = run(CR, {"content": CONFIG})
    found = ids(result)
    assert {"credential.private_key", "credential.connection_string", "credential.url_credentials"} <= found
    assert result["classification"] == "suspicious"
    no_secret_leak(result, "S3cr3tPassw0rd!", "Qx7pLm2zR9", "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu")


def test_074_075_clean_and_placeholders(run):
    text = 'api_key = "<YOUR_KEY>"\npassword = "changeme"\nAuthorization: Bearer ${TOKEN}\n'
    assert run(AK, {"content": text})["classification"] == "clean"
    assert run(CR, {"content": text})["classification"] == "clean"


# ---- 076 logs --------------------------------------------------------------------------------
LG = "cyberscan.privacy.log-privacy"
LOG = f"""2026-11-10T10:00:01Z INFO GET /login?next=/home 200 client=62.104.12.9
2026-11-10T10:00:02Z DEBUG POST /api/login body={{"user":"jane","password":"Winter2026!"}}
2026-11-10T10:00:03Z INFO GET /reset?token=8f9c2a7b1e4d6f3a&user=jane 302
2026-11-10T10:00:04Z DEBUG headers Cookie: JSESSIONID=9A8B7C6D5E4F3A2B1C0D; theme=dark
2026-11-10T10:00:05Z DEBUG Authorization: Bearer {GITHUB}
2026-11-10T10:00:06Z ERROR Traceback (most recent call last):
  File "/srv/app/payments.py", line 42, in charge
2026-11-10T10:00:07Z INFO charged card {CARD} for jane.doe@corp-mail.net
"""


def test_076_log_findings_and_masking(run):
    result = run(LG, {"content": LOG, "path": "app.log"})
    found = ids(result)
    assert {"log.logged_password", "log.query_secret", "log.session_cookie", "log.auth_header", "log.stack_trace",
            "log.pii.payment_card", "log.pii.email", "log.pii.ip_address"} <= found
    assert result["artifacts"]["suggested_masking"]
    no_secret_leak(result, "Winter2026!", "8f9c2a7b1e4d6f3a", "9A8B7C6D5E4F3A2B1C0D", GITHUB, "4111 1111 1111 1111")


def test_076_clean_log(run):
    clean = "2026-11-10 INFO service started\n2026-11-10 INFO health check ok (latency 12ms)\n"
    assert run(LG, {"content": clean})["classification"] == "clean"


# ---- 077 cookies -----------------------------------------------------------------------------
CK = "cyberscan.privacy.cookie-tracking"
NOW = 1_794_000_000


def test_077_set_cookie_headers(run):
    headers = "\n".join([
        "Set-Cookie: sessionid=abc123def456ghi789; Path=/",
        "Set-Cookie: _ga=GA1.2.111.222; Domain=.shop.example.test; Max-Age=63072000; Path=/",
        "Set-Cookie: _fbp=fb.1.2.3; Domain=.shop.example.test; Max-Age=7776000; SameSite=None",
        "Set-Cookie: __Host-csrf=x; Path=/app; Secure",
        "Set-Cookie: auth_token=zzz; Secure; HttpOnly; SameSite=Lax; Path=/",
    ])
    result = run(CK, {"set_cookie": headers, "site": "shop.example.test", "now": NOW})
    found = ids(result)
    assert {"cookie.session-not-secure.sessionid", "cookie.session-not-httponly.sessionid", "cookie.long-lived._ga",
            "cookie.samesite-none-insecure._fbp", "cookie.host-prefix.__Host-csrf"} <= found
    assert any(f.startswith("tracker.google-analytics") for f in found) and any(f.startswith("tracker.meta") for f in found)
    assert not any("auth_token" in f for f in found)
    no_secret_leak(result, "abc123def456ghi789")


def test_077_har_third_party(run):
    har = {"log": {"entries": [
        {"request": {"url": "https://www.news.example.test/"}, "response": {"content": {"mimeType": "text/html"}, "headers": [
            {"name": "Set-Cookie", "value": "pref=1; Secure; HttpOnly; SameSite=Lax"}]}},
        {"_initiator": {"type": "script"}, "request": {"url": "https://ads.tracker.test/pixel"},
         "response": {"content": {"mimeType": "image/gif"}, "headers": [{"name": "Set-Cookie", "value": "IDE=xyz; Domain=.tracker.test; Secure; SameSite=None"}]}},
    ]}}
    result = run(CK, {"har": json.dumps(har), "now": NOW})
    assert "cookie.third-party" in ids(result) and result["artifacts"]["first_party"] == "example.test"
    assert run(CK, {"set_cookie": "no cookies here"})["status"] == "invalid_input"


# ---- 078 browser privacy ---------------------------------------------------------------------
BP = "cyberscan.privacy.browser-privacy"


def test_078_chromium_and_firefox(run):
    prefs = {"safebrowsing": {"enabled": False}, "profile": {"cookie_controls_mode": 0, "password_manager_leak_detection": False,
             "default_content_setting_values": {"geolocation": 1, "notifications": 3}}}
    result = run(BP, {"chromium_preferences": json.dumps(prefs), "chromium_local_state": json.dumps({"dns_over_https": {"mode": "off"}})})
    assert {"chromium.safe-browsing-off", "chromium.third-party-cookies", "chromium.leak-detection-off",
            "chromium.permission-allowed.geolocation", "chromium.doh-off"} <= ids(result)
    assert "chromium.permission-allowed.notifications" not in ids(result)
    ff = run(BP, {"firefox_prefs": 'user_pref("network.cookie.cookieBehavior", 0);\nuser_pref("browser.safebrowsing.malware.enabled", false);\n'})
    assert {"firefox.network.cookie.cookieBehavior", "firefox.browser.safebrowsing.malware.enabled"} <= ids(ff)


def test_078_defaults_are_not_judged(run):
    result = run(BP, {"chromium_preferences": json.dumps({"profile": {"name": "Person 1"}}), "firefox_prefs": 'user_pref("browser.startup.page", 3);'})
    assert result["classification"] == "clean"


# ---- 079 data leakage ------------------------------------------------------------------------
DL = "cyberscan.privacy.data-leakage"


def test_079_text_leakage(run):
    text = (f"Deploy notes: connect to db01.corp.internal (10.20.30.40), share \\\\fileserver\\finance$\n"
            f"logs in C:\\Users\\jdoe\\AppData\\deploy.log, token {GITHUB}\n")
    result = run(DL, {"content": text, "internal_domains": ["corp.internal"]})
    assert {"leak.internal-hosts", "leak.private-ips", "leak.unc-paths", "leak.user-paths", "leak.secret.github_token"} <= ids(result)
    no_secret_leak(result, GITHUB)


def test_079_documents(run):
    docx = run(DL, {"data_base64": b64(_docx()), "file_name": "plan.docx"})
    assert {"leak.doc-people", "leak.comments", "leak.tracked-changes", "leak.hidden-text"} <= ids(docx)
    pdf = run(DL, {"data_base64": b64(_pdf()), "file_name": "report.pdf"})
    assert {"leak.pdf-author", "leak.pdf-revisions"} <= ids(pdf)
    clean = run(DL, {"data_base64": b64(_docx(author=None, company=None, comments=False, tracked=False, hidden=False))})
    assert clean["classification"] == "clean", clean["findings"]


# ---- 080 metadata removal --------------------------------------------------------------------
MR = "cyberscan.privacy.metadata-removal"


def test_080_image_pass_and_fail(run):
    dirty, cleaned = _jpeg(), _jpeg(gps=False, serial=False, artist=False)
    passed = run(MR, {"cleaned_base64": b64(cleaned), "original_base64": b64(dirty)})
    assert passed["artifacts"]["passed"] is True and passed["summary"].startswith("PASS")
    assert {"gps", "camera_serial", "author"} <= set(passed["artifacts"]["removed"])
    failed = run(MR, {"cleaned_base64": b64(dirty)})
    assert failed["artifacts"]["passed"] is False and {"remains.gps", "remains.author"} <= ids(failed)


def test_080_documents(run):
    assert {"remains.author", "remains.tracked_changes", "remains.comments"} <= ids(run(MR, {"cleaned_base64": b64(_docx())}))
    clean_docx = _docx(author=None, company=None, comments=False, tracked=False, hidden=False)
    assert run(MR, {"cleaned_base64": b64(clean_docx)})["artifacts"]["passed"] is True
    assert "remains.pdf_revisions" in ids(run(MR, {"cleaned_base64": b64(_pdf(author="", revisions=2))}))
    assert run(MR, {"cleaned_base64": b64(b"plain text file")})["status"] == "unsupported"


def test_072_float_fractions_are_not_card_numbers(run):
    # 16 fractional digits that happen to pass Luhn (found in evaluation JSON during the pre-push scan)
    assert run(PI, {"content": '{"seconds": 0.4111111111111111, "threshold": 0.5555555555554444}'})["classification"] == "clean"
