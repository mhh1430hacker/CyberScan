"""URL/phishing intelligence and email/SMS analysis. All offline; domains are fictitious or reserved."""
from __future__ import annotations

import pytest

from core.scanner import scan_target
from detection.messages import analyze_message
from detection.url_intel import analyze_url_intel, damerau_levenshtein, extract_urls, registrable_domain, skeleton

LEGITIMATE = [
    "https://www.paypal.com/signin",
    "https://accounts.google.com/ServiceLogin",
    "https://login.microsoftonline.com/common/oauth2/authorize",
    "https://github.com/org/repo",
    "https://amazon.co.uk/",
    "https://en.wikipedia.org/wiki/Finance",
    "https://my-finance-blog.com/discard",      # one edit from 'binance' / 'discord': real words
    "https://www.netflix.com/browse",
]

PHISHING = [
    ("http://paypal-secure-login.com/webscr", "Brand impersonation in domain name"),
    ("http://paypal.com.account-verify.xyz/login", "Brand name in subdomain of unrelated domain"),
    ("https://xn--pple-43d.com/", "Mixed-script domain (homograph)"),  # Cyrillic 'а' + 'pple'
    ("http://paypa1.com/", "Lookalike (homoglyph) domain"),
    ("http://paypall.com/", "Typosquatting domain"),
    ("https://faceb00k.com/login", "Lookalike (homoglyph) domain"),
    ("https://www.google.com@evil.example/", "Embedded credential marker in URL"),
    ("javascript:alert(1)", "Script URL scheme"),
    ("data:text/html;base64,PHNjcmlwdD4=", "Data URL"),
    ("https://www.google.com/url?q=http://paypal-verify.top/login", "Suspicious redirect destination"),
]


@pytest.mark.parametrize("url", LEGITIMATE)
def test_legitimate_urls_are_not_flagged(url):
    result = analyze_url_intel(url)
    assert result["score"] == 0, result["findings"]
    assert result["classification"] == "SAFE"


@pytest.mark.parametrize("url,label", PHISHING)
def test_phishing_urls_are_suspicious_with_explanation(url, label):
    result = analyze_url_intel(url)
    labels = [item["label"] for item in result["findings"]]
    assert label in labels
    assert result["classification"] == "SUSPICIOUS", labels
    assert all(item["explanation"] for item in result["findings"])


def test_weak_signals_alone_do_not_reach_suspicious():
    # A shortener, an abused TLD or a brand word in an unrelated domain is context, not a verdict.
    for url in ("https://bit.ly/abc", "https://example.xyz/", "https://apple-pie-recipes.com/"):
        assert analyze_url_intel(url)["classification"] != "SUSPICIOUS", url


@pytest.mark.parametrize("url,ip", [("http://0xC0A80001/", "192.168.0.1"), ("http://3232235521/", "192.168.0.1"),
                                    ("http://0177.0.0.1/", "127.0.0.1")])
def test_obfuscated_ip_hosts_are_decoded(url, ip):
    result = analyze_url_intel(url)
    assert result["registrable_domain"] == ip
    assert any(item["label"] == "Obfuscated IP address host" for item in result["findings"])


@pytest.mark.parametrize("url", ["http://[::1", "http://", "http://exa mple.com/\x00", "ht!tp://x", "", "   ",
                                 "http://" + "a" * 20000 + ".com"])
def test_malformed_urls_never_raise(url):
    result = analyze_url_intel(url)
    assert 0 <= result["score"] <= 100


def test_registrable_domain_and_skeleton_helpers():
    assert registrable_domain("a.b.example.co.uk") == "example.co.uk"
    assert registrable_domain("login.paypal.com") == "paypal.com"
    assert skeleton("rnicr0soft") == "microsoft"
    assert damerau_levenshtein("netflix", "netfilx") == 1  # transposition


def test_url_extraction_refangs_defanged_indicators():
    urls = extract_urls("Visit hxxps://dhl-redelivery[.]top/pay now or www.example.com/x.")
    assert urls == ["https://dhl-redelivery.top/pay", "www.example.com/x"]


def test_scanner_routes_bare_url_tokens_to_url_analysis():
    result = scan_target("paypal-secure-login.com/webscr")
    assert any(item.category == "phishing" for item in result.evidence)
    assert result.content_analysis.get("url_intel", {}).get("impersonated_brand") == "paypal"


def test_sms_delivery_scam_is_suspicious():
    sms = "USPS: Your package is on hold due to an incomplete address. Pay the redelivery fee within 24 hours: https://usps-redelivery.example-track.top/pay"
    result = analyze_message(sms)
    labels = {item["label"] for item in result["findings"]}
    assert {"Parcel delivery lure", "Suspicious link in message"} <= labels
    assert result["classification"] == "SUSPICIOUS"


def test_legitimate_otp_notification_is_not_an_otp_scam():
    sms = "Your verification code is 482913. Do not share this code with anyone. It expires in 10 minutes."
    result = analyze_message(sms)
    assert not any(item["label"] == "Request to share a one-time code" for item in result["findings"])
    assert result["classification"] != "SUSPICIOUS"


def test_otp_sharing_request_is_flagged():
    result = analyze_message("Hi, this is the bank security team. Please send us the verification code you just received.")
    assert any(item["label"] == "Request to share a one-time code" for item in result["findings"])


def test_arabic_account_suspension_lure_is_detected():
    result = analyze_message("عاجل: تم إيقاف حسابك. يرجى تأكيد حسابك عبر الرابط http://alrajhi-verify.example.top/login")
    labels = {item["label"] for item in result["findings"]}
    assert "Urgency or threat language" in labels and "Credential or verification request" in labels
    assert result["classification"] == "SUSPICIOUS"


def test_ordinary_message_is_safe():
    assert analyze_message("Lunch at 1pm tomorrow? The agenda is in the shared folder.")["score"] == 0


SPOOFED_EMAIL = """From: "PayPal Service" <billing@paypa1-support.example>
Reply-To: collector@other.example
To: user@example.org
Subject: Your account is suspended
Authentication-Results: mx.example.org; spf=fail smtp.mailfrom=paypa1-support.example; dkim=none; dmarc=fail

Your account has been suspended. Verify your account within 24 hours: http://paypa1-support.example/login
"""


def test_email_header_spoofing_is_explained():
    result = analyze_message(SPOOFED_EMAIL)
    labels = {item["label"] for item in result["findings"]}
    assert {"Sender display name impersonates a brand", "Reply-To differs from sender", "Email authentication failed"} <= labels
    assert result["email_headers"]["authentication_failures"] == ["dmarc", "spf"]
    assert result["evidence_agreement"] == "strong"


def test_legitimate_brand_email_from_official_domain_is_not_spoofing():
    email = 'From: "PayPal" <service@paypal.com>\nTo: a@example.org\nSubject: Receipt\nAuthentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\nThanks for your payment.'
    result = analyze_message(email)
    assert result["score"] == 0, result["findings"]
