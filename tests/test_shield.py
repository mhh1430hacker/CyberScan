"""Tests for the web interface's protection tools (web_v/shield)."""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "web_v")]

from shield import core, engine, privacy, scans, system, winutil  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "CONFIG_PATH", tmp_path / "shield.json")
    core._unlocks.clear()
    yield


# ---------------------------------------------------------------- settings
def test_update_config_accepts_known_keys_and_nested_changes():
    old, new = core.update_config({"web": {"botnet": False}, "smart_scan": {"schedule": "daily", "time": "08:30"}})
    assert old["web"]["botnet"] is True
    assert new["web"]["botnet"] is False
    assert core.load_config()["smart_scan"]["time"] == "08:30"


@pytest.mark.parametrize("changes", [
    {"web": {"made_up": True}},
    {"file_shield": "yes"},
    {"smart_scan": {"time": "25:00"}},
    {"smart_scan": {"schedule": "hourly"}},
    {"virus_scan": {"max_mb": 0}},
    {"password": {"hash": "x"}},          # the hash can only be set through set_password
])
def test_update_config_rejects_unknown_keys_and_bad_values(changes):
    with pytest.raises(ValueError):
        core.update_config(changes)


def test_lists_are_deduplicated_and_trimmed():
    _, new = core.update_config({"exclusions": {"paths": [" C:\\A ", "C:\\A", "C:\\B"]}})
    assert new["exclusions"]["paths"] == ["C:\\A", "C:\\B"]


def test_public_config_never_exposes_the_password_hash():
    core.set_password("", "secret123")
    out = core.public_config()
    assert out["password"] == {"set": True, "protect": ["settings", "shields", "quarantine"]}
    assert "hash" not in str(out["password"]) and "salt" not in out["password"]


# ---------------------------------------------------------------- password
def test_password_lock_and_unlock(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda _s: None)
    assert core.unlocked(None, "settings")          # no password: everything open
    core.set_password("", "secret123")
    assert not core.unlocked(None, "settings")
    assert core.unlock("wrong") is None
    token = core.unlock("secret123")
    assert token and core.unlocked(token, "settings")
    with pytest.raises(PermissionError):
        core.set_password("wrong", "other123")
    with pytest.raises(ValueError):
        core.set_password("secret123", "123")         # too short
    core.set_password("secret123", "")                # removed
    assert core.unlocked(None, "quarantine")


def test_unprotected_area_needs_no_unlock():
    core.set_password("", "secret123")
    core.update_config({"password": {"protect": ["quarantine"]}})
    assert core.unlocked(None, "settings")
    assert not core.unlocked(None, "quarantine")


# ---------------------------------------------------------------- engine
def test_exclusions_match_folders_and_patterns(tmp_path):
    inside = tmp_path / "games" / "x.exe"
    assert engine.excluded(inside, [str(tmp_path / "games")])
    assert engine.excluded(tmp_path / "disk.iso", ["*.iso"])
    assert not engine.excluded(tmp_path / "gamesX" / "x.exe", [str(tmp_path / "games")])


def test_sniff_finds_real_type_whatever_the_name():
    assert engine.sniff(b"MZ\x90\x00") == "pe"
    assert engine.sniff(b"%PDF-1.7") == "pdf"
    assert engine.sniff(b"  <html><body>") == "markup"
    assert engine.sniff(b"hello") == ""


def test_media_files_are_not_deep_scanned(tmp_path):
    photo = tmp_path / "photo.jpg"
    photo.write_bytes(b"\xff\xd8\xff\xe0" + b"0" * 100)
    assert engine.inspect(photo) == {"status": "clean", "kind": "data", "deep": False}


def test_program_disguised_as_picture_is_deep_scanned(tmp_path, monkeypatch):
    fake = tmp_path / "holiday.jpg"
    fake.write_bytes(b"MZ" + b"\x00" * 200)
    monkeypatch.setattr(engine, "CACHE_PATH", tmp_path / "cache.json")
    monkeypatch.setattr(engine, "_cache", None)
    out = engine.inspect(fake)
    assert out.get("deep") is True and out["kind"] == "pe"


def test_walk_respects_depth_and_skips_noise(tmp_path):
    (tmp_path / "a" / "b").mkdir(parents=True)
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "top.exe").write_text("x")
    (tmp_path / "a" / "one.exe").write_text("x")
    (tmp_path / "a" / "b" / "two.exe").write_text("x")
    (tmp_path / "node_modules" / "skip.js").write_text("x")
    names = {p.name for p in engine.walk([tmp_path], [], max_depth=1)}
    assert names == {"top.exe", "one.exe"}


# ---------------------------------------------------------------- scheduling
def test_smart_scan_schedule():
    cfg = core.load_config()
    cfg["smart_scan"].update(schedule="off", last_run=0)
    assert not scans.due(cfg)
    cfg["smart_scan"].update(schedule="auto", last_run=time.time())
    assert not scans.due(cfg)
    cfg["smart_scan"].update(last_run=time.time() - 8 * 86400)
    assert scans.due(cfg)


# ---------------------------------------------------------------- privacy tools
def test_card_and_iban_detection_uses_checksums():
    text = "card 4111 1111 1111 1111, fake 4111 1111 1111 1112, IBAN GB82 WEST 1234 5698 7654 32, bad GB00 WEST 1234 5698 7654 32"
    hits = privacy.find_sensitive(text, ["card", "iban"])
    assert hits == {"card": 1, "iban": 1}


def test_written_down_passwords_and_private_keys():
    hits = privacy.find_sensitive("password: hunter22\n-----BEGIN RSA PRIVATE KEY-----", ["password", "secret"])
    assert hits["password"] == 1 and hits["secret"] >= 1


def test_phishing_email_is_flagged():
    raw = (b"From: PayPal Support <alerts@paypa1-secure.xyz>\r\nReply-To: x@evil.example\r\n"
           b"Subject: Urgent: verify your account\r\nAuthentication-Results: mx; spf=fail; dmarc=fail\r\n"
           b"Content-Type: text/html\r\n\r\n<a href='http://evil.example/login'>www.paypal.com</a> verify your account")
    out = privacy.analyze_email(raw)
    keys = {f["key"] for f in out["findings"]}
    assert {"spf_fail", "dmarc_fail", "reply_to_differs", "brand_impersonation", "link_text_mismatch"} <= keys
    assert out["verdict"] == "bad"


def test_plain_email_has_no_findings():
    raw = (b"From: Sam <sam@example.org>\r\nSubject: Lunch\r\n"
           b"Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\r\n\r\nSee you at noon.")
    assert privacy.analyze_email(raw)["verdict"] == "ok"


def test_risky_extension_assessment():
    ext = {"browser": "Chrome", "permissions": ["<all_urls>", "debugger"], "store": False, "sideloaded": True, "mv": 3}
    assert privacy._assess_ext(dict(ext))["risk"] == "bad"
    safe = {"browser": "Chrome", "permissions": ["storage"], "store": True, "sideloaded": False, "mv": 3}
    assert privacy._assess_ext(dict(safe))["risk"] == "ok"


def test_shredder_refuses_system_and_home_folders(tmp_path):
    for path in (Path.home(), Path(winutil.os.environ.get("SystemRoot", r"C:\Windows")), ROOT):
        assert winutil.protected_path(path)
    assert not winutil.protected_path(tmp_path / "x.txt")


def test_shredder_overwrites_and_removes(tmp_path):
    target = tmp_path / "secret.txt"
    target.write_bytes(b"top secret" * 1000)
    assert privacy._shred_file(target, 3) == 10000
    assert not target.exists() and not list(tmp_path.iterdir())


def test_hosts_rules(monkeypatch):
    monkeypatch.setattr(system, "hosts_entries", lambda: [
        ("0.0.0.0", "ads.doubleclick.net"),        # ad-blocking: fine
        ("0.0.0.0", "www.google.com"),             # blocked, not redirected: fine
        ("6.6.6.6", "www.paypal.com"),             # pharming
        ("127.0.0.1", "update.avast.com"),         # silencing a security vendor
        ("127.0.0.1", "localhost"),
    ])
    assert sorted(system.hosts_tampering()) == ["update.avast.com", "www.paypal.com"]


def test_startup_command_target_parsing():
    assert system.command_target('"C:\\Program Files\\App\\app.exe" --min') == "C:\\Program Files\\App\\app.exe"
    assert system.command_target("C:\\Tools\\run.exe -q").lower() == "c:\\tools\\run.exe"
