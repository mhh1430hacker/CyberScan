import json

import pytest

from ui.persistence import LocalUiStore
from ui.translations import shape_arabic_text, translate_text


def test_missing_local_ui_data_uses_defaults(tmp_path):
    store = LocalUiStore(tmp_path / "settings.json", tmp_path / "history.json")
    defaults = {"osint_enabled": False, "large_text": False}

    assert store.load_settings(defaults) == defaults
    assert store.load_history() == []


def test_settings_round_trip_ignores_unknown_and_wrongly_typed_values(tmp_path):
    settings_path = tmp_path / "settings.json"
    history_path = tmp_path / "history.json"
    settings_path.write_text(
        json.dumps({"osint_enabled": True, "large_text": "yes", "unknown": "value"}),
        encoding="utf-8",
    )
    store = LocalUiStore(settings_path, history_path)

    assert store.load_settings({"osint_enabled": False, "large_text": False}) == {
        "osint_enabled": True,
        "large_text": False,
    }


def test_language_preference_round_trips_alongside_analysis_settings(tmp_path):
    store = LocalUiStore(tmp_path / "settings.json", tmp_path / "history.json")
    defaults = {"osint_enabled": False, "ui_language": "en"}

    store.save_settings({"osint_enabled": True, "ui_language": "ar"})

    assert store.load_settings(defaults) == {
        "osint_enabled": True,
        "ui_language": "ar",
    }


def test_history_round_trip_and_record_validation(tmp_path):
    store = LocalUiStore(tmp_path / "settings.json", tmp_path / "history.json")
    history = [{
        "id": "scan-1",
        "timestamp": "2025-01-01T00:00:00+00:00",
        "target": "sample.bin",
        "classification": "REVIEW",
        "score": 15,
        "sha256": "abc123",
        "report_path": "reports/scan-1.json",
    }]

    store.save_history(history)

    assert store.load_history() == history
    store.history_path.write_text(json.dumps([{"id": "scan-2"}]), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid record"):
        store.load_history()


@pytest.mark.parametrize("content", ["{", "[]"])
def test_invalid_settings_data_is_reported(tmp_path, content):
    settings_path = tmp_path / "settings.json"
    settings_path.write_text(content, encoding="utf-8")
    store = LocalUiStore(settings_path, tmp_path / "history.json")

    with pytest.raises(ValueError, match="Unable to read|invalid format"):
        store.load_settings({"large_text": False})


def test_history_read_errors_are_reported(tmp_path):
    history_path = tmp_path / "history.json"
    history_path.write_text("{", encoding="utf-8")
    store = LocalUiStore(tmp_path / "settings.json", history_path)

    with pytest.raises(ValueError, match="Unable to read"):
        store.load_history()


def test_history_is_bounded_to_the_most_recent_200_entries(tmp_path):
    store = LocalUiStore(tmp_path / "settings.json", tmp_path / "history.json")
    history = [
        {
            "id": f"scan-{index}",
            "timestamp": "2025-01-01T00:00:00+00:00",
            "target": f"sample-{index}.bin",
            "classification": "NO_INDICATORS_OBSERVED",
            "score": 0,
            "sha256": "",
            "report_path": f"reports/scan-{index}.json",
        }
        for index in range(205)
    ]
    store.save_history(history)

    loaded = store.load_history()

    assert len(loaded) == 200
    assert loaded[0]["id"] == "scan-5"
    assert loaded[-1]["id"] == "scan-204"


def test_exact_mode_labels_translate_without_mutating_paths():
    assert translate_text("File", "ar") == "ملف"
    assert translate_text(r"C:\Samples\File.exe", "ar") == r"C:\Samples\File.exe"
    assert translate_text("URL", "ar") == "رابط"


def test_arabic_translates_long_project_and_model_descriptions():
    assert translate_text(
        "Project theory · defensive static analysis",
        "ar",
    ) == "نبذة عن المشروع · تحليل ساكن دفاعي"
    assert translate_text(
        "The supervised three-class structural classifier starts unavailable. "
        "Train it from a reviewed manifest with clean, suspicious, and malware samples. "
        "Class scores are uncalibrated; no accuracy or zero-day claim is made.",
        "ar",
    ).startswith("يبدأ المصنف البنيوي المُراقب ذي الفئات الثلاث")
    assert translate_text("milliseconds", "ar") == "مللي ثانية"


def test_arabic_translates_welcome_actions_and_secondary_tools():
    assert translate_text("Start with a file, link, or indicator", "ar") == "ابدأ بملف أو رابط أو مؤشر"
    assert translate_text("Scan a local file", "ar") == "افحص ملفًا محليًا"
    assert translate_text("Inspect text or an IOC", "ar") == "افحص نصًا أو مؤشر اختراق"
    assert translate_text("More tools", "ar") == "المزيد من الأدوات"
    assert translate_text("Structural Classifier", "ar") == "المصنف البنيوي"
    assert translate_text(
        "Paste a hash, domain, IP, or suspicious text",
        "ar",
    ) == "الصق بصمة أو نطاقًا أو عنوان IP أو نصًا مشبوهًا"


def test_arabic_display_shapes_glyphs_and_orders_text_visually():
    logical = "ما الذي تريد فحصه؟"

    rendered = shape_arabic_text(logical)

    assert rendered != logical
    assert translate_text("Input required", "ar") == "الإدخال مطلوب"
    assert shape_arabic_text("C:\\Samples\\file.exe") == "C:\\Samples\\file.exe"
