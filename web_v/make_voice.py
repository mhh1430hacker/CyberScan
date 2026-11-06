"""Generate the explainer film's narration with ElevenLabs (run once, on your computer).

The API key is read from the ELEVENLABS_API_KEY environment variable and is
only sent to api.elevenlabs.io. It is never written to disk or into the site:
the result is plain MP3 files that the film plays for every visitor.

    set ELEVENLABS_API_KEY=...            (PowerShell: $env:ELEVENLABS_API_KEY = "...")
    .venv\\Scripts\\python.exe web_v\\make_voice.py --list           # see your voices
    .venv\\Scripts\\python.exe web_v\\make_voice.py                  # English narration
    .venv\\Scripts\\python.exe web_v\\make_voice.py --voice Brian

Writes web_v/static/captions/voice/en/NN.mp3 and en.json (timings). The film is
narrated in English only; Arabic is shown as subtitles.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

API = "https://api.elevenlabs.io/v1"
CAPTIONS = Path(__file__).resolve().parent / "static" / "captions"
OUT = CAPTIONS / "voice"
# any voice name or ID from --list
DEFAULT_VOICE = "Eric"                            # smooth, trustworthy
MODEL = "eleven_multilingual_v2"


def key() -> str:
    value = os.environ.get("ELEVENLABS_API_KEY", "").strip()
    if not value:
        sys.exit("Set ELEVENLABS_API_KEY first (see the top of this file).")
    return value


def request(method: str, path: str, body: dict | None = None) -> dict:
    req = urllib.request.Request(
        f"{API}{path}", method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"xi-api-key": key(), "Content-Type": "application/json", "Accept": "application/json"},
    )
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:300]
            if e.code == 429 and attempt < 3:
                time.sleep(4 * (attempt + 1))
                continue
            sys.exit(f"ElevenLabs answered {e.code}: {detail}")
        except urllib.error.URLError as e:
            if attempt < 3:
                time.sleep(3)
                continue
            sys.exit(f"Couldn't reach ElevenLabs: {e.reason}")
    sys.exit("ElevenLabs kept refusing the request.")


def voices() -> list[dict]:
    return request("GET", "/voices").get("voices", [])


def resolve(voice: str, all_voices: list[dict]) -> tuple[str, str]:
    for v in all_voices:
        if voice in (v.get("voice_id"), v.get("name")) or v.get("name", "").lower().startswith(voice.lower()):
            return v["voice_id"], v["name"]
    if re.fullmatch(r"[A-Za-z0-9]{20}", voice):
        return voice, voice
    names = ", ".join(sorted(v.get("name", "?") for v in all_voices))
    sys.exit(f"No voice called {voice!r}. Your voices: {names}")


def cues(lang: str) -> list[dict]:
    text = (CAPTIONS / f"{lang}.vtt").read_text(encoding="utf-8").replace("\r", "")
    out = []
    for block in re.split(r"\n\n+", text):
        lines = block.split("\n")
        timing = next((i for i, l in enumerate(lines) if "-->" in l), None)
        if timing is None:
            continue
        def sec(s: str) -> float:
            h, m, rest = s.strip().split(":")
            return int(h) * 3600 + int(m) * 60 + float(rest)
        a, b = lines[timing].split("-->")
        out.append({"start": sec(a), "end": sec(b), "text": " ".join(lines[timing + 1:]).strip()})
    return out


def spoken(text: str) -> str:
    """Written text → what a narrator should say."""
    text = text.replace("invoice_2026.pdf.exe", "invoice twenty twenty-six, dot P D F, dot E X E")
    return text.replace("YARA", "Yara").replace("CyberScan", "Cyber Scan")


def generate(voice: str, model: str, stability: float, style: float, speed: float) -> None:
    all_voices = voices()
    voice_id, voice_name = resolve(voice, all_voices)
    lang = "en"
    items = cues(lang)
    folder = OUT / lang
    folder.mkdir(parents=True, exist_ok=True)
    manifest = {"voice": voice_name, "model": model, "lang": lang, "cues": []}
    print(f"{lang}: {len(items)} lines with {voice_name} ({model})")
    for i, cue in enumerate(items):
        text = spoken(cue["text"])
        body = {
            "text": text,
            "model_id": model,
            # neighbouring lines make the delivery flow like one narration
            "previous_text": spoken(items[i - 1]["text"]) if i else None,
            "next_text": spoken(items[i + 1]["text"]) if i + 1 < len(items) else None,
            "voice_settings": {"stability": stability, "similarity_boost": 0.8, "style": style, "use_speaker_boost": True, "speed": speed},
        }
        data = request("POST", f"/text-to-speech/{voice_id}/with-timestamps?output_format=mp3_44100_128", {k: v for k, v in body.items() if v is not None})
        audio = base64.b64decode(data["audio_base64"])
        ends = (data.get("alignment") or {}).get("character_end_times_seconds") or [0]
        duration = round(float(ends[-1]), 2)
        name = f"{i + 1:02d}.mp3"
        (folder / name).write_bytes(audio)
        room = cue["end"] - cue["start"]
        warn = "  (longer than its subtitle: the next line will wait)" if duration > room + 0.4 else ""
        print(f"  {name}  {duration:5.2f}s / {room:4.1f}s{warn}")
        manifest["cues"].append({"start": cue["start"], "end": cue["end"], "file": f"{lang}/{name}", "duration": duration})
    (OUT / f"{lang}.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"wrote {OUT / (lang + '.json')}")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--list", action="store_true", help="list the voices on your account")
    p.add_argument("--voice", default=DEFAULT_VOICE, help="voice name or ID (default: Eric)")
    p.add_argument("--model", default=MODEL)
    p.add_argument("--stability", type=float, default=0.45, help="lower = more expressive")
    p.add_argument("--style", type=float, default=0.25)
    p.add_argument("--speed", type=float, default=1.0)
    args = p.parse_args()
    if args.list:
        for v in voices():
            labels = ", ".join(f"{k}: {val}" for k, val in (v.get("labels") or {}).items())
            print(f"{v['name']:<22} {v['voice_id']}  {labels}")
        return
    generate(args.voice, args.model, args.stability, args.style, args.speed)


if __name__ == "__main__":
    main()
