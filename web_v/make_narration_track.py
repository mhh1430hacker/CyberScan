"""Build the explainer film's continuous narration track from the recorded clips.

The film's narration was recorded as one MP3 per line (web_v/make_voice.py writes
static/captions/voice/en/NN.mp3 and en.json with each line's start on the film's timeline).
This script places every clip at its exact start on one silent 86-second track and writes
static/captions/voice/en-full.mp3. The film plays that single file and reads its clock from it,
so picture, voice and subtitles share one time base: seeking, pausing, speed changes and
volume all act on one audio source, and two lines can never overlap.

The original clips are not changed. Before writing, the script checks that every clip's real
length matches en.json and that no clip runs into the next one.

    python web_v/make_narration_track.py          (needs ffmpeg and ffprobe on PATH)
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

VOICE = Path(__file__).resolve().parent / "static" / "captions" / "voice"
DURATION = 86.0          # the film's length (static/js/film.js)
RATE = 44100


def probe(path: Path) -> float:
    out = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "json", str(path)],
                         capture_output=True, text=True, check=True).stdout
    return float(json.loads(out)["format"]["duration"])


def main() -> None:
    meta = json.loads((VOICE / "en.json").read_text(encoding="utf-8"))
    cues = meta["cues"]
    problems = []
    for i, c in enumerate(cues):
        real = probe(VOICE / c["file"])
        if abs(real - c["duration"]) > 0.05:
            problems.append(f'{c["file"]}: en.json says {c["duration"]}s, the file is {real:.2f}s')
        end = c["start"] + real
        nxt = cues[i + 1]["start"] if i + 1 < len(cues) else DURATION
        if end > nxt:
            problems.append(f'{c["file"]} ends at {end:.2f}s, after the next line starts at {nxt:.2f}s')
    if problems:
        sys.exit("Not writing the track:\n  " + "\n  ".join(problems))

    inputs, chains = [], []
    for i, c in enumerate(cues):
        inputs += ["-i", str(VOICE / c["file"])]
        ms = int(round(c["start"] * 1000))
        chains.append(f"[{i}:a]aresample={RATE},aformat=channel_layouts=mono,adelay={ms}:all=1[a{i}]")
    mix = "".join(f"[a{i}]" for i in range(len(cues)))
    graph = ";".join(chains) + f";{mix}amix=inputs={len(cues)}:normalize=0:dropout_transition=0,apad,atrim=0:{DURATION}[out]"
    out = VOICE / "en-full.mp3"
    subprocess.run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", *inputs, "-filter_complex", graph, "-map", "[out]",
                    "-ar", str(RATE), "-ac", "1", "-c:a", "libmp3lame", "-b:a", "96k", str(out)], check=True)
    meta["track"] = {"file": out.name, "duration": round(probe(out), 3)}
    (VOICE / "en.json").write_text(json.dumps(meta, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {out} ({meta['track']['duration']}s) from {len(cues)} clips")


if __name__ == "__main__":
    main()
