# CyberScan — web edition

Static analysis of files, links and text, explained in plain words, in English and Arabic.
Nothing you check is ever run.

CyberScan reads a file byte by byte, runs nine analysis engines over it (file type, randomness map,
warning signs, YARA rules, program anatomy, archive contents, signature, an optional learning model,
optional public threat intelligence), fuses them into one score that is never lower than the strongest
evidence, and explains the result in a sentence anyone can read. When something doesn't belong in a
file's format, it can cut it out of a copy and seal the removed bytes in an encrypted vault.

> A defensive research prototype. It is not a replacement for commercial endpoint security.

## Run it

Python 3.11 or newer.

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt        # Windows: .venv\Scripts\pip install -r requirements.txt
.venv/bin/python web_v/run.py                     # Windows: .venv\Scripts\python web_v\run.py
```

The server starts on `http://127.0.0.1:8765/` and opens your browser (or a desktop window if
`pywebview` is installed). Useful flags:

| flag | meaning |
|---|---|
| `--port 8765` | port to listen on (`0` picks a free one) |
| `--browser` | always use the default browser |
| `--no-open` | only start the server |

## What's in it

**Landing page**
- language choice on first visit (English / العربية), remembered
- WebGL2 particle field that takes a shape per section, written from scratch
- a 74-second explainer film drawn on a canvas, with English narration, English and Arabic subtitles
  (`web_v/static/captions/*.vtt`), chapters and export to `.webm`
- scroll scenes, an interactive engine pipeline, generated calm lo-fi music (off by default)

**App**
- scan uploads, files on disk, links or pasted text; batch scanning; in-browser SHA-256 fingerprint
  with "seen before"
- plain-language verdicts and findings in both languages, a 3D structure map of the file, PE anatomy,
  MITRE ATT&CK, YARA, engine checks and raw evidence
- quarantine and restore, repair a copy, export reports (.txt / .json / print to PDF)
- optional AI explanation through a local Ollama model
- history with insights, settings, downloads watch, command palette (Ctrl+K), installable as a PWA

## Layout

```
web_v/          the web server (standard library only) and the front end in web_v/static/
core/           analysis engines
ml/             structural classifier runtime
repair_engine/  format parsers, blind repair and the encrypted vault
monitoring/     downloads watch
reports/        report export
ui/             shared presentation logic (plain-language text, translations, structure map)
rules/          YARA rules
data/models/    trained models; everything else under data/ is local and git-ignored
```

## Security model

The server is built to run **on the user's own computer**:

- it binds to `127.0.0.1` and rejects requests whose `Host` or `Origin` is not that address
  (DNS-rebinding protection);
- every API call needs a random token that changes on each launch and is only injected into the page
  the server itself serves;
- a strict Content-Security-Policy allows no inline or third-party scripts;
- scan history, settings, keys and the quarantine stay in `data/`, which is never committed.

## Deploying it online (read before putting it on a server)

Running this on a public host such as AWS needs deliberate changes, because several endpoints act
on **the machine the server runs on**:

1. **Turn off host-file features.** `POST /api/scan` with `mode: "path"`, `/api/repair/path`,
   `/api/pick` (native file dialog), `/api/history/*/reveal`, `/quarantine`, `/restore` and the
   downloads watch all read or move files on the server. On a public server they would let any visitor
   read the server's files. Keep only uploads, links and text.
2. **Bind and allow your real address.** `create_server()` binds to `127.0.0.1` and `make_handler()`
   only accepts `127.0.0.1:<port>` / `localhost:<port>` as `Host`. Put the app behind a reverse proxy
   (nginx, an AWS load balancer) with HTTPS, and add your domain to the allowed hosts and origins.
3. **Give each visitor their own data.** History, settings and the vault are single-user files in
   `data/`. A multi-user deployment needs per-user storage and real authentication (the per-launch
   token is not a login).
4. **Keys and the vault use Windows DPAPI** (`ui/secrets.py`). On Linux, replace them with your
   platform's secret store (for example AWS KMS / Secrets Manager).
5. **Limit uploads** (size, rate) at the proxy as well as in Settings, and keep the analysis timeout.
6. Optional features that call out: public threat lookups (only fingerprints or links are sent) and the
   AI explanation (expects Ollama at `127.0.0.1:11434`).

## Licence

No licence has been chosen yet; all rights reserved by the author.
