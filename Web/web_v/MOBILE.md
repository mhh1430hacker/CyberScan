# Mobile compatibility

The canonical Android and on-device application source is in
[`Mobile/MOBILE.md`](../../Mobile/MOBILE.md). The website keeps generated
`static/m/` and `static/pyodide/` assets so the existing `/m/` route remains
available.

The scripts in this directory delegate to `Mobile/build_mobile.py` and
`Mobile/build_android_www.py`. Pass `--worktree` when the engine bundle should
include current Web worktree files; compatibility scripts refresh Web's
generated `/m/` assets.
