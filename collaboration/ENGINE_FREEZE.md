# Engine freeze — detection/ (SENTINEL)

Frozen: 2026-11-10 · Engine version `2026.11.10` · Regression baseline: **204 passed** (`python -m pytest -q`)

The `detection/` implementation is frozen. Changes require a DISCUSSION message, a new baseline run,
and a new manifest. Website copies must match this manifest exactly.

Tree digest (SHA-256 of the lines below): `30c15d6a14cbad575f83dd490a764f8f9fd09e82d8dccfb893c5bca6a6c8a471`

```text
5cd987c0f47dcf9258b66d75de31cffe9be58a287774569345f1c24dedb3b71d  detection/__init__.py
0b8373619f29dd5558464051ca86b6bf83e2fa4d79227fa3aa07bfad73ea65d0  detection/archives.py
e72928fe262740bab174ae5426468ed157796d3227e3e253c503d5424ff4665f  detection/common.py
696279745142f7316c5234d3bbe45f7ef3b43c8be9e4952c42980f3c03dbd677  detection/documents.py
dbcd36d632b2c642ff5b5964b6f28e190e6265f5c861620125a7bc5f69376998  detection/engine.py
bc38dd9b7c2ee588cf247c3bf47ba373dadaf74d02f8cd94771ca38a6a346e95  detection/executables.py
69879ded109a9430d8c921a478c056dd3f618b156d73e21bdf5b4e474f142917  detection/host.py
2a2587d6f844cac636bffe9b3aa16847b208590a4343704faa1bc1a4eef70d5e  detection/INTEGRATION.md
8b29bf461ceebceb8988d4128d9f94a9a48163a503bcd5358a1276833b0075d3  detection/messages.py
f10aede574718b55c657993a748f2bf545facbd3ed318136aac12ab071f03976  detection/ole.py
2820033fdfd82ddf55c69ecd9da3a714e4bf9ae1119d2135dff0d1deb3d16388  detection/script_rules.py
0bf88a859c772375a3eaf959446e8e3bff655668136cafc0070c0b01810d38c4  detection/secrets.py
c8bb9cc4e1decc276d1b26a271bc247bf7c6a2ff3bbe89902e61b488f89e56fc  detection/service.py
4260232f5f50dc319938826bf83a569be66a59859cf32a6e9f8059d1b620c071  detection/url_intel.py
```

Verify a copy (run from the repository root that contains `detection/`):

```bash
python -c "import hashlib,pathlib;[print(('OK  ' if hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()==h else 'DIFF ')+p) for h,p in (l.split('  ',1) for l in open('ENGINE_FREEZE.lines'))]"
```

(`ENGINE_FREEZE.lines` = the block above saved to a file.)

Revision history:
- 2026-11-10 r1 — tree `ab133507…`: initial freeze.
- 2026-11-10 r2 — tree `30c15d6a…`: fixed the `detection/service.py` docstring erratum (spawn on Lambda
  is unverified, not impossible). Docstring only; no behaviour change. Baseline re-run: 204 passed.
