# External threat intelligence

CyberScan can ask outside threat-intelligence services what they already know about what is being
checked. Code: `core/external_intel.py` (requests, quotas, cache, verdict weighting),
`core/hash_intel.py` (offline hash table + the file lookups), `ui/scan_service.py` (wiring),
`web_v/services.py::external_payload` (the result card), `web_v/static/js/external-intel.js` (UI).

**Only a fingerprint or a link is sent. Nothing is ever uploaded or submitted for scanning.**

| Service | What is sent | Endpoint (lookup only) | Environment variable |
|---|---|---|---|
| VirusTotal | file SHA-256; a link; its host | `GET /api/v3/files/{sha256}`, `/urls/{base64url(url)}`, `/domains/{d}` or `/ip_addresses/{ip}` | `VT_API_KEY` |
| CIRCL hashlookup | file SHA-256 | `GET /lookup/sha256/{sha256}` | none needed |
| MalwareBazaar | file SHA-256 | `POST query=get_info` | `ABUSECH_AUTH_KEY` |
| URLhaus | a link, then its host | `POST /v1/url/`, `/v1/host/` | `ABUSECH_AUTH_KEY` (or `URLHAUS_API_KEY`) |
| AlienVault OTX | the host | `GET /api/v1/indicators/hostname/{h}/general` | `OTX_API_KEY` |
| Google Safe Browsing | a link | `POST /v4/threatMatches:find` | `GOOGLE_SAFE_BROWSING_KEY` |
| urlscan.io | the host | `GET /api/v1/search/?q=domain:{d}` (search only, never submit) | `URLSCAN_API_KEY` |

Links to private, local or reserved addresses are never sent. Pasted text is never sent. A service
without a key is shown as "Not configured" and is not called.

## Free keys

- **VirusTotal**: sign up at <https://www.virustotal.com/gui/join-us>, then *API key* in your profile
  (community key: 4 requests a minute, 500 a day, non-commercial use).
- **abuse.ch** (MalwareBazaar, URLhaus, ThreatFox: one key): <https://auth.abuse.ch/> (sign in, *Optional: API key*).
- **AlienVault OTX**: <https://otx.alienvault.com/> → *Settings* → *OTX Key*.
- **Google Safe Browsing**: a Google Cloud project with the *Safe Browsing API* enabled, then
  *APIs & Services → Credentials → Create API key* (restrict it to the Safe Browsing API). Free for
  non-commercial use (Google's Web Risk API is the commercial equivalent).
- **urlscan.io**: <https://urlscan.io/user/signup> → *Settings & API* → *New API key*.

## Where the keys go

- **Desktop app**: Settings → Online → paste the keys (stored encrypted with DPAPI for the Windows
  user, `ui/secrets.py`); online lookups stay off until "Check links and fingerprints against public
  lists" is on.
- **Local web app**: Settings → Online lookup keys (same encrypted store).
- **Website (AWS Lambda, `CYBERSCAN_PUBLIC=1`)**: environment variables of the function. Lookups are
  on by default for website scans (a per-scan switch turns them off; `CYBERSCAN_EXTERNAL_INTEL=0`
  turns them off for everyone). Do not paste keys into a shell history you share; for example (keep the
  function's existing variables: `--environment` replaces the whole set, so merge them first):

```sh
aws lambda get-function-configuration --function-name CyberScan --region eu-north-1 \
    --query Environment.Variables > env.json        # edit env.json: add the keys below
aws lambda update-function-configuration --function-name CyberScan --region eu-north-1 \
    --environment "{\"Variables\": $(cat env.json)}"
```

Variables to add: `VT_API_KEY`, `ABUSECH_AUTH_KEY`, `OTX_API_KEY`, `GOOGLE_SAFE_BROWSING_KEY`,
`URLSCAN_API_KEY` (each optional). Optional tuning: `CYBERSCAN_INTEL_CACHE_S3=0` (no S3 cache),
`CYBERSCAN_STATS_BUCKET` (default `cyberscan-assets`), `CYBERSCAN_INTEL_CACHE_PREFIX` (default
`intel-cache/`). The S3 cache needs `s3:GetObject` and `s3:PutObject` on
`arn:aws:s3:::cyberscan-assets/intel-cache/*` for the function's role; without them it switches itself
off and the in-memory cache carries on. An S3 lifecycle rule expiring `intel-cache/` after 1 day keeps it small.

## Quotas and limits

- VirusTotal: a per-process token bucket of **4 requests a minute and 500 a day** (a file scan uses 1,
  a link scan 2: the link and its site). HTTP 429 pauses VirusTotal for a minute. When the bucket is
  empty the card says "Quota reached" and the scan carries on.
- The other services have generous free tiers; per-process caps (60 a minute) only stop runaway loops.
- Every answer, including "not found", is cached for **6 hours** (in memory, LRU of 4096 entries; on
  Lambda also in S3). Cached values hold only the service's numbers, under a hash of what was looked
  up, never the link itself. Errors and timeouts are not cached.
- Website: each visitor (first `X-Forwarded-For` address) may start **6 scans with lookups a minute
  and 40 an hour**; after that the scan runs without them and the card says why.
- Time: all file sources together get 4 s, all link sources 4.5 s (each request at most 3.5 s), in
  parallel; a source that hasn't answered is shown as "Didn't answer in time".

## How answers weigh in the verdict

CyberScan's own evidence and rules keep the final say; a clean answer never lowers the score. Each
finding's explanation shows the numbers and the rule, so "Why this result?" shows the arithmetic.

| Answer | Finding | Weight |
|---|---|---|
| VirusTotal file: ≥ 10 engines, or ≥ 5 with a family name | Known malware (→ KNOWN_MALWARE) | +95 |
| VirusTotal file: 5-9 engines, no family name / 3-4 engines | Several antivirus engines flag this file | +60 / +45 |
| VirusTotal file: 1-2 engines (or only "suspicious") | A few engines flag it (often false positives) | +15 |
| VirusTotal file: 0 of 60+ engines, first seen 30+ days ago | Widely seen as clean (supporting) | +0 |
| MalwareBazaar or CIRCL "KnownMalicious" listing | Known malware | +95 |
| CIRCL known file (NSRL) | Known software (supporting) | +0 |
| Google Safe Browsing / URLhaus exact link listing | listed link | +80 |
| VirusTotal link: ≥ 5 / 2-4 / 1 vendors | vendors flag this link | +75 / +40 / +15 |
| VirusTotal site: ≥ 5 / 2-4 / 1 vendors | vendors flag the site | +55 / +30 / +10 |
| URLhaus: other malware links on the same host | | +45 |
| urlscan.io: public scans marked malicious | | +30 |
| AlienVault OTX: host in community pulses (no allow-list entry) | | +20 |

The score is the strongest piece of evidence or the weighted sum, whichever is higher
(`core/risk_engine.py`); 50+ is SUSPICIOUS.
