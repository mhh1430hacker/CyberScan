# CyberScan on AWS: Lambda + S3

```
visitor ──► Lambda Function URL ──► web_v/server.py (public mode): pages, API, scans
                │
                └─ 302 for big files ──► S3 bucket: Pyodide (phone engine) + the APK
```

Build both packages (from the last commit):

```powershell
.venv\Scripts\python.exe web_v\aws\build_lambda.py
```

| file | what | where it goes |
|---|---|---|
| `web_v/aws/out/cyberscan-lambda.zip` | website + engine + Linux libraries (Python 3.13, x86_64), ~23 MB | Lambda function code |
| `web_v/aws/out/cyberscan-assets.zip` | `pyodide/…` and `downloads/CyberScan-*.apk`, ~23 MB | S3 bucket (unzipped) |

## 1. S3 bucket for the large files

1. S3 › **Create bucket**, e.g. `cyberscan-assets` (same region as the function).
2. Unzip `cyberscan-assets.zip` and upload it **keeping the folders** (`pyodide/`, `downloads/`).
   With the AWS CLI (sets the right types; the APK downloads instead of opening):

   ```bash
   aws s3 cp pyodide/ s3://cyberscan-assets/pyodide/ --recursive
   aws s3 cp pyodide/pyodide.asm.wasm s3://cyberscan-assets/pyodide/pyodide.asm.wasm --content-type application/wasm
   aws s3 cp pyodide/pyodide.asm.mjs s3://cyberscan-assets/pyodide/pyodide.asm.mjs --content-type text/javascript
   aws s3 cp pyodide/pyodide.js s3://cyberscan-assets/pyodide/pyodide.js --content-type text/javascript
   aws s3 cp downloads/ s3://cyberscan-assets/downloads/ --recursive --content-type application/vnd.android.package-archive --content-disposition attachment
   ```

3. **Public read** for these files (they're public anyway): Permissions › turn off "Block all public
   access" for this bucket, then the bucket policy:

   ```json
   {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*",
     "Action": "s3:GetObject", "Resource": "arn:aws:s3:::cyberscan-assets/*"}]}
   ```

   (Or keep the bucket private and put CloudFront with Origin Access Control in front; then use the
   CloudFront URL in step 2.)

4. **CORS** (Permissions › CORS): the phone engine loads these files from the site's pages:

   ```json
   [{"AllowedOrigins": ["*"], "AllowedMethods": ["GET", "HEAD"], "AllowedHeaders": ["*"], "MaxAgeSeconds": 86400}]
   ```

   Once you know the site's address, replace `"*"` with it (e.g. `"https://abc.lambda-url.eu-central-1.on.aws"`,
   your own domain).

The asset base URL is `https://cyberscan-assets.s3.<region>.amazonaws.com` (no trailing slash).

## 2. The Lambda function

1. Lambda › **Create function** › Author from scratch: name `cyberscan`, runtime **Python 3.13**,
   architecture **x86_64**.
2. Code › Upload from › .zip file › `cyberscan-lambda.zip` (over 10 MB: the console may ask you to
   upload it to S3 first and give the S3 link).
3. Runtime settings › Handler: **`lambda_function.handler`**.
4. Configuration › General: **Memory 2048 MB**, **Timeout 1 min**, Ephemeral storage 1024 MB.
5. Configuration › Environment variables:
   - `CYBERSCAN_ASSET_BASE` = `https://cyberscan-assets.s3.<region>.amazonaws.com` (**required**:
     without it the phone engine and the APK return 404)
   - `CYBERSCAN_SITE_ORIGINS` = your site's addresses, comma-separated, e.g.
     `https://ainex-ai.xyz,https://www.ainex-ai.xyz` (**required behind CloudFront or a custom
     domain**: Lambda sees its own address as Host, so without this every scan fails with
     "bad origin")
   - optional `CYBERSCAN_TOKEN` = any random string
6. Configuration › **Function URL** › Create: Auth type **NONE** (a public website). Leave CORS off
   (pages and API share the same address).
7. Configuration › Concurrency: set a **reserved concurrency** (e.g. 10) so a flood of requests can't
   run up your bill.

Open the Function URL: the landing page, the scan app, the phone app at `/m/` and the APK download all
work from there.

## 3. Optional but recommended

- **Your own domain + HTTPS**: CloudFront in front of the Function URL, then Route 53 / your DNS.
  - Origin: the Function URL's host, protocol HTTPS only.
  - Default behaviour: allowed methods GET, HEAD, OPTIONS, PUT, POST, PATCH, DELETE;
    cache policy **UseOriginCacheControlHeaders** (the site sets how long each file may be kept);
    origin request policy **AllViewerExceptHostHeader** (forwards `Origin`, `X-CyberScan-Token`,
    `X-Filename`, `Content-Type`).
  - Behaviour for `/api/*`: cache policy **CachingDisabled**, same origin request policy.
  - Set `CYBERSCAN_SITE_ORIGINS` on the function (step 2.5).
  - After every new upload of the code: CloudFront › Invalidations › create `/*`, so visitors get
    the new files (they're cached for up to a day).
- **AWS WAF** on CloudFront with a rate-based rule (e.g. 100 requests / 5 min per IP).
- **Budget alert** in AWS Billing.

## What the online version does differently (public mode)

- Upload limit **4 MB** (Lambda accepts 6 MB per request, base64 included). For bigger files the page
  points people to the phone app (`/m/`, runs in the browser, up to 40 MB) or the Android app.
- No access to the server's disk: no scanning by path, file picker, quarantine, restore or reveal.
- Settings and keys are fixed (online lookups and the local AI are off); nothing is saved on the server
  and there is no shared history: each visitor's results stay in their browser; reports are exported
  from the browser.
- Scans finish inside the request (Lambda pauses background work between requests).
- Requests from other websites are refused (Origin check); security headers: CSP, HSTS, frame and
  permissions policies.

Run it locally the same way (no S3 needed: big files are served directly when `CYBERSCAN_ASSET_BASE`
is empty):

```powershell
$env:CYBERSCAN_PUBLIC = "1"; .venv\Scripts\python.exe web_v\run.py --port 8766
```
