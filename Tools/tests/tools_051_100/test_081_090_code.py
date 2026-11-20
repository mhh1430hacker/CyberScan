"""Tools 081-090 (code & dependency security). Advisories here are synthetic test records (TEST-*), not real data."""
import base64
import json
import pickle

import pytest

from conftest import b64, ids, no_secret_leak

# ---- 081 source scanner ----------------------------------------------------------------------
SC = "cyberscan.code.source-scanner"
PY_BAD = '''
import subprocess, os, random, hashlib, requests, tempfile
import jwt
from flask import Flask
app = Flask(__name__)

def run(cmd, user):
    subprocess.run(f"ls {user}", shell=True)
    os.system("ping " + user)
    eval(user)
    token = random.randint(0, 10**6)
    digest = hashlib.md5(user.encode()).hexdigest()
    requests.get("https://api.example.test", verify=False)
    path = tempfile.mktemp()
    claims = jwt.decode(cmd, options={"verify_signature": False})
    os.chmod(path, 0o777)

app.run(debug=True)
'''
PY_GOOD = '''
import subprocess, secrets, hashlib, requests
def run(user):
    subprocess.run(["ls", user])
    token = secrets.token_urlsafe(32)
    checksum = hashlib.md5(b"data", usedforsecurity=False).hexdigest()
    requests.get("https://api.example.test", timeout=5)
'''


def test_081_python_findings_and_clean_code(run):
    found = ids(run(SC, {"files": [{"path": "app.py", "content": PY_BAD}]}))
    assert {"py.shell-true", "py.os-system", "py.eval", "py.insecure-random", "py.weak-hash", "py.tls-verify-false", "py.mktemp",
            "py.jwt-unverified", "py.world-writable", "py.debug-mode"} <= found
    assert run(SC, {"content": PY_GOOD, "path": "ok.py"})["classification"] == "clean"


def test_081_other_languages(run):
    files = [
        {"path": "server.js", "content": "const { exec } = require('child_process');\nexec(`git log ${req.query.ref}`);\nhttps.request({rejectUnauthorized: false});\nconst sessionToken = Math.random().toString(36);\n"},
        {"path": "Main.java", "content": 'MessageDigest md = MessageDigest.getInstance("MD5");\nCipher c = Cipher.getInstance("AES");\nRuntime.getRuntime().exec("sh -c " + input);\n'},
        {"path": "main.go", "content": 'tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}\nexec.Command("sh", "-c", cmd)\n'},
        {"path": "copy.c", "content": "char buf[16];\ngets(buf);\nstrcpy(buf, argv[1]);\n// strcpy in a comment is ignored\n"},
        {"path": "page.php", "content": "<?php include($_GET['page']); system('ls ' . $dir); ?>"},
    ]
    found = ids(run(SC, {"files": files}))
    assert {"js.child-process", "js.tls-disabled", "js.insecure-random", "java.weak-digest", "java.weak-cipher", "java.runtime-exec",
            "go.tls-skip", "go.shell", "c.unsafe-function", "php.include-input", "php.code-exec"} <= found


# ---- 082 dependency vulnerabilities ----------------------------------------------------------
DV = "cyberscan.code.dependency-vulnerabilities"
REQS = "requests==2.19.0\nflask>=2.0\nurllib3==2.2.1\n"
LOCK = json.dumps({"lockfileVersion": 3, "packages": {"": {"dependencies": {"lodash": "^4.17.0"}},
                                                      "node_modules/lodash": {"version": "4.17.20", "integrity": "sha512-AAAA", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"}}})
ADVISORIES = [
    {"id": "TEST-0001", "summary": "Synthetic test advisory for requests", "aliases": ["CVE-0000-0001"],
     "affected": [{"package": {"ecosystem": "PyPI", "name": "Requests"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}]}],
     "database_specific": {"severity": "HIGH"}},
    {"id": "TEST-0002", "summary": "Synthetic test advisory for lodash",
     "affected": [{"package": {"ecosystem": "npm", "name": "lodash"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "4.0.0"}, {"fixed": "4.17.21"}]}]}],
     "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]},
    {"id": "TEST-0003", "summary": "Not affecting the pinned urllib3",
     "affected": [{"package": {"ecosystem": "PyPI", "name": "urllib3"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "1.26.18"}]}]}]},
]


def test_082_offline_advisories(run):
    result = run(DV, {"files": [{"path": "requirements.txt", "content": REQS}, {"path": "package-lock.json", "content": LOCK}],
                      "advisories": ADVISORIES})
    found = ids(result)
    assert {"vuln.TEST-0001.requests", "vuln.TEST-0002.lodash"} <= found and not any("TEST-0003" in f for f in found)
    by_id = {f["id"]: f for f in result["findings"]}
    assert by_id["vuln.TEST-0001.requests"]["assurance"] == "advisory_match" and by_id["vuln.TEST-0002.lodash"]["severity"] == "critical"
    assert any("range" in l for l in result["limitations"])  # flask>=2.0 cannot be checked without a lockfile


def test_082_requires_a_source_and_online_mode(run, monkeypatch):
    assert run(DV, {"files": [{"path": "requirements.txt", "content": REQS}]})["status"] == "invalid_input"  # no bundled data
    import security_toolkit.httputil as httputil
    sent = {}

    def fake_post(url, payload, **kwargs):
        sent["payload"] = payload
        return {"results": [{"vulns": [{"id": "TEST-ONLINE-1"}]}, {}]}
    monkeypatch.setattr(httputil, "post_json", fake_post)
    online = run(DV, {"files": [{"path": "requirements.txt", "content": REQS}], "online": True})
    assert "vuln.TEST-ONLINE-1.requests" in ids(online) and online["metadata"]["execution_mode"] == "network-passive"
    assert {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.19.0"} in sent["payload"]["queries"]

    def down(*a, **k):
        raise httputil.FetchFailed("timeout")
    monkeypatch.setattr(httputil, "post_json", down)
    assert run(DV, {"files": [{"path": "requirements.txt", "content": REQS}], "online": True})["status"] == "unavailable"


def test_082_version_ordering():
    from security_toolkit.manifests import version_key
    assert version_key("npm", "1.0.0-alpha") < version_key("npm", "1.0.0") < version_key("npm", "1.0.1")
    assert version_key("npm", "1.10.0") > version_key("npm", "1.9.9")
    assert version_key("PyPI", "2.0rc1") < version_key("PyPI", "2.0")


# ---- 083 secrets scanner ---------------------------------------------------------------------
SS = "cyberscan.code.secrets-scanner"
GH = "ghp_" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2"


def test_083_repository_scan(run, tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "client.py").write_text(f'TOKEN = "{GH}"\n')
    (tmp_path / "src" / "other.py").write_text(f'import os\nBACKUP = "{GH}"\n')
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_api.py").write_text('API = "sk_live_' + "a" * 10 + 'b1c2d3e4f5g6h7i8j9k0"\n')
    (tmp_path / ".env").write_text("DB_PASSWORD=x\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "leak.js").write_text(f'"{GH}"')
    result = run(SS, {"directory": str(tmp_path)})
    gh = [f for f in result["findings"] if f["id"].startswith("secret.github_token")]
    assert len(gh) == 1 and "2 place(s)" in gh[0]["description"]          # de-duplicated across files; node_modules skipped
    stripe = [f for f in result["findings"] if f["id"].startswith("secret.stripe")]
    assert stripe and stripe[0]["severity"] == "medium" and "tests/docs" in stripe[0]["title"]  # critical downgraded in tests
    assert "file.secret-bearing" in ids(result)
    no_secret_leak(result, GH)


def test_083_files_input_and_excludes(run):
    files = [{"path": "README.md", "content": "export API_KEY=<your-key-here>"}, {"path": "app/config.js", "content": "const x = 1;"}]
    assert run(SS, {"files": files})["classification"] == "clean"
    assert run(SS, {"files": files, "exclude": ["("]})["status"] == "invalid_input"


# ---- 084 licenses ----------------------------------------------------------------------------
LC = "cyberscan.code.license-compliance"


def test_084_expressions_and_models(run):
    packages = [{"name": "left-pad", "license": "MIT"}, {"name": "dual", "license": "MIT OR GPL-3.0-or-later"},
                {"name": "copyleft", "license": "GPL-3.0-only"}, {"name": "agpl", "license": "AGPL-3.0"},
                {"name": "java-lib", "license": "GPL-2.0-only WITH Classpath-exception-2.0"}, {"name": "mystery", "license": ""},
                {"name": "bsl", "license": "BUSL-1.1"}, {"name": "named", "license": "Apache 2.0"}]
    proprietary = run(LC, {"packages": packages, "distribution": "proprietary"})
    found = ids(proprietary)
    assert {"license.strong-copyleft.copyleft", "license.network-copyleft.agpl", "license.unknown.mystery", "license.source-available.bsl",
            "license.weak-copyleft.java-lib"} <= found
    assert not any(f.endswith((".left-pad", ".dual", ".named")) for f in found)
    saas = ids(run(LC, {"packages": packages, "distribution": "saas"}))
    assert "license.network-copyleft.agpl" in saas and "license.weak-copyleft.java-lib" not in saas
    denied = ids(run(LC, {"packages": [{"name": "x", "license": "WTFPL"}], "deny": ["WTFPL"]}))
    assert denied == {"license.denied.x"}


def test_084_license_file_text(run):
    gpl = "GNU GENERAL PUBLIC LICENSE\n   Version 3, 29 June 2007\n..."
    mit = "Permission is hereby granted, free of charge, to any person obtaining a copy of this software..."
    found = ids(run(LC, {"files": [{"path": "vendor/a/LICENSE", "content": gpl}, {"path": "vendor/b/LICENSE", "content": mit}]}))
    assert found == {"license.strong-copyleft.LICENSE"}


# ---- 085 SBOM --------------------------------------------------------------------------------
SB = "cyberscan.code.sbom-generator"


def test_085_cyclonedx_is_reproducible(run):
    sha = "a" * 64
    files = [{"path": "requirements.txt", "content": f"requests==2.32.3 --hash=sha256:{sha}\nflask>=3\n"},
             {"path": "package-lock.json", "content": json.dumps({"lockfileVersion": 3, "packages": {
                 "": {}, "node_modules/@types/node": {"version": "22.1.0", "integrity": "sha512-" + base64.b64encode(b"\x01" * 64).decode(), "license": "MIT"}}})}]
    first = run(SB, {"files": files, "project_name": "demo", "project_version": "1.0"})
    second = run(SB, {"files": files, "project_name": "demo", "project_version": "1.0"})
    sbom = first["artifacts"]["sbom"]
    assert sbom == second["artifacts"]["sbom"] and sbom["bomFormat"] == "CycloneDX" and sbom["specVersion"] == "1.5"
    refs = {c["purl"] for c in sbom["components"]}
    assert refs == {"pkg:pypi/requests@2.32.3", "pkg:npm/%40types/node@22.1.0"}
    by_ref = {c["purl"]: c for c in sbom["components"]}
    assert by_ref["pkg:pypi/requests@2.32.3"]["hashes"] == [{"alg": "SHA-256", "content": sha}]
    assert by_ref["pkg:npm/%40types/node@22.1.0"]["hashes"][0]["alg"] == "SHA-512"
    assert "sbom.unresolved-versions" in ids(first) and first["classification"] == "clean"
    assert run(SB, {"files": [{"path": "notes.txt", "content": "x"}]})["status"] == "invalid_input"


# ---- 086 lockfile integrity ------------------------------------------------------------------
LI = "cyberscan.code.lockfile-integrity"


def test_086_requirements_and_npm(run):
    reqs = ("--index-url http://pypi.internal.example.test/simple\n--extra-index-url https://pypi.org/simple\n"
            f"requests==2.32.3 --hash=sha256:{'b' * 64}\nflask>=3.0\ngit+https://github.com/example/pkg.git@main#egg=pkg\n")
    lock = json.dumps({"lockfileVersion": 3, "packages": {"": {"dependencies": {"a": "1", "b": "1", "c": "1"}},
                       "node_modules/a": {"version": "1.0.0", "resolved": "http://registry.npmjs.org/a/-/a-1.0.0.tgz", "integrity": "sha1-AAAA"},
                       "node_modules/b": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/b/-/b-1.0.0.tgz"}}})
    pkg = json.dumps({"dependencies": {"a": "^1.0.0", "b": "^1.0.0", "c": "^2.0.0"}})
    found = ids(run(LI, {"files": [{"path": "requirements.txt", "content": reqs}, {"path": "package-lock.json", "content": lock},
                                   {"path": "package.json", "content": pkg}]}))
    assert {"pin.unpinned", "hash.partial", "index.http", "index.extra", "source.url", "source.http.a", "integrity.missing",
            "integrity.sha1", "drift.npm"} <= found


def test_086_clean_lockfile_and_go_drift(run):
    lock = json.dumps({"lockfileVersion": 3, "packages": {"": {"dependencies": {"a": "1"}},
                       "node_modules/a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz", "integrity": "sha512-AAAA"}}})
    assert run(LI, {"files": [{"path": "package-lock.json", "content": lock}]})["classification"] == "clean"
    gomod = "module example.test/app\n\ngo 1.22\n\nrequire (\n\tgolang.org/x/text v0.14.0\n\tgithub.com/pkg/errors v0.9.1\n)\n"
    gosum = "golang.org/x/text v0.14.0 h1:abc=\ngolang.org/x/text v0.14.0/go.mod h1:def=\n"
    assert "drift.go" in ids(run(LI, {"files": [{"path": "go.mod", "content": gomod}, {"path": "go.sum", "content": gosum}]}))


# ---- 087 deserialization ---------------------------------------------------------------------
DS = "cyberscan.code.unsafe-deserialization"
PY_DESER = '''
import pickle, yaml, torch
import numpy as np
from flask import request

def load():
    data = request.get_data()
    obj = pickle.loads(data)
    cfg = yaml.load(open("c.yml"))
    safe = yaml.load(open("c.yml"), Loader=yaml.SafeLoader)
    model = torch.load("m.pt")
    arr = np.load("a.npy", allow_pickle=True)
'''


def test_087_code(run):
    result = run(DS, {"files": [{"path": "loader.py", "content": PY_DESER},
                                {"path": "Svc.java", "content": "ObjectInputStream in = new ObjectInputStream(sock.getInputStream());\nObject o = in.readObject();\n"},
                                {"path": "Api.cs", "content": "var f = new BinaryFormatter();\nsettings.TypeNameHandling = TypeNameHandling.All;\n"},
                                {"path": "x.php", "content": "<?php $o = unserialize($_COOKIE['state']); ?>"}]})
    by_id = {f["id"]: f for f in result["findings"]}
    assert by_id["py.pickle.loads"]["severity"] == "critical"           # reads request input in the same function
    assert {"py.yaml.load", "py.torch.load", "py.numpy.allow_pickle", "java.object-input-stream", "dotnet.binaryformatter",
            "dotnet.typenamehandling", "php.unserialize"} <= set(by_id)
    assert sum(1 for f in result["findings"] if f["id"] == "py.yaml.load") == 1  # the SafeLoader call is not flagged


def test_087_blobs_are_inspected_not_loaded(run):
    malicious = b"cos\nsystem\n(S'echo pwned'\ntR."           # protocol-0 pickle calling os.system; never unpickled here
    result = run(DS, {"blob_base64": b64(malicious)})
    assert result["artifacts"]["format"] == "python-pickle" and "os.system" in result["artifacts"]["imports"]
    assert ids(result) == {"blob.pickle-callable"} and result["classification"] == "suspicious"
    plain = run(DS, {"blob_base64": b64(pickle.dumps({"a": [1, 2, 3]}))})
    assert ids(plain) == {"blob.pickle-plain"} and plain["classification"] == "clean"
    java = run(DS, {"blob_base64": b64(b"\xac\xed\x00\x05sr\x00\x3aorg.apache.commons.collections.functors.InvokerTransformer")})
    assert "blob.java" in ids(java) and java["findings"][0]["severity"] == "high"
    php = run(DS, {"blob_base64": b64(b'O:8:"Exploit":1:{s:3:"cmd";s:2:"id";}')})
    assert "blob.php" in ids(php)


# ---- 088 SQL injection -----------------------------------------------------------------------
SQ = "cyberscan.code.sql-injection"
PY_SQL = '''
from flask import request
def search(cur):
    name = request.args["name"]
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    cur.execute("SELECT * FROM users WHERE id = %s" % name)
    cur.execute("SELECT * FROM users WHERE id = %s", (name,))
    query = "DELETE FROM t WHERE id = " + name
    cur.execute(query)
    label.text(f"Hello {name}")

def report(session, day):
    session.execute(text(f"SELECT * FROM logs WHERE day = '{day}'"))
'''


def test_088_python(run):
    result = run(SQ, {"content": PY_SQL, "path": "views.py"})
    dynamic = [f for f in result["findings"] if f["id"] == "py.dynamic-sql"]
    assert len(dynamic) == 3                                      # f-string, % formatting, text(f"...")
    assert {f["location"] for f in dynamic} == {"views.py:5", "views.py:6", "views.py:13"}
    assert [f["severity"] for f in dynamic if f["location"] != "views.py:13"] == ["critical", "critical"]
    assert "py.dynamic-sql-variable" in ids(result)
    assert not any(f["location"] in ("views.py:7", "views.py:10") for f in result["findings"])  # parameterized / non-SQL text()


def test_088_other_languages(run):
    files = [{"path": "db.js", "content": "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);\ndb.query('SELECT * FROM t WHERE id = ?', [id]);\n"},
             {"path": "Repo.java", "content": 'stmt.executeQuery("SELECT * FROM users WHERE name = \'" + name + "\'");\n'},
             {"path": "q.php", "content": '<?php mysqli_query($c, "SELECT * FROM t WHERE id = " . $_GET["id"]); ?>'},
             {"path": "repo.go", "content": 'db.Query(fmt.Sprintf("SELECT * FROM t WHERE id = %s", id))\n'},
             {"path": "user.rb", "content": 'User.where("name = \'#{params[:name]}\'")\n'}]
    found = ids(run(SQ, {"files": files}))
    assert {"js.template-sql", "java.concat-sql", "php.concat-sql", "go.sprintf-sql", "rb.interpolated-sql"} <= found


# ---- 089 XSS ---------------------------------------------------------------------------------
XS = "cyberscan.code.xss-patterns"


def test_089_patterns(run):
    files = [
        {"path": "app.js", "content": "el.innerHTML = location.hash.slice(1);\nbox.innerHTML = msg;\nsafe.innerHTML = DOMPurify.sanitize(msg);\n"
                                      "document.write(userName);\n$('#out').html(data);\nel.textContent = msg;\n"},
        {"path": "Comp.jsx", "content": "<div dangerouslySetInnerHTML={{ __html: post.body }} />\n"},
        {"path": "page.html", "content": "{{ comment|safe }}\n{% autoescape false %}{{ x }}{% endautoescape %}\n<a href=\"javascript:run()\">x</a>\n{{{ raw }}}\n"},
        {"path": "show.php", "content": "<?php echo $_GET['q']; echo htmlspecialchars($_GET['q']); ?>"},
        {"path": "views.py", "content": "from flask import request, render_template_string\nfrom markupsafe import Markup\n"
                                         "def hello():\n    name = request.args.get('n')\n    return render_template_string('<h1>' + name + '</h1>')\n"
                                         "def card(x):\n    return Markup(f'<b>{x}</b>')\n"},
    ]
    result = run(XS, {"files": files})
    by_location = {(f["id"], f["location"]) for f in result["findings"]}
    found = {f for f, _ in by_location}
    assert {"dom.innerhtml-source", "dom.innerhtml", "dom.document-write", "jquery.html", "react.dangerously", "template.safe-filter",
            "template.autoescape-off", "html.javascript-url", "template.handlebars-triple", "php.echo-request",
            "py.render-template-string", "py.markup-dynamic"} <= found
    assert ("dom.innerhtml", "app.js:3") not in by_location               # DOMPurify-sanitized
    assert [f for f in result["findings"] if f["id"] == "php.echo-request"][0]["location"] == "show.php:1"


# ---- 090 secure configuration ----------------------------------------------------------------
CF = "cyberscan.code.secure-config"


def test_090_formats(run):
    files = [
        {"path": "proj/settings.py", "content": "INSTALLED_APPS = []\nDEBUG = True\nALLOWED_HOSTS = ['*']\nSECRET_KEY = 'q8#k2!zv9m@x4p7w1r6t3y0u5i'\nSESSION_COOKIE_SECURE = False\n"},
        {"path": "nginx/site.conf", "content": "server {\n  listen 443 ssl;\n  ssl_certificate /etc/x.pem;\n  server_tokens on;\n  autoindex on;\n  ssl_protocols TLSv1 TLSv1.2;\n  ssl_ciphers HIGH:!aNULL:RC4-SHA;\n}\n"},
        {"path": "php.ini", "content": "display_errors = On\nexpose_php = On\nallow_url_include = On\n;display_errors = Off\n"},
        {"path": "src/main/resources/application.properties", "content": "management.endpoints.web.exposure.include=*\nspring.h2.console.enabled=true\n"},
        {"path": ".env", "content": f"APP_DEBUG=true\nGITHUB_TOKEN={GH}\n"},
    ]
    result = run(CF, {"files": files})
    found = ids(result)
    assert {"django.debug", "django.allowed-hosts", "django.secret-key-literal", "django.cookie-insecure", "nginx.server-tokens",
            "nginx.autoindex", "nginx.legacy-tls", "nginx.weak-ciphers", "nginx.no-hsts", "php.display-errors", "php.expose-php",
            "php.url-include", "spring.actuator-all", "spring.h2-console", "env.debug", "config.secret.github_token"} <= found
    assert result["artifacts"]["formats"]["php.ini"] == "php"
    no_secret_leak(result, GH, "q8#k2!zv9m@x4p7w1r6t3y0u5i")


def test_090_hardened_and_unknown(run):
    nginx = "server {\n  listen 443 ssl;\n  ssl_certificate /etc/x.pem;\n  server_tokens off;\n  ssl_protocols TLSv1.2 TLSv1.3;\n" \
            "  add_header Strict-Transport-Security \"max-age=63072000\" always;\n  add_header X-Content-Type-Options nosniff;\n}\n"
    assert run(CF, {"content": nginx, "path": "site.conf"})["classification"] == "clean"
    assert run(CF, {"content": "hello world", "path": "notes.txt"})["status"] == "invalid_input"
