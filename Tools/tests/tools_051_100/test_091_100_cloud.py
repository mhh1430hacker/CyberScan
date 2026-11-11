"""Tools 091-100 (cloud & infrastructure). All inputs are synthetic exports; nothing contacts a cloud provider."""
import json

from conftest import ids, no_secret_leak

ADMIN = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
READ_ONLY = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::app/*"}]})

FAKE_STRIPE = "sk_" + "live_abcdefghijklmnopqrstuvwx"  # fake, split so the source holds no full token

# ---- 091 cloud configuration -----------------------------------------------------------------
CC = "cyberscan.cloud.config-analyzer"


def _doc(path, obj):
    return {"path": path, "content": json.dumps(obj)}


def test_091_aws_exports(run):
    sgs = {"SecurityGroups": [
        {"GroupId": "sg-1", "GroupName": "web", "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]},
        {"GroupId": "sg-2", "GroupName": "db", "IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "IpRanges": [{"CidrIp": "10.0.0.0/16"}]}]},
        {"GroupId": "sg-3", "GroupName": "all", "IpPermissions": [{"IpProtocol": "-1", "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}]}]}
    ec2 = {"Reservations": [{"Instances": [{"InstanceId": "i-1", "MetadataOptions": {"HttpTokens": "optional", "HttpEndpoint": "enabled"},
                                           "PublicIpAddress": "203.0.113.4", "IamInstanceProfile": {"Arn": "x"}}]}]}
    rds = {"DBInstances": [{"DBInstanceIdentifier": "prod", "PubliclyAccessible": True, "StorageEncrypted": False, "BackupRetentionPeriod": 0,
                            "DeletionProtection": False}]}
    trails = {"trailList": [{"Name": "t", "IsMultiRegionTrail": False, "LogFileValidationEnabled": False}]}
    result = run(CC, {"documents": [_doc("sg.json", sgs), _doc("ec2.json", ec2), _doc("rds.json", rds), _doc("trails.json", trails),
                                    _doc("vol.json", {"Volumes": [{"VolumeId": "vol-1", "Encrypted": False}]})]})
    found = ids(result)
    assert {"aws.sg.open.22", "aws.sg.all-open", "aws.ec2.imdsv1.i-1", "aws.rds.public.prod", "aws.rds.unencrypted.prod",
            "aws.rds.no-backups.prod", "aws.cloudtrail.single-region", "aws.ebs.unencrypted"} <= found
    assert not any("5432" in f for f in found)  # private-range database rule is fine
    assert result["classification"] == "suspicious"


def test_091_azure_gcp_and_unknown(run):
    storage = [{"name": "acct", "allowBlobPublicAccess": True, "enableHttpsTrafficOnly": False, "minimumTlsVersion": "TLS1_0",
                "networkRuleSet": {"defaultAction": "Allow"}}]
    nsg = [{"name": "nsg1", "securityRules": [{"access": "Allow", "direction": "Inbound", "protocol": "Tcp", "destinationPortRange": "3389",
                                                "sourceAddressPrefix": "Internet"}]}]
    fw = [{"name": "allow-ssh", "direction": "INGRESS", "network": "default", "sourceRanges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]}]
    sql = [{"name": "pg", "databaseVersion": "POSTGRES_15", "settings": {"ipConfiguration": {"ipv4Enabled": True, "requireSsl": False,
                                                                                          "authorizedNetworks": [{"value": "0.0.0.0/0"}]}}}]
    found = ids(run(CC, {"documents": [_doc("st.json", storage), _doc("nsg.json", nsg), _doc("fw.json", fw), _doc("sql.json", sql)]}))
    assert {"azure.storage.public-blobs.acct", "azure.storage.http.acct", "azure.storage.tls.acct", "azure.nsg.open.3389",
            "gcp.firewall.open.22", "gcp.sql.public.pg", "gcp.sql.no-ssl.pg"} <= found
    assert run(CC, {"documents": [_doc("x.json", {"hello": 1})]})["status"] == "invalid_input"
    assert run(CC, {"documents": [{"path": "bad.json", "content": "{"}]})["status"] == "invalid_input"


# ---- 092 public storage ----------------------------------------------------------------------
PS = "cyberscan.cloud.public-storage"


def test_092_s3_policy_acl_and_block(run):
    policy = json.dumps({"Statement": [
        {"Sid": "PublicRead", "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"},
        {"Sid": "VpcOnly", "Effect": "Allow", "Principal": "*", "Action": "s3:*", "Resource": "*",
         "Condition": {"StringEquals": {"aws:SourceVpce": "vpce-1"}}}]})
    acl = json.dumps({"Grants": [{"Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "WRITE"}]})
    block = json.dumps({"PublicAccessBlockConfiguration": {"BlockPublicAcls": False, "IgnorePublicAcls": False, "BlockPublicPolicy": True,
                                                           "RestrictPublicBuckets": False}})
    result = run(PS, {"bucket": "b", "bucket_policy": policy, "bucket_acl": acl, "public_access_block": block})
    found = ids(result)
    assert {"s3.policy.public-read.0", "s3.acl.everyone.write", "s3.block-public-access-off"} <= found
    assert "s3.policy.public-write.1" not in found  # restricted by aws:SourceVpce


def test_092_azure_gcs_and_probe(run, monkeypatch):
    containers = json.dumps([{"name": "public", "properties": {"publicAccess": "container"}}, {"name": "private", "properties": {"publicAccess": None}}])
    gcs = json.dumps({"bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]})
    found = ids(run(PS, {"azure_containers": containers, "gcs_iam_policy": gcs}))
    assert found == {"azure.container-public.public", "gcs.public.storage.objectViewer"}
    assert run(PS, {"probe_url": "https://b.s3.amazonaws.com/"})["status"] == "invalid_input"  # needs authorization
    import security_toolkit.httputil as httputil
    monkeypatch.setattr(httputil, "fetch", lambda url, **k: httputil.Response(url, 200, [], b"<ListBucketResult><Contents/></ListBucketResult>"))
    probed = run(PS, {"probe_url": "https://b.s3.amazonaws.com/", "authorization_confirmed": True})
    assert "probe.anonymous-listing" in ids(probed) and probed["metadata"]["execution_mode"] == "network-passive"
    assert run(PS, {})["status"] == "invalid_input"


# ---- 093 IAM ---------------------------------------------------------------------------------
IA = "cyberscan.cloud.iam-auditor"


def test_093_policies(run):
    escalation = json.dumps({"Statement": [{"Effect": "Allow", "Action": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"], "Resource": "*"},
                                           {"Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*"}]})
    not_action = json.dumps({"Statement": [{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]})
    trust = json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]})
    vendor = json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111122223333:root"}, "Action": "sts:AssumeRole"}]})
    result = run(IA, {"policies": [{"name": "Admin", "document": ADMIN}, {"name": "Dev", "document": escalation},
                                   {"name": "Broad", "document": not_action}, {"name": "Open", "document": trust, "kind": "trust"},
                                   {"name": "Vendor", "document": vendor}, {"name": "Reader", "document": READ_ONLY}]})
    found = ids(result)
    assert {"iam.admin", "iam.passrole-any", "iam.not-action.0", "trust.public.0", "trust.cross-account-no-external-id.0",
            "iam.escalation.iam:passrole+lambda:createfunction+lambda:invokefunction", "iam.escalation.iam:createpolicyversion"} <= found
    assert not any(f["location"] == "Reader" for f in result["findings"])


def test_093_credential_report_azure_gcp(run):
    report = ("user,arn,password_enabled,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,"
              "access_key_2_active,password_last_used\n"
              "<root_account>,arn,not_supported,false,true,2024-01-01T00:00:00+00:00,2026-11-01T00:00:00+00:00,false,2026-11-01T00:00:00+00:00\n"
              "alice,arn,true,false,true,2025-01-01T00:00:00+00:00,2025-02-01T00:00:00+00:00,false,N/A\n"
              "bob,arn,true,true,true,2026-10-01T00:00:00+00:00,2026-11-09T00:00:00+00:00,false,N/A\n")
    found = ids(run(IA, {"credential_report": report, "today": "2026-11-11"}))
    assert {"root.access-keys", "root.no-mfa", "root.recent-use", "user.no-mfa.alice", "user.old-key.alice.1", "user.unused-key.alice.1"} <= found
    assert not any(".bob" in f for f in found)
    azure = json.dumps([{"roleName": "God", "roleType": "CustomRole", "permissions": [{"actions": ["*"]}], "assignableScopes": ["/"]}])
    gcp = json.dumps({"bindings": [{"role": "roles/owner", "members": ["user:a@example.test"]}, {"role": "roles/viewer", "members": ["allUsers"]}]})
    found = ids(run(IA, {"azure_role_definitions": azure, "gcp_iam_policy": gcp}))
    assert {"azure.role-wildcard.God", "azure.role-root-scope.God", "gcp.primitive.roles/owner", "gcp.public.roles/viewer"} <= found


# ---- 094 IaC ---------------------------------------------------------------------------------
IC = "cyberscan.cloud.iac-scanner"
TF = '''
resource "aws_security_group" "ssh" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_s3_bucket_acl" "site" { acl = "public-read" }
resource "aws_s3_bucket_public_access_block" "site" {
  block_public_acls = false
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}
resource "aws_db_instance" "db" {
  publicly_accessible = true
  storage_encrypted   = false
}
resource "aws_instance" "web" {
  ami = var.ami
  metadata_options { http_tokens = "optional" }
}
resource "aws_iam_policy" "admin" {
  policy = <<EOT
{"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
EOT
}
resource "aws_iam_policy" "computed" { policy = jsonencode({ Statement = [] }) }
'''
CFN = '''AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Sg:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: rdp
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 3389
          ToPort: 3389
          CidrIp: 0.0.0.0/0
  Vol:
    Type: AWS::EC2::Volume
    Properties:
      Size: 10
      AvailabilityZone: !Select [0, !GetAZs ""]
  Role:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal: "*"
            Action: sts:AssumeRole
'''


def test_094_terraform(run):
    result = run(IC, {"files": [{"path": "main.tf", "content": TF}]})
    found = ids(result)
    assert {"iac.sg.open.22", "iac.s3.public-acl", "iac.s3.block-public-access-off", "iac.rds.public", "iac.rds.unencrypted",
            "iac.ec2.imdsv1", "iac.iam.admin"} <= found
    assert any("expression" in u for u in result["artifacts"]["unresolved"])  # jsonencode policy is reported, not guessed


def test_094_cloudformation_and_errors(run):
    found = ids(run(IC, {"files": [{"path": "stack.yaml", "content": CFN}]}))
    assert {"iac.sg.open.3389", "iac.ebs.unencrypted", "iac.trust.public.0"} <= found
    assert run(IC, {"files": [{"path": "broken.tf", "content": 'resource "x" "y" {'}]})["status"] == "invalid_input"
    secure = 'resource "aws_ebs_volume" "v" {\n  encrypted = true\n}\n'
    assert run(IC, {"files": [{"path": "ok.tf", "content": secure}]})["classification"] == "clean"


# ---- 095 containers --------------------------------------------------------------------------
CT = "cyberscan.cloud.container-config"
DOCKERFILE = """FROM python:latest
ENV API_KEY=""" + FAKE_STRIPE + """
COPY .env /app/.env
ADD https://example.test/tool.tar.gz /opt/
RUN curl -fsSL https://example.test/install.sh | bash && chmod -R 777 /app
EXPOSE 22
CMD ["python", "app.py"]
"""
GOOD_DOCKERFILE = """FROM python:3.13-slim@sha256:""" + "a" * 64 + """
RUN useradd -r app
USER app
HEALTHCHECK CMD python -c "print(1)"
CMD ["python", "app.py"]
"""
COMPOSE = """services:
  app:
    image: app:1.0
    privileged: true
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /etc:/host-etc
    cap_add: [SYS_ADMIN]
    security_opt: ["seccomp:unconfined"]
    environment:
      DB_PASSWORD: hunter2hunter2
  db:
    image: postgres:16
    ports: ["5432:5432"]
"""


def test_095_dockerfile(run):
    result = run(CT, {"files": [{"path": "Dockerfile", "content": DOCKERFILE}]})
    found = ids(result)
    assert {"docker.unpinned-image", "docker.secret-in-env", "docker.copies-secret-file", "docker.add-url", "docker.chmod-777",
            "docker.ssh", "docker.runs-as-root"} <= found
    assert any("download" in f for f in found)
    no_secret_leak(result, FAKE_STRIPE)
    good = run(CT, {"files": [{"path": "Dockerfile", "content": GOOD_DOCKERFILE}]})
    assert good["classification"] == "clean", good["findings"]


def test_095_compose(run):
    result = run(CT, {"files": [{"path": "docker-compose.yml", "content": COMPOSE}]})
    assert {"compose.privileged.app", "compose.host-network_mode.app", "compose.docker-socket.app", "compose.host-mount.app",
            "compose.capabilities.app", "compose.unconfined.app", "compose.secret-env.app", "compose.db-published.db"} <= ids(result)
    no_secret_leak(result, "hunter2hunter2")


# ---- 096 Kubernetes --------------------------------------------------------------------------
K8 = "cyberscan.cloud.kubernetes-auditor"
BAD_K8S = """apiVersion: apps/v1
kind: Deployment
metadata: {name: web}
spec:
  template:
    spec:
      hostNetwork: true
      volumes:
        - name: sock
          hostPath: {path: /var/run/docker.sock}
      containers:
        - name: app
          image: nginx
          securityContext: {privileged: true, runAsUser: 0, capabilities: {add: [SYS_ADMIN]}}
          env:
            - {name: DB_PASSWORD, value: hunter2hunter2}
        - name: sidecar
          image: busybox:latest
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: everything}
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: anon}
roleRef: {kind: ClusterRole, name: view}
subjects: [{kind: User, name: system:anonymous}]
---
apiVersion: v1
kind: Service
metadata: {name: web}
spec: {type: LoadBalancer}
"""
GOOD_K8S = """apiVersion: v1
kind: Pod
metadata: {name: ok}
spec:
  automountServiceAccountToken: false
  securityContext: {runAsNonRoot: true, seccompProfile: {type: RuntimeDefault}}
  containers:
    - name: app
      image: registry.example.test/app@sha256:""" + "b" * 64 + """
      securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}
      resources: {limits: {cpu: 500m, memory: 256Mi}}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: deny-all}
spec: {podSelector: {}}
"""


def test_096_bad_manifests(run):
    result = run(K8, {"files": [{"path": "deploy.yaml", "content": BAD_K8S}]})
    found = ids(result)
    assert {"k8s.hostNetwork", "k8s.hostpath.sensitive", "k8s.privileged", "k8s.run-as-root", "k8s.capabilities", "k8s.secret-in-env",
            "k8s.image-latest", "rbac.wildcard", "rbac.anonymous-binding", "k8s.service-loadbalancer", "k8s.no-network-policy"} <= found
    latest = [f for f in result["findings"] if f["id"] == "k8s.image-latest"]
    assert len(latest) == 2  # both containers reported separately
    no_secret_leak(result, "hunter2hunter2")


def test_096_hardened_pod(run):
    result = run(K8, {"files": [{"path": "pod.yaml", "content": GOOD_K8S}]})
    assert result["classification"] == "clean", result["findings"]
    assert run(K8, {"files": [{"path": "x.yaml", "content": "just: data"}]})["status"] == "invalid_input"


# ---- 097 Git repository ----------------------------------------------------------------------
GR = "cyberscan.cloud.git-repository"
GH = "ghp_" + "Q1w2E3r4T5y6U7i8O9p0A1s2D3f4G5h6J7k8"


def test_097_local_repository(run, tmp_path):
    git = tmp_path / ".git"
    (git / "hooks").mkdir(parents=True)
    (git / "config").write_text(f'[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://deploy:{GH}@github.com/acme/app.git\n'
                                '[http]\n\tsslVerify = false\n[credential]\n\thelper = store\n')
    (git / "hooks" / "pre-commit").write_text("#!/bin/sh\necho hi\n")
    (git / "hooks" / "pre-push.sample").write_text("sample")
    (tmp_path / ".gitmodules").write_text('[submodule "lib"]\n\tpath = lib\n\turl = http://git.example.test/lib.git\n')
    (tmp_path / ".gitignore").write_text("node_modules/\n")
    (tmp_path / "terraform.tfstate").write_text("{}")
    (tmp_path / "deploy.pem").write_text("-----BEGIN CERTIFICATE-----\n")
    (tmp_path / "app.py").write_text(f'TOKEN = "{GH}"\n')
    result = run(GR, {"directory": str(tmp_path)})
    found = ids(result)
    assert {"git.remote-credentials", "git.sslverify-off", "git.credential-store", "git.active-hooks", "git.submodule-insecure",
            "git.gitignore-gaps", "git.tracked.terraform-state", "git.tracked.private-key-or-keystore", "git.secret.github_token"} <= found
    no_secret_leak(result, GH)


def test_097_provided_inputs(run):
    clean = run(GR, {"git_config": '[remote "origin"]\n\turl = git@github.com:acme/app.git\n', "tracked_files": ["src/app.py", "README.md"],
                     "gitignore": ".env\n*.pem\n*.tfstate\n"})
    assert clean["classification"] == "clean", clean["findings"]
    assert run(GR, {"directory": "C:/definitely/not/a/repo/here"})["status"] == "invalid_input"


# ---- 098 CI/CD -------------------------------------------------------------------------------
CI = "cyberscan.cloud.cicd-config"
PWN = """name: ci
on:
  pull_request_target:
    types: [opened]
jobs:
  build:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: some-org/some-action@v1
      - run: |
          echo "Title: ${{ github.event.pull_request.title }}"
      - run: echo ${{ secrets.DEPLOY_TOKEN }}
      - run: curl -sSL https://example.test/get.sh | bash
"""
SAFE = """name: ci
on: [pull_request]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@""" + "c" * 40 + """
      - env:
          TITLE: ${{ github.event.pull_request.title }}
        run: echo "$TITLE"
"""


def test_098_github_actions(run):
    found = ids(run(CI, {"files": [{"path": ".github/workflows/ci.yml", "content": PWN}]}))
    assert {"gha.pwn-request", "gha.script-injection", "gha.secret-echo", "gha.self-hosted-pr", "gha.no-permissions",
            "gha.unpinned-action.some-org/some-action"} <= found
    assert any("download" in f for f in found)
    assert run(CI, {"files": [{"path": ".github/workflows/safe.yml", "content": SAFE}]})["classification"] == "clean"


def test_098_gitlab_and_jenkins(run):
    gitlab = "image: python:latest\nvariables:\n  DEPLOY_PASSWORD: s3cretvalue99\nstages: [test]\ntest:\n  stage: test\n  services: [docker:dind]\n  script:\n    - wget -qO- https://example.test/x.sh | sh\n"
    jenkins = 'pipeline {\n  stages {\n    stage("x") {\n      steps {\n        sh "git checkout ${params.BRANCH}"\n      }\n    }\n  }\n}\n'
    result = run(CI, {"files": [{"path": ".gitlab-ci.yml", "content": gitlab}, {"path": "Jenkinsfile", "content": jenkins}]})
    found = ids(result)
    assert {"gitlab.secret-variable", "gitlab.unpinned-image.test", "gitlab.dind.test", "jenkins.param-injection"} <= found
    no_secret_leak(result, "s3cretvalue99")


# ---- 099 backups -----------------------------------------------------------------------------
BK = "cyberscan.cloud.backup-config"


def test_099_generic_policy(run):
    weak = json.dumps({"backups": [{"name": "files", "frequency_hours": 168, "retention_days": 5, "encrypted": False,
                                    "last_success": "2026-10-01", "copies": [{"location": "nas"}]}]})
    found = ids(run(BK, {"policy": weak, "today": "2026-11-11"}))
    assert {"backup.copies.files", "backup.media.files", "backup.no-offsite.files", "backup.no-immutable.files", "backup.unencrypted.files",
            "backup.retention-short.files", "backup.infrequent.files", "backup.failing.files", "backup.restore-untested.files"} <= found
    strong = json.dumps({"backups": [{"name": "db", "frequency_hours": 4, "retention_days": 90, "encrypted": True, "last_success": "2026-11-11",
                                      "last_restore_test": "2026-09-01", "copies": [{"location": "nas", "encrypted": True},
                                                                                    {"location": "cloud", "immutable": True, "encrypted": True}]}]})
    assert run(BK, {"policy": strong, "today": "2026-11-11"})["classification"] == "clean"


def test_099_aws_backup(run):
    plan = json.dumps({"BackupPlan": {"Rules": [{"RuleName": "daily", "ScheduleExpression": "cron(0 5 * * ? *)", "Lifecycle": {"DeleteAfterDays": 14}}]}})
    vaults = json.dumps({"BackupVaultList": [{"BackupVaultName": "main", "Locked": False}]})
    found = ids(run(BK, {"aws_backup_plan": plan, "aws_backup_vaults": vaults}))
    assert {"aws.backup.no-copy.daily", "aws.backup.short-retention.daily", "aws.backup.vault-unlocked.main"} <= found
    assert run(BK, {"policy": json.dumps({"nothing": 1})})["status"] == "invalid_input"


# ---- 100 asset exposure ----------------------------------------------------------------------
AE = "cyberscan.cloud.asset-exposure"


def test_100_exposure_map_and_dangling_dns(run):
    inventory = {
        "assets": [
            {"id": "i-web", "type": "ec2-instance", "public_ip": "203.0.113.10", "hostname": "web.example.test",
             "listeners": [{"port": 80, "protocol": "HTTP"}], "tags": {}, "ingress": [{"protocol": "tcp", "from_port": 22, "to_port": 22, "sources": ["0.0.0.0/0"]}]},
            {"id": "db-1", "type": "rds-database", "public_endpoint": True, "tags": {"owner": "data"}},
            {"id": "i-internal", "type": "ec2-instance", "tags": {}},
            {"id": "bucket-site", "type": "s3-website", "hostname": "site.s3-website-us-east-1.amazonaws.com", "tags": {"owner": "web"}},
        ],
        "dns_records": [
            {"name": "old.example.test", "type": "CNAME", "value": "old-app.azurewebsites.net."},
            {"name": "www.example.test", "type": "CNAME", "value": "site.s3-website-us-east-1.amazonaws.com"},
            {"name": "mail.example.test", "type": "A", "value": "203.0.113.20"},
        ],
    }
    result = run(AE, {"inventory": json.dumps(inventory)})
    found = ids(result)
    assert {"exposure.i-web.open.22", "exposure.http.i-web", "exposure.unowned.i-web", "exposure.data-store.db-1", "dns.dangling.old.example.test"} <= found
    assert "dns.dangling.www.example.test" not in found  # target exists in the inventory
    assert {e["asset"] for e in result["artifacts"]["internet_facing"]} == {"i-web", "db-1"}
    assert run(AE, {})["status"] == "invalid_input"
