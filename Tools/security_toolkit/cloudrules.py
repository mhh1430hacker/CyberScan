"""Cloud security checks shared by tools 091-094 and 100, on provider-neutral shapes.

* network exposure: ingress rules {protocol, from_port, to_port, sources[]} open to the internet;
* resource policies (S3 bucket policies, KMS/SQS/SNS style): statements that grant access to anyone,
  unless a restricting condition applies;
* IAM identity policies: administrator wildcards, NotAction allows, iam:PassRole on *, and the action
  combinations known to allow privilege escalation; trust policies open to any principal.
These are configuration facts ("verified_condition"): they show what the configuration permits, not
that anyone has abused it.
"""
from __future__ import annotations

import fnmatch
import json
from typing import Any

from security_toolkit.core import Context

WORLD = {"0.0.0.0/0", "::/0", "*", "internet", "any"}
SENSITIVE_PORTS = {22: "SSH", 23: "Telnet", 3389: "RDP", 445: "SMB", 135: "MS-RPC", 1433: "MS SQL", 1521: "Oracle", 3306: "MySQL",
                   5432: "PostgreSQL", 6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB", 2375: "Docker API", 2379: "etcd",
                   5601: "Kibana", 11211: "Memcached", 5984: "CouchDB", 9042: "Cassandra", 8080: "HTTP alt", 5900: "VNC"}
RESTRICTING_CONDITIONS = ("aws:sourceip", "aws:sourcevpc", "aws:sourcevpce", "aws:principalorgid", "aws:principalaccount",
                          "aws:sourceaccount", "aws:sourcearn", "aws:userid", "aws:principalarn", "aws:calledvia", "s3:dataaccesspointaccount")
ESCALATION_SETS = [
    ({"iam:createpolicyversion"}, "can create a new default version of a policy it is attached to"),
    ({"iam:setdefaultpolicyversion"}, "can switch a policy to an older, more permissive version"),
    ({"iam:attachuserpolicy"}, "can attach AdministratorAccess to a user"), ({"iam:attachrolepolicy"}, "can attach any policy to a role"),
    ({"iam:attachgrouppolicy"}, "can attach any policy to a group"), ({"iam:putuserpolicy"}, "can write an inline admin policy on a user"),
    ({"iam:putrolepolicy"}, "can write an inline policy on a role"), ({"iam:putgrouppolicy"}, "can write an inline policy on a group"),
    ({"iam:createaccesskey"}, "can create access keys for other users"), ({"iam:createloginprofile"}, "can set console passwords for other users"),
    ({"iam:updateloginprofile"}, "can change other users' console passwords"), ({"iam:addusertogroup"}, "can add itself to an admin group"),
    ({"iam:updateassumerolepolicy", "sts:assumerole"}, "can rewrite a role's trust policy and assume it"),
    ({"iam:passrole", "lambda:createfunction", "lambda:invokefunction"}, "can run code as a more privileged role via Lambda"),
    ({"iam:passrole", "ec2:runinstances"}, "can launch an instance with a more privileged role"),
    ({"iam:passrole", "cloudformation:createstack"}, "can deploy a stack with a more privileged role"),
    ({"iam:passrole", "glue:createdevendpoint"}, "can start a Glue endpoint with a more privileged role"),
    ({"lambda:updatefunctioncode"}, "can replace the code of existing (possibly privileged) Lambda functions"),
]


def port_range_exposes(from_port: int | None, to_port: int | None) -> list[int]:
    low = 0 if from_port in (None, -1) else int(from_port)
    high = 65535 if to_port in (None, -1) else int(to_port)
    return sorted(p for p in SENSITIVE_PORTS if low <= p <= high)


def check_ingress(ctx: Context, rules: list[dict[str, Any]], *, resource: str, prefix: str = "network") -> None:
    """rules: [{protocol, from_port, to_port, sources: [cidr/tag]}]"""
    for rule in rules:
        sources = {str(s).lower() for s in rule.get("sources") or []}
        open_sources = sorted(sources & WORLD)
        if not open_sources:
            continue
        protocol = str(rule.get("protocol", "tcp")).lower()
        all_traffic = protocol in ("-1", "all", "*") or (rule.get("from_port") in (None, -1, 0) and rule.get("to_port") in (None, -1, 65535))
        if all_traffic:
            ctx.finding(f"{prefix}.all-open", f"{resource}: all ports open to the internet", "critical",
                        f"Inbound traffic on every port is allowed from {', '.join(open_sources)}.", assurance="verified_condition",
                        location=resource, recommendation="Allow only the ports you serve, from the addresses that need them.")
            continue
        for port in port_range_exposes(rule.get("from_port"), rule.get("to_port")):
            severity = "critical" if port in (2375, 2379, 6379, 9200, 27017, 11211) else "high"
            ctx.finding(f"{prefix}.open.{port}", f"{resource}: {SENSITIVE_PORTS[port]} (port {port}) open to the internet", severity,
                        f"Port {port} accepts connections from {', '.join(open_sources)}; administrative and database services should "
                        "never be internet-facing.", assurance="verified_condition", location=resource,
                        recommendation="Restrict the source to a VPN/bastion range or use private connectivity.")


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _principal_is_public(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        for key in ("AWS", "CanonicalUser", "Federated"):
            if "*" in _as_list(principal.get(key)):
                return True
    return False


def _restricting(condition: Any) -> bool:
    if not isinstance(condition, dict):
        return False
    for operator, clauses in condition.items():
        if not isinstance(clauses, dict):
            continue
        for key in clauses:
            if key.lower() in RESTRICTING_CONDITIONS:
                return True
    return False


def load_policy(policy: Any) -> dict[str, Any] | None:
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except ValueError:
            return None
    return policy if isinstance(policy, dict) else None


def check_resource_policy(ctx: Context, policy: Any, *, resource: str, prefix: str = "policy") -> int:
    """Statements that grant access to anyone. Returns the number of public statements."""
    document = load_policy(policy)
    if document is None:
        return 0
    public = 0
    for index, statement in enumerate(_as_list(document.get("Statement"))):
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        if not _principal_is_public(statement.get("Principal")) or _restricting(statement.get("Condition")):
            continue
        actions = [str(a).lower() for a in _as_list(statement.get("Action"))]
        write = [a for a in actions if a in ("*", "s3:*") or fnmatch.fnmatch("s3:putobject", a) or fnmatch.fnmatch("s3:deleteobject", a)
                 or a.startswith(("s3:put", "s3:delete")) or a.endswith(":*")]
        read = [a for a in actions if fnmatch.fnmatch("s3:getobject", a) or fnmatch.fnmatch("s3:listbucket", a) or a.startswith(("s3:get", "s3:list"))]
        public += 1
        ctx.finding(f"{prefix}.public-{'write' if write else 'read' if read else 'access'}.{index}",
                    f"{resource}: policy grants {'write' if write else 'read' if read else ''} access to anyone".replace("  ", " "),
                    "critical" if write else "high",
                    f"Statement {statement.get('Sid', index)} allows Principal * to {', '.join(actions[:6])} without a restricting condition.",
                    assurance="verified_condition", location=resource,
                    recommendation="Remove the public principal or add aws:SourceVpce / aws:PrincipalOrgID conditions; enable Block Public Access.")
    return public


def check_identity_policy(ctx: Context, policy: Any, *, resource: str, prefix: str = "iam") -> None:
    document = load_policy(policy)
    if document is None:
        return
    allowed: set[str] = set()
    for index, statement in enumerate(_as_list(document.get("Statement"))):
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        actions = [str(a).lower() for a in _as_list(statement.get("Action"))]
        resources = [str(r) for r in _as_list(statement.get("Resource"))]
        if statement.get("NotAction") is not None:
            ctx.finding(f"{prefix}.not-action.{index}", f"{resource}: Allow with NotAction", "high",
                        "Allow + NotAction grants every action except those listed, including future services.",
                        assurance="verified_condition", location=resource)
            continue
        allowed.update(actions)
        if "*" in actions and "*" in resources:
            ctx.finding(f"{prefix}.admin", f"{resource}: full administrator access (Action * on Resource *)", "critical",
                        "The identity can do anything in the account.", assurance="verified_condition", location=resource,
                        recommendation="Grant only the actions and resources the workload needs.")
            continue
        services = sorted({a.split(":")[0] for a in actions if a.endswith(":*")})
        if services and "*" in resources:
            ctx.finding(f"{prefix}.service-wildcard.{index}", f"{resource}: all actions on {', '.join(services[:5])}", "high" if "iam" in services else "medium",
                        "Service-wide wildcards on all resources rarely follow least privilege" + (" and iam:* allows full escalation." if "iam" in services else "."),
                        assurance="verified_condition", location=resource)
        if any(fnmatch.fnmatch("iam:passrole", a) for a in actions) and "*" in resources:
            ctx.finding(f"{prefix}.passrole-any", f"{resource}: iam:PassRole on any role", "high",
                        "Can hand any role, including admin roles, to services it controls.", assurance="verified_condition", location=resource)
    for required, why in ESCALATION_SETS:
        if all(any(fnmatch.fnmatch(action, granted) for granted in allowed) for action in required) and "*" not in allowed:
            ctx.finding(f"{prefix}.escalation.{'+'.join(sorted(required))}", f"{resource}: privilege-escalation path", "high",
                        f"Holding {', '.join(sorted(required))} means the identity {why}.", assurance="verified_condition", location=resource)


def check_trust_policy(ctx: Context, policy: Any, *, resource: str, prefix: str = "trust") -> None:
    document = load_policy(policy)
    if document is None:
        return
    for index, statement in enumerate(_as_list(document.get("Statement"))):
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        principal = statement.get("Principal")
        condition = statement.get("Condition")
        if _principal_is_public(principal) and not _restricting(condition) and "sts:externalid" not in json.dumps(condition or {}).lower():
            ctx.finding(f"{prefix}.public.{index}", f"{resource}: any AWS principal can assume this role", "critical",
                        "The trust policy allows Principal * without conditions; anyone with an AWS account can assume it.",
                        assurance="verified_condition", location=resource)
        aws = _as_list(principal.get("AWS")) if isinstance(principal, dict) else []
        if any(str(p).endswith(":root") for p in aws) and "sts:externalid" not in json.dumps(condition or {}).lower():
            ctx.finding(f"{prefix}.cross-account-no-external-id.{index}", f"{resource}: cross-account trust without ExternalId", "low",
                        "Third-party role assumption without sts:ExternalId is exposed to the confused-deputy problem.",
                        assurance="verified_condition", location=resource)
