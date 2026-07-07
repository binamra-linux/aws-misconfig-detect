"""
Read-only IAM misconfiguration checks:
  - overly permissive policies: any reachable Allow statement granting
    Action:"*" on Resource:"*" (inline user policy, attached managed policy,
    or inherited via inline/attached group policy)
  - IAM users with a console password but no MFA device
    (CIS AWS Foundations Benchmark 1.2)
  - access keys that are Active but unused for IAM_UNUSED_KEY_DAYS+ days
    (or never used), per config.IAM_UNUSED_KEY_DAYS

Required IAM permissions (read-only):
  iam:ListUsers, iam:ListUserPolicies, iam:GetUserPolicy,
  iam:ListAttachedUserPolicies, iam:ListGroupsForUser,
  iam:ListGroupPolicies, iam:GetGroupPolicy, iam:ListAttachedGroupPolicies,
  iam:GetPolicy, iam:GetPolicyVersion, iam:GetLoginProfile,
  iam:ListMFADevices, iam:ListAccessKeys, iam:GetAccessKeyLastUsed
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

from backend import config
from backend.models import Finding, Severity


def _as_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else [value]


def _statement_is_overly_permissive(statement: Dict[str, Any]) -> bool:
    if statement.get("Effect") != "Allow":
        return False
    actions = _as_list(statement.get("Action", []))
    resources = _as_list(statement.get("Resource", []))
    return "*" in actions and "*" in resources


def _document_is_overly_permissive(document: Dict[str, Any]) -> bool:
    return any(_statement_is_overly_permissive(s) for s in _as_list(document.get("Statement", [])))


def _managed_policy_document(iam, policy_arn: str) -> Dict[str, Any]:
    policy = iam.get_policy(PolicyArn=policy_arn)["Policy"]
    version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=policy["DefaultVersionId"])
    return version["PolicyVersion"]["Document"]


def _overly_permissive_sources(iam, user_name: str) -> List[Dict[str, Any]]:
    """Every policy reachable by this user (directly or via group) that grants Action:*/Resource:*."""
    hits: List[Dict[str, Any]] = []

    for policy_name in iam.list_user_policies(UserName=user_name)["PolicyNames"]:
        doc = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)["PolicyDocument"]
        if _document_is_overly_permissive(doc):
            hits.append({"source": "inline_user_policy", "name": policy_name})

    for policy in iam.list_attached_user_policies(UserName=user_name)["AttachedPolicies"]:
        if _document_is_overly_permissive(_managed_policy_document(iam, policy["PolicyArn"])):
            hits.append({"source": "attached_user_policy", "name": policy["PolicyName"], "arn": policy["PolicyArn"]})

    for group in iam.list_groups_for_user(UserName=user_name)["Groups"]:
        group_name = group["GroupName"]

        for policy_name in iam.list_group_policies(GroupName=group_name)["PolicyNames"]:
            doc = iam.get_group_policy(GroupName=group_name, PolicyName=policy_name)["PolicyDocument"]
            if _document_is_overly_permissive(doc):
                hits.append({"source": "inline_group_policy", "group": group_name, "name": policy_name})

        for policy in iam.list_attached_group_policies(GroupName=group_name)["AttachedPolicies"]:
            if _document_is_overly_permissive(_managed_policy_document(iam, policy["PolicyArn"])):
                hits.append({
                    "source": "attached_group_policy",
                    "group": group_name,
                    "name": policy["PolicyName"],
                    "arn": policy["PolicyArn"],
                })

    return hits


def _check_overly_permissive(iam, user_name: str) -> Optional[Finding]:
    hits = _overly_permissive_sources(iam, user_name)
    if not hits:
        return None
    return Finding(
        resource_id=user_name,
        resource_type="IAMUser",
        check_type="IAM_OVERLY_PERMISSIVE_POLICY",
        severity=Severity.CRITICAL,
        description=f"IAM user '{user_name}' has effective access to a policy granting Action:\"*\" on Resource:\"*\".",
        detail={"policies": hits},
    )


def _check_mfa(iam, user_name: str) -> Optional[Finding]:
    try:
        iam.get_login_profile(UserName=user_name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            return None  # no console password -> MFA doesn't apply
        raise

    if iam.list_mfa_devices(UserName=user_name)["MFADevices"]:
        return None

    return Finding(
        resource_id=user_name,
        resource_type="IAMUser",
        check_type="IAM_NO_MFA",
        severity=Severity.HIGH,
        description=f"IAM user '{user_name}' has a console password but no MFA device enabled.",
        detail={},
    )


def _check_unused_access_keys(iam, user_name: str) -> List[Finding]:
    findings: List[Finding] = []
    now = datetime.now(timezone.utc)

    for key in iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]:
        if key["Status"] != "Active":
            continue

        key_id = key["AccessKeyId"]
        last_used = iam.get_access_key_last_used(AccessKeyId=key_id).get("AccessKeyLastUsed", {})
        last_used_date = last_used.get("LastUsedDate")
        reference_date = last_used_date or key["CreateDate"]
        age_days = (now - reference_date).days

        if age_days >= config.IAM_UNUSED_KEY_DAYS:
            never_used_note = "" if last_used_date else " (never used)"
            findings.append(Finding(
                resource_id=f"{user_name}/{key_id}",
                resource_type="IAMAccessKey",
                check_type="IAM_UNUSED_ACCESS_KEY",
                severity=Severity.MEDIUM,
                description=(
                    f"Access key '{key_id}' for user '{user_name}' has been unused for "
                    f"{age_days} day(s){never_used_note}."
                ),
                detail={
                    "created": key["CreateDate"].isoformat(),
                    "last_used_date": last_used_date.isoformat() if last_used_date else None,
                    "service_last_used": last_used.get("ServiceName"),
                    "threshold_days": config.IAM_UNUSED_KEY_DAYS,
                },
            ))

    return findings


def scan_iam(session: Optional[boto3.Session] = None) -> List[Finding]:
    session = session or boto3.Session()
    iam = session.client("iam")
    findings: List[Finding] = []

    for user in iam.list_users()["Users"]:
        user_name = user["UserName"]

        try:
            permissive_finding = _check_overly_permissive(iam, user_name)
            if permissive_finding:
                findings.append(permissive_finding)

            mfa_finding = _check_mfa(iam, user_name)
            if mfa_finding:
                findings.append(mfa_finding)

            findings.extend(_check_unused_access_keys(iam, user_name))

        except ClientError as e:
            findings.append(Finding(
                resource_id=user_name,
                resource_type="IAMUser",
                check_type="SCAN_ERROR",
                severity=Severity.LOW,
                description=f"Could not fully scan IAM user '{user_name}': {e.response['Error']['Code']}",
                detail={"error": str(e)},
            ))

    return findings


if __name__ == "__main__":
    import json

    from backend.scanner import build_session

    results = scan_iam(build_session())
    print(json.dumps([f.to_dict() for f in results], indent=2))
