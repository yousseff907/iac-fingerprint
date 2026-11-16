"""
iac-fingerprint — scan.py

Scans every active region in an AWS account, inventories all taggable
resources via the Resource Groups Tagging API, parses each ARN into
granular fields, and classifies each resource by which IaC tool (if any)
created it — based on the tag signatures defined in signatures.yaml.

Output: a single .xlsx workbook with two sheets:
  - "CDK Managed"     — resources tagged by AWS CDK
  - "Non-CDK Managed" — everything else (CloudFormation, unknown, etc.)

Usage:
    python scan.py
    python scan.py --regions us-east-1 us-west-2
    python scan.py --output my_inventory.xlsx
"""

import argparse
import re
import sys
from datetime import datetime, timezone

import boto3
import pandas as pd
import yaml
from botocore.config import Config
from botocore.exceptions import (
    ClientError,
    ConnectTimeoutError,
    EndpointConnectionError,
    ReadTimeoutError,
)

# Applied to every AWS client. Without this, a slow/flaky region (opt-in
# regions like me-south-1, af-south-1, ap-east-1 are the usual culprits)
# can hang for minutes — boto3's default retry behavior is several
# attempts with exponential backoff before it gives up. This makes a
# stuck region fail fast (~15s) instead.
BOTO_CONFIG = Config(
    connect_timeout=5,
    read_timeout=10,
    retries={"max_attempts": 2, "mode": "standard"},
)

# Matches AWS's own "immutable version, stable base name" ID patterns:
#   - ECS task definition ARNs: .../family-name:<revision>
#   - ElastiCache cache-cluster IDs spawned under a replication group:
#     <replication-group-id>-<3-digit index>  (e.g. "...-redis-001")
#   - RDS automated snapshots: rds:<db-instance-id>-<YYYY-MM-DD-HH-MM>
#     (the "rds:" prefix marks it as an AWS-automated backup, as opposed
#     to a manually/CFN-created snapshot, which has no prefix at all)
# CloudFormation only ever tracks the CURRENT task-def revision, the
# replication group itself, or the DB instance itself -- never the
# derived/versioned resources AWS spins off from them -- even though
# those derived resources are just as much a product of that same
# CDK-managed resource. Stripping the suffix recovers the stable
# identity CloudFormation actually tracks.
_REVISION_SUFFIX_RE = re.compile(r":\d+$")
_CLUSTER_NODE_SUFFIX_RE = re.compile(r"-\d{3}$")
_RDS_AUTOMATED_SNAPSHOT_RE = re.compile(r"^rds:(?P<db_instance_id>.+)-\d{4}-\d{2}-\d{2}-\d{2}-\d{2}$")


def _strip_versioned_suffix(identifier: str | None) -> str | None:
    """
    Returns the stable "base" form of an identifier that carries an
    AWS-generated version/index/timestamp suffix (or "rds:" prefix), or
    None if it doesn't match any known pattern (nothing to strip).
    """
    if not identifier:
        return None
    match = _RDS_AUTOMATED_SNAPSHOT_RE.match(identifier)
    if match:
        return match.group("db_instance_id")
    stripped = _REVISION_SUFFIX_RE.sub("", identifier)
    if stripped != identifier:
        return stripped
    stripped = _CLUSTER_NODE_SUFFIX_RE.sub("", identifier)
    if stripped != identifier:
        return stripped
    return None


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

def load_signatures(path: str = "signatures.yaml") -> dict:
    """
    Loads the IaC detection config. Returns a dict with:
        - "signatures": ordered dict of {tool_name: {tag_key, reliability, notes}}
        - "unmatched_label": string label for resources matching nothing

    Fails loudly (lets the exception propagate) if the file is missing or
    malformed — a personal scanning tool should not silently run with no
    detection rules and produce a misleading "everything is unknown" result.
    """
    with open(path, "r") as f:
        config = yaml.safe_load(f)

    if not config or "signatures" not in config:
        raise ValueError(
            f"'{path}' is missing a top-level 'signatures' key. "
            "Check the file against the example in the repo."
        )

    return config


# ---------------------------------------------------------------------------
# AWS discovery
# ---------------------------------------------------------------------------

def get_active_regions(session: boto3.Session) -> list[str]:
    """
    Returns all regions this account can currently operate in (opted-in
    or opt-in-not-required). Uses us-east-1 to make the call since
    DescribeRegions is a partition-level API and doesn't require a
    specific region to be meaningful.

    Deliberately does NOT catch exceptions here — if this call fails,
    the tool has no valid region list to work with at all, and should
    fail loudly rather than silently scanning zero regions.
    """
    ec2_client = session.client("ec2", region_name="us-east-1", config=BOTO_CONFIG)
    response = ec2_client.describe_regions(AllRegions=False)
    return [r["RegionName"] for r in response["Regions"]]


def get_referenced_stack_names(raw_resources: list[dict], stack_name_tag_key: str) -> set[str]:
    """
    Scans the already-fetched Tagging API results and returns the distinct
    set of CloudFormation stack names referenced by any resource's tags.

    KNOWN GAP: CloudFormation does NOT auto-inject the
    "aws:cloudformation:stack-name" tag onto every resource type it
    manages -- this is resource-type dependent and undocumented. Things
    like ECS Services, ALBs/Listeners/TargetGroups, ACM Certificates, and
    IAM Roles/Policies routinely come back from the Tagging API with only
    their explicit user-defined tags (e.g. Project/Environment) and NO
    CloudFormation stack tag at all, despite being 100% CFN/CDK-managed.
    Relying on this alone means most of a stack's resources -- and
    sometimes the stack itself -- never surface. See get_all_stack_names
    for the authoritative source; this function now only backs a fallback
    path in classify_resource_ownership.
    """
    stack_names = set()
    for item in raw_resources:
        tag_map = {t["Key"]: t["Value"] for t in item.get("Tags", [])}
        if stack_name_tag_key in tag_map:
            stack_names.add(tag_map[stack_name_tag_key])
    return stack_names


# Stack statuses that mean the stack still exists and can own live resources.
# Deliberately excludes *_COMPLETE deletion states and REVIEW_IN_PROGRESS
# (a stack that failed to ever actually create anything).
_LIVE_STACK_STATUSES = [
    "CREATE_COMPLETE", "CREATE_IN_PROGRESS", "CREATE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_IN_PROGRESS", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_IN_PROGRESS", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_IN_PROGRESS", "UPDATE_ROLLBACK_FAILED",
    "IMPORT_COMPLETE", "IMPORT_IN_PROGRESS", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_IN_PROGRESS", "IMPORT_ROLLBACK_FAILED",
]


def get_all_stack_names(session: boto3.Session, region: str) -> set[str]:
    """
    Returns every live CloudFormation stack name in the region, straight
    from CloudFormation itself -- not derived from resource tags.

    This is the authoritative source: CloudFormation always knows exactly
    which stacks exist, regardless of whether any of their resources
    happen to carry the "aws:cloudformation:stack-name" tag. Using this
    instead of (or alongside) get_referenced_stack_names is what lets us
    inspect stacks whose resources are under-tagged, rather than only the
    stacks we got lucky enough to spot via a tag.
    """
    client = session.client("cloudformation", region_name=region, config=BOTO_CONFIG)
    paginator = client.get_paginator("list_stacks")
    stack_names = set()
    try:
        for page in paginator.paginate(StackStatusFilter=_LIVE_STACK_STATUSES):
            for summary in page.get("StackSummaries", []):
                stack_names.add(summary["StackName"])
    except ClientError as e:
        print(f"  [warn] Could not list stacks in {region}: {e.response['Error']['Code']} - {e.response['Error']['Message']}")
    except (EndpointConnectionError, ReadTimeoutError, ConnectTimeoutError):
        print(f"  [warn] Timed out listing stacks in {region}")
    return stack_names


def build_cdk_resource_lookup(session: boto3.Session, region: str, stack_names: set[str]) -> tuple[dict[str, str], set[str], dict[str, str], list[dict]]:
    """
    Returns (physical_id -> cdk_construct_path, set of CDK stack names),
    across all given stacks, using TWO independent signals:

      1. PER-RESOURCE (precise): get_template() -> Resources.<id>.Metadata
         contains "aws:cdk:path" for anything CDK authored. Best fidelity
         — gives the actual construct path — but SOME ORGS STRIP THIS
         from templates before deploy (commonly done to avoid leaking
         local developer file paths via the sibling "aws:cdk:trace" key).
         If that's happening, this signal will legitimately find nothing
         for an entire account, even one that's 100% CDK.

      2. STACK-LEVEL (fallback, can't be stripped): every CDK-synthesized
         stack automatically gets a "BootstrapVersion" CloudFormation
         parameter. This is a real deployment parameter, not decorative
         metadata, so no reasonable Aspect/cleanup step removes it.

    A resource is "cdk" if EITHER signal says so. Signal 1 additionally
    gives the construct path when available; signal 2 alone only tells
    you the resource's *stack* was CDK-synthesized, not the resource
    itself specifically (so it won't catch an escape-hatch resource
    dropped into a CDK stack — that's the tradeoff for resilience against
    stripped metadata).

    Known limitation: raw/hand-written templates are sometimes returned
    as a YAML string using CloudFormation's short-form intrinsics
    (!Ref, !GetAtt) that a plain parser can't read. We skip parsing those
    for signal 1 (they're not CDK anyway), but signal 2 still works since
    it only reads stack Parameters, not the template body.

    Also returns resource_stack_lookup: {physical_id/ARN -> stack_name}
    for EVERY resource CloudFormation reports owning across all given
    stacks, independent of CDK-ness or tags. This is what lets classify_resource_ownership
    place a resource under its true stack even when the resource type
    never got the "aws:cloudformation:stack-name" tag from CloudFormation
    (see get_all_stack_names for why that happens routinely).

    Also returns all_stack_resources: a flat list of every resource CFN
    reports owning ({physical_id, cfn_resource_type, stack_name}). Some
    resource types are NEVER indexed by the Resource Groups Tagging API
    at all, tags or no tags -- confirmed for IAM roles/policies, Route53
    RecordSets, WAFv2 WebACLs (account/region-dependent), API Gateway
    REST API resources (only v2 HTTP/WebSocket APIs are indexed), and
    Lambda::Permission (no ARN of its own). classify_resources() can only
    ever classify what the Tagging API returned, so these resources are
    otherwise invisible no matter how good the classification logic is.
    Returning CFN's own resource list lets the caller synthesize rows for
    exactly the ones the Tagging API silently dropped.
    """
    import json

    cfn_client = session.client("cloudformation", region_name=region, config=BOTO_CONFIG)
    lookup: dict[str, str] = {}
    cdk_stack_names: set[str] = set()
    resource_stack_lookup: dict[str, str] = {}
    all_stack_resources: list[dict] = []

    for stack_name in stack_names:
        try:
            # Signal 2: stack-level BootstrapVersion check (cheap, one call)
            stack_info = cfn_client.describe_stacks(StackName=stack_name)["Stacks"][0]
            param_keys = {p["ParameterKey"] for p in stack_info.get("Parameters", [])}
            if "BootstrapVersion" in param_keys:
                cdk_stack_names.add(stack_name)

            # Authoritative membership: every resource CFN says this stack
            # owns, regardless of whether it carries the stack-name tag.
            # Uses the paginated list_stack_resources rather than
            # describe_stack_resources, which silently returns only the
            # first 100 resources of a stack.
            stack_resources = [
                summary
                for page in cfn_client.get_paginator("list_stack_resources").paginate(StackName=stack_name)
                for summary in page.get("StackResourceSummaries", [])
            ]
            for res in stack_resources:
                physical_id = res.get("PhysicalResourceId")
                if not physical_id:
                    continue
                resource_stack_lookup[physical_id] = stack_name
                # Also index by the stable base identity (revision/node
                # suffix stripped), so a differently-versioned/indexed
                # sibling resource can still be matched on the query side.
                base_id = _strip_versioned_suffix(physical_id)
                if base_id:
                    resource_stack_lookup.setdefault(base_id, stack_name)
                all_stack_resources.append({
                    "physical_id": physical_id,
                    "cfn_resource_type": res.get("ResourceType"),
                    "stack_name": stack_name,
                    "stack_region": region,
                })

            # Signal 1: per-resource Metadata check (precise, when available)
            template_body = cfn_client.get_template(StackName=stack_name)["TemplateBody"]

            if isinstance(template_body, str):
                try:
                    template_body = json.loads(template_body)
                except (ValueError, TypeError):
                    continue  # raw YAML template with intrinsics — signal 2 still applies

            resources_section = template_body.get("Resources", {}) if isinstance(template_body, dict) else {}
            cdk_paths_by_logical_id = {
                logical_id: definition.get("Metadata", {}).get("aws:cdk:path")
                for logical_id, definition in resources_section.items()
                if definition.get("Metadata", {}).get("aws:cdk:path")
            }
            if not cdk_paths_by_logical_id:
                continue  # no per-resource paths found — signal 2 still applies if set above

            for res in stack_resources:
                logical_id = res["LogicalResourceId"]
                physical_id = res.get("PhysicalResourceId")
                if physical_id and logical_id in cdk_paths_by_logical_id:
                    lookup[physical_id] = cdk_paths_by_logical_id[logical_id]

        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"]["Message"]
            print(f"  [warn] Could not inspect stack '{stack_name}': {code} - {message}")
        except (EndpointConnectionError, ReadTimeoutError, ConnectTimeoutError):
            print(f"  [warn] Timed out inspecting stack '{stack_name}'")

    # Special case: the bootstrap stack ("CDKToolkit" by default, unless
    # customized via `cdk bootstrap --toolkit-stack-name`) is CDK tooling
    # infrastructure, but it's deployed via `cdk bootstrap` using a
    # pre-built template shipped with the CDK CLI -- NOT synthesized from
    # application code via app.synth(). So it legitimately carries neither
    # of our two signals: no per-resource Metadata (never synthesized that
    # way), and no BootstrapVersion parameter (it's the stack that CREATES
    # that version info for other stacks to reference, not a consumer of
    # it). We treat it as CDK anyway since it only exists because CDK is
    # in use -- this is a labeling choice, not a detection fact.
    if "CDKToolkit" in stack_names:
        cdk_stack_names.add("CDKToolkit")

    return lookup, cdk_stack_names, resource_stack_lookup, all_stack_resources


def get_resource_inventory(session: boto3.Session, region: str) -> list[dict]:
    """
    Returns the raw ResourceTagMappingList entries for a single region,
    using the Tagging API's paginator to handle large accounts safely.

    Returns an empty list (and prints a warning) if the region is
    disabled, unreachable, or the call is otherwise rejected — this is
    the "expected, recoverable" failure case, unlike get_active_regions.
    """
    client = session.client("resourcegroupstaggingapi", region_name=region, config=BOTO_CONFIG)
    paginator = client.get_paginator("get_resources")

    resources = []
    try:
        for page in paginator.paginate():
            resources.extend(page.get("ResourceTagMappingList", []))
    except ClientError as e:
        print(f"  [skip] {region}: {e.response['Error']['Code']} - {e.response['Error']['Message']}")
        return []
    except (EndpointConnectionError, ReadTimeoutError, ConnectTimeoutError) as e:
        print(f"  [skip] {region}: timed out / unreachable ({e})")
        return []

    return resources


# ---------------------------------------------------------------------------
# Pure parsing / classification logic (no AWS calls — easy to unit test)
# ---------------------------------------------------------------------------

def parse_arn(arn: str) -> dict:
    """
    Breaks an ARN into its component fields.

    ARN shape: arn:partition:service:region:account-id:resource
    The trailing "resource" segment itself varies by service:
        - type/id   (e.g. instance/i-0abcd1234)
        - type:id   (e.g. function:my-function)
        - id only   (e.g. my-bucket, for S3)

    region and account_id may legitimately be empty in the source ARN
    (e.g. S3 and IAM) — these are normalized to None rather than "",
    so downstream code can distinguish "not present" from "empty string".
    """
    parts = arn.split(":", 5)

    if len(parts) < 6:
        # Malformed / unexpected ARN shape — don't crash the whole scan,
        # return a record that's clearly flagged as unparseable instead.
        return {
            "account_id": None,
            "arn_region": None,
            "service": None,
            "resource_type": None,
            "resource_id": arn,
            "parse_error": True,
        }

    _, _partition, service, region, account_id, resource = parts

    if "/" in resource:
        resource_type, resource_id = resource.split("/", 1)
    elif ":" in resource:
        resource_type, resource_id = resource.split(":", 1)
    else:
        resource_type, resource_id = None, resource

    return {
        "account_id": account_id or None,
        "arn_region": region or None,
        "service": service or None,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "parse_error": False,
    }


def classify_resource_ownership(
    tags: list[dict],
    arn: str,
    physical_resource_id: str,
    cdk_resource_lookup: dict[str, str],
    resource_stack_lookup: dict[str, str],
    stack_name_tag_key: str,
    unmatched_label: str,
) -> tuple[str, str | None, str | None]:
    """
    Given a resource's raw Tags, its ARN/physical resource ID, and the CDK
    signals from build_cdk_resource_lookup, returns (tool_name, stack_name, cdk_path).

    Logic (authoritative signals first, tag-based fallback last):
      1. If this resource (matched by full ARN OR bare physical ID -- CFN
         physical IDs come back as either depending on resource type) has
         a known CDK construct path (per-resource Metadata signal)
         -> "cdk", with the precise path.
      2. Else if CloudFormation's own resource listing (resource_stack_lookup,
         built from list_stack_resources across every stack in the
         region -- NOT from tags) says this resource belongs to a stack
         -> "cdk", with no path (see NOTE on folding). This is what catches
         resource types CloudFormation doesn't auto-tag with its
         stack-name tag (ECS services, ALBs/Listeners/TargetGroups, ACM
         certs, IAM roles/policies, etc.) -- they're still 100% CFN-owned,
         CFN just never told the Tagging API about it via a tag.
      3. FALLBACK -- only reached if CloudFormation's own listing didn't
         place this resource in any stack (e.g. list_stacks/list_stack_resources
         failed for that stack, or some other enumeration gap): fall back
         to the resource's own "aws:cloudformation:stack-name" tag, if
         present -> "cdk" (see NOTE on folding).
      4. Else -> unmatched_label (no CloudFormation involvement detected
         by any signal).

    NOTE: steps 2-3 fold plain/raw CloudFormation into "cdk" rather than a
    separate "cloudformation" bucket. This was a deliberate choice for
    this account, where essentially everything traces back to CDK and
    separating out a near-empty "raw CloudFormation" bucket wasn't useful.
    If you ever need to tell genuinely hand-written CloudFormation apart
    again, change those branches to `return "cloudformation", stack_name, None`.

    Safe against tags being an empty list or missing keys entirely.
    """
    tag_map = {t["Key"]: t["Value"] for t in (tags or [])}
    tag_stack_name = tag_map.get(stack_name_tag_key)

    cdk_path = cdk_resource_lookup.get(arn) or cdk_resource_lookup.get(physical_resource_id)
    if cdk_path:
        stack_name = resource_stack_lookup.get(arn) or resource_stack_lookup.get(physical_resource_id) or tag_stack_name
        return "cdk", stack_name, cdk_path

    authoritative_stack_name = resource_stack_lookup.get(arn) or resource_stack_lookup.get(physical_resource_id)
    if not authoritative_stack_name:
        # Versioned/indexed sibling of a tracked resource (e.g. an older
        # ECS task-definition revision, or an ElastiCache per-node
        # cluster under a CFN-managed replication group) -- retry against
        # the stable base identity.
        base_arn = _strip_versioned_suffix(arn)
        base_physical_id = _strip_versioned_suffix(physical_resource_id)
        authoritative_stack_name = (
            resource_stack_lookup.get(base_arn) or resource_stack_lookup.get(base_physical_id)
        )
    if authoritative_stack_name:
        return "cdk", authoritative_stack_name, None

    # Fallback: authoritative CFN resource listing didn't place this
    # resource anywhere -- fall back to its own stack-name tag, if any.
    if tag_stack_name:
        return "cdk", tag_stack_name, None

    return unmatched_label, None, None


def classify_resources(
    raw_resources: list[dict],
    config: dict,
    cdk_resource_lookup: dict[str, str],
    resource_stack_lookup: dict[str, str],
    scanned_region: str,
) -> list[dict]:
    """
    Orchestrates parse_arn + classify_resource_ownership across a batch
    of raw ResourceTagMappingList entries. Returns a flat list of fully
    populated output records matching our agreed schema.
    """
    stack_name_tag_key = config["signatures"]["cloudformation"]["tag_key"]
    unmatched_label = config.get("unmatched_label", "unknown")

    records = []
    for item in raw_resources:
        arn = item.get("ResourceARN", "")
        tags = item.get("Tags", [])  # defensive default — Tags can legally be []

        arn_fields = parse_arn(arn)
        tool, stack_name, cdk_path = classify_resource_ownership(
            tags, arn, arn_fields["resource_id"], cdk_resource_lookup,
            resource_stack_lookup, stack_name_tag_key, unmatched_label
        )

        # A resource whose ARN's own service is "cloudformation" IS a
        # CloudFormation stack resource itself (arn:aws:cloudformation:...
        # :stack/StackName/id). These typically don't carry a
        # stack-name tag pointing at themselves, so the tag-based checks
        # above miss them. Treat them as CDK per explicit request.
        if arn_fields["service"] == "cloudformation":
            tool = "cdk"

        is_cdk = tool == "cdk"

        records.append({
            "arn": arn,
            "account_id": arn_fields["account_id"],
            "arn_region": arn_fields["arn_region"],
            "scanned_region": scanned_region,
            "service": arn_fields["service"],
            "resource_type": arn_fields["resource_type"],
            "resource_id": arn_fields["resource_id"],
            "iac_tool": tool,
            "is_cdk": is_cdk,
            "cloudformation_stack": stack_name,
            "cdk_construct_path": cdk_path,
        })

    return records


def synthesize_missing_records(
    raw_resources: list[dict],
    all_stack_resources: list[dict],
    cdk_resource_lookup: dict[str, str],
) -> list[dict]:
    """
    Adds a record for every resource CloudFormation reports owning that
    NEVER appeared in the Tagging API results at all -- not mis-tagged,
    not mis-classified, just structurally invisible to get_resources().

    raw_resources must be the FULL, ALL-REGIONS Tagging API result set
    (not one region's slice) -- otherwise a global-service resource
    (e.g. a CloudFront distribution, which the Tagging API always
    reports under us-east-1 regardless of which region its owning stack
    actually lives in) looks "missing" everywhere except the one region
    it happens to be tagged under, and gets wrongly synthesized as a
    duplicate. scanned_region is likewise taken from each resource's own
    stack (all_stack_resources["stack_region"]), not a single fixed
    value, for the same reason.

    Confirmed cases in practice: IAM roles/policies, Route53 RecordSets,
    WAFv2 WebACLs (account/region-dependent), API Gateway REST API
    resources (RestApi/Resource/Method/Deployment/Stage/DomainName --
    the Tagging API only indexes v2 HTTP/WebSocket APIs), and
    Lambda::Permission (a sub-resource with no ARN of its own).
    classify_resources() can only classify what's in raw_resources, so
    these need to be added separately using CloudFormation's own
    knowledge instead of the Tagging API's.

    These synthesized rows have no real ARN (the resource was never
    indexed with one), so the "arn" field holds a clearly-marked
    placeholder instead of a real ARN -- don't mistake it for one.

    Skips AWS::CDK::Metadata: a template-only pseudo-resource with no
    underlying AWS resource, present in every CDK stack's template by
    design, and not what anyone doing an inventory audit is looking for.
    """
    covered_arns = {item.get("ResourceARN") for item in raw_resources}
    covered_resource_ids = {parse_arn(item.get("ResourceARN", ""))["resource_id"] for item in raw_resources}

    records = []
    seen_keys = set()  # (stack_name, physical_id) -- physical_id alone isn't
    # unique across stacks (e.g. two different stacks can each have an
    # API Gateway Stage physical ID of "prod")
    for res in all_stack_resources:
        physical_id = res["physical_id"]
        cfn_resource_type = res["cfn_resource_type"]
        stack_name = res["stack_name"]

        if cfn_resource_type == "AWS::CDK::Metadata":
            continue
        if physical_id in covered_arns or physical_id in covered_resource_ids:
            continue  # the Tagging API already returned this one
        key = (stack_name, physical_id)
        if key in seen_keys:
            continue  # already synthesized this exact (stack, resource) pair
        seen_keys.add(key)

        records.append({
            "arn": f"(no ARN in Tagging API — CFN-tracked only) {physical_id}",
            "account_id": None,
            "arn_region": None,
            "scanned_region": res["stack_region"],
            "service": None,
            "resource_type": cfn_resource_type,
            "resource_id": physical_id,
            "iac_tool": "cdk",
            "is_cdk": True,
            "cloudformation_stack": res["stack_name"],
            "cdk_construct_path": cdk_resource_lookup.get(physical_id),
        })

    return records


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

COLUMN_ORDER = [
    "arn",
    "account_id",
    "arn_region",
    "scanned_region",
    "service",
    "resource_type",
    "resource_id",
    "iac_tool",
    "is_cdk",
    "cloudformation_stack",
    "cdk_construct_path",
]

COLUMN_WIDTHS = {
    "arn": 70,
    "account_id": 14,
    "arn_region": 14,
    "scanned_region": 14,
    "service": 14,
    "resource_type": 18,
    "resource_id": 40,
    "iac_tool": 14,
    "is_cdk": 10,
    "cloudformation_stack": 30,
    "cdk_construct_path": 50,
}


def dedupe_records(records: list[dict]) -> list[dict]:
    """
    Merges duplicate rows for the same ARN into one. Duplicates happen
    for global/account-wide resources (e.g. AWS Chatbot configurations,
    some SNS topics) that the Tagging API returns under every region you
    scan, not just one. Without this step, the same resource could show
    up more than once in the output -- and, worse, with two different
    classifications if tag visibility differed slightly between calls
    (eventual consistency), landing it in BOTH the CDK and non-CDK sheets.

    Merge rule: if ANY occurrence of a given ARN was classified as CDK,
    the merged row is CDK. All regions the resource was seen in are
    combined into one comma-separated scanned_region value.
    """
    merged: dict[str, dict] = {}

    for record in records:
        arn = record["arn"]
        if arn not in merged:
            merged[arn] = dict(record)
            merged[arn]["_regions_seen"] = {record["scanned_region"]}
            continue

        existing = merged[arn]
        existing["_regions_seen"].add(record["scanned_region"])

        if record["is_cdk"] and not existing["is_cdk"]:
            existing["is_cdk"] = True
            existing["iac_tool"] = "cdk"

        if not existing.get("cloudformation_stack") and record.get("cloudformation_stack"):
            existing["cloudformation_stack"] = record["cloudformation_stack"]
        if not existing.get("cdk_construct_path") and record.get("cdk_construct_path"):
            existing["cdk_construct_path"] = record["cdk_construct_path"]

    deduped = []
    for record in merged.values():
        record["scanned_region"] = ", ".join(sorted(record.pop("_regions_seen")))
        deduped.append(record)

    return deduped


def write_output(records: list[dict], output_path: str) -> None:
    """
    Writes results to a single .xlsx workbook with two sheets:
    "CDK Managed" and "Non-CDK Managed". Column headers are clear,
    human-readable field names; column widths are set so nothing is
    truncated by default. No formulas are used, so there's nothing to
    recalculate — every cell is a plain written value.
    """
    df = pd.DataFrame(records, columns=COLUMN_ORDER)

    cdk_df = df[df["is_cdk"]].drop(columns=["is_cdk"])
    non_cdk_df = df[~df["is_cdk"]].drop(columns=["is_cdk"])

    with pd.ExcelWriter(output_path, engine="openpyxl") as writer:
        cdk_df.to_excel(writer, sheet_name="CDK Managed", index=False)
        non_cdk_df.to_excel(writer, sheet_name="Non-CDK Managed", index=False)

        for sheet_name in ("CDK Managed", "Non-CDK Managed"):
            worksheet = writer.sheets[sheet_name]

            # Bold, frozen header row so it's clear and stays visible on scroll.
            for cell in worksheet[1]:
                cell.font = cell.font.copy(bold=True)
            worksheet.freeze_panes = "A2"

            # Explicit column widths keyed by field name, so nothing renders
            # squished regardless of which sheet/order pandas wrote them in.
            for idx, col_name in enumerate(df.drop(columns=["is_cdk"]).columns, start=1):
                width = COLUMN_WIDTHS.get(col_name, 20)
                worksheet.column_dimensions[worksheet.cell(row=1, column=idx).column_letter].width = width

    print(f"\nWrote {len(cdk_df)} CDK-managed and {len(non_cdk_df)} non-CDK resources to {output_path}")


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def run(regions: list[str] | None = None, signatures_path: str = "signatures.yaml") -> list[dict]:
    """
    Runs the full scan across all (or specified) regions and returns a
    flat list of classified resource records. Written as a plain function
    that takes inputs and returns data — no printing-only side effects
    baked into the control flow — so it can later be reused from a CLI
    wrapper, a Lambda handler, or a test, without modification.
    """
    config = load_signatures(signatures_path)
    session = boto3.Session()

    target_regions = regions or get_active_regions(session)
    print(f"Scanning {len(target_regions)} region(s): {', '.join(target_regions)}\n")
    stack_name_tag_key = config["signatures"]["cloudformation"]["tag_key"]

    # --- Pass 1: build ONE global stack-membership lookup across every
    # region before classifying anything. This has to happen up front,
    # not per-region, because global AWS services (CloudFront
    # distributions being the clearest case) are always reported by the
    # Tagging API under a single fixed region (us-east-1) regardless of
    # which region their owning CloudFormation stack actually lives in.
    # Classifying a region's resources against only that region's own
    # stacks means a CloudFront distribution owned by a stack in
    # us-west-2 can never be matched while processing us-east-1's
    # results -- the us-east-1 CFN client has no idea that stack exists.
    per_region_raw: dict[str, list[dict]] = {}
    global_cdk_resource_lookup: dict[str, str] = {}
    global_resource_stack_lookup: dict[str, str] = {}
    global_all_stack_resources: list[dict] = []

    for region in target_regions:
        print(f"Scanning {region}...")
        raw_resources = get_resource_inventory(session, region)
        if not raw_resources:
            continue
        per_region_raw[region] = raw_resources

        # Authoritative: every live stack in the region, straight from
        # CloudFormation. Union in tag-referenced names too as a safety
        # net in case list_stacks ever misses something a tag caught.
        stack_names = get_all_stack_names(session, region)
        stack_names |= get_referenced_stack_names(raw_resources, stack_name_tag_key)
        cdk_resource_lookup, _cdk_stack_names, resource_stack_lookup, all_stack_resources = build_cdk_resource_lookup(
            session, region, stack_names
        )

        # setdefault, not update: first stack seen for a given physical
        # ID wins, so an accidental cross-region ID collision doesn't
        # silently reassign an already-resolved resource to a different
        # stack on a later region's pass.
        for key, value in cdk_resource_lookup.items():
            global_cdk_resource_lookup.setdefault(key, value)
        for key, value in resource_stack_lookup.items():
            global_resource_stack_lookup.setdefault(key, value)
        global_all_stack_resources.extend(all_stack_resources)

        print(f"  found {len(raw_resources)} resource(s) tagged in this region, across {len(stack_names)} stack(s) seen here")

    # --- Pass 2: classify every region's resources against the GLOBAL
    # lookup, then synthesize once for the account as a whole (using
    # every region's raw resources together as the "already covered"
    # set -- otherwise a global-service resource tagged under
    # us-east-1 looks "missing" while processing us-west-2 and gets
    # wrongly synthesized as a duplicate of itself).
    all_records = []
    for region, raw_resources in per_region_raw.items():
        records = classify_resources(
            raw_resources, config, global_cdk_resource_lookup, global_resource_stack_lookup,
            scanned_region=region
        )
        all_records.extend(records)
        cdk_count = sum(1 for r in records if r["is_cdk"])
        print(f"  {region}: {cdk_count}/{len(records)} classified CDK")

    all_raw_resources = [item for raw in per_region_raw.values() for item in raw]
    synthesized = synthesize_missing_records(all_raw_resources, global_all_stack_resources, global_cdk_resource_lookup)
    all_records.extend(synthesized)
    if synthesized:
        print(f"\n{len(synthesized)} resource(s) were never in the Tagging API at all -- added from CloudFormation's own resource listing")

    deduped_records = dedupe_records(all_records)
    duplicate_count = len(all_records) - len(deduped_records)
    if duplicate_count:
        print(f"\nMerged {duplicate_count} duplicate row(s) for globally-visible resources (e.g. Chatbot, SNS)")

    return deduped_records


def main():
    parser = argparse.ArgumentParser(
        description="Scan an AWS account and classify resources by IaC tool (CDK, CloudFormation, etc.)."
    )
    parser.add_argument(
        "--regions", nargs="+", default=None,
        help="Limit the scan to specific regions (default: all active regions on the account)."
    )
    parser.add_argument(
        "--config", default="signatures.yaml",
        help="Path to the signatures config file (default: signatures.yaml)."
    )
    parser.add_argument(
        "--output", default=None,
        help="Output .xlsx path (default: iac_fingerprint_<timestamp>.xlsx)."
    )
    args = parser.parse_args()

    output_path = args.output or f"iac_fingerprint_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.xlsx"

    try:
        records = run(regions=args.regions, signatures_path=args.config)
    except FileNotFoundError as e:
        print(f"Config error: {e}")
        sys.exit(1)
    except ClientError as e:
        print(f"AWS error while discovering regions: {e}")
        sys.exit(1)

    if not records:
        print("No resources found (or all regions were skipped). Nothing to write.")
        sys.exit(0)

    write_output(records, output_path)


if __name__ == "__main__":
    main()