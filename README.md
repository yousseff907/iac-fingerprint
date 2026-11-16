# iac-fingerprint

Scans an AWS account across every active region, inventories its resources, and works out which ones were deployed through AWS CDK / CloudFormation and which weren't. The result is an Excel workbook with two sheets, **CDK Managed** and **Non-CDK Managed**, so you can see at a glance what in the account sits outside infrastructure-as-code.

## Requirements

- Python 3.11 (see `.python-version`)
- AWS credentials that boto3 can find (environment variables, `~/.aws/credentials`, SSO profile, instance role, etc.)
- Read-only IAM permissions:
  - `ec2:DescribeRegions`
  - `tag:GetResources`
  - `cloudformation:ListStacks`
  - `cloudformation:DescribeStacks`
  - `cloudformation:ListStackResources`
  - `cloudformation:GetTemplate`

The tool makes no write calls.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
# Scan every active region in the account
python scan.py

# Limit to specific regions
python scan.py --regions us-east-1 us-west-2

# Pick the output file name
python scan.py --output my_inventory.xlsx

# Use a different signatures file
python scan.py --config path/to/signatures.yaml
```

To scan with a specific AWS profile, set it in the environment:

```bash
AWS_PROFILE=my-profile python scan.py
```

| Flag | Default | Description |
| --- | --- | --- |
| `--regions` | all active regions | One or more regions to scan |
| `--output` | `iac_fingerprint_<UTC timestamp>.xlsx` | Path of the workbook to write |
| `--config` | `signatures.yaml` | Path of the detection config |

## Output

The workbook has two sheets with the same columns:

| Column | Meaning |
| --- | --- |
| `arn` | Resource ARN (or a placeholder, see below) |
| `account_id` | Account ID from the ARN |
| `arn_region` | Region from the ARN (empty for global services like S3 and IAM) |
| `scanned_region` | Region(s) the resource was found in, comma-separated if it showed up in several |
| `service` | AWS service from the ARN |
| `resource_type` | Resource type from the ARN, or the CloudFormation type for synthesized rows |
| `resource_id` | Resource identifier |
| `iac_tool` | `cdk` or `unknown` |
| `cloudformation_stack` | Owning stack, if any |
| `cdk_construct_path` | CDK construct path, when the template still carries `aws:cdk:path` metadata |

Rows whose `arn` starts with `(no ARN in Tagging API — CFN-tracked only)` are resources CloudFormation reports owning that the Tagging API never returns (IAM roles and policies, Route53 record sets, API Gateway REST API resources, Lambda permissions, and so on). They are added from CloudFormation's own resource listing so the inventory is complete.

## How it works

1. **Discover regions** with `ec2:DescribeRegions`, unless `--regions` was given.
2. **Inventory resources** in each region with the Resource Groups Tagging API (`tag:GetResources`).
3. **Map stacks to resources.** For every live CloudFormation stack in each region, the scanner records:
   - which physical resources the stack owns (`ListStackResources`),
   - whether the stack was synthesized by CDK (it has a `BootstrapVersion` parameter),
   - the `aws:cdk:path` construct path of each resource, when the template metadata hasn't been stripped.

   These lookups are merged across all regions before anything is classified, because global services such as CloudFront are reported under `us-east-1` even when their stack lives elsewhere.
4. **Classify** each resource, strongest signal first:
   1. it has a known CDK construct path, so it's `cdk`
   2. CloudFormation lists it as part of a stack, so it's `cdk`
   3. it carries an `aws:cloudformation:stack-name` tag, so it's `cdk`
   4. otherwise it's `unknown`

   Versioned siblings of stack resources (older ECS task definition revisions, ElastiCache per-node clusters, RDS automated snapshots) are matched back to their base resource. CloudFormation stacks themselves and the `CDKToolkit` bootstrap stack are counted as CDK.
5. **Fill gaps** by adding rows for stack resources the Tagging API never returned.
6. **Deduplicate** resources that appear in several regions (Chatbot configurations, some SNS topics). If any occurrence was classified CDK, the merged row is CDK.
7. **Write** the workbook.

Regions that are disabled, unreachable, or time out are skipped with a warning; each AWS call fails after about 15 seconds instead of hanging.

## Configuration

`signatures.yaml` holds the detection settings:

- `signatures.cloudformation.tag_key`: the tag that carries the CloudFormation stack name. You shouldn't need to change it.
- `unmatched_label`: the label for resources with no CloudFormation involvement (default `unknown`). It says "unknown" rather than "manual" because a resource could come from Terraform or another tool that doesn't tag in a way the scanner recognizes.

## Known limitations

- **Plain CloudFormation is counted as CDK.** Any resource owned by a CloudFormation stack lands in the CDK sheet, whether or not the stack came from CDK. To split them out again, change the fallback branches in `classify_resource_ownership` in `scan.py` to return `"cloudformation"`.
- **Terraform, Pulumi, and other tools aren't detected.** Their resources appear as `unknown`.
- **Untagged, non-CloudFormation resources may be missed.** The inventory relies on the Tagging API, which only indexes some resource types.
- **Construct paths depend on template metadata.** If your CDK apps strip `aws:cdk:path` before deploying, `cdk_construct_path` will be empty, though the resources are still classified correctly.
