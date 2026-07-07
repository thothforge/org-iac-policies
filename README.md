# Organization IaC Policies

[![ThothCTL Compatible](https://img.shields.io/badge/ThothCTL-Policy%20Repository-blue)](https://github.com/thothforge/thothctl)

Organization-level policy repository for Infrastructure as Code governance. This repository defines the security, compliance, naming, and architectural rules enforced across all IaC projects via [ThothCTL](https://github.com/thothforge/thothctl).

## Structure

```
org-iac-policies/
├── rules/                              # ThothCTL project structure rules
│   ├── base.toml                       # All project types (mandatory)
│   ├── terraform-terragrunt.toml       # Terraform+Terragrunt projects
│   ├── terraform_module.toml           # Terraform modules
│   └── cdkv2.toml                      # CDK v2 projects
├── shared/policy/                      # Cross-project OPA/Rego policies
│   ├── hcl/                            # Terraform/OpenTofu input
│   │   ├── naming.rego
│   │   ├── tagging.rego
│   │   └── regions.rego
│   └── cloudformation/                 # CloudFormation/SAM/CDK input
│       ├── naming.rego
│       ├── tagging.rego
│       └── regions.rego
├── compliance/
│   ├── features/                       # Terraform-compliance BDD scenarios
│   │   ├── encryption.feature
│   │   ├── tagging.feature
│   │   └── networking.feature
│   └── soc2/policy/
│       ├── hcl/soc2_controls.rego
│       └── cloudformation/soc2_controls.rego
├── layers/                             # Infrastructure layer policies
│   ├── networking/policy/{hcl,cloudformation}/vpc.rego
│   └── security/policy/{hcl,cloudformation}/{encryption,iam}.rego
├── workloads/                          # Workload-type policies
│   ├── containers/policy/{hcl,cloudformation}/ecs.rego
│   ├── databases/policy/{hcl,cloudformation}/rds.rego
│   └── serverless/policy/{hcl,cloudformation}/lambda.rego
├── domains/                            # Business domain policies
│   ├── fintech/policy/{hcl,cloudformation}/data.rego
│   └── platform/policy/{hcl,cloudformation}/modules.rego
├── configs/                            # ThothCTL configuration
├── templates/                          # Project templates
└── shared/
    ├── .driftpolicy                    # Drift detection policy
    └── ai_decision_config.yaml         # AI auto-decision thresholds
```

## Multi-IaC Support

Policies are organized by **input format** to support multiple IaC tools:

| Directory | Input Structure | Use With |
|-----------|----------------|----------|
| `*/policy/hcl/` | `input.resource.aws_*[name]` | Terraform, OpenTofu, Terragrunt (via conftest) |
| `*/policy/cloudformation/` | `input.Resources[name].Properties` | AWS CloudFormation, SAM, CDK synth output |

### Input Format Differences

| Aspect | HCL Policies | CloudFormation Policies |
|--------|--------------|------------------------|
| Root key | `input.resource` | `input.Resources` |
| Resource type | `aws_s3_bucket` (snake_case) | `AWS::S3::Bucket` (colon-separated) |
| Resource access | `input.resource.aws_s3_bucket[name]` | `input.Resources[name].Properties` |
| Properties | `storage_encrypted` | `StorageEncrypted` (PascalCase) |
| Tags | `{"Key": "value"}` map | `[{"Key": "k", "Value": "v"}]` array |
| Booleans | `true` / `false` | `true` / `false` (or `"true"` string) |

## Quick Start

### Set the Environment Variable

```bash
export THOTH_ORG_POLICY=https://github.com/thothforge/org-iac-policies.git
```

### Terraform/OpenTofu Projects

```bash
# Structure enforcement
thothctl check project iac --enforcement hard

# OPA policy scan (auto-selects hcl/ policies)
thothctl scan iac -t opa

# BDD compliance scenarios
thothctl scan iac -t terraform-compliance

# Full DevSecOps pipeline
thothctl scan iac -t checkov -t trivy -t opa -t terraform-compliance --enforcement hard
```

### CloudFormation/SAM/CDK Projects

```bash
# Scan a CloudFormation template directly with conftest
conftest test template.yaml --policy shared/policy/cloudformation

# Scan CDK synth output
cdk synth > template.json
conftest test template.json --policy shared/policy/cloudformation

# Combine multiple policy directories
conftest test template.yaml \
  --policy shared/policy/cloudformation \
  --policy layers/security/policy/cloudformation \
  --policy workloads/databases/policy/cloudformation
```

## Policy Catalog

### Shared Policies (All Projects)

| Policy | Rule | Severity |
|--------|------|----------|
| `tagging.rego` | Required tags: Environment, Owner, CostCenter, ManagedBy | deny |
| `naming.rego` | Resource naming convention enforcement | warn |
| `regions.rego` | Restrict deployments to approved regions | deny |

### Security Layer

| Policy | Rule | Severity |
|--------|------|----------|
| `encryption.rego` | S3 encryption, RDS storage encryption, EBS encryption | deny |
| `iam.rego` | No wildcard `*` in IAM actions/resources | deny |

### Networking Layer

| Policy | Rule | Severity |
|--------|------|----------|
| `vpc.rego` | VPC flow logs required | deny |
| `vpc.rego` | No unrestricted ingress (0.0.0.0/0 all ports) | deny |
| `vpc.rego` | No public subnets in production | deny |

### Workloads — Databases

| Policy | Rule | Severity |
|--------|------|----------|
| `rds.rego` | Multi-AZ required in production | deny |
| `rds.rego` | Backup retention ≥ 7 days | deny |
| `rds.rego` | No publicly accessible instances | deny |

### Workloads — Serverless

| Policy | Rule | Severity |
|--------|------|----------|
| `lambda.rego` | Explicit timeout configured | warn |
| `lambda.rego` | Dead letter queue configured | warn |

### Workloads — Containers

| Policy | Rule | Severity |
|--------|------|----------|
| `ecs.rego` | No root user in containers | deny |
| `ecs.rego` | Logging driver required | deny |
| `ecs.rego` | Minimum 2 tasks in production | warn |

### Compliance — SOC2

| Policy | Rule | Control |
|--------|------|---------|
| `soc2_controls.rego` | No public S3 buckets | CC6.1 |
| `soc2_controls.rego` | Encryption at rest required | CC6.6 |
| `soc2_controls.rego` | CloudTrail enabled | CC7.2 |

### Domains — Fintech

| Policy | Rule | Severity |
|--------|------|----------|
| `data.rego` | KMS-only encryption for sensitive data | deny |
| `data.rego` | Approved replication regions | deny |
| `data.rego` | Point-in-time recovery for DynamoDB | deny |

### Domains — Platform

| Policy | Rule | Severity |
|--------|------|----------|
| `modules.rego` | Versioned module/stack sources | deny |
| `modules.rego` | Ownership tags on all resources | warn |

## Project Structure Rules (`rules/`)

Rules enforce that projects follow organizational standards. Projects **cannot override** mandatory rules.

### `rules/base.toml` — All Projects

```toml
[metadata]
name = "ThothForge Infrastructure Standards"
version = "1.0.0"
enforcement = "mandatory"

[project_structure]
root_files = [".gitignore", "README.md", ".thothcf.toml", ".pre-commit-config.yaml"]

[[project_structure.folders]]
name = "docs"
mandatory = true
enforcement = "mandatory"

[rules.naming]
pattern = "^[a-z][a-z0-9-]*$"
enforcement = "mandatory"

[rules.tagging]
required_tags = ["Environment", "Owner", "Project"]
enforcement = "mandatory"
```

### Enforcement Levels

| Level | Behavior | Can Project Override? |
|-------|----------|---------------------|
| `mandatory` | Fails pipeline with `--enforcement hard` | ❌ No |
| `recommended` | Warning | ⚠️ Can opt-out |
| `informational` | Report only | ✅ Yes |

## Terraform-compliance Features (`compliance/features/`)

BDD scenarios evaluated against `tfplan.json`:

```gherkin
Feature: Ensure encryption is enabled for all storage resources

  Scenario: S3 buckets must have encryption
    Given I have aws_s3_bucket defined
    Then it must have server_side_encryption_configuration
```

### Usage

```bash
# Direct reference with //subpath
thothctl scan iac -t terraform-compliance \
  -o "features_dir=https://github.com/thothforge/org-iac-policies.git//compliance/features"

# Or via THOTH_ORG_POLICY (auto-discovers compliance/features/)
export THOTH_ORG_POLICY=https://github.com/thothforge/org-iac-policies.git
thothctl scan iac -t terraform-compliance
```

## OPA/Rego Policy Examples

### HCL (Terraform/OpenTofu)

```rego
# shared/policy/hcl/tagging.rego
package main

required_tags := {"Environment", "Owner", "CostCenter", "ManagedBy"}

deny[msg] {
    resource := input.resource[type][name]
    tags := object.get(resource, "tags", {})
    missing := required_tags - {key | tags[key]}
    count(missing) > 0
    msg := sprintf("%s.%s is missing required tags: %v", [type, name, missing])
}
```

### CloudFormation

```rego
# shared/policy/cloudformation/tagging.rego
package main

required_tags := {"Environment", "Owner", "CostCenter", "ManagedBy"}

deny[msg] {
    resource := input.Resources[name]
    tags := object.get(resource.Properties, "Tags", [])
    tag_keys := {tag.Key | tag := tags[_]}
    missing := required_tags - tag_keys
    count(missing) > 0
    msg := sprintf("%s (%s) is missing required tags: %v", [name, resource.Type, missing])
}
```

## CI/CD Integration

### GitHub Actions — Terraform

```yaml
name: IaC Governance

on: [pull_request]

jobs:
  compliance:
    runs-on: ubuntu-latest
    env:
      THOTH_ORG_POLICY: https://github.com/thothforge/org-iac-policies.git@main
    steps:
      - uses: actions/checkout@v4
      - run: pip install thothctl terraform-compliance

      - name: Project structure check
        run: thothctl check project iac --enforcement hard

      - name: Security scan
        run: thothctl scan iac -t checkov -t trivy -t opa -t terraform-compliance --enforcement hard --post-to-pr
```

### GitHub Actions — CloudFormation

```yaml
name: CFN Policy Check

on: [pull_request]

jobs:
  policy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install conftest
        run: |
          curl -Lo conftest.tar.gz https://github.com/open-policy-agent/conftest/releases/latest/download/conftest_*_Linux_x86_64.tar.gz
          tar xzf conftest.tar.gz && sudo mv conftest /usr/local/bin/

      - name: Clone policies
        run: git clone https://github.com/thothforge/org-iac-policies.git /tmp/policies

      - name: Validate CloudFormation templates
        run: |
          conftest test templates/*.yaml \
            --policy /tmp/policies/shared/policy/cloudformation \
            --policy /tmp/policies/layers/security/policy/cloudformation \
            --policy /tmp/policies/compliance/soc2/policy/cloudformation
```

## Policy Resolution Order (OPA)

When using `thothctl scan iac -t opa`, policies are resolved in this order:

1. `shared/policy/hcl/*.rego` — Always applied
2. `layers/<layer>/policy/hcl/*.rego` — Matches project layer
3. `workloads/<workload>/policy/hcl/*.rego` — Matches workload type
4. `domains/<domain>/policy/hcl/*.rego` — Matches business domain
5. `compliance/<framework>/policy/hcl/*.rego` — Per compliance framework

## Policy Parameterization (config.yaml)

Policies use `config.yaml` files to externalize parameters, enabling scalability across teams, environments, and domains without duplicating Rego code.

### How It Works

Place a `config.yaml` alongside your `.rego` files. ThothCTL's OPA scanner auto-converts it to JSON and passes it as `--data` to conftest. Policies access values via `data.config.*`.

```
shared/policy/hcl/
├── config.yaml       ← Parameters (YAML)
├── tagging.rego      ← References data.config.required_tags
├── regions.rego      ← References data.config.allowed_regions
└── naming.rego       ← References data.config.naming_pattern
```

### config.yaml Example

```yaml
# Organization-wide policy parameters
required_tags:
  - Environment
  - Owner
  - CostCenter
  - ManagedBy

allowed_regions:
  - us-east-1
  - us-east-2
  - us-west-2
  - eu-west-1

naming_pattern: "^(dev|stg|prd)-[a-z]+-[a-z0-9-]+$"

production_patterns:
  - "prd"
  - "prod"

rds:
  min_backup_retention_days: 7
  require_multi_az_in_prod: true
  allowed_instance_classes:
    - db.t3.medium
    - db.r5.large
    - db.r6g.large
```

### Rego Policy Referencing Parameters

```rego
package main

# Load from config.yaml, with sensible defaults as fallback
default_required_tags := {"Environment", "Owner"}

required_tags := {t | t := data.config.required_tags[_]} {
    data.config.required_tags
}

required_tags := default_required_tags {
    not data.config.required_tags
}

deny[msg] {
    resource := input.resource[type][name]
    tags := object.get(resource, "tags", {})
    missing := required_tags - {key | tags[key]}
    count(missing) > 0
    msg := sprintf("%s.%s is missing required tags: %v", [type, name, missing])
}
```

### Override per Environment/Team

Projects can override organization defaults by placing their own `config.yaml` in their local `policy/` directory:

```yaml
# my-project/policy/config.yaml — overrides org defaults
required_tags:
  - Environment
  - Owner
  - CostCenter
  - ManagedBy
  - DataClassification    # Extra tag for this team

allowed_regions:
  - eu-west-1             # This team only deploys to EU
  - eu-central-1

rds:
  min_backup_retention_days: 14  # Stricter for this project
```

### Benefits

| Before (hardcoded) | After (parameterized) |
|--------------------|-----------------------|
| Edit Rego to change a tag | Edit YAML, no Rego changes |
| Duplicate policies per team | One policy, many configs |
| Review Rego PRs for simple value changes | YAML changes are self-evident |
| Can't override per-project | Projects override with local config.yaml |

## Writing New Policies

When adding a new policy, create both HCL and CloudFormation versions:

```bash
# 1. Write the HCL version
vim layers/security/policy/hcl/my_check.rego

# 2. Write the CloudFormation equivalent
vim layers/security/policy/cloudformation/my_check.rego

# 3. Test locally
conftest test my_project/*.tf --policy layers/security/policy/hcl
conftest test template.yaml --policy layers/security/policy/cloudformation
```

## Related

- [ThothCTL](https://github.com/thothforge/thothctl) — AI-Powered Infrastructure Lifecycle CLI
- [ThothCTL Scan Docs](https://thothforge.github.io/thothctl/framework/commands/scan/scan_iac/)
- [OPA/Rego Reference](https://www.openpolicyagent.org/docs/latest/policy-reference/)
- [Conftest](https://www.conftest.dev/)
- [Terraform-compliance](https://terraform-compliance.com/)

## License

MIT
