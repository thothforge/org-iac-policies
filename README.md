# Organization IaC Policies

[![ThothCTL Compatible](https://img.shields.io/badge/ThothCTL-Policy%20Repository-blue)](https://github.com/thothforge/thothctl)

Organization-level policy repository for Infrastructure as Code governance. This repository defines the security, compliance, naming, and architectural rules enforced across all IaC projects via [ThothCTL](https://github.com/thothforge/thothctl).

## Structure

```
org-iac-policies/
├── rules/                        # ThothCTL project structure rules
│   ├── base.toml                 # All project types (mandatory)
│   ├── terraform-terragrunt.toml # Terraform+Terragrunt projects
│   ├── terraform_module.toml     # Terraform modules
│   └── cdkv2.toml                # CDK v2 projects
├── shared/policy/                # OPA/Rego policies (all projects)
│   ├── hcl/                      # Terraform/OpenTofu/HCL input structure
│   │   ├── naming.rego
│   │   ├── tagging.rego
│   │   └── regions.rego
│   └── cloudformation/           # CloudFormation JSON input structure
│       ├── naming.rego
│       ├── tagging.rego
│       └── regions.rego
├── compliance/
│   ├── features/                 # Terraform-compliance BDD scenarios
│   │   ├── encryption.feature
│   │   ├── tagging.feature
│   │   └── networking.feature
│   └── soc2/policy/
│       ├── hcl/                  # SOC2 policies for HCL
│       └── cloudformation/       # SOC2 policies for CloudFormation
├── domains/                      # Business domain policies
│   └── */policy/{hcl,cloudformation}/
├── workloads/                    # Workload-type policies
│   └── */policy/{hcl,cloudformation}/
├── layers/                       # Infrastructure layer policies
│   └── */policy/{hcl,cloudformation}/
└── README.md
```

## Multi-IaC Support

Policies are organized by **input format** to support both Terraform/HCL and CloudFormation templates:

| Directory | Input Structure | Use With |
|-----------|----------------|----------|
| `*/policy/hcl/` | `input.resource.aws_*[name]` | Terraform, OpenTofu, Terragrunt (via conftest) |
| `*/policy/cloudformation/` | `input.Resources[name].Properties` | AWS CloudFormation, SAM, CDK (synth output) |

### Key Differences

| Aspect | HCL Policies | CloudFormation Policies |
|--------|--------------|------------------------|
| Root key | `input.resource` | `input.Resources` |
| Resource type | `aws_s3_bucket` (snake_case) | `AWS::S3::Bucket` (colon-separated) |
| Properties | `storage_encrypted` | `StorageEncrypted` (PascalCase) |
| Tags | `{"Key": "value"}` map | `[{"Key": "k", "Value": "v"}]` array |

## Quick Start

### Set the Environment Variable

```bash
export THOTH_ORG_POLICY=https://github.com/thothforge/org-iac-policies.git
```

### Run All Governance Checks

```bash
# Project structure enforcement (mandatory rules cannot be overridden)
thothctl check project iac --enforcement hard

# OPA/Rego policy scan (shared + domain policies)
thothctl scan iac -t opa

# BDD compliance scenarios against terraform plans
thothctl scan iac -t terraform-compliance

# All security scanners + org policies
thothctl scan iac -t checkov -t trivy -t opa -t terraform-compliance --enforcement hard
```

## What Each Folder Does

| Folder | Tool | Purpose |
|--------|------|---------|
| `rules/` | `thothctl check project iac` | Enforce project structure (files, folders, naming) |
| `shared/policy/` | `thothctl scan iac -t opa` | OPA/Rego security policies for all projects |
| `compliance/features/` | `thothctl scan iac -t terraform-compliance` | BDD scenarios against tfplan.json |
| `domains/*/policy/` | `thothctl scan iac -t opa` | Domain-specific Rego policies |
| `layers/*/policy/` | `thothctl scan iac -t opa` | Layer-specific Rego policies |
| `workloads/*/policy/` | `thothctl scan iac -t opa` | Workload-specific Rego policies |

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
thothctl scan iac -t terraform-compliance -o "features_dir=https://github.com/thothforge/org-iac-policies.git//compliance/features"

# Or via THOTH_ORG_POLICY (auto-discovers compliance/features/)
export THOTH_ORG_POLICY=https://github.com/thothforge/org-iac-policies.git
thothctl scan iac -t terraform-compliance
```

## OPA/Rego Policies (`shared/policy/`)

Policies use [OPA Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) and are split by input format:

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

### Usage

```bash
# Terraform/HCL — uses hcl/ policies
thothctl scan iac -t opa -o "policy_dir=shared/policy/hcl"

# CloudFormation — uses cloudformation/ policies
conftest test template.yaml --policy shared/policy/cloudformation

# Auto-discovers from THOTH_ORG_POLICY (defaults to hcl/)
export THOTH_ORG_POLICY=https://github.com/thothforge/org-iac-policies.git
thothctl scan iac -t opa
```

## CI/CD Integration

```yaml
# GitHub Actions
name: IaC Governance

on: [pull_request]

jobs:
  compliance:
    runs-on: ubuntu-latest
    env:
      THOTH_ORG_POLICY: https://github.com/thothforge/org-iac-policies.git@v1.0
    steps:
      - uses: actions/checkout@v4
      - run: pip install thothctl terraform-compliance
      
      - name: Project structure check
        run: thothctl check project iac --enforcement hard
      
      - name: Security scan
        run: thothctl scan iac -t checkov -t trivy -t opa -t terraform-compliance --enforcement hard --post-to-pr
```

## Policy Resolution Order (OPA)

1. `shared/policy/*.rego` — Always applied
2. `layers/<layer>/policy/*.rego` — Matches project layer
3. `workloads/<workload>/policy/*.rego` — Matches workload type
4. `domains/<domain>/policy/*.rego` — Matches business domain
5. `compliance/<framework>/policy/*.rego` — Per compliance framework

## Related

- [ThothCTL](https://github.com/thothforge/thothctl)
- [ThothCTL Scan Docs](https://thothforge.github.io/thothctl/framework/commands/scan/scan_iac/)
- [OPA/Rego Reference](https://www.openpolicyagent.org/docs/latest/policy-reference/)
- [Terraform-compliance](https://terraform-compliance.com/)
- [Conftest](https://www.conftest.dev/)

## License

MIT
