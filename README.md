# Organization IaC Policies

[![ThothCTL Compatible](https://img.shields.io/badge/ThothCTL-Policy%20Repository-blue)](https://github.com/thothforge/thothctl)

Organization-level policy repository for Infrastructure as Code governance. This repository defines the security, compliance, naming, and architectural rules enforced across all IaC projects via [ThothCTL](https://github.com/thothforge/thothctl).

## Structure

```
org-iac-policies/
├── domains/          # Business domain policies
├── workloads/        # Workload-type policies (containers, serverless, databases)
├── layers/           # Infrastructure layer policies (networking, security, observability)
├── compliance/       # Compliance framework mappings (SOC2, CIS, ISO27001)
└── shared/           # Policies applied to ALL projects
```

## Quick Start

### 1. Configure in your Space

```bash
thothctl init space --policy-repo https://github.com/your-org/org-iac-policies.git
```

Or set the environment variable:

```bash
export THOTH_POLICY_REPO=https://github.com/your-org/org-iac-policies.git
```

### 2. Declare governance selectors in your project

```toml
# .thothcf.toml
[thothcf]
project_id = "my-service"
project_type = "terraform-terragrunt"

[thothcf.governance]
domain = "platform"
workload = "containers"
layer = "networking"
compliance = ["soc2", "cis-aws"]
```

### 3. Evaluate policies

```bash
thothctl scan iac --tools opa
# Evaluates: shared + layer/networking + workload/containers + domain/platform
```

## Policy Resolution Order

1. `shared/policy/*.rego` — Always applied
2. `layers/<layer>/policy/*.rego` — Matches project layer
3. `workloads/<workload>/policy/*.rego` — Matches workload type
4. `domains/<domain>/policy/*.rego` — Matches business domain
5. `compliance/<framework>/policy/*.rego` — Per compliance framework
6. Project-local `policy/*.rego` — Project-specific overrides

## Writing Policies

Policies use [OPA Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) language:

```rego
# shared/policy/tagging.rego
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

## Related

- [ThothCTL Policy as Code Documentation](https://thothforge.github.io/thothctl/framework/policy_as_code/)
- [OPA/Rego Language Reference](https://www.openpolicyagent.org/docs/latest/policy-reference/)
- [Conftest](https://www.conftest.dev/)

## License

MIT
