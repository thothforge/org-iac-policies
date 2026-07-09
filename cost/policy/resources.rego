# cost/policy/resources.rego
# Resource-level cost policies (instance types, expensive resources)
package main

import rego.v1

# ── Expensive Resources ──────────────────────────────────────────────────────

# Warn on individual resources exceeding cost threshold
warn contains msg if {
    data.budget.expensive_resource_threshold
    resource := input.resources[_]
    resource.monthly_cost > data.budget.expensive_resource_threshold
    msg := sprintf("Resource '%s' (%s) costs $%.2f/month — review for optimization", [
        resource.address, resource.service, resource.monthly_cost,
    ])
}

# ── Blocked Instance Types ───────────────────────────────────────────────────

# Deny blocked instance types
deny contains msg if {
    data.instance_types.blocked
    resource := input.resources[_]
    resource.type == "aws_instance"
    instance_type := resource.details.instance_type
    instance_type in data.instance_types.blocked
    msg := sprintf("Instance type '%s' is blocked by cost policy (resource: %s)", [
        instance_type, resource.address,
    ])
}

# Deny blocked RDS instance classes
deny contains msg if {
    data.instance_types.blocked
    resource := input.resources[_]
    resource.type in ["aws_db_instance", "aws_rds_cluster_instance"]
    instance_class := resource.details.instance_class
    instance_class in data.instance_types.blocked
    msg := sprintf("RDS instance class '%s' is blocked by cost policy (resource: %s)", [
        instance_class, resource.address,
    ])
}

# ── Cost Efficiency ──────────────────────────────────────────────────────────

# Warn on low-confidence estimates
warn contains msg if {
    resource := input.resources[_]
    resource.confidence == "low"
    resource.monthly_cost > 50
    msg := sprintf("Resource '%s' has low confidence estimate ($%.2f/month) — verify manually", [
        resource.address, resource.monthly_cost,
    ])
}

# Warn when too many resources have zero cost (may indicate missing pricing)
warn contains msg if {
    total := count(input.resources)
    total > 0
    zero_cost := count([r | r := input.resources[_]; r.monthly_cost == 0])
    ratio := zero_cost / total
    ratio > 0.8
    msg := sprintf("%.0f%% of resources (%d/%d) have $0 cost — pricing data may be incomplete", [
        ratio * 100, zero_cost, total,
    ])
}
