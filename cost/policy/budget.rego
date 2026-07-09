# cost/policy/budget.rego
# Budget enforcement policies for infrastructure cost governance
package main

import rego.v1

# ── Budget Limits ────────────────────────────────────────────────────────────

# Deny if total monthly cost exceeds maximum budget
deny contains msg if {
    data.config.budget.max_monthly_total
    input.summary.total_monthly_cost > data.config.budget.max_monthly_total
    msg := sprintf("Total monthly cost $%.2f exceeds budget limit $%.2f", [
        input.summary.total_monthly_cost,
        data.config.budget.max_monthly_total,
    ])
}

# Deny if cost increase exceeds maximum allowed
deny contains msg if {
    data.config.budget.max_monthly_increase
    input.summary.total_running_monthly_cost
    input.summary.total_monthly_cost > input.summary.total_running_monthly_cost
    increase := input.summary.total_monthly_cost - input.summary.total_running_monthly_cost
    increase > data.config.budget.max_monthly_increase
    msg := sprintf("Cost increase $%.2f exceeds maximum allowed $%.2f", [
        increase, data.config.budget.max_monthly_increase,
    ])
}

# Warn if approaching budget limit
warn contains msg if {
    data.config.budget.warn_monthly_total
    input.summary.total_monthly_cost > data.config.budget.warn_monthly_total
    input.summary.total_monthly_cost <= data.config.budget.max_monthly_total
    msg := sprintf("Monthly cost $%.2f approaching budget limit (warn threshold: $%.2f)", [
        input.summary.total_monthly_cost,
        data.config.budget.warn_monthly_total,
    ])
}

# ── Per-Service Limits ───────────────────────────────────────────────────────

# Deny if any single service exceeds its budget
deny contains msg if {
    data.config.services.max_per_service
    service := input.cost_by_service[service_name]
    limit := data.config.services.max_per_service[service_name]
    service > limit
    msg := sprintf("Service '%s' cost $%.2f exceeds limit $%.2f/month", [
        service_name, service, limit,
    ])
}
