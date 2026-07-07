# workloads/databases/policy/hcl/rds.rego
package main

# ── Parameters from config.yaml ─────────────────────────────────────────────
default_min_backup_days := 7
default_production_patterns := ["prd", "prod", "production"]

min_backup_days := data.config.rds.min_backup_retention_days {
    data.config.rds.min_backup_retention_days
}

min_backup_days := default_min_backup_days {
    not data.config.rds.min_backup_retention_days
}

production_patterns := data.config.production_patterns {
    data.config.production_patterns
}

production_patterns := default_production_patterns {
    not data.config.production_patterns
}

is_production(name) {
    pattern := production_patterns[_]
    contains(name, pattern)
}

# ── Rules ────────────────────────────────────────────────────────────────────

# RDS must have multi-AZ in production
deny[msg] {
    resource := input.resource.aws_db_instance[name]
    is_production(name)
    not resource.multi_az
    msg := sprintf("RDS instance '%s' must have Multi-AZ enabled in production", [name])
}

# RDS must have backup retention >= configured minimum
deny[msg] {
    resource := input.resource.aws_db_instance[name]
    resource.backup_retention_period < min_backup_days
    msg := sprintf("RDS instance '%s' must have backup retention >= %d days (current: %d)", [name, min_backup_days, resource.backup_retention_period])
}

# RDS must not be publicly accessible
deny[msg] {
    resource := input.resource.aws_db_instance[name]
    resource.publicly_accessible == true
    msg := sprintf("RDS instance '%s' must not be publicly accessible", [name])
}

# RDS instance class must be in allowed list (if configured)
warn[msg] {
    data.config.rds.allowed_instance_classes
    resource := input.resource.aws_db_instance[name]
    allowed := {c | c := data.config.rds.allowed_instance_classes[_]}
    not resource.instance_class in allowed
    msg := sprintf("RDS instance '%s' uses non-standard instance class '%s'", [name, resource.instance_class])
}
