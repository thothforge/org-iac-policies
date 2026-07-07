# workloads/databases/policy/rds.rego
package main

import rego.v1

# RDS must have multi-AZ in production
deny contains msg if {
    resource := input.resource.aws_db_instance[name]
    contains(name, "prd")
    not resource.multi_az
    msg := sprintf("RDS instance '%s' must have Multi-AZ enabled in production", [name])
}

# RDS must have backup retention >= 7 days
deny contains msg if {
    resource := input.resource.aws_db_instance[name]
    resource.backup_retention_period < 7
    msg := sprintf("RDS instance '%s' must have backup retention >= 7 days (current: %d)", [name, resource.backup_retention_period])
}

# RDS must not be publicly accessible
deny contains msg if {
    resource := input.resource.aws_db_instance[name]
    resource.publicly_accessible == true
    msg := sprintf("RDS instance '%s' must not be publicly accessible", [name])
}
