package main

# RDS must have multi-AZ in production
deny[msg] {
    resource := input.Resources[name]
    resource.Type == "AWS::RDS::DBInstance"
    contains(lower(name), "prd")
    not resource.Properties.MultiAZ
    msg := sprintf("RDS instance '%s' must have Multi-AZ enabled in production", [name])
}

# RDS must have backup retention >= 7 days
deny[msg] {
    resource := input.Resources[name]
    resource.Type == "AWS::RDS::DBInstance"
    resource.Properties.BackupRetentionPeriod < 7
    msg := sprintf("RDS instance '%s' must have backup retention >= 7 days (current: %d)", [name, resource.Properties.BackupRetentionPeriod])
}

# RDS must not be publicly accessible
deny[msg] {
    resource := input.Resources[name]
    resource.Type == "AWS::RDS::DBInstance"
    resource.Properties.PubliclyAccessible == true
    msg := sprintf("RDS instance '%s' must not be publicly accessible", [name])
}
