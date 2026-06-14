# compliance/soc2/policy/soc2_controls.rego
package main

# SOC2 CC6.1 - Logical access security: No public access to storage
deny[msg] {
    resource := input.resource.aws_s3_bucket[name]
    resource.acl == "public-read"
    msg := sprintf("[SOC2-CC6.1] S3 bucket '%s' must not have public read access", [name])
}

# SOC2 CC6.6 - Encryption of data at rest
deny[msg] {
    resource := input.resource.aws_db_instance[name]
    not resource.storage_encrypted
    msg := sprintf("[SOC2-CC6.6] RDS instance '%s' must encrypt data at rest", [name])
}

# SOC2 CC7.2 - System monitoring: CloudTrail must be enabled
deny[msg] {
    not input.resource.aws_cloudtrail
    msg := "[SOC2-CC7.2] CloudTrail must be enabled for audit logging"
}
