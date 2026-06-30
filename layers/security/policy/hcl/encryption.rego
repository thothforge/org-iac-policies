# layers/security/policy/encryption.rego
package main

# S3 buckets must have encryption
deny[msg] {
    resource := input.resource.aws_s3_bucket[name]
    not resource.server_side_encryption_configuration
    msg := sprintf("S3 bucket '%s' must have server-side encryption enabled", [name])
}

# RDS instances must have encryption at rest
deny[msg] {
    resource := input.resource.aws_db_instance[name]
    not resource.storage_encrypted
    msg := sprintf("RDS instance '%s' must have storage encryption enabled", [name])
}

# EBS volumes must be encrypted
deny[msg] {
    resource := input.resource.aws_ebs_volume[name]
    not resource.encrypted
    msg := sprintf("EBS volume '%s' must be encrypted", [name])
}
