package main

# Fintech: All S3 buckets must use KMS (CMK) encryption, not AES-256
deny[msg] {
    resource := input.Resources[name]
    resource.Type == "AWS::S3::Bucket"
    encryption_rule := resource.Properties.BucketEncryption.ServerSideEncryptionConfiguration[_]
    algorithm := encryption_rule.ServerSideEncryptionByDefault.SSEAlgorithm
    algorithm != "aws:kms"
    msg := sprintf("Fintech: S3 bucket '%s' must use KMS (CMK) encryption, not AES-256", [name])
}

# Fintech: S3 buckets must have encryption configured
deny[msg] {
    resource := input.Resources[name]
    resource.Type == "AWS::S3::Bucket"
    not resource.Properties.BucketEncryption
    msg := sprintf("Fintech: S3 bucket '%s' must have KMS encryption configured", [name])
}

# Fintech: No cross-region replication to non-approved regions
deny[msg] {
    resource := input.Resources[name]
    resource.Type == "AWS::S3::Bucket"
    replication := resource.Properties.ReplicationConfiguration
    rule := replication.Rules[_]
    dest_bucket := rule.Destination.Bucket
    not contains(dest_bucket, "us-east")
    msg := sprintf("Fintech: Replication destination for '%s' must be in approved US regions", [name])
}

# Fintech: RDS must use KMS encryption
deny[msg] {
    resource := input.Resources[name]
    resource.Type == "AWS::RDS::DBInstance"
    not resource.Properties.KmsKeyId
    msg := sprintf("Fintech: RDS instance '%s' must use a customer-managed KMS key", [name])
}

# Fintech: DynamoDB tables must have point-in-time recovery
deny[msg] {
    resource := input.Resources[name]
    resource.Type == "AWS::DynamoDB::Table"
    not resource.Properties.PointInTimeRecoverySpecification
    msg := sprintf("Fintech: DynamoDB table '%s' must have point-in-time recovery enabled", [name])
}

deny[msg] {
    resource := input.Resources[name]
    resource.Type == "AWS::DynamoDB::Table"
    resource.Properties.PointInTimeRecoverySpecification.PointInTimeRecoveryEnabled != true
    msg := sprintf("Fintech: DynamoDB table '%s' must have point-in-time recovery enabled", [name])
}
