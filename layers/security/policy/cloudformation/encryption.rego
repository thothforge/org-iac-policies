package main

# S3 buckets must have encryption
deny[msg] {
    resource := input.Resources[name]
    resource.Type == "AWS::S3::Bucket"
    not resource.Properties.BucketEncryption
    msg := sprintf("S3 bucket '%s' must have server-side encryption enabled", [name])
}

# RDS instances must have encryption at rest
deny[msg] {
    resource := input.Resources[name]
    resource.Type == "AWS::RDS::DBInstance"
    not resource.Properties.StorageEncrypted
    msg := sprintf("RDS instance '%s' must have storage encryption enabled", [name])
}

# EBS volumes must be encrypted
deny[msg] {
    resource := input.Resources[name]
    resource.Type == "AWS::EC2::Volume"
    not resource.Properties.Encrypted
    msg := sprintf("EBS volume '%s' must be encrypted", [name])
}
