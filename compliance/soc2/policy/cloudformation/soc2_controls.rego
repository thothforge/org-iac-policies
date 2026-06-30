package main

# SOC2 CC6.1 - No public access to storage
deny[msg] {
    resource := input.Resources[name]
    resource.Type == "AWS::S3::Bucket"
    resource.Properties.AccessControl == "PublicRead"
    msg := sprintf("[SOC2-CC6.1] S3 bucket '%s' must not have public read access", [name])
}

# SOC2 CC6.6 - Encryption of data at rest
deny[msg] {
    resource := input.Resources[name]
    resource.Type == "AWS::RDS::DBInstance"
    not resource.Properties.StorageEncrypted
    msg := sprintf("[SOC2-CC6.6] RDS instance '%s' must encrypt data at rest", [name])
}

# SOC2 CC7.2 - CloudTrail must be enabled
deny[msg] {
    not has_cloudtrail
    msg := "[SOC2-CC7.2] CloudTrail must be enabled for audit logging"
}

has_cloudtrail {
    resource := input.Resources[_]
    resource.Type == "AWS::CloudTrail::Trail"
}
