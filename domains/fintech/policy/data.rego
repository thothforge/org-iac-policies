# domains/fintech/policy/data.rego
package main

import rego.v1

# Fintech: All data stores must have encryption with CMK (not AWS-managed key)
deny contains msg if {
    resource := input.resource.aws_s3_bucket[name]
    sse := resource.server_side_encryption_configuration
    rule := sse.rule[_]
    rule.apply_server_side_encryption_by_default.sse_algorithm != "aws:kms"
    msg := sprintf("Fintech: S3 bucket '%s' must use KMS (CMK) encryption, not AES-256", [name])
}

# Fintech: No cross-region replication to non-approved regions
deny contains msg if {
    resource := input.resource.aws_s3_bucket_replication_configuration[name]
    rule := resource.rule[_]
    dest_region := rule.destination.bucket
    not contains(dest_region, "us-east")
    msg := sprintf("Fintech: Replication destination for '%s' must be in approved US regions", [name])
}
