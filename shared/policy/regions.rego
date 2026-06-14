# shared/policy/regions.rego
package main

allowed_regions := {"us-east-1", "us-east-2", "us-west-2", "eu-west-1"}

deny[msg] {
    resource := input.resource.aws_instance[name]
    provider := input.provider.aws
    not provider.region in allowed_regions
    msg := sprintf("Region '%s' is not allowed. Approved regions: %v", [provider.region, allowed_regions])
}
