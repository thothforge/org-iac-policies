# shared/policy/hcl/regions.rego
package main

# Allowed regions loaded from config.yaml via data.config.allowed_regions
default_allowed_regions := {"us-east-1", "us-east-2", "us-west-2", "eu-west-1"}

allowed_regions := {r | r := data.config.allowed_regions[_]} {
    data.config.allowed_regions
}

allowed_regions := default_allowed_regions {
    not data.config.allowed_regions
}

deny[msg] {
    resource := input.resource.aws_instance[name]
    provider := input.provider.aws
    not provider.region in allowed_regions
    msg := sprintf("Region '%s' is not allowed. Approved regions: %v", [provider.region, allowed_regions])
}
