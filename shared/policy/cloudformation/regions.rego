package main

import rego.v1

allowed_regions := {"us-east-1", "us-east-2", "us-west-2", "eu-west-1"}

deny contains msg if {
    resource := input.Resources[name]
    resource.Type == "AWS::EC2::Instance"
    resource.Properties.AvailabilityZone
    region := substring(resource.Properties.AvailabilityZone, 0, count(resource.Properties.AvailabilityZone) - 1)
    not region in allowed_regions
    msg := sprintf("Resource '%s' is in region '%s' which is not allowed. Approved: %v", [name, region, allowed_regions])
}
