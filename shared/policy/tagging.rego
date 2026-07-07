# shared/policy/tagging.rego
package main

import rego.v1

required_tags := {"Environment", "Owner", "CostCenter", "ManagedBy"}

deny contains msg if {
    resource := input.resource[type][name]
    tags := object.get(resource, "tags", {})
    missing := required_tags - {key | tags[key]}
    count(missing) > 0
    msg := sprintf("%s.%s is missing required tags: %v", [type, name, missing])
}
