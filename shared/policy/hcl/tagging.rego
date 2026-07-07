# shared/policy/hcl/tagging.rego
package main

import rego.v1

# Required tags loaded from config.yaml via data.config.required_tags
default_required_tags := {"Environment", "Owner", "CostCenter", "ManagedBy"}

required_tags := {t | t := data.config.required_tags[_]} if {
    data.config.required_tags
}

required_tags := default_required_tags if {
    not data.config.required_tags
}

deny contains msg if {
    resource := input.resource[type][name]
    tags := object.get(resource, "tags", {})
    missing := required_tags - {key | tags[key]}
    count(missing) > 0
    msg := sprintf("%s.%s is missing required tags: %v", [type, name, missing])
}

# Recommended tags (warn only, not deny)
warn contains msg if {
    data.config.recommended_tags
    resource := input.resource[type][name]
    tags := object.get(resource, "tags", {})
    recommended := {t | t := data.config.recommended_tags[_]}
    missing := recommended - {key | tags[key]}
    count(missing) > 0
    msg := sprintf("%s.%s is missing recommended tags: %v", [type, name, missing])
}
