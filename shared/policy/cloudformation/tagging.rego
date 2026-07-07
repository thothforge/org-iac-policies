# shared/policy/cloudformation/tagging.rego
package main

# Required tags loaded from config.yaml via data.config.required_tags
default_required_tags := {"Environment", "Owner", "CostCenter", "ManagedBy"}

required_tags := {t | t := data.config.required_tags[_]} {
    data.config.required_tags
}

required_tags := default_required_tags {
    not data.config.required_tags
}

deny[msg] {
    resource := input.Resources[name]
    tags := object.get(resource.Properties, "Tags", [])
    tag_keys := {tag.Key | tag := tags[_]}
    missing := required_tags - tag_keys
    count(missing) > 0
    msg := sprintf("%s (%s) is missing required tags: %v", [name, resource.Type, missing])
}

# Recommended tags (warn only)
warn[msg] {
    data.config.recommended_tags
    resource := input.Resources[name]
    tags := object.get(resource.Properties, "Tags", [])
    tag_keys := {tag.Key | tag := tags[_]}
    recommended := {t | t := data.config.recommended_tags[_]}
    missing := recommended - tag_keys
    count(missing) > 0
    msg := sprintf("%s (%s) is missing recommended tags: %v", [name, resource.Type, missing])
}
