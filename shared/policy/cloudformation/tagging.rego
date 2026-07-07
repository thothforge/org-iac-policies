# shared/policy/cloudformation/tagging.rego
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
    resource := input.Resources[name]
    tags := object.get(resource.Properties, "Tags", [])
    tag_keys := {tag.Key | tag := tags[_]}
    missing := required_tags - tag_keys
    count(missing) > 0
    msg := sprintf("%s (%s) is missing required tags: %v", [name, resource.Type, missing])
}

# Recommended tags (warn only)
warn contains msg if {
    data.config.recommended_tags
    resource := input.Resources[name]
    tags := object.get(resource.Properties, "Tags", [])
    tag_keys := {tag.Key | tag := tags[_]}
    recommended := {t | t := data.config.recommended_tags[_]}
    missing := recommended - tag_keys
    count(missing) > 0
    msg := sprintf("%s (%s) is missing recommended tags: %v", [name, resource.Type, missing])
}
