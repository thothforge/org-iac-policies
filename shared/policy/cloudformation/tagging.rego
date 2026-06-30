package main

required_tags := {"Environment", "Owner", "CostCenter", "ManagedBy"}

deny[msg] {
    resource := input.Resources[name]
    tags := object.get(resource.Properties, "Tags", [])
    tag_keys := {tag.Key | tag := tags[_]}
    missing := required_tags - tag_keys
    count(missing) > 0
    msg := sprintf("%s (%s) is missing required tags: %v", [name, resource.Type, missing])
}
