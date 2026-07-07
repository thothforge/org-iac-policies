# shared/policy/hcl/naming.rego
package main

# Naming pattern loaded from config.yaml via data.config.naming_pattern
default_naming_pattern := `^(dev|stg|prd)-[a-z]+-[a-z0-9-]+$`

naming_pattern := data.config.naming_pattern {
    data.config.naming_pattern
}

naming_pattern := default_naming_pattern {
    not data.config.naming_pattern
}

naming_description := data.config.naming_description {
    data.config.naming_description
}

naming_description := "{env}-{service}-{name}" {
    not data.config.naming_description
}

warn[msg] {
    resource := input.resource[type][name]
    not regex.match(naming_pattern, name)
    msg := sprintf("%s.%s does not follow naming convention '%s'", [type, name, naming_description])
}
