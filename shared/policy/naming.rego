# shared/policy/naming.rego
package main

naming_pattern := `^(dev|stg|prd)-[a-z]+-[a-z0-9-]+$`

warn[msg] {
    resource := input.resource[type][name]
    not regex.match(naming_pattern, name)
    msg := sprintf("%s.%s does not follow naming convention '{env}-{service}-{name}'", [type, name])
}
