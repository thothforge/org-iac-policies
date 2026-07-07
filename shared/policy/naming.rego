# shared/policy/naming.rego
package main

import rego.v1

naming_pattern := `^(dev|stg|prd)-[a-z]+-[a-z0-9-]+$`

warn contains msg if {
    resource := input.resource[type][name]
    not regex.match(naming_pattern, name)
    msg := sprintf("%s.%s does not follow naming convention '{env}-{service}-{name}'", [type, name])
}
