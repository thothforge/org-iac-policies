package main

import rego.v1

naming_pattern := `^(Dev|Stg|Prd)[A-Z][a-zA-Z0-9]+$`

warn contains msg if {
    resource := input.Resources[name]
    not regex.match(naming_pattern, name)
    msg := sprintf("%s (%s) does not follow naming convention '{Env}{ServiceName}'", [name, resource.Type])
}
