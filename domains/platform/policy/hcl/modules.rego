# domains/platform/policy/modules.rego
package main

import rego.v1

# Platform: All modules must use pinned versions (no "latest" or ranges)
deny contains msg if {
    module := input.module[name]
    not regex.match(`\?ref=v?\d+\.\d+\.\d+`, module.source)
    not regex.match(`registry\.terraform\.io.*\d+\.\d+\.\d+`, module.source)
    contains(module.source, "github.com")
    msg := sprintf("Module '%s' must pin an exact version (use ?ref=vX.Y.Z)", [name])
}
