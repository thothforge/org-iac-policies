# workloads/containers/policy/ecs.rego
package main

import rego.v1

# ECS tasks must not run as root
deny contains msg if {
    resource := input.resource.aws_ecs_task_definition[name]
    container := resource.container_definitions[_]
    container.user == "root"
    msg := sprintf("ECS task '%s' must not run containers as root", [name])
}

# ECS tasks must have logging configured
deny contains msg if {
    resource := input.resource.aws_ecs_task_definition[name]
    container := resource.container_definitions[_]
    not container.logConfiguration
    msg := sprintf("ECS task '%s' container must have logging configured", [name])
}
