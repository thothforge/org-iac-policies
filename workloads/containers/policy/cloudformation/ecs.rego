package main

import rego.v1

# ECS tasks must not run as root
deny contains msg if {
    resource := input.Resources[name]
    resource.Type == "AWS::ECS::TaskDefinition"
    container := resource.Properties.ContainerDefinitions[_]
    container.User == "root"
    msg := sprintf("ECS task '%s' must not run containers as root", [name])
}

# ECS tasks must have logging configured
deny contains msg if {
    resource := input.Resources[name]
    resource.Type == "AWS::ECS::TaskDefinition"
    container := resource.Properties.ContainerDefinitions[_]
    not container.LogConfiguration
    msg := sprintf("ECS task '%s' container '%s' must have logging configured", [name, container.Name])
}

# ECS services must have desired count >= 2 in production
deny contains msg if {
    resource := input.Resources[name]
    resource.Type == "AWS::ECS::Service"
    contains(lower(name), "prd")
    resource.Properties.DesiredCount < 2
    msg := sprintf("ECS service '%s' must have at least 2 tasks in production", [name])
}

# ECS tasks should use Fargate for production workloads
warn contains msg if {
    resource := input.Resources[name]
    resource.Type == "AWS::ECS::TaskDefinition"
    contains(lower(name), "prd")
    not resource.Properties.RequiresCompatibilities
    msg := sprintf("ECS task '%s' should specify Fargate compatibility for production", [name])
}
