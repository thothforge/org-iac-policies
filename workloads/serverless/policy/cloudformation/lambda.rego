package main

import rego.v1

# Lambda functions must have a timeout set
warn contains msg if {
    resource := input.Resources[name]
    resource.Type == "AWS::Lambda::Function"
    not resource.Properties.Timeout
    msg := sprintf("Lambda '%s' should have an explicit timeout configured", [name])
}

# Lambda functions must have dead letter queue
warn contains msg if {
    resource := input.Resources[name]
    resource.Type == "AWS::Lambda::Function"
    not resource.Properties.DeadLetterConfig
    msg := sprintf("Lambda '%s' should have a dead letter queue configured", [name])
}
