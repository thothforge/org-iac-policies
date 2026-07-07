package main

import rego.v1

# No wildcard actions in IAM policies
deny contains msg if {
    resource := input.Resources[name]
    resource.Type == "AWS::IAM::Policy"
    statement := resource.Properties.PolicyDocument.Statement[_]
    statement.Effect == "Allow"
    action := statement.Action[_]
    action == "*"
    msg := sprintf("IAM policy '%s' must not use wildcard (*) actions", [name])
}

# No wildcard actions in IAM managed policies
deny contains msg if {
    resource := input.Resources[name]
    resource.Type == "AWS::IAM::ManagedPolicy"
    statement := resource.Properties.PolicyDocument.Statement[_]
    statement.Effect == "Allow"
    action := statement.Action[_]
    action == "*"
    msg := sprintf("IAM managed policy '%s' must not use wildcard (*) actions", [name])
}

# No wildcard resources in IAM policies
deny contains msg if {
    resource := input.Resources[name]
    resource.Type == "AWS::IAM::Policy"
    statement := resource.Properties.PolicyDocument.Statement[_]
    statement.Effect == "Allow"
    statement.Resource == "*"
    action := statement.Action[_]
    action != "sts:AssumeRole"
    msg := sprintf("IAM policy '%s' must not use wildcard (*) resources", [name])
}

# No wildcard resources in IAM managed policies
deny contains msg if {
    resource := input.Resources[name]
    resource.Type == "AWS::IAM::ManagedPolicy"
    statement := resource.Properties.PolicyDocument.Statement[_]
    statement.Effect == "Allow"
    statement.Resource == "*"
    action := statement.Action[_]
    action != "sts:AssumeRole"
    msg := sprintf("IAM managed policy '%s' must not use wildcard (*) resources", [name])
}

# IAM roles must have a permissions boundary
warn contains msg if {
    resource := input.Resources[name]
    resource.Type == "AWS::IAM::Role"
    not resource.Properties.PermissionsBoundary
    msg := sprintf("IAM role '%s' should have a permissions boundary attached", [name])
}
