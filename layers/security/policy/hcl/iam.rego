# layers/security/policy/iam.rego
package main

# No wildcard actions in IAM policies
deny[msg] {
    resource := input.resource.aws_iam_policy[name]
    statement := resource.policy.Statement[_]
    statement.Effect == "Allow"
    statement.Action[_] == "*"
    msg := sprintf("IAM policy '%s' must not use wildcard (*) actions", [name])
}

# No wildcard resources in IAM policies
deny[msg] {
    resource := input.resource.aws_iam_policy[name]
    statement := resource.policy.Statement[_]
    statement.Effect == "Allow"
    statement.Resource == "*"
    statement.Action[_] != "sts:AssumeRole"
    msg := sprintf("IAM policy '%s' must not use wildcard (*) resources", [name])
}
