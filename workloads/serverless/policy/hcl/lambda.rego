# workloads/serverless/policy/lambda.rego
package main

# Lambda functions must have a timeout set (not default 3s)
warn[msg] {
    resource := input.resource.aws_lambda_function[name]
    not resource.timeout
    msg := sprintf("Lambda '%s' should have an explicit timeout configured", [name])
}

# Lambda functions must have dead letter queue
warn[msg] {
    resource := input.resource.aws_lambda_function[name]
    not resource.dead_letter_config
    msg := sprintf("Lambda '%s' should have a dead letter queue configured", [name])
}
