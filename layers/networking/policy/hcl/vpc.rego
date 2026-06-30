# layers/networking/policy/vpc.rego
package main

# VPC must have flow logs enabled
deny[msg] {
    resource := input.resource.aws_vpc[name]
    not input.resource.aws_flow_log
    msg := sprintf("VPC '%s' must have flow logs enabled", [name])
}

# Security groups must not allow unrestricted ingress
deny[msg] {
    resource := input.resource.aws_security_group_rule[name]
    resource.type == "ingress"
    resource.cidr_blocks[_] == "0.0.0.0/0"
    resource.from_port == 0
    resource.to_port == 65535
    msg := sprintf("Security group rule '%s' allows unrestricted ingress (0.0.0.0/0 all ports)", [name])
}

# No public subnets in production
deny[msg] {
    resource := input.resource.aws_subnet[name]
    resource.map_public_ip_on_launch == true
    contains(name, "prd")
    msg := sprintf("Subnet '%s' must not map public IPs in production", [name])
}
