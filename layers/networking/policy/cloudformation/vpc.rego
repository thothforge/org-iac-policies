package main

# VPC must have flow logs enabled
deny[msg] {
    resource := input.Resources[name]
    resource.Type == "AWS::EC2::VPC"
    not has_flow_log(name)
    msg := sprintf("VPC '%s' must have flow logs enabled", [name])
}

has_flow_log(vpc_name) {
    resource := input.Resources[_]
    resource.Type == "AWS::EC2::FlowLog"
    resource.Properties.ResourceId.Ref == vpc_name
}

has_flow_log(vpc_name) {
    resource := input.Resources[_]
    resource.Type == "AWS::EC2::FlowLog"
    resource.Properties.ResourceId == vpc_name
}

# Security groups must not allow unrestricted ingress
deny[msg] {
    resource := input.Resources[name]
    resource.Type == "AWS::EC2::SecurityGroup"
    ingress := resource.Properties.SecurityGroupIngress[_]
    ingress.CidrIp == "0.0.0.0/0"
    ingress.FromPort == 0
    ingress.ToPort == 65535
    msg := sprintf("Security group '%s' allows unrestricted ingress (0.0.0.0/0 all ports)", [name])
}

# No public subnets in production
deny[msg] {
    resource := input.Resources[name]
    resource.Type == "AWS::EC2::Subnet"
    resource.Properties.MapPublicIpOnLaunch == true
    contains(lower(name), "prd")
    msg := sprintf("Subnet '%s' must not map public IPs in production", [name])
}
