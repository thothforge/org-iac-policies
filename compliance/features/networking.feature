Feature: Ensure network security best practices

  Scenario: Security groups must not allow ingress from 0.0.0.0/0
    Given I have aws_security_group defined
    When it has ingress
    Then it must not have cidr_blocks
    And its value must not contain 0.0.0.0/0

  Scenario: VPC must have flow logs enabled
    Given I have aws_vpc defined
    When I count them
    Then I expect the result is greater than 0

  Scenario: No public subnets in production
    Given I have aws_subnet defined
    Then it must have map_public_ip_on_launch
    And its value must be false
