Feature: Ensure all resources have required tags

  Scenario Outline: Resources must have mandatory tags
    Given I have resource that supports tags defined
    Then it must have tags
    And it must contain <tag>

    Examples:
      | tag         |
      | Environment |
      | Owner       |
      | Project     |
