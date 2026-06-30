package main

# Platform: Nested stacks must use versioned template URLs (no "latest" or unversioned)
deny[msg] {
    resource := input.Resources[name]
    resource.Type == "AWS::CloudFormation::Stack"
    url := resource.Properties.TemplateURL
    not regex.match(`/v?\d+\.\d+\.\d+/`, url)
    not regex.match(`\?versionId=`, url)
    msg := sprintf("Nested stack '%s' must reference a versioned template URL (include version in path or versionId parameter)", [name])
}

# Platform: Nested stacks must not use hardcoded parameter values for environment-specific settings
warn[msg] {
    resource := input.Resources[name]
    resource.Type == "AWS::CloudFormation::Stack"
    params := resource.Properties.Parameters
    params.Environment
    not contains(params.Environment, "Ref")
    not contains(params.Environment, "Fn::")
    msg := sprintf("Nested stack '%s' should use Ref or Fn:: for Environment parameter instead of hardcoded values", [name])
}

# Platform: All stacks must have tags for ownership
deny[msg] {
    resource := input.Resources[name]
    resource.Type == "AWS::CloudFormation::Stack"
    tags := object.get(resource.Properties, "Tags", [])
    tag_keys := {tag.Key | tag := tags[_]}
    not "Team" in tag_keys
    msg := sprintf("Nested stack '%s' must have a 'Team' tag for ownership tracking", [name])
}

# Platform: Stacks must enable termination protection via NotificationARNs or tags
warn[msg] {
    resource := input.Resources[name]
    resource.Type == "AWS::CloudFormation::Stack"
    contains(lower(name), "prd")
    not resource.Properties.NotificationARNs
    msg := sprintf("Production nested stack '%s' should have NotificationARNs configured for change alerts", [name])
}
