Feature: Ensure encryption is enabled for all storage resources

  Scenario: S3 buckets must have encryption
    Given I have aws_s3_bucket defined
    Then it must have server_side_encryption_configuration

  Scenario: EBS volumes must be encrypted
    Given I have aws_ebs_volume defined
    Then it must have encrypted
    And its value must be true

  Scenario: RDS instances must be encrypted
    Given I have aws_db_instance defined
    Then it must have storage_encrypted
    And its value must be true
