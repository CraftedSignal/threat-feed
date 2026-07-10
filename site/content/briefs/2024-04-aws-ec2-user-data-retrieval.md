---
title: AWS EC2 User Data Retrieval for EC2 Instance
slug: 2024-04-aws-ec2-user-data-retrieval
description: Detection of the AWS EC2 DescribeInstanceAttribute API call to retrieve the userData attribute, potentially exposing sensitive information like credentials or configuration details.
date: "2024-04-14T00:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - cloudtrail
  - ec2
  - userdata
  - discovery
  - credential-access
vendors:
  - AWS
products:
  - EC2
  - IAM
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1580
    technique_name: Cloud Infrastructure Discovery
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstanceAttribute.html
  - https://hackingthe.cloud/aws/exploitation/local_ec2_priv_esc_through_user_data
rules:
  - title: Detect EC2 User Data Retrieval via DescribeInstanceAttribute
    description: Detects attempts to retrieve EC2 instance user data via the DescribeInstanceAttribute API call.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - discovery
    techniques:
      - T1552.005
      - T1580
    data_sources:
      - cloudtrail
      - aws
  - title: AWS EC2 User Data Retrieval by Unusual Identity
    description: Detects EC2 user data retrieval by identities that are not typically associated with this activity.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - discovery
    techniques:
      - T1552.005
      - T1580
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection identifies attempts to retrieve EC2 instance user data within AWS environments. The rule specifically focuses on the `DescribeInstanceAttribute` API call, used to query the `userData` attribute of an EC2 instance. This attribute, intended for instance initialization scripts, may inadvertently contain sensitive information such as hardcoded credentials, API keys, or other configuration details. An adversary gaining access to this information could leverage it for lateral movement, privilege escalation, or data exfiltration. The rule uses AWS CloudTrail logs to monitor for this specific API call and aims to detect unusual or unauthorized access to EC2 instance user data. The rule is designed to trigger the first time an IAM user or role requests the user data for a specific EC2 instance.

## Attack Chain

1. An attacker gains initial access to an AWS account, possibly through compromised credentials or a misconfigured IAM role.
2. The attacker attempts to discover EC2 instances within the environment.
3. The attacker uses the `DescribeInstanceAttribute` API call with the `userData` attribute specified.
4. The attacker extracts the user data from the API response.
5. The attacker analyzes the user data for sensitive information like hardcoded credentials, API keys, or configuration details.
6. The attacker leverages the discovered credentials or configuration to gain access to other AWS resources or services.
7. The attacker escalates privileges by assuming roles or creating new IAM users with elevated permissions.
8. The attacker exfiltrates sensitive data or disrupts services within the AWS environment.

## Impact

A successful attack could lead to the exposure of sensitive data, including credentials and API keys, potentially granting unauthorized access to critical AWS resources and services. This could result in data breaches, service disruption, and financial loss. The impact extends to any application or service relying on the exposed credentials. The number of affected instances depends on the scope of the attacker's access and the sensitivity of the data stored within the `userData` attribute.

## Recommendation

*   Deploy the Sigma rule provided below to your SIEM to detect unauthorized attempts to retrieve EC2 user data.
*   Review IAM policies and restrict access to the `DescribeInstanceAttribute` API call to only authorized users and roles.
*   Avoid storing sensitive information directly in EC2 user data; instead, use AWS Secrets Manager or Parameter Store.
*   Enable multi-factor authentication (MFA) for all IAM users to reduce the risk of credential compromise.
*   Monitor AWS CloudTrail logs for suspicious API activity, including unusual patterns of `DescribeInstanceAttribute` calls.
*   Implement the recommendations in the "Response and Remediation" section of the provided documentation for handling detected instances.
