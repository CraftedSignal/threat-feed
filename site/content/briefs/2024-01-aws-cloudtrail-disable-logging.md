---
title: AWS CloudTrail Logging Disabled or Modified
slug: 2024-01-aws-cloudtrail-disable-logging
description: Detection of AWS CloudTrail being disabled, deleted, or updated by an adversary to impair defenses and evade detection.
date: "2024-01-23T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-impairment
  - cloud
vendors:
  - Amazon
products:
  - AWS CloudTrail
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_cloudtrail_disable_logging.yml
rules:
  - title: AWS CloudTrail Trail Modification
    description: Detects changes to an AWS CloudTrail trail configuration.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
    techniques:
      - T1562.008
    data_sources:
      - aws
      - cloudtrail
  - title: AWS CloudTrail Logging Stopped
    description: Detects when CloudTrail logging is stopped.
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
    techniques:
      - T1562.008
    data_sources:
      - aws
      - cloudtrail
  - title: AWS CloudTrail Trail Deletion
    description: Detects when a CloudTrail trail is deleted.
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
    techniques:
      - T1562.008
    data_sources:
      - aws
      - cloudtrail
rules_count: 3
---

AWS CloudTrail is a service that enables governance, compliance, operational auditing, and risk auditing of your AWS account. By recording API calls, CloudTrail provides a history of AWS account activity, including actions taken through the AWS Management Console, AWS SDKs, command line tools, and other AWS services. Attackers may attempt to disable or modify CloudTrail logging to remove traces of their malicious activity, hindering incident response and forensic investigations. This brief focuses on detecting actions that stop logging, update the trail configuration, or delete the trail altogether. These actions directly impact an organization's ability to detect and respond to security incidents within their AWS environment.

## Attack Chain

1. An attacker gains unauthorized access to an AWS account with sufficient privileges.
2. The attacker authenticates to the AWS environment using compromised credentials or an exploited IAM role.
3. The attacker executes the `StopLogging` API call against the CloudTrail service, effectively halting the recording of events.
4. Alternatively, the attacker may execute the `UpdateTrail` API call to modify the CloudTrail configuration. This could involve changing the S3 bucket destination, disabling log file validation, or altering event selectors to exclude specific events.
5. As another option, the attacker may execute the `DeleteTrail` API call, completely removing the CloudTrail configuration from the AWS account.
6. After disabling, modifying, or deleting the trail, the attacker proceeds with their malicious activities, knowing that their actions are less likely to be recorded and detected.
7. The attacker may then attempt to further obfuscate their activities by deleting or modifying any remaining log data.

## Impact

Disabling or modifying CloudTrail logging can have severe consequences. It impairs an organization's ability to detect and respond to security incidents in their AWS environment. Without proper logging, incident responders may struggle to determine the scope and impact of a breach, leading to delayed or ineffective remediation efforts. The inability to audit user activity can also hinder compliance efforts and potentially lead to regulatory penalties.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect `StopLogging`, `UpdateTrail`, and `DeleteTrail` events in CloudTrail logs.
*   Implement multi-factor authentication (MFA) for all AWS accounts, especially those with administrative privileges, to reduce the risk of unauthorized access.
*   Monitor AWS CloudTrail logs for unexpected changes to IAM policies, which could grant excessive permissions to attackers.
*   Enable log file validation to ensure the integrity of CloudTrail logs.
*   Use AWS Config to monitor CloudTrail configuration and alert on any deviations from the desired state.
*   Review AWS documentation on security best practices for AWS CloudTrail to ensure proper configuration and monitoring.
