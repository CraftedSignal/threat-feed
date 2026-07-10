---
title: AWS VPC Flow Logs Deletion
slug: 2024-02-29-aws-vpc-flow-log-deletion
description: An adversary may delete flow logs in AWS EC2 using the DeleteFlowLogs API to evade defenses and hinder security monitoring, impacting incident response and log auditing capabilities.
date: "2024-02-29T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - cloudtrail
  - defense-evasion
vendors:
  - Amazon Web Services
products:
  - VPC Flow Logs
  - EC2
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/delete-flow-logs.html
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteFlowLogs.html
  - https://attack.mitre.org/techniques/T1562/
  - https://attack.mitre.org/techniques/T1562/008/
  - https://attack.mitre.org/tactics/TA0005/
  - https://aws.amazon.com/premiumsupport/knowledge-center/security-best-practices/
rules:
  - title: AWS VPC Flow Logs Deletion
    description: Detects the deletion of VPC flow logs via the DeleteFlowLogs API call in AWS CloudTrail logs.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
  - title: AWS VPC Flow Logs Deletion by Specific User Agent
    description: Detects VPC flow logs deletion using a specific user agent, potentially indicating a compromised or malicious tool.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This rule detects the deletion of VPC flow logs in Amazon Web Services Elastic Compute Cloud (EC2). Flow logs capture information about IP traffic going to and from network interfaces within a VPC, and their deletion can severely impact security monitoring and incident response. An attacker may delete these logs to cover their tracks, making it difficult to detect and investigate malicious activity. This activity is detected via the `DeleteFlowLogs` API action. This poses a risk to organizations relying on VPC flow logs for auditing and security analysis, hindering their ability to identify and respond to potential security incidents.

## Attack Chain

1. An attacker gains unauthorized access to an AWS account with sufficient privileges.
2. The attacker enumerates existing VPC flow logs using AWS APIs or CLI tools.
3. The attacker identifies the flow logs they want to delete to cover their tracks.
4. The attacker uses the `DeleteFlowLogs` API action to initiate the deletion of the targeted flow logs.
5. AWS EC2 service processes the `DeleteFlowLogs` API request.
6. The targeted flow logs are permanently deleted from the configured storage location (CloudWatch Logs or S3).
7. Security monitoring and alerting systems relying on flow log data are rendered ineffective for the period covered by the deleted logs.
8. The attacker continues their malicious activities, now with a reduced risk of detection due to the absence of flow log data.

## Impact

Successful deletion of VPC flow logs can severely impair an organization's ability to detect and respond to security incidents. The absence of flow log data hinders network traffic analysis, anomaly detection, and forensic investigations. This can lead to delayed incident response, increased dwell time for attackers, and potential data breaches. The impact is especially significant for organizations that rely heavily on VPC flow logs for compliance and security auditing. The rule is rated high severity (73) because it directly impacts an organization's visibility into its network traffic.

## Recommendation

*   Deploy the Sigma rule "AWS VPC Flow Logs Deletion" to your SIEM and tune for your environment to detect this activity (see rule below).
*   Investigate any detected instances of `DeleteFlowLogs` events to determine if they are authorized and legitimate.
*   Review IAM policies to ensure the principle of least privilege is being followed, limiting the ability of users and roles to delete flow logs.
*   Enable multi-factor authentication (MFA) for all AWS accounts, especially those with administrative privileges.
*   Monitor CloudTrail logs for other suspicious activities associated with the user account that performed the `DeleteFlowLogs` action.
*   Implement AWS security best practices as outlined by AWS in their knowledge center to strengthen overall security posture (references).
