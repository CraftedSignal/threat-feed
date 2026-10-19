---
title: Detecting Unauthorized AWS IAM Access Key Creation
slug: 2026-10-aws-iam-access-key-creation
description: This brief highlights the risk of unauthorized AWS IAM access key creation, where one IAM user generates keys for another, potentially indicating account takeover or privilege escalation.
date: "2026-10-19T13:57:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - persistence
  - privilege-escalation
vendors:
  - Amazon
products:
  - AWS IAM
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136.003
    technique_name: 'Create Account: Cloud Account'
    evidence: Such activity may indicate persistence or privilege escalation, particularly when the target user has elevated permissions.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1136.003
    technique_name: 'Create Account: Cloud Account'
    evidence: This hunting query identifies successful AWS IAM access key creation events where a named IAM user creates a key for a different named IAM user.
    confidence_band: high
references:
  - https://bishopfox.com/blog/privilege-escalation-in-aws
  - https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation-part-2/
rules:
  - title: Detect Unauthorized AWS IAM Access Key Creation
    description: Detects scenarios where an IAM user creates an access key for a different user, potentially indicating persistence or privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1136.003
    data_sources:
      - cloud
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the detection rule to monitor CloudTrail for cross-user key creation.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific logic for identifying suspicious key creation events.
  hunt_leads:
    - lead: Search historic CloudTrail logs for instances of 'CreateAccessKey' where user identities do not match.
      technique_id: T1136.003
      data_needed:
        - AWS CloudTrail logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: The provided hunting query is designed for manual threat hunting.
---

Unauthorized creation of AWS IAM access keys is a technique used by adversaries to establish persistence or facilitate privilege escalation within an AWS environment. By leveraging the 'CreateAccessKey' API call, an attacker who has compromised an IAM user with appropriate permissions can generate new, long-lived access credentials for other users within the same AWS account. This behavior is particularly dangerous when the target user maintains higher privileges than the caller. Monitoring for discrepancies between the IAM user performing the action and the IAM user for whom the key is being created is a critical control for identifying suspicious administrative activity and potential lateral movement or persistence attempts.

## Impact

Successful exploitation of this technique can lead to full account compromise, unauthorized data exfiltration, and the creation of backdoors that allow attackers to maintain access even if their initial entry point is remediated. Organizations relying on AWS IAM are at risk if they do not maintain strict least-privilege policies for the 'iam:CreateAccessKey' permission.

## Recommendation

- Implement monitoring for 'CreateAccessKey' events where the 'userIdentity.userName' does not match the 'requestParameters.userName' in AWS CloudTrail logs.
- Review and tighten IAM policies to ensure that only authorized administrators possess the 'iam:CreateAccessKey' permission.
- Audit existing IAM access keys regularly to identify and disable unused or suspicious keys.
