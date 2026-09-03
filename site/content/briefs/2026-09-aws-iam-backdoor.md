---
title: AWS IAM Access Key Creation Monitoring
slug: 2026-09-aws-iam-backdoor
description: Detection of unauthorized or suspicious creation of AWS IAM access keys by one user for another, a technique used for persistence and privilege escalation.
date: "2026-09-03T13:35:39Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud-security
  - persistence
  - privilege-escalation
  - aws
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Backdoored users can be used to obtain persistence in the AWS environment.
    confidence_band: high
rules:
  - title: Detect AWS IAM Access Key Creation by Another User
    description: Detects instances where a user creates an IAM access key for a different user, which may indicate account backdooring.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1098
    data_sources:
      - cloudtrail
      - aws
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
    - Cloud Security Team
  immediate_actions:
    - action: Deploy Sigma detection rule to SIEM
      owner: Detection Engineering
      due: 72h
      evidence: Source rule repository documentation
  hunt_leads:
    - lead: Search historical CloudTrail logs for CreateAccessKey events where Actor ARN != Target UserName
      technique_id: T1098
      data_needed:
        - CloudTrail logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Source logic for identifying backdoor activity
---

This brief addresses the detection of AWS IAM access key creation, which can be leveraged by attackers for persistence and privilege escalation. Unauthorized creation of access keys for existing IAM users allows an adversary to maintain long-term access to a cloud environment even if original credentials are revoked or rotated. This technique is frequently observed in post-exploitation scenarios, such as when tools like the Pacu framework are used to automate the backdooring of IAM users. Defenders should monitor CloudTrail logs for the CreateAccessKey API event, specifically focusing on instances where a user account creates access keys for a different identity, as this behavior often indicates malicious intent rather than standard administrative lifecycle management.

## Impact

Successful exploitation results in the creation of unauthorized backdoors, allowing persistent access to the AWS environment. This significantly increases the risk of data exfiltration, resource hijacking, and lateral movement within the cloud infrastructure.

## Recommendation

Deploy the provided Sigma rule to your SIEM environment to monitor CloudTrail logs for anomalous IAM access key creation. Prioritize alerts where the actor performing the CreateAccessKey action is distinct from the target user. Conduct regular audits of IAM access keys to identify over-privileged or stale credentials.
