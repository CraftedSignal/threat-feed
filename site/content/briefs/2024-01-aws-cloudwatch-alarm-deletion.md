---
title: AWS CloudWatch Alarm Deletion for Defense Evasion
slug: 2024-01-aws-cloudwatch-alarm-deletion
description: Successful deletion of Amazon CloudWatch alarms via the `DeleteAlarms` API, potentially indicating an adversary attempting to impair visibility, silence alerts, and evade detection after malicious activity within an AWS environment.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloudwatch
  - defense-evasion
  - aws
vendors:
  - AWS
products:
  - CloudWatch
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://awscli.amazonaws.com/v2/documentation/api/latest/reference/cloudwatch/delete-alarms.html
  - https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_DeleteAlarms.html
rules:
  - title: AWS CloudWatch Alarm Deletion
    description: Detects the deletion of one or more Amazon CloudWatch alarms using the DeleteAlarms API, potentially indicating defense evasion.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
      - T1562.006
    data_sources:
      - cloudtrail
      - aws
  - title: AWS CloudWatch Alarm Deletion from Unusual Source IP
    description: Detects CloudWatch alarm deletions originating from source IPs not commonly associated with AWS management.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

The deletion of CloudWatch alarms can be indicative of malicious activity within an AWS environment. CloudWatch alarms are crucial for monitoring metrics and triggering alerts when predefined thresholds are exceeded. Adversaries might delete these alarms to impair visibility, silence alerts, and evade detection following unauthorized access or other malicious operations. This behavior typically occurs during the post-exploitation or cleanup phases as the attacker attempts to remove traces of their compromise or disable automated incident response mechanisms. The focus of this brief is on identifying successful calls to the `DeleteAlarms` API in AWS CloudTrail logs. It is important to differentiate between legitimate alarm deletions performed during scheduled maintenance or automated infrastructure deployments, and those indicative of malicious intent. This activity can be detected through analysis of CloudTrail logs, focusing on the `DeleteAlarms` event.

## Attack Chain

1. **Initial Access:** An attacker gains unauthorized access to an AWS account through compromised credentials or exploiting a misconfigured IAM role (T1078).
2. **Privilege Escalation:** The attacker attempts to elevate their privileges within the AWS environment to gain sufficient permissions to modify CloudWatch alarms (T1068).
3. **Discovery:** The attacker uses AWS CLI or API calls to enumerate existing CloudWatch alarms and identify potential targets for deletion (T1082).
4. **Defense Evasion:** The attacker executes the `DeleteAlarms` API call to remove specific CloudWatch alarms, effectively disabling monitoring and alerting capabilities (T1562.001).
5. **Persistence:** The attacker may create new, less sensitive alarms or modify existing alarms to maintain a minimal level of monitoring while evading detection (T1543.004).
6. **Lateral Movement:** With alarms disabled, the attacker moves laterally to other AWS resources or accounts without triggering immediate alerts (TA0008).
7. **Data Exfiltration/Impact:** The attacker proceeds with their objectives, such as exfiltrating sensitive data or causing disruption, while the disabled alarms prevent or delay detection (TA0010).

## Impact

Successful deletion of CloudWatch alarms can severely degrade an organization's ability to detect and respond to security incidents in their AWS environment. This can lead to delayed detection of data breaches, unauthorized access, or service disruptions. The impact can range from compliance violations and financial losses to reputational damage. The number of alarms deleted and their criticality determines the severity of the impact. If critical security alarms are removed, an attacker can operate undetected for extended periods, maximizing the potential damage.

## Recommendation

*   Deploy the Sigma rule `AWS CloudWatch Alarm Deletion` to your SIEM, ingesting `filebeat-*` and `logs-aws.cloudtrail-*` indices, and tune for your environment to detect suspicious alarm deletions.
*   Investigate any detected `DeleteAlarms` events by examining the `aws.cloudtrail.user_identity.arn`, `source.ip`, and `user_agent.original` fields as suggested in the rule's description.
*   Implement AWS Config rules to monitor alarm existence and alert on `DeleteAlarms` API calls as recommended in the rule's note.
*   Restrict permissions to `cloudwatch:DeleteAlarms` and enforce MFA for users performing monitoring configuration changes to reduce the attack surface.
