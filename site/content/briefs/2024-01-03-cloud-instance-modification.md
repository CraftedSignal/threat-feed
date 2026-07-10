---
title: Cloud Instance Modified by Previously Unseen User
slug: 2024-01-03-cloud-instance-modification
description: This analytic identifies cloud instances being modified by users who have not previously modified them, specifically focusing on successful modifications of EC2 instances, potentially indicating unauthorized access and configuration changes.
date: "2024-01-03T18:25:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - ec2
  - anomaly
vendors:
  - AWS
products:
  - EC2
  - CloudTrail
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/cloud_instance_modified_by_previously_unseen_user.yml
rules:
  - title: Cloud Instance Modified By Previously Unseen User
    description: Detects cloud instances being modified by users who have not previously modified them.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1078.004
    data_sources:
      - cloudtrail
      - aws
  - title: Cloud Instance Modification Events
    description: Detects AWS CloudTrail events associated with cloud instance modifications.
    platform: sigma
    severity: informational
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1078.004
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection identifies cloud instances, specifically EC2 instances, being modified by users who have not previously been observed making such modifications. The activity is monitored through AWS CloudTrail logs. The focus is on successful modifications. This behavior is considered anomalous because it deviates from established user activity patterns and could signify a compromised account, insider threat, or a malicious actor attempting to gain unauthorized access and control over cloud resources. The detection leverages a baseline of previously seen cloud instance modifications by user to identify these anomalies. Proper functionality relies on the "Previously Seen Cloud Instance Modifications By User - Update" search being enabled.

## Attack Chain

1. An attacker gains unauthorized access to a cloud environment using compromised credentials (T1078.004).
2. The attacker enumerates available EC2 instances within the AWS environment.
3. The attacker selects a target EC2 instance for modification.
4. The attacker modifies the selected EC2 instance, potentially changing configurations, security settings, or installed software.
5. AWS CloudTrail logs the successful modification event, capturing the user, instance ID, and modification details.
6. The detection analytic identifies the modification event and compares the user against a baseline of previously seen modifiers.
7. If the user is not found in the baseline or has not modified the instance in the last 24 hours, an alert is triggered.
8. The attacker achieves unauthorized changes within the cloud environment.

## Impact

A successful attack can lead to unauthorized access, privilege escalation, data exfiltration, and disruption of cloud services. If an attacker modifies an EC2 instance, they could potentially gain control over the instance and the applications running on it. This could result in sensitive data being compromised, critical services being interrupted, and significant financial losses for the organization. The alert is triggered on the first modification by the "unseen user" within a 24 hour period.

## Recommendation

*   Enable the "Previously Seen Cloud Instance Modifications By User - Update" search to maintain an accurate baseline (refer to the "how_to_implement" section).
*   Deploy the Sigma rule below to your SIEM and tune the threshold for `firstTimeSeenUser` based on your environment.
*   Investigate triggered alerts to determine the legitimacy of the user's activity (refer to the "known_false_positives" section).
*   Review user access controls and permissions to ensure the principle of least privilege is enforced (T1078.004).
