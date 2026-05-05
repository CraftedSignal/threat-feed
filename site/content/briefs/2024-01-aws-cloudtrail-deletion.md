---
title: AWS CloudTrail Deletion Detection
slug: 2024-01-aws-cloudtrail-deletion
description: Detection of AWS CloudTrail deletion events indicating potential defense evasion by adversaries attempting to remove audit trails.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - cloudtrail
  - defense_evasion
vendors:
  - Amazon
  - Splunk
products:
  - CloudTrail
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Splunk Add-on for Amazon Web Services
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://attack.mitre.org/techniques/T1562/008/
rules:
  - title: Detect AWS CloudTrail Deletion via ASL
    description: Detects AWS CloudTrail deletion events using Amazon Security Lake logs.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
  - title: Detect AWS CloudTrail Stop Logging via ASL
    description: Detects AWS CloudTrail stop logging events using Amazon Security Lake logs.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This threat brief focuses on the detection of AWS CloudTrail deletion events.
CloudTrail is a critical AWS service that logs API calls made within an AWS
environment, providing an audit trail for security investigations and
compliance purposes. An adversary who has gained unauthorized access to an AWS
account may attempt to delete CloudTrail trails to remove evidence of their
malicious activities. This brief outlines how to detect such attempts using
Amazon Security Lake logs parsed in the Open Cybersecurity Schema Framework (OCSF) format.

## Attack Chain

1.  **Initial Access:** Adversary gains unauthorized access to an AWS account, potentially through compromised credentials or exploiting a misconfiguration.
2.  **Privilege Escalation (if necessary):** If the initial access does not provide sufficient permissions, the adversary attempts to escalate privileges to gain the necessary rights to delete CloudTrail trails.
3.  **Discovery:** The adversary identifies existing CloudTrail trails within the AWS environment.
4.  **Disable Logging (Optional):** Adversary disables CloudTrail logging to prevent further activity from being recorded.
5.  **Deletion of CloudTrail:** Adversary executes the `DeleteTrail` API call to delete the CloudTrail trail. This removes the historical audit logs.
6.  **Confirmation:** The adversary verifies the CloudTrail trail has been successfully deleted.
7.  **Covering Tracks:** The adversary may attempt to further cover their tracks by deleting other log sources or manipulating AWS configurations.

## Impact

The successful deletion of CloudTrail trails can have a significant impact on
an organization's security posture. It allows attackers to operate with
stealth, making it difficult to detect and respond to ongoing attacks. This
can lead to prolonged breaches, increased data exfiltration, and significant
financial losses. Organizations relying on CloudTrail for compliance may also
face regulatory penalties.

## Recommendation

*   Deploy the provided Sigma rule to detect `DeleteTrail` events in your SIEM using Amazon Security Lake logs.
*   Investigate any detected `DeleteTrail` events promptly to determine if they are authorized or malicious.
*   Implement multi-factor authentication (MFA) for all AWS accounts, especially those with administrative privileges, to reduce the risk of credential compromise.
*   Monitor AWS CloudTrail logs for suspicious activity, such as unusual API calls or attempts to modify logging configurations.
*   Review and enforce the principle of least privilege to minimize the potential impact of compromised credentials.
