---
title: AWS SES Identity Deletion
slug: 2024-01-ses-identity-deleted
description: Detection of an AWS Simple Email Service (SES) identity deletion event, potentially indicating an adversary attempting to cover their tracks after malicious activity.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - attack.stealth
  - attack.t1070
  - cloud
vendors:
  - Amazon
products:
  - Simple Email Service
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
references:
  - https://unit42.paloaltonetworks.com/compromised-cloud-compute-credentials/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_delete_identity.yml
rules:
  - title: SES Identity Has Been Deleted
    description: Detects an instance of an SES identity being deleted via the 'DeleteIdentity' event.
    platform: sigma
    severity: medium
    tactics:
      - stealth
    techniques:
      - T1070
    data_sources:
      - aws
      - cloudtrail
  - title: Suspicious User Agent Deleting SES Identity
    description: Detects deletion of an SES identity with a suspicious user agent
    platform: sigma
    severity: medium
    tactics:
      - stealth
    techniques:
      - T1070
    data_sources:
      - aws
      - cloudtrail
rules_count: 2
---

This threat brief focuses on the detection of the "DeleteIdentity" event within AWS Simple Email Service (SES) logs. An adversary who has gained unauthorized access to an AWS environment and utilized SES for malicious purposes, such as sending phishing emails or distributing malware, might attempt to erase their activity by deleting the SES identity (email address or domain) used in the attack. This action is a form of obfuscation and aims to hinder forensic investigations. While legitimate users may occasionally delete SES identities, the event warrants scrutiny, especially in the context of other suspicious cloud activity.

## Attack Chain

1. An attacker gains initial access to an AWS account, potentially through compromised credentials or exploiting a vulnerability.
2. The attacker explores the AWS environment, identifying SES as a service to abuse for sending malicious emails.
3. The attacker configures SES, verifies an email address or domain, and establishes sending capabilities.
4. The attacker crafts and sends phishing emails or emails containing malicious attachments to external targets.
5. After the malicious campaign, the attacker attempts to cover their tracks by deleting the SES identity to remove evidence of their activity.
6. The attacker executes the "DeleteIdentity" API call within SES, specifying the identity to be removed.
7. AWS CloudTrail logs record the "DeleteIdentity" event, capturing details such as the event source, event name, and user identity.
8. The attacker may further attempt to delete or modify other CloudTrail logs to eliminate the traces of their actions.

## Impact

The successful deletion of an SES identity hinders incident response and forensic investigations. If an attacker successfully removes the SES identity, it becomes more difficult to trace the origin of malicious emails and attribute the activity to a specific actor. The deletion itself does not directly cause harm, but it obstructs the ability to understand the full scope and impact of the attack.

## Recommendation

*   Implement the provided Sigma rule (`SES Identity Has Been Deleted`) to detect SES identity deletion events within your CloudTrail logs.
*   Investigate any detected `DeleteIdentity` events, correlating them with other suspicious AWS activity, such as unusual IAM role usage or unauthorized access attempts.
*   Enable and monitor AWS CloudTrail logs for all regions within your AWS account to ensure comprehensive event capture.
*   Implement strong IAM policies and multi-factor authentication (MFA) to prevent unauthorized access to AWS accounts.
