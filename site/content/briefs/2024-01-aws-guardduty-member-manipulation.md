---
title: AWS GuardDuty Member Account Manipulation
slug: 2024-01-aws-guardduty-member-manipulation
description: Adversaries may attempt to disassociate or manipulate Amazon GuardDuty member accounts within an AWS organization to break centralized visibility, allowing them to operate undetected in member accounts.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - guardduty
  - defense_evasion
vendors:
  - AWS
products:
  - GuardDuty
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://docs.aws.amazon.com/guardduty/latest/APIReference/API_DisassociateFromAdministratorAccount.html
  - https://docs.aws.amazon.com/guardduty/latest/APIReference/API_DeleteMembers.html
  - https://docs.aws.amazon.com/guardduty/latest/APIReference/API_StopMonitoringMembers.html
  - https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_accounts.html
  - https://permiso.io/blog/lucr-3-scattered-spider-getting-saas-y-in-the-cloud
rules:
  - title: AWS GuardDuty Member Account Manipulation
    description: Detects attempts to disassociate or manipulate Amazon GuardDuty member accounts within an AWS organization.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - cloudtrail
      - aws
  - title: AWS GuardDuty Stop Monitoring Members
    description: Detects attempts to stop monitoring GuardDuty member accounts within an AWS organization.
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

This alert detects attempts to disassociate or manipulate Amazon GuardDuty member accounts within an AWS organization. In multi-account GuardDuty deployments, a delegated administrator account aggregates findings from member accounts. Attackers who have compromised a member account, or the administrator account, may attempt to break this centralized visibility by disassociating member accounts, deleting member relationships, stopping monitoring of members, or deleting pending invitations. These actions can precede or substitute for deleting GuardDuty detectors entirely, enabling attackers to operate undetected in member accounts while the administrator account loses visibility. The rule identifies successful API calls that manipulate GuardDuty member relationships within AWS, which are rare and warrant investigation.

## Attack Chain

1. An attacker gains initial access to an AWS account, potentially through compromised credentials or an EC2 instance.
2. The attacker enumerates GuardDuty member accounts and the delegated administrator account.
3. If the attacker has compromised a member account, they attempt to call the `DisassociateFromAdministratorAccount` or `DisassociateMembers` API to break the connection to the administrator account.
4. Alternatively, if the attacker has compromised the administrator account, they call `DeleteMembers` or `StopMonitoringMembers` to remove or stop monitoring member accounts.
5. The attacker may also call `DeleteInvitations` to prevent member accounts from associating with the GuardDuty administrator.
6. After successfully manipulating the member account relationships, the attacker performs malicious actions within the affected AWS accounts, such as deploying malware, exfiltrating data, or establishing persistence.
7. The attacker avoids detection by the central GuardDuty administrator account because the compromised member accounts are no longer actively monitored.
8. The attacker may attempt to delete CloudTrail logs or other security configurations to further evade detection.

## Impact

A successful attack can lead to a significant loss of visibility into the security posture of AWS member accounts. If GuardDuty monitoring is disrupted, attackers can operate undetected, potentially leading to data breaches, resource hijacking, or other malicious activities. The number of affected accounts depends on the scope of the attack and the attacker's objectives. This is especially critical for organizations relying on centralized security monitoring and incident response across multiple AWS accounts.

## Recommendation

*   Deploy the Sigma rule "AWS GuardDuty Member Account Manipulation" to your SIEM and tune for your environment.
*   Restrict IAM permissions for `guardduty:DisassociateFromAdministratorAccount`, `guardduty:DeleteMembers`, `guardduty:StopMonitoringMembers`, and `guardduty:DeleteInvitations` to only authorized personnel.
*   Monitor CloudTrail logs for any unauthorized API calls related to GuardDuty member account manipulation.
*   Implement Service Control Policies (SCPs) to prevent member accounts from disassociating from GuardDuty administrators, as referenced in the overview.
*   Enable AWS Security Hub controls to detect changes to GuardDuty organization configurations, as mentioned in the hardening section.
*   Investigate any alerts generated by the Sigma rule "AWS GuardDuty Member Account Manipulation" by following the triage and analysis steps outlined in the rule documentation.
