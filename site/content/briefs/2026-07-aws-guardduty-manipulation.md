---
title: AWS GuardDuty Member Account Manipulation
slug: 2026-07-aws-guardduty-manipulation
description: Adversaries manipulate Amazon GuardDuty member accounts within an AWS organization by using API calls such as `DisassociateFromAdministratorAccount`, `DeleteMembers`, `StopMonitoringMembers`, or `DeleteInvitations` to break centralized security visibility, enabling them to operate undetected in compromised member accounts.
date: "2026-07-15T13:59:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - aws
  - defense-evasion
  - amazon-guardduty
vendors:
  - Amazon
products:
  - Amazon GuardDuty
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Adversaries may attempt to disassociate member accounts, delete member relationships, stop monitoring members, or delete pending invitations to break this centralized visibility.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/guardduty/latest/APIReference/API_DisassociateFromAdministratorAccount.html
  - https://docs.aws.amazon.com/guardduty/latest/APIReference/API_DeleteMembers.html
  - https://docs.aws.amazon.com/guardduty/latest/APIReference/API_StopMonitoringMembers.html
  - https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_accounts.html
  - https://permiso.io/blog/lucr-3-scattered-spider-getting-saas-y-in-the-cloud
rules:
  - title: AWS GuardDuty Member Account Manipulation
    description: Detects attempts to disassociate or manipulate Amazon GuardDuty member accounts within an AWS organization by observing successful API calls to disrupt centralized security visibility.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562
      - T1562.001
    data_sources:
      - cloud
      - aws
      - cloudtrail
rules_count: 1
---

Adversaries targeting AWS environments may attempt to disrupt security monitoring capabilities, specifically Amazon GuardDuty, to operate undetected within compromised accounts. In multi-account GuardDuty deployments, a delegated administrator account aggregates security findings from member accounts, providing critical centralized visibility. This threat involves an attacker, having gained initial access to an AWS account (either a member or administrator account), executing specific GuardDuty API calls to disassociate member accounts, delete member relationships, stop monitoring members, or delete pending invitations. These actions, which include `DisassociateFromAdministratorAccount`, `DeleteMembers`, `StopMonitoringMembers`, `DeleteInvitations`, and `DisassociateMembers`, are rare in legitimate operations and serve as a strong indicator of defense evasion. Successful manipulation allows attackers to bypass detection, potentially preceding more significant malicious activities like complete GuardDuty detector deletion or undetected resource compromise.

## Attack Chain

1. An attacker gains initial access to an AWS account, typically through compromised credentials or exploitation of a vulnerable resource.
2. The attacker identifies that AWS GuardDuty is enabled across an AWS organization, providing centralized security monitoring.
3. To evade detection, the attacker attempts to break GuardDuty's centralized visibility.
4. If the attacker controls a member account, they may call `DisassociateFromAdministratorAccount` to sever its connection to the GuardDuty administrator.
5. If the attacker controls the delegated administrator account, they might use `DeleteMembers` or `StopMonitoringMembers` to selectively remove or cease monitoring specific member accounts.
6. Alternatively, the attacker could use `DeleteInvitations` to prevent future GuardDuty association for pending accounts.
7. Upon successful execution of these API calls, the affected member accounts lose their connection to the central GuardDuty administrator, creating a blind spot.
8. The attacker can then operate within the disassociated accounts without generating alerts visible to the central security team, potentially leading to further exploitation or data exfiltration.

## Impact

The primary impact of this attack is a significant loss of centralized security visibility within an AWS organization. When GuardDuty member accounts are disassociated or cease to be monitored, any malicious activity occurring within those accounts will not be detected or alerted to the delegated administrator. This creates blind spots that attackers can exploit for extended periods, leading to undetected resource compromise, data exfiltration, or the deployment of persistent backdoors. Organizations may only discover the compromise much later, after significant damage has occurred, making incident response and recovery more complex and costly.

## Recommendation

* Deploy the provided Sigma rule to your SIEM and tune for your environment to detect successful GuardDuty member account manipulation.
* Restrict permissions for GuardDuty API calls such as `guardduty:DisassociateFromAdministratorAccount`, `guardduty:DeleteMembers`, `guardduty:StopMonitoringMembers`, `guardduty:DeleteInvitations`, and `guardduty:DisassociateMembers` to only authorized administrators following strict change management processes.
* Implement Service Control Policies (SCPs) within AWS Organizations to prevent member accounts from disassociating from GuardDuty administrators, providing an additional layer of defense.
* Enable and configure Security Hub controls to detect and alert on changes to GuardDuty organization configurations.
* Investigate the `aws.cloudtrail.user_identity.arn` and `source.ip` from events matching the Sigma rule to identify who performed the action and their access patterns, correlating with change tickets or migration documentation.
