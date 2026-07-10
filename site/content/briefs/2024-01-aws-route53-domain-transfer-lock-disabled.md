---
title: AWS Route 53 Domain Transfer Lock Disabled
slug: 2024-01-aws-route53-domain-transfer-lock-disabled
description: The disabling of the transfer lock on an AWS Route 53 domain is detected, potentially indicating unauthorized domain transfer, takeover, or service disruption by an adversary gaining domain-management permissions.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - route53
  - domain-hijacking
  - persistence
vendors:
  - AWS
products:
  - Route 53
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1584
    technique_name: Compromise Infrastructure
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://docs.aws.amazon.com/Route53/latest/APIReference/API_Operations_Amazon_Route_53.html
  - https://docs.aws.amazon.com/Route53/latest/APIReference/API_domains_DisableDomainTransferLock.html
  - https://attack.mitre.org/techniques/T1098/
  - https://attack.mitre.org/techniques/T1584/
  - https://attack.mitre.org/techniques/T1584/001/
  - https://attack.mitre.org/techniques/T1562/
rules:
  - title: AWS Route 53 Domain Transfer Lock Disabled
    description: Detects when the transfer lock is disabled on an AWS Route 53 domain, which can be a precursor to unauthorized domain transfer.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
      - resource_development
    techniques:
      - T1098
      - T1562
      - T1584
      - T1584.001
    data_sources:
      - cloudtrail
      - aws
  - title: AWS Route53 Domain Transfer Initiated After Lock Disabled
    description: Detects domain transfer initiated within a short timeframe after disabling the transfer lock.
    platform: sigma
    severity: critical
    tactics:
      - persistence
      - resource_development
    techniques:
      - T1584.001
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

The disabling of a domain transfer lock within AWS Route 53 is a critical event that can signal malicious activity. The transfer lock is a security feature that prevents unauthorized transfer of a domain to another registrar or AWS account. An attacker who compromises an AWS account with sufficient permissions may disable this lock as a prerequisite for hijacking the domain, potentially leading to service disruption, data exfiltration, or brand damage. This activity is particularly concerning because domains underpin many critical services, including websites, email, and authentication mechanisms. The alert specifically triggers on the `DisableDomainTransferLock` event within AWS CloudTrail logs, providing visibility into this specific action. The targeted scope includes any AWS Route 53 domains managed by the organization.

## Attack Chain

1. **Initial Access:** An attacker gains unauthorized access to an AWS account, possibly through compromised credentials or an IAM role with excessive privileges (T1078, T1098).
2. **Privilege Escalation (if needed):** The attacker escalates privileges within the AWS environment to gain the necessary permissions to manage Route 53 domains (T1068).
3. **Discovery:** The attacker enumerates the Route 53 domains associated with the compromised AWS account (T1082).
4. **Disable Domain Transfer Lock:** The attacker disables the domain transfer lock for a target domain by calling the `DisableDomainTransferLock` API (T1584.001).
5. **Modify Contact Information:** The attacker changes the contact information associated with the domain to gain control over authorization emails (T1586).
6. **Initiate Domain Transfer:** The attacker initiates a transfer of the domain to a registrar or AWS account under their control (T1584.001).
7. **DNS Manipulation:** After the transfer, the attacker modifies DNS records to redirect traffic to malicious servers, enabling phishing attacks or data theft (T1584.001).
8. **Impact:** The attacker disrupts services, steals sensitive information, or conducts further attacks leveraging the hijacked domain.

## Impact

A successful domain hijacking can have severe consequences, including website defacement, email interception, and redirection of user traffic to malicious sites. Depending on the criticality of the domain, this could lead to significant financial losses, reputational damage, and legal liabilities. Organizations in all sectors are vulnerable, especially those heavily reliant on online services. The impact is amplified if the hijacked domain is used for authentication or other security-sensitive functions. Without proper detection and response, a domain hijacking can persist for an extended period, causing ongoing harm.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect instances of `DisableDomainTransferLock` events in AWS CloudTrail logs (logsource: aws.cloudtrail, event.action: DisableDomainTransferLock).
*   Immediately investigate any detected instances of disabled domain transfer locks, focusing on the user identity (`aws.cloudtrail.user_identity.arn`) and request parameters (`aws.cloudtrail.request_parameters`).
*   Enforce multi-factor authentication (MFA) for all AWS accounts, especially those with permissions to manage Route 53 domains.
*   Implement AWS Organizations service control policies (SCPs) to restrict domain-level actions to designated accounts, as mentioned in the overview.
*   Review and restrict domain-management permissions to the minimum set of authorized administrators as per the guide.
*   Monitor for modifications to contact details, attempted transfers, DNS record changes, or updates to hosted zones following lock disablement.
