---
title: Detection of AWS SES Identity Verify-Use-Delete Abusive Pattern
slug: 2026-08-aws-ses-abuse
description: Adversaries with unauthorized access to AWS Simple Email Service (SES) credentials may verify an attacker-controlled identity, send phishing or spam emails, and promptly delete the identity to evade detection and attribution.
date: "2026-08-31T17:52:25Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - ses
  - resource-development
  - defense-evasion
vendors:
  - Amazon
products:
  - Simple Email Service (SES)
mitre_ttps:
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1583
    technique_name: Acquire Infrastructure
    evidence: An adversary who obtains SES credentials may verify a domain or address they control, use it to send phishing or spam email, then delete the identity to remove evidence.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: An adversary who obtains SES credentials may... delete the identity to remove evidence of the sending domain from the account's verified identity list.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/ses/latest/APIReference/API_VerifyEmailIdentity.html
  - https://docs.aws.amazon.com/ses/latest/APIReference/API_DeleteIdentity.html
  - https://permiso.io/blog/s/aws-ses-pionage-detecting-ses-abuse/
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy detection logic to monitor for Verify-then-Delete SES identity patterns in CloudTrail.
      owner: Detection Engineering
      due: 72h
      evidence: Source provides specific ESQL rule for detecting this pattern.
  mitigation_plan:
    - priority: immediate
      action: Restrict SES management permissions (Verify/Delete actions) to a dedicated IAM role.
      owner: IT Operations
      addresses: T1583.001
      evidence: Standard IAM best practice to reduce the blast radius of compromised credentials.
---

Adversaries who obtain unauthorized AWS credentials with SES permissions often abuse the service to send bulk unsolicited email using the victim account's reputation and sending quota. To minimize the forensic footprint, attackers employ a specific 'verify-use-delete' technique. This involves programmatically verifying a domain or email identity they control, utilizing the account to send malicious traffic, and subsequently deleting the identity within a short timeframe (typically under 30 minutes). This deletion removes the evidence from the account's verified identity list, complicating post-incident forensic review and attribution. Defenders must monitor CloudTrail management events to identify this rapid lifecycle of SES identities.

## Attack Chain

1. Attacker gains unauthorized access to AWS credentials with SES write permissions (e.g., via leaked access keys or compromised IAM roles).
2. Attacker calls `VerifyDomainIdentity` or `VerifyEmailIdentity` to register an attacker-controlled domain or email address within the victim's AWS environment.
3. Attacker completes the domain verification process (e.g., via DNS record validation).
4. Attacker uses the `SendEmail` or `SendRawEmail` API actions to dispatch phishing or spam campaigns using the victim's reputation.
5. Attacker calls `DeleteIdentity` to remove the domain or email address from the account.
6. Victim's list of verified SES identities no longer shows the attacker's domain, effectively hiding the configuration used for the malicious campaign.

## Impact

Successful abuse of AWS SES results in the degradation of the victim account's email sender reputation, potential blacklisting by major email providers, and utilization of the organization's email sending quotas for malicious activities. Furthermore, the rapid deletion of identities hinders security teams' ability to perform root cause analysis and attribute the campaign to a specific domain or sender, potentially leading to persistent or recurring abuse.

## Recommendation

- Implement the detection logic provided in this brief to alert on the verify-then-delete pattern observed in CloudTrail logs.
- Restrict the `ses:VerifyEmailIdentity`, `ses:VerifyDomainIdentity`, and `ses:DeleteIdentity` IAM actions to a dedicated SES-management role using Least Privilege principles.
- Enable SES sending quotas and configured alerts to identify anomalous traffic spikes in real time.
- Review all SES management events if a sudden drop in account sender reputation or an abuse complaint from an external provider is identified.
