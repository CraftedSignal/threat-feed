---
title: Abuse of AWS SES Account-Level Email Sending
slug: 2026-09-aws-ses-abuse
description: Threat actors with compromised AWS credentials may enable account-level email sending in Amazon SES to restore suspended infrastructure for mass phishing campaigns.
date: "2026-09-08T07:31:36Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - resource-development
  - ses
vendors:
  - Amazon
products:
  - AWS SES
mitre_ttps:
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1608
    technique_name: Stage Capabilities
    evidence: An attacker who compromises an AWS account may re-enable sending to restore a paused capability as part of phishing infrastructure setup.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/ses/latest/APIReference/API_UpdateAccountSendingEnabled.html
  - https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_PutAccountSendingAttributes.html
  - https://permiso.io/blog/s/aws-ses-pionage-detecting-ses-abuse/
  - https://www.rapid7.com/blog/post/dr-threat-actors-aws-workmail-phishing-campaigns/
rules:
  - title: Detect AWS SES Account Email Sending Enabled
    description: Detects unauthorized activation of SES account-level email sending via CloudTrail management APIs.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1608
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
    - action: Deploy Sigma rule to identify unauthorized SES sending activations.
      owner: Detection Engineering
      due: 24h
      evidence: Source provides explicit API actions for detection.
  hunt_leads:
    - lead: Search CloudTrail logs for ses:UpdateAccountSendingEnabled or ses:PutAccountSendingAttributes events.
      technique_id: T1608
      data_needed:
        - CloudTrail Management Events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: These APIs are rarely called in standard production operations.
  mitigation_plan:
    - priority: immediate
      action: Restrict IAM permissions for SES configuration APIs to authorized personnel only.
      owner: IT Operations
      addresses: T1608
      evidence: Source notes that attackers require SES permissions to modify sending attributes.
---

Attackers who compromise AWS environments frequently seek to leverage existing cloud services for malicious operations. A specific tactic involves re-enabling email sending capabilities within Amazon Simple Email Service (SES). By invoking the v1 `UpdateAccountSendingEnabled` API or the v2 `PutAccountSendingAttributes` API, an attacker can override an existing administrative pause on email sending. This capability is critical for establishing phishing infrastructure that utilizes the victim organization's trusted, high-reputation domain to bypass email security filters. Because these APIs are rarely invoked in standard production environments, successful execution by unauthorized identities serves as a high-fidelity indicator of potential infrastructure staging for further abuse.

## Impact

Successful abuse of this capability allows attackers to conduct bulk email campaigns using the compromised entity's reputation, significantly increasing the probability of phishing success. This activity often precedes large-scale email fraud, brand impersonation, or credential theft campaigns, potentially leading to reputational damage and the blacklisting of the organization's legitimate sending domains by major mail providers.

## Recommendation

- Deploy the provided Sigma rule to monitor `aws.cloudtrail` logs for successful calls to `UpdateAccountSendingEnabled` or `PutAccountSendingAttributes` where the sending status is enabled.
- Establish an alert for any manual change to SES account sending status that does not correlate with an authorized change management ticket.
- Review SES sending statistics and identity configurations for unauthorized verified domains or templates immediately following any alert trigger.
- Ensure that IAM roles and users with `ses:UpdateAccountSendingEnabled` or `ses:PutAccountSendingAttributes` permissions are restricted according to the principle of least privilege.
