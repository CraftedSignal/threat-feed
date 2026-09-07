---
title: Detection of Anomalous AWS Service Quota Increases
slug: 2026-09-aws-quota-increase
description: Adversaries with compromised AWS credentials may request service quota increases to facilitate large-scale malicious operations, detectable by identifying rare identities invoking the RequestServiceQuotaIncrease API.
date: "2026-09-07T10:42:30Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - resource-development
  - cloudtrail
vendors:
  - Amazon
products:
  - AWS Service Quotas
mitre_ttps:
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1583
    technique_name: Acquire Infrastructure
    evidence: An adversary who obtains AWS credentials may request quota increases as infrastructure preparation for large-scale cryptomining, DDoS amplification, phishing campaigns, or data exfiltration operations.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/servicequotas/2019-06-24/apireference/API_RequestServiceQuotaIncrease.html
  - https://www.rapid7.com/blog/post/dr-threat-actors-aws-workmail-phishing-campaigns/
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review existing AWS CloudTrail logging for RequestServiceQuotaIncrease events
      owner: Detection Engineering
      due: 48h
      evidence: Source indicates Service Quotas management events are logged by default.
  mitigation_plan:
    - priority: medium_term
      action: Implement Service Control Policies (SCP) to restrict quota increase requests to approved roles
      owner: Cloud Security
      addresses: Unauthorized quota modification
      evidence: Suggested response and remediation steps in source.
---

Adversaries who obtain AWS credentials often perform resource development as a prerequisite for larger campaigns. By requesting AWS Service Quota increases, attackers can bypass default account limits that are intended to prevent runaway resource consumption. Increasing these limits allows for the deployment of industrial-scale infrastructure for activities such as cryptomining, DDoS amplification, high-volume phishing through Amazon SES, or large-scale credential stuffing using Lambda. 

Defenders should monitor the AWS Service Quotas API for the 'RequestServiceQuotaIncrease' action, specifically focusing on identities that have no recent history (within a 7-day window) of performing such requests. Because legitimate cloud infrastructure teams also perform these tasks, filtering by common Infrastructure-as-Code (IaC) toolsets like Terraform, Pulumi, or Ansible is critical to reduce false positives.

## Impact

Successful exploitation of service quotas enables attackers to scale malicious operations beyond the organization's expected capacity. This can lead to significant financial costs due to unauthorized resource usage, increased exposure to downstream abuse reports for phishing, or the compromise of internal data through high-bandwidth exfiltration channels.

## Recommendation

Detection engineering teams should implement monitoring for rare AWS Service Quota increase requests to identify potential malicious infrastructure preparation.

* Deploy detection logic to monitor 'RequestServiceQuotaIncrease' events in AWS CloudTrail for identities without a 7-day history of this API call.
* Filter out service principals or IAM roles used by known IaC tools (e.g., Terraform, Pulumi, Ansible) to minimize noise.
* Investigate triggered alerts by cross-referencing the requesting identity with recent activity in the affected services (EC2, Lambda, SES).
* Use AWS Service Control Policies (SCPs) to restrict 'servicequotas:RequestServiceQuotaIncrease' to authorized cloud-operations roles only.
