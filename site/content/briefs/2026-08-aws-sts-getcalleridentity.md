---
title: Detection of Unauthorized AWS STS GetCallerIdentity Discovery
slug: 2026-08-aws-sts-getcalleridentity
description: Adversaries with compromised credentials may abuse the AWS STS GetCallerIdentity API to verify access and identify the current account context, serving as a primary indicator of initial cloud reconnaissance.
date: "2026-08-24T09:47:07Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - cloudtrail
  - discovery
  - credential-abuse
vendors:
  - Amazon
products:
  - AWS Security Token Service
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1033
    technique_name: System Owner/User Discovery
    evidence: This rule looks for the first time an identity has called the STS GetCallerIdentity API, which may be an indicator of compromised credentials.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
    evidence: The GetCallerIdentity API returns details about the IAM user or role owning the credentials used to perform the operation.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html
  - https://www.secureworks.com/research/detecting-the-use-of-stolen-aws-lambda-credentials
  - https://detectioninthe.cloud/ttps/discovery/sts_get_caller_identity
rules:
  - title: AWS STS GetCallerIdentity API Called for the First Time
    description: Detects the first time an IAM identity calls the GetCallerIdentity API, which may indicate account discovery by an attacker using stolen credentials.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1033
      - T1087.004
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy the Sigma rule to monitor for GetCallerIdentity usage.
      owner: Detection Engineering
      due: 48h
      evidence: Rule ID 30fbf4db-c502-4e68-a239-2e99af0f70da.
  enrichment_needed:
    - item: Known-good service account list
      owner: SOC
      reason: To tune out legitimate automation tools and reduce noise.
      evidence: False positive analysis section of the brief.
  hunt_leads:
    - lead: Analyze CloudTrail logs for GetCallerIdentity usage in the past 48 hours for anomalous user agents.
      technique_id: T1087.004
      data_needed:
        - CloudTrail logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Investigative guidance provided in the source.
  mitigation_plan:
    - priority: short_term
      action: Enable MFA for all IAM users and apply least-privilege policies.
      owner: IT Operations
      addresses: Account compromise mitigation
      evidence: Response and remediation section.
---

Adversaries frequently target AWS environments by leveraging stolen IAM credentials to conduct discovery and lateral movement. A common reconnaissance tactic is the use of the AWS Security Token Service (STS) `GetCallerIdentity` API, which provides details about the IAM user or role associated with the credentials currently in use. This operation requires no specific permissions and returns consistent information even if access to other resources is denied, making it a low-noise method for attackers to verify if their hijacked credentials are valid and to map their current environment context. This threat is particularly concerning because legitimate human users rarely need to call this API, as they are typically aware of the account context in which they are operating. Monitoring for the first-time usage of this API by specific identities provides a reliable signal for identifying credential abuse, provided that automated service accounts are appropriately tuned out of the detection logic.

## Impact

Successful abuse of the `GetCallerIdentity` API indicates that an attacker has gained a functional foothold in an AWS account using compromised credentials. This discovery phase allows the attacker to confirm their access level before proceeding with more aggressive actions, such as resource enumeration, sensitive data exfiltration, or persistence establishment. If undetected, this initial access can lead to significant data breaches and unauthorized control over cloud infrastructure.

## Recommendation

Detection engineering teams should implement monitoring for the `GetCallerIdentity` event within AWS CloudTrail, specifically focusing on the first instance of an identity performing this call.

* Deploy the provided detection logic to your SIEM to alert on anomalous `GetCallerIdentity` calls from non-service identities.
* Establish a baseline of known-good service accounts and automated tooling that legitimately use this API to reduce false positives.
* Integrate CloudTrail logs with security analytics platforms and tune alerts by excluding known `user_agent.original` strings associated with infrastructure-as-code tools like Terraform or Pulumi.
* Conduct periodic reviews of IAM permissions and enable multi-factor authentication (MFA) for all IAM users to mitigate the risk of credential compromise.
