---
title: Detection of Rare AWS SNS Protocol Subscriptions
slug: 2026-08-aws-sns-rare-protocol
description: Adversaries may exploit AWS SNS by subscribing to topics using rare or unauthorized protocols to exfiltrate sensitive data or establish command-and-control communication channels.
date: "2026-08-24T09:47:41Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - cloud
  - aws
  - exfiltration
  - sns
  - cloud-security
vendors:
  - Amazon
products:
  - AWS Simple Notification Service (SNS)
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: Adversaries may subscribe to an SNS topic to collect sensitive information or exfiltrate data via an external email address, cross-account AWS service or other means.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage
    evidence: Adversaries may subscribe to an SNS topic to collect sensitive information.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1496
    technique_name: Resource Hijacking
    evidence: Adversaries may subscribe to an SNS topic to ... exfiltrate data via ... cross-account AWS service like Lambda.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1102
    technique_name: Web Service
    evidence: Adversaries may subscribe to an SNS topic to ... exfiltrate data via ... cross-account AWS service or other means.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/sns/latest/api/API_Subscribe.html
  - https://permiso.io/blog/s/smishing-attack-on-aws-sms-new-phone-who-dis/
  - https://www.sentinelone.com/labs/sns-sender-active-campaigns-unleash-messaging-spam-through-the-cloud/
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Review CloudTrail logs for unexpected sns:Subscribe events targeting sensitive topics.
      owner: SOC
      due: 48h
      evidence: Source documentation identifies SNS subscription as a potential vector for exfiltration.
  hunt_leads:
    - lead: Identify new SNS protocols used by non-human IAM roles.
      technique_id: T1567
      data_needed:
        - AWS CloudTrail logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Rule documentation explicitly identifies new protocol usage as an indicator of potential hijacking.
  mitigation_plan:
    - priority: medium_term
      action: Implement IAM least-privilege for SNS subscription actions.
      owner: IT Operations
      addresses: T1496.004
      evidence: Source documentation recommends policy review to prevent unauthorized subscriptions.
---

Adversaries may abuse the AWS Simple Notification Service (SNS) subscription mechanism to exfiltrate information or collect sensitive data. By subscribing an external, attacker-controlled endpoint - such as an email address, mobile number, or cross-account Lambda function - to an existing SNS topic, an attacker can gain unauthorized access to notification streams. This activity often involves creating a new subscription with an uncommon protocol that deviates from established operational norms within an AWS environment.

Because SNS is a legitimate service used for inter-service communication and alerting, this technique allows attackers to mask data exfiltration as benign message routing. Detection is challenging due to the inherent flexibility of SNS, but monitoring for "new terms" (previously unseen protocol/user combinations) within CloudTrail logs can provide visibility into deviations from standard administrative behavior. This is particularly relevant when such actions originate from non-human identities or roles that do not typically manage notification infrastructure.

## Impact

Successful exploitation allows for the unauthorized exfiltration of sensitive data contained within SNS notification messages, the collection of system alerts by external third parties, or the potential for resource hijacking via cross-account service execution. Organizations may suffer data leakage or the integration of malicious infrastructure into their internal notification chains, leading to potential operational disruption or compliance violations.

## Recommendation

* Deploy the detection logic focusing on `aws.cloudtrail` events with `event.action: Subscribe` to identify new protocol usage by specific users.
* Audit existing SNS subscriptions periodically to ensure endpoints match known and authorized external or internal resources.
* Restrict IAM permissions for the `sns:Subscribe` action to only those identities and roles that require them for legitimate operational workflows.
* Investigate any detected subscriptions that utilize non-standard protocols (e.g., protocols rarely used in the environment) in conjunction with other suspicious CloudTrail activity like unauthorized S3 access.
