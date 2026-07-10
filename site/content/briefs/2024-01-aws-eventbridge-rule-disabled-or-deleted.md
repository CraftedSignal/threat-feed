---
title: AWS EventBridge Rule Disabled or Deleted
slug: 2024-01-aws-eventbridge-rule-disabled-or-deleted
description: Detection of Amazon EventBridge rule disabling or deletion events, which can disrupt operational workflows and security monitoring.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - aws
  - eventbridge
  - impact
  - defense-evasion
vendors:
  - Amazon Web Services
products:
  - EventBridge
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1489
    technique_name: Service Stop
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_DeleteRule.html
  - https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_DisableRule.html
  - https://attack.mitre.org/techniques/T1489/
  - https://attack.mitre.org/techniques/T1562/
  - https://attack.mitre.org/techniques/T1562/001/
rules:
  - title: AWS EventBridge Rule Disabled or Deleted via CloudTrail
    description: Detects when an Amazon EventBridge rule is disabled or deleted via AWS CloudTrail logs.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - impact
    techniques:
      - T1489
      - T1562.001
    data_sources:
      - cloudtrail
      - aws
  - title: AWS EventBridge DeleteRule with specific User Agent
    description: Detects DeleteRule events from AWS EventBridge with suspicious User Agent.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - impact
    techniques:
      - T1489
      - T1562.001
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection identifies when an Amazon EventBridge rule is disabled or deleted. EventBridge rules automate operational workflows and forward security-relevant events to services like Lambda, SNS, or security tools. Disabling or deleting a rule can break integrations, suppress detections, and reduce visibility, potentially allowing adversaries to impair monitoring, delay incident response, or hide malicious activity. The actions of `DeleteRule` or `DisableRule` are monitored to identify suspicious activity related to event rules within AWS environments.

## Attack Chain

1. An attacker gains access to an AWS account with sufficient permissions to manage EventBridge rules, potentially through compromised credentials or an IAM role with excessive privileges.
2. The attacker enumerates existing EventBridge rules to identify those that are critical for security monitoring or incident response.
3. The attacker executes the `DisableRule` API call to temporarily stop a targeted EventBridge rule from processing events.
4. Alternatively, the attacker executes the `DeleteRule` API call to permanently remove the targeted EventBridge rule.
5. The CloudTrail logs record the `DisableRule` or `DeleteRule` event, including the user identity, timestamp, and affected rule details.
6. If the deleted or disabled rule was responsible for forwarding security events (e.g., CloudTrail findings, GuardDuty alerts) to a SIEM or other security tool, the flow of alerts is disrupted.
7. The attacker leverages the gap in monitoring to perform further malicious activities within the AWS environment without immediate detection.
8. The final objective is to maintain persistence, escalate privileges, or exfiltrate data without triggering alerts, taking advantage of the disabled or deleted EventBridge rule.

## Impact

Disabling or deleting EventBridge rules can disrupt critical security monitoring and incident response workflows, creating blind spots in detection coverage. Depending on the affected rule, this can lead to delayed detection of security incidents, allowing attackers to perform malicious activities undetected. A successful attack could lead to data breaches, unauthorized access to resources, or other security compromises. The severity of the impact depends on the criticality of the disabled or deleted rule and the scope of its responsibilities.

## Recommendation

*   Deploy the Sigma rule provided to detect `DeleteRule` or `DisableRule` events within CloudTrail logs, and tune it to your environment.
*   Restrict `events:DisableRule` and `events:DeleteRule` permissions to a small set of administrative roles using IAM conditions to reduce the likelihood of silent impairment.
*   Monitor `aws.cloudtrail.user_identity.arn` and `aws.cloudtrail.user_identity.access_key_id` to identify which principal performed the change.
*   Restore critical rules immediately by re-enabling disabled rules or recreating deleted rules from known-good baselines if the activity is unauthorized.
