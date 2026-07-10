---
title: AWS Security Services Impairment via Deletion Operations
slug: 2024-01-aws-security-services-impairment
description: Attackers attempt to impair or disable AWS security services such as GuardDuty, WAF, CloudWatch, Route 53 and CloudWatch Logs by deleting detectors, rule groups, IP sets, web ACLs, logging configurations, alarms and log streams, in order to evade detection and operate undetected.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - aws
  - cloudtrail
  - defense-evasion
vendors:
  - AWS
products:
  - AWS GuardDuty
  - AWS WAF
  - AWS CloudWatch
  - AWS CloudWatch Logs
  - AWS Route 53
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://docs.aws.amazon.com/cli/latest/reference/guardduty/index.html
  - https://docs.aws.amazon.com/cli/latest/reference/waf/index.html
  - https://www.elastic.co/guide/en/security/current/prebuilt-rules.html
rules:
  - title: AWS Defense Evasion Impair Security Services
    description: Detects attempts to impair or disable AWS security services by monitoring deletion operations across GuardDuty, AWS WAF, CloudWatch, Route 53, and CloudWatch Logs.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
  - title: AWS CloudWatch Alarm Deletion
    description: Detects the deletion of CloudWatch Alarms which could indicate an attempt to evade detection.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
  - title: AWS Log Stream Deletion
    description: Detects the deletion of CloudWatch Log Streams.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
rules_count: 3
---

This threat brief focuses on adversaries attempting to impair or disable AWS security services to evade detection and maintain persistence within a compromised environment. The activity involves deleting critical security components across GuardDuty, AWS WAF (classic and v2), CloudWatch, Route 53, and CloudWatch Logs. These operations include deleting detectors, rule groups, IP sets, web ACLs, logging configurations, alarms, and log streams. The attacks leverage valid AWS credentials (either compromised or belonging to a rogue insider) to make legitimate API calls that have the effect of disabling security monitoring. The impact can be significant, as successful impairment of these services allows attackers to operate undetected, potentially escalating privileges, exfiltrating sensitive data, or deploying ransomware without triggering security alerts. This activity is observed via AWS CloudTrail logs, specifically monitoring for "Delete" operations targeting core security services. The scope of this threat covers any AWS environment utilizing these services.

## Attack Chain

1.  The attacker gains initial access to the AWS environment, either through compromised credentials, a rogue insider, or exploiting a misconfiguration.
2.  The attacker enumerates existing AWS security services to identify potential targets for impairment, such as GuardDuty detectors, WAF ACLs, or CloudWatch alarms.
3.  The attacker attempts to delete GuardDuty detectors using the `DeleteDetector` API call (eventSource: guardduty.amazonaws.com).
4.  The attacker removes AWS WAF rule groups, IP sets, and Web ACLs using the `DeleteRuleGroup`, `DeleteIPSet`, and `DeleteWebACL` API calls (eventSource: wafv2.amazonaws.com, waf.amazonaws.com).
5.  The attacker deletes CloudWatch logging configurations and alarms using the `DeleteLoggingConfiguration` (eventSource: route53.amazonaws.com, wafv2.amazonaws.com, waf.amazonaws.com) and `DeleteAlarms` API calls.
6.  The attacker may delete CloudWatch Log Streams using the `DeleteLogStream` API call.
7.  With security services impaired, the attacker performs malicious activities, such as data exfiltration, lateral movement, or deploying ransomware, with reduced risk of detection.
8.  The attacker attempts to maintain persistence within the AWS environment by creating new IAM users or roles or modifying existing ones.

## Impact

Successful execution of this attack can lead to a significant degradation of the AWS environment's security posture. This allows attackers to operate undetected, escalating privileges, and exfiltrating data or deploying ransomware without triggering security alerts. Organizations may face significant financial losses, reputational damage, and regulatory penalties due to data breaches and service disruptions. Observed damage includes disabled security logging, deleted detection rules, and a general loss of visibility into malicious activity within the AWS environment. The number of potential victims is vast, encompassing any organization utilizing the affected AWS security services.

## Recommendation

*   Enable AWS CloudTrail logging and ensure logs are being ingested into your SIEM to monitor for API calls related to deleting security services.
*   Deploy the Sigma rule "AWS Defense Evasion Impair Security Services" to your SIEM to detect attempts to disable security services. Tune the rule for known-good administrator activity (e.g., filtering based on user agent or ARN) to reduce false positives.
*   Implement multi-factor authentication (MFA) for all AWS accounts, especially those with administrative privileges, to reduce the risk of compromised credentials.
*   Enforce the principle of least privilege by granting users only the necessary permissions to perform their tasks, minimizing the potential impact of compromised credentials.
*   Review and audit IAM policies regularly to identify and remediate overly permissive permissions that could be abused by attackers.
*   Implement infrastructure-as-code practices and version control for AWS infrastructure to easily detect and revert unauthorized changes.
