---
title: AWS Security Services Configuration Deletion
slug: 2024-01-03-aws-security-services-deletion
description: Detection of deletion of critical AWS Security Services configurations like CloudWatch alarms, GuardDuty detectors, and Web Application Firewall rules to evade detection, potentially leading to data breaches and unauthorized access.
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
  - security-service
vendors:
  - Amazon
  - Splunk
products:
  - CloudWatch
  - GuardDuty
  - Web Application Firewall
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
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
  - title: AWS Security Services Deletion via CloudTrail
    description: Detects the deletion of AWS security services such as CloudWatch alarms, GuardDuty detectors, and WAF rules by monitoring relevant CloudTrail API calls.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
  - title: AWS Security Services Deletion via ASL
    description: Detects deletion of AWS Security Services via Amazon Security Lake logs.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.008
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This threat brief addresses the tactic of adversaries deleting critical AWS security service configurations to evade detection. This includes deleting CloudWatch alarms, GuardDuty detectors, and Web Application Firewall (WAF) rules. The activity is identified through specific API calls such as "DeleteLogStream", "DeleteDetector", "DeleteIPSet", "DeleteWebACL", "DeleteRule", "DeleteRuleGroup", "DeleteLoggingConfiguration", and "DeleteAlarms" within Amazon Security Lake logs. By successfully removing or impairing these services, attackers can operate undetected within an AWS environment, increasing the risk of data breaches, unauthorized access, and persistent compromise. The scope includes any AWS environment utilizing the mentioned security services and logging via Amazon Security Lake.

## Attack Chain

1.  **Initial Access:** The attacker gains initial access to the AWS environment, potentially through compromised credentials or exploiting a vulnerability.
2.  **Privilege Escalation:** The attacker escalates privileges to obtain the necessary permissions to modify or delete security service configurations.
3.  **Discovery:** The attacker enumerates existing security configurations, such as CloudWatch alarms, GuardDuty detectors, and WAF rules, to identify targets for deletion.
4.  **Defense Evasion - Service Deletion:** The attacker executes API calls like `DeleteLogStream`, `DeleteDetector`, `DeleteIPSet`, `DeleteWebACL`, `DeleteRule`, `DeleteRuleGroup`, `DeleteLoggingConfiguration`, or `DeleteAlarms` to delete security service configurations.
5.  **Persistence:** With security monitoring impaired, the attacker establishes persistence mechanisms, such as creating new IAM users or roles with excessive permissions, or deploying backdoors within EC2 instances.
6.  **Lateral Movement:** The attacker moves laterally through the AWS environment, accessing sensitive data and resources.
7.  **Data Exfiltration:** The attacker exfiltrates sensitive data from the compromised AWS environment.
8.  **Impact:** The attacker achieves their objective, which could include data theft, disruption of services, or financial gain.

## Impact

Successful deletion of AWS security services can have severe consequences, potentially affecting any organization using AWS. Consequences range from data breaches and unauthorized resource access to prolonged persistence of malicious actors within the AWS environment. The number of affected victims and the scope of damage depends on the scale of the AWS environment and the sensitivity of the data stored within. Organizations in all sectors are potentially at risk.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect the deletion of critical AWS security service configurations based on Amazon Security Lake logs.
*   Investigate any identified instances of API calls related to the deletion of security services (e.g., "DeleteLogStream", "DeleteDetector") using the provided Sigma rule.
*   Implement multi-factor authentication (MFA) for all IAM users and roles to reduce the risk of compromised credentials.
*   Review and restrict IAM policies to ensure that users and roles have only the necessary permissions to perform their duties.
*   Monitor CloudTrail logs for unusual activity, such as unexpected API calls or changes to IAM policies.
*   Regularly audit AWS security configurations to ensure that they are properly configured and maintained.
