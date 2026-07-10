---
title: AWS WAF Rule or Rule Group Deletion
slug: 2024-01-09-aws-waf-deletion
description: Detection of AWS WAF rule or rule group deletions, which can weaken web application security and expose applications to various attacks.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - waf
  - defense-evasion
  - cloud
vendors:
  - AWS
products:
  - AWS WAF
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://docs.aws.amazon.com/waf/latest/APIReference/API_waf_DeleteRule.html
  - https://docs.aws.amazon.com/waf/latest/APIReference/API_waf_DeleteRuleGroup.html
rules:
  - title: AWS WAF Rule Deletion
    description: Detects deletion of AWS WAF Rules via CloudTrail logs.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.007
    data_sources:
      - cloudtrail
      - aws
  - title: AWS WAF Rule Group Deletion
    description: Detects deletion of AWS WAF Rule Groups via CloudTrail logs.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.007
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This threat brief focuses on the deletion of AWS Web Application Firewall (WAF) rules or rule groups. AWS WAF rules and rule groups are essential for protecting web applications by filtering malicious HTTP requests, blocking known attack patterns, and enforcing access controls. The deletion of these rules, even temporarily, can expose applications to significant risks, including SQL injection, cross-site scripting, and credential stuffing. Threat actors with sufficient permissions may remove WAF protections as part of a defense evasion or impact strategy, with the goal of data theft or application compromise. The focus is on detecting successful `DeleteRule` or `DeleteRuleGroup` API calls within CloudTrail logs.

## Attack Chain

1. **Initial Access:** The attacker gains access to an AWS account with sufficient permissions to modify WAF configurations. This could be achieved through compromised credentials or an IAM role with excessive privileges.
2. **Privilege Escalation (Optional):** If the initial access lacks the necessary permissions, the attacker may attempt to escalate privileges within the AWS environment, potentially exploiting misconfigured IAM policies.
3. **Discovery:** The attacker enumerates existing WAF rules and rule groups within the targeted AWS account, identifying the rules that provide key protections for web applications.
4. **Defense Evasion:** The attacker deletes a WAF rule or rule group using the `DeleteRule` or `DeleteRuleGroup` API call, effectively disabling the protections it provided.
5. **Exploitation:** With the WAF rule removed, the attacker exploits vulnerabilities in the web application that were previously protected by the rule. This could involve SQL injection, cross-site scripting, or other attack vectors.
6. **Data Exfiltration (Optional):** If the exploitation is successful, the attacker may exfiltrate sensitive data from the compromised web application or its backend systems.
7. **Impact:** The attacker achieves their objective, which could include data theft, application compromise, or denial of service.

## Impact

Successful deletion of WAF rules can have significant consequences, potentially affecting numerous web applications and their users. The number of affected applications and users depends on the scope of the deleted rules and the criticality of the protected applications. If an attack succeeds, organizations may experience data breaches, financial losses, reputational damage, and regulatory fines.

## Recommendation

*   Enable AWS CloudTrail logging and monitor for `DeleteRule` and `DeleteRuleGroup` API calls to detect WAF rule deletions (reference: query in the source).
*   Implement the Sigma rule `AWS WAF Rule Deletion` to identify suspicious WAF rule deletion activity (reference: Sigma rule below).
*   Implement the Sigma rule `AWS WAF Rule Group Deletion` to identify suspicious WAF rule group deletion activity (reference: Sigma rule below).
*   Review IAM policies to ensure that only authorized users and roles have permissions to modify WAF configurations.
*   Implement multi-factor authentication (MFA) for all AWS accounts, especially those with privileged access.
