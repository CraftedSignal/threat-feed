---
title: Detection of Unauthorized AWS WAF Rule Deletion
slug: 2026-09-aws-waf-rule-deletion
description: Adversaries may delete AWS WAF rules or rule groups via API to impair security boundaries and facilitate follow-on exploitation of web applications.
date: "2026-09-18T19:29:11Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - defense-evasion
vendors:
  - Amazon
products:
  - AWS WAF
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Adversaries who have gained sufficient permissions may remove WAF protections as part of a broader defense evasion or impact strategy.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/waf/latest/APIReference/API_waf_DeleteRule.html
  - https://docs.aws.amazon.com/waf/latest/APIReference/API_waf_DeleteRuleGroup.html
rules:
  - title: Detect Unauthorized AWS WAF Rule or Rule Group Deletion
    description: Detects successful DeleteRule or DeleteRuleGroup API calls in CloudTrail, excluding known CI/CD automation tools like Terraform or Pulumi.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.007
    data_sources:
      - cloudtrail
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to SIEM and tune against known CI/CD automation tools.
      owner: Detection Engineering
      due: 48h
      evidence: Rule documentation and KQL query provided in the source.
  mitigation_plan:
    - priority: immediate
      action: Restrict IAM permissions for waf:DeleteRule and waf:DeleteRuleGroup to strictly controlled service principals.
      owner: IT Operations
      addresses: T1562.007
      evidence: Recommendation section of the source content.
---

The deletion of AWS WAF rules and rule groups represents a deliberate effort to impair an organization's defensive posture. By removing these protections, adversaries can bypass rate-limiting, access controls, and signature-based filtering for SQL injection, cross-site scripting (XSS), and credential-stuffing attacks. This behavior is often observed in the reconnaissance or pre-exploitation phase of a breach, where attackers attempt to erase defenses protecting high-value APIs or specific application endpoints. 

Defenders should monitor AWS CloudTrail logs for `DeleteRule` or `DeleteRuleGroup` events originating from unexpected principals, sources, or automation tools. While some organizations utilize infrastructure-as-code (IaC) to manage WAF lifecycles, unauthorized deletions - especially those occurring outside of CI/CD windows - should be treated as high-priority security incidents. The scope of this threat is global across all AWS accounts utilizing WAF for web protection.

## Impact

Successful unauthorized deletion of WAF rules leaves web applications exposed to direct exploitation. Observed consequences include the bypass of established security boundaries, enabling attackers to execute malicious payloads that were previously blocked, potentially leading to unauthorized data exfiltration, service disruption, or complete application compromise.

## Recommendation

- Deploy the provided Sigma rule to detect unauthorized WAF API activity in CloudTrail logs.
- Establish a baseline for authorized WAF maintenance; monitor and alert on deletions that originate outside of established CI/CD service roles (e.g., Terraform or Pulumi).
- Implement service control policies (SCPs) or AWS Config rules to prevent the modification or deletion of WAF resources in production environments.
- Audit IAM permissions to ensure that the principle of least privilege is applied, specifically restricting `waf:DeleteRule` and `waf:DeleteRuleGroup` permissions to highly restricted administration roles.
- Integrate CloudTrail event analysis into incident response playbooks for immediate verification of WAF changes.
