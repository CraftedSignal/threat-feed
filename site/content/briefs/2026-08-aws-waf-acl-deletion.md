---
title: AWS WAF Web ACL Deletion Defense Evasion
slug: 2026-08-aws-waf-acl-deletion
description: Adversaries with high-level privileges may delete AWS Web Application Firewall (WAF) Web ACLs to disable security controls and facilitate unauthorized access to protected applications.
date: "2026-08-24T09:46:47Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - cloud-security
  - aws
  - waf
vendors:
  - Amazon
products:
  - AWS WAF
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Adversaries who obtain sufficient privileges may delete a Web ACL to disable critical security controls, evade detection, or prepare for downstream attacks.
    confidence_band: high
references:
  - https://docs.aws.amazon.com/waf/latest/APIReference/API_DeleteWebACL.html
  - https://docs.aws.amazon.com/waf/latest/APIReference/API_wafRegional_DeleteWebACL.html
rules:
  - title: Detect AWS WAF Access Control List Deletion
    description: Detects successful deletion of AWS WAF Web ACLs, potentially indicating defense evasion by an adversary.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.007
    data_sources:
      - cloud_management
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided Sigma rule to detect unauthorized WAF ACL deletions.
      owner: Detection Engineering
      due: 48h
      evidence: Rule defined in brief content
  mitigation_plan:
    - priority: immediate
      action: Review IAM policies to ensure 'waf:DeleteWebACL' is restricted to minimal, essential roles.
      owner: IT Operations
      addresses: T1562.007
      evidence: Source IR Playbooks recommendations
---

Adversaries with compromised administrative credentials may target AWS Web Application Firewall (WAF) configurations as a means of defense evasion. By deleting a Web ACL, an attacker removes the security policies, rule groups, and logging configurations protecting critical cloud resources such as CloudFront distributions, Application Load Balancers, API Gateways, and AppSync APIs. This action effectively disables traffic inspection, exposing the application to direct exploitation, data theft, or resource abuse without triggering traditional application-layer alerts. 

This activity is rarely performed manually outside of planned maintenance or automated infrastructure pipelines, making unexpected deletions a significant indicator of potential compromise. Security teams should monitor for unauthorized 'DeleteWebACL' events, particularly when initiated by identities that do not typically manage WAF infrastructure or through unusual toolsets.

## Impact

Successful deletion of a Web ACL leaves the associated application entry points entirely unprotected by WAF rules, enabling unauthenticated attackers to probe for vulnerabilities, perform credential stuffing, or exploit application-layer weaknesses. If not detected and remediated immediately, this can lead to data exfiltration, service disruption, or complete system compromise, depending on the sensitivity of the exposed backend services.

## Recommendation

* Deploy the Sigma rule provided in this brief to detect unauthorized 'DeleteWebACL' API calls in AWS CloudTrail logs.
* Restrict the IAM permission 'waf:DeleteWebACL' and 'wafv2:DeleteWebACL' to a minimal set of highly trusted roles or service accounts.
* Implement Multi-Factor Authentication (MFA) for all administrative identities with permissions to modify WAF resources.
* Integrate AWS Config or Security Hub to alert on modifications to WAF Web ACLs that bypass standard IaC deployment workflows.
* Baseline 'user_agent' strings and source IP addresses associated with infrastructure-as-code (IaC) tools like Terraform or Pulumi to differentiate automated updates from manual malicious activity.
