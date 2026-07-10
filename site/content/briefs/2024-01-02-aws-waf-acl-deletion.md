---
title: AWS WAF Access Control List Deletion
slug: 2024-01-02-aws-waf-acl-deletion
description: Detection of AWS Web Application Firewall (WAF) Web ACL deletion, which adversaries may perform to disable security controls, evade detection, and prepare for subsequent attacks, potentially leading to web-application compromise, data theft, or resource abuse.
date: "2024-01-02T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - waf
  - defense-evasion
vendors:
  - AWS
products:
  - AWS WAF
  - AWS WAF Classic
  - AWS WAF Regional
  - AWS WAFv2
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://docs.aws.amazon.com/waf/latest/APIReference/API_DeleteWebACL.html
  - https://docs.aws.amazon.com/waf/latest/APIReference/API_wafRegional_DeleteWebACL.html
rules:
  - title: AWS WAF ACL Deletion via CloudTrail
    description: Detects deletion of AWS WAF ACL via CloudTrail logs
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.007
    data_sources:
      - cloudtrail
      - aws
      - cloudtrail
  - title: AWS WAF ACL Deletion Source IP Anomaly
    description: Detects WAF ACL Deletion from uncommon source IP addresses
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - discovery
    techniques:
      - T1016
      - T1562.007
    data_sources:
      - cloudtrail
      - aws
      - cloudtrail
rules_count: 2
---

This threat brief focuses on the detection of AWS Web Application Firewall (WAF) Web ACL deletion. AWS WAF protects web applications by filtering malicious HTTP/S traffic. A Web ACL acts as the central enforcement point, determining which traffic is inspected, allowed, or blocked. An attacker with sufficient privileges may delete a Web ACL to disable these protections. This action bypasses configured rules, protections, and logging, potentially leading to web-application compromise, data theft, or resource abuse. Because Web ACLs are critical security components, their deletion is rare and can signal malicious activity. This detection focuses on identifying successful `DeleteWebACL` events across WAF Classic, WAF Regional, and WAFv2 APIs in AWS CloudTrail logs.

## Attack Chain

1.  The attacker gains unauthorized access to an AWS account with sufficient IAM permissions to manage WAF resources, potentially through compromised credentials or privilege escalation.
2.  The attacker authenticates to the AWS environment using the compromised credentials or assumed role.
3.  The attacker uses the AWS CLI, SDK, or Management Console to issue a `DeleteWebACL` API call targeting a specific Web ACL.
4.  The API call is successful, and the targeted Web ACL is removed from the AWS environment.
5.  All rules, protections, and logging configurations associated with the deleted Web ACL are immediately disabled.
6.  Web applications previously protected by the deleted Web ACL are now exposed to potentially malicious traffic without filtering or monitoring.
7.  The attacker may then exploit vulnerabilities in the exposed web applications to gain unauthorized access or steal sensitive data.

## Impact

The deletion of a Web ACL can have significant consequences. Applications previously protected by the Web ACL are exposed to direct exploitation. This could lead to web application compromise, data theft, or resource abuse. The number of affected applications depends on the scope of the deleted Web ACL. Successful exploitation can result in financial loss, reputational damage, and legal liabilities.

## Recommendation

*   Enable AWS CloudTrail logging for all regions to capture API activity related to WAF configurations and deletions. Use `data_stream.dataset: aws.cloudtrail` and `event.provider: (waf.amazonaws.com or waf-regional.amazonaws.com or wafv2.amazonaws.com)` to filter logs (see query in this brief).
*   Deploy the Sigma rule to detect unauthorized Web ACL deletions and tune it to your environment, accounting for authorized deletions during maintenance windows or IaC deployments.
*   Restrict IAM permissions for `waf:DeleteWebACL` and `wafv2:DeleteWebACL` to a limited set of trusted roles, enforcing MFA for administrative access to prevent unauthorized deletions.
*   Monitor `aws.cloudtrail.user_identity.arn` and `access_key_id` in CloudTrail logs to identify the actor initiating the deletion and determine if the principal normally manages WAF resources (see investigation fields).
