---
title: '@hulumi/policies GitHub OIDC Trust Policy Bypass via AWS Set-Qualified Condition Operators'
slug: 2026-05-hulumi-policies-bypass
description: '@hulumi/policies versions before 1.3.2 are vulnerable to a critical trust policy bypass where set-qualified operators such as ForAnyValue:StringLike could hide wildcard GitHub Actions OIDC sub conditions from the mandatory guardrail, potentially allowing unauthorized access to AWS resources.'
date: "2026-05-21T20:48:15Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - github
  - aws
  - iam
  - oidc
  - trust-policy
vendors:
  - GitHub
  - AWS
products:
  - '@hulumi/policies (< 1.3.2)'
  - GitHub Actions
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Trusted Relationship
references:
  - https://github.com/advisories/GHSA-q2f7-m237-v562
rules:
  - title: Detect AWS IAM Role Trust Policy Creation with Set-Qualified Operators Bypassing OIDC Sub Validation
    description: Detects the creation or modification of AWS IAM role trust policies that use set-qualified operators (e.g., ForAnyValue:StringLike) in a way that could bypass the intended validation of GitHub OIDC sub conditions.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - cloudtrail
      - cloudtrail
  - title: Detect AWS IAM Role Trust Policy Modification with Set-Qualified Operators Bypassing OIDC Sub Validation
    description: Detects the modification of AWS IAM role trust policies to use set-qualified operators (e.g., ForAnyValue:StringLike) in a way that could bypass the intended validation of GitHub OIDC sub conditions.
    platform: sigma
    severity: high
    tactics:
      - persistence
    data_sources:
      - cloudtrail
      - cloudtrail
rules_count: 2
---

@hulumi/policies versions before 1.3.2 contain a critical vulnerability related to AWS IAM trust policies. The vulnerability arises because the software's trust policy inspector only checks for exact AWS IAM `StringLike` and `StringEquals` condition operator keys. Attackers can bypass the intended security checks by using set-qualified operators such as `ForAnyValue:StringLike`. These set-qualified operators can obscure wildcard GitHub Actions OIDC `sub` conditions, which are supposed to be validated by the mandatory guardrail. This bypass can potentially lead to unauthorized access to AWS resources. The vulnerability is patched in version 1.3.2, which introduces proper evaluation of set-qualified string operators and rejects unsafe GitHub OIDC `sub` conditions.

## Attack Chain

1. An attacker gains control of a GitHub Actions workflow.
2. The attacker modifies the workflow to request an OIDC token from the GitHub Actions environment.
3. The attacker crafts a malicious AWS IAM role trust policy using a set-qualified condition operator (e.g., `ForAnyValue:StringLike`) to bypass the guardrail implemented by @hulumi/policies. This crafted policy obscures the intended `StringLike` or `StringEquals` checks on the `sub` claim of the OIDC token.
4. The attacker's workflow uses the AWS CLI or SDK with the crafted trust policy to assume the IAM role.
5. Due to the bypassed validation, the attacker's request succeeds, and the workflow obtains temporary AWS credentials associated with the IAM role.
6. The attacker leverages the acquired AWS credentials to perform unauthorized actions within the AWS environment.
7. The attacker may exfiltrate sensitive data, modify infrastructure configurations, or deploy malicious resources, depending on the permissions granted to the assumed IAM role.

## Impact

Successful exploitation of this vulnerability allows attackers to bypass the intended OIDC-based access controls for AWS resources. This can lead to unauthorized access to sensitive data, infrastructure modifications, or deployment of malicious resources within the AWS environment. The severity is critical because it directly undermines the trust relationship between GitHub Actions and AWS, potentially affecting any organization using @hulumi/policies for managing these integrations.

## Recommendation

*   Upgrade `@hulumi/policies` to version 1.3.2 or later to incorporate the patch that properly evaluates set-qualified string operators.
*   Manually review existing AWS IAM role trust policies that rely on @hulumi/policies to identify and remediate any instances where set-qualified operators are used in a way that could bypass the intended validation of GitHub OIDC `sub` conditions.
*   Implement monitoring and alerting on AWS IAM role assumption events to detect any suspicious activity that may indicate exploitation attempts, using the principle of least privilege to limit the impact of compromised roles.
*   Consider using tools and services that provide continuous monitoring of IAM configurations and compliance with security best practices.
