---
title: AWS Credentials Used from GitHub Actions and Non-CI/CD Infrastructure
slug: 2024-01-aws-github-actions-credential-theft
description: Attackers are stealing AWS credentials configured as GitHub Actions secrets and using them from non-CI/CD infrastructure, indicating potential credential theft and unauthorized access to AWS resources.
date: "2026-04-22T17:45:55Z"
severities:
  - high
tags:
  - cloud
  - aws
  - github
  - credential-theft
  - initial-access
  - lateral-movement
vendors:
  - Amazon
  - Microsoft
  - Google
products:
  - AWS IAM
  - GitHub Actions
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
references:
  - https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html
rules:
  - title: AWS Credentials Used from Non-CI/CD Infrastructure
    description: Detects AWS access keys used from non-CI/CD infrastructure, indicating potential credential theft.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078.004
    data_sources:
      - cloudtrail
      - aws
  - title: AWS Credentials Used by GitHub Actions User Agent from Non-CI/CD Infrastructure
    description: Detects AWS access keys used by the GitHub Actions user agent string from non-CI/CD infrastructure.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078.004
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This threat involves the unauthorized use of AWS credentials stolen from GitHub Actions secrets. Attackers exfiltrate these credentials and use them from their own infrastructure, bypassing the intended CI/CD environment. The activity is detected by observing AWS access keys appearing in CloudTrail logs originating from both legitimate GitHub Actions runners (identified by Microsoft ASN or the `github-actions` user agent string) and suspicious infrastructure outside the expected CI/CD provider…
