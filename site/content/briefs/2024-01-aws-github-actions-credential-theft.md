---
title: AWS Credentials Used from GitHub Actions and Non-CI/CD Infrastructure
slug: 2024-01-aws-github-actions-credential-theft
description: Attackers are stealing AWS credentials configured as GitHub Actions secrets and using them from non-CI/CD infrastructure, indicating potential credential theft and unauthorized access to AWS resources.
date: "2026-04-22T17:45:55Z"
type: advisory
types:
  - advisory
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

This threat involves the unauthorized use of AWS credentials stolen from GitHub Actions secrets. Attackers exfiltrate these credentials and use them from their own infrastructure, bypassing the intended CI/CD environment. The activity is detected by observing AWS access keys appearing in CloudTrail logs originating from both legitimate GitHub Actions runners (identified by Microsoft ASN or the `github-actions` user agent string) and suspicious infrastructure outside the expected CI/CD provider ASNs (Amazon, Google, Microsoft). This indicates a breach of GitHub repository or organization secrets, leading to potential unauthorized access and control over AWS resources. This activity can begin with compromised Github accounts.

## Attack Chain

1. An attacker gains unauthorized access to a GitHub repository or organization with AWS credentials stored as secrets.
2. The attacker exfiltrates the AWS access key ID and secret access key, either manually or through automated means, such as modifying a GitHub Action workflow to expose the secrets.
3. The attacker configures the stolen AWS credentials on their own infrastructure, using tools like the AWS CLI or boto3.
4. The attacker attempts to authenticate to AWS using the stolen credentials. This generates CloudTrail logs with the attacker's source IP address and ASN.
5. The attacker performs reconnaissance activities, such as calling `sts:GetCallerIdentity`, `ListBuckets`, `DescribeInstances`, or `ListUsers`, to understand the AWS environment and identify potential targets.
6. The attacker attempts to escalate privileges or move laterally within the AWS environment by exploiting the compromised credentials.
7. The attacker may create, modify, or delete AWS resources, such as EC2 instances, S3 buckets, or IAM roles, depending on the permissions associated with the stolen credentials.

## Impact

Successful exploitation leads to unauthorized access to AWS resources, potentially resulting in data breaches, service disruptions, or financial losses. The impact depends on the permissions associated with the stolen AWS credentials. A single compromised credential could expose sensitive data, disrupt critical services, or allow attackers to deploy malicious infrastructure within the victim's AWS environment. Identifying and responding to this threat quickly is vital to minimize damages.

## Recommendation

*   Deploy the Sigma rule "AWS Credentials Used from GitHub Actions and Non-CI/CD Infrastructure" to your SIEM and tune for your environment to detect suspicious usage patterns.
*   Rotate the compromised AWS access key in IAM immediately and update the corresponding GitHub repository/organization secret as described in the rule documentation.
*   Implement OIDC-based authentication (`aws-actions/configure-aws-credentials` with `role-to-assume`) instead of long-lived access keys as mentioned in the rule documentation.
*   If using OIDC, add IP condition policies to the IAM role trust policy to restrict `AssumeRoleWithWebIdentity` to known GitHub runner IP ranges, based on the information in the rule documentation.
